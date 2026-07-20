//! Runtime v10 durable PairInvite 与 OpenPairRoute outbox。
//!
//! 本片只实现 `routeOpening -> unused`。PairRequest、确认、grant、close 与撤销由后续
//! 子片扩展；当前 loader 对未知状态或未实现表 fail-close。

use std::collections::HashSet;

use agentdeck_crypto::{
    HpkePrivateKey, HpkePublicKey, VerifiedPairRequestV1, open_pair_request_verified,
};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind, PairInviteV1, PairRequestInfoV1,
    PairRequestPlaintextV1, PairRequestV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    OpaqueRouteFrame, OpenPairRoute, PairData, PairRouteOpened, RelayFrameBody, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    MachineRouteId, PairRouteId, RELAY_PROTOCOL_VERSION, decode, encode,
};
use agentdeck_protocol::runtime::identity::PairingId;
use agentdeck_protocol::runtime::{
    PairingReceipt, PairingState, PendingPairing, RUNTIME_PROTOCOL_VERSION,
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::model::{
    IdempotencyOwner, MAX_IDEMPOTENCY_KEY_BYTES, MachineEnrollmentState, RuntimeCommitOperation,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::SecretBytes;

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle};
use super::identity::{
    MAX_RUNTIME_ID_COLLISION_ATTEMPTS, RuntimeId, RuntimeIdError, RuntimeIdKind,
};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const PAIRING_TABLE: &[u8] = b"remote_pairings";
const PAIRING_COLUMN: &[u8] = b"sealed_state";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
const PAIRING_PAYLOAD_MAGIC_V1: &[u8; 4] = b"ADP1";
const PAIRING_PAYLOAD_MAGIC_V2: &[u8; 4] = b"ADP2";
const PAIRING_PAYLOAD_MAGIC_V3: &[u8; 4] = b"ADP3";
const PAIRING_PAYLOAD_MAGIC_V4: &[u8; 4] = b"ADP4";
const PAIRING_PAYLOAD_MAGIC_V5: &[u8; 4] = b"ADP5";
const PAIRING_METADATA_DOMAIN: &[u8] = b"remote.pairing.metadata.v1";
const PAIRING_REQUEST_METADATA_DOMAIN: &[u8] = b"remote.pairing.metadata.v2";
const PAIRING_GRANT_METADATA_DOMAIN: &[u8] = b"remote.pairing.metadata.v3";
const PAIRING_IDEMPOTENCY_DOMAIN: &[u8] = b"remote.pairing.idempotency.v1";
const OUTBOX_METADATA_DOMAIN: &[u8] = b"remote.control.outbox.metadata.v1";
const OPEN_OPERATION_DOMAIN: &[u8] = b"remote.control.open-pair-route.operation.v1";
pub(crate) const MAX_PAIRING_STATE_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CONTROL_FRAME_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_ACTIVE_PAIRINGS: u64 = 8;
pub(super) const MAX_PAIRING_SEALED_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_CONTROL_OUTBOX: u64 = 1_024;
pub(super) const MAX_CONTROL_OUTBOX_SEALED_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) struct PreparePairingInvite {
    owner: IdempotencyOwner,
    idempotency_key: String,
    canonical_invite: SecretBytes,
    invite_hpke_private_key: SecretBytes,
}

impl PreparePairingInvite {
    #[must_use]
    pub(crate) fn new(
        owner: IdempotencyOwner,
        idempotency_key: String,
        canonical_invite: SecretBytes,
        invite_hpke_private_key: SecretBytes,
    ) -> Self {
        Self {
            owner,
            idempotency_key,
            canonical_invite,
            invite_hpke_private_key,
        }
    }
}

impl std::fmt::Debug for PreparePairingInvite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparePairingInvite([REDACTED])")
    }
}

pub(crate) struct PreparedPairingInviteWrite {
    owner: Vec<u8>,
    idempotency_key: String,
    canonical_invite: SecretBytes,
    invite_hpke_private_key: SecretBytes,
    input_hash: [u8; 32],
    retained_bytes: usize,
}

pub(crate) struct AcceptPairRequest {
    pairing_id: RuntimeId,
    verified: VerifiedPairRequestV1,
}

pub(crate) struct CommitPairPending {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    envelope: PairingControlEnvelopeV1,
}

impl CommitPairPending {
    #[must_use]
    pub(crate) const fn new(
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        envelope: PairingControlEnvelopeV1,
    ) -> Self {
        Self {
            pairing_id,
            request_hash,
            envelope,
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.envelope.enc.capacity() + self.envelope.ciphertext.capacity()
    }
}

impl std::fmt::Debug for CommitPairPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommitPairPending([REDACTED])")
    }
}

impl AcceptPairRequest {
    #[must_use]
    pub(crate) const fn new(pairing_id: RuntimeId, verified: VerifiedPairRequestV1) -> Self {
        Self {
            pairing_id,
            verified,
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.verified.retained_bytes()
    }
}

impl std::fmt::Debug for AcceptPairRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcceptPairRequest([REDACTED])")
    }
}

impl PreparedPairingInviteWrite {
    pub(crate) const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingInviteLifecycle {
    RouteOpening,
    Unused,
    Preparing,
    AwaitingLocalConfirmation,
    GrantPreparing,
    GrantCommitted,
    Delivered,
    OrphanRevoking,
    Canceled,
    Expired,
}

impl PairingInviteLifecycle {
    const fn tag(self) -> u8 {
        match self {
            Self::RouteOpening => 0,
            Self::Unused => 1,
            Self::Preparing => 2,
            Self::AwaitingLocalConfirmation => 3,
            Self::GrantPreparing => 4,
            Self::GrantCommitted => 5,
            Self::Delivered => 6,
            Self::OrphanRevoking => 7,
            Self::Canceled => 8,
            Self::Expired => 9,
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "routeOpening" => Ok(Self::RouteOpening),
            "unused" => Ok(Self::Unused),
            "preparing" => Ok(Self::Preparing),
            "awaitingLocalConfirmation" => Ok(Self::AwaitingLocalConfirmation),
            "grantPreparing" => Ok(Self::GrantPreparing),
            "grantCommitted" => Ok(Self::GrantCommitted),
            "delivered" => Ok(Self::Delivered),
            "orphanRevoking" => Ok(Self::OrphanRevoking),
            "canceled" => Ok(Self::Canceled),
            "expired" => Ok(Self::Expired),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

pub(crate) struct PairingInviteRecord {
    pub(super) pairing_id: RuntimeId,
    pub(super) pair_route: RuntimeId,
    pub(super) lifecycle: PairingInviteLifecycle,
    pub(super) relay_server_id: [u8; 16],
    pub(super) machine_route: [u8; 16],
    pub(super) expires_at_ms: u64,
    pub(super) created_at_ms: u64,
    pub(super) state_changed_at_ms: u64,
    pub(super) canonical_invite: SecretBytes,
    pub(super) invite_hpke_private_key: SecretBytes,
    pub(super) canonical_open_frame: Vec<u8>,
    pub(super) request_hash: Option<[u8; 32]>,
    pub(super) device_sign_fingerprint: Option<[u8; 32]>,
    pub(super) request_received_at_ms: Option<u64>,
    pub(super) canonical_pair_request: Option<SecretBytes>,
    pub(super) canonical_pair_request_plaintext: Option<SecretBytes>,
    pub(super) canonical_pending_frame: Option<Vec<u8>>,
    pub(super) grant_hash: Option<[u8; 32]>,
    pub(super) response_hash: Option<[u8; 32]>,
    pub(super) canonical_relay_grant: Option<Vec<u8>>,
    pub(super) canonical_device_authorization: Option<SecretBytes>,
    pub(super) canonical_key_directory_view: Option<SecretBytes>,
    pub(super) canonical_pair_response: Option<SecretBytes>,
    pub(super) canonical_install_frame: Option<Vec<u8>>,
    pub(super) global_key_state_hash: Option<[u8; 32]>,
    pub(super) delivery_receipt_hash: Option<[u8; 32]>,
}

pub(crate) struct PairPendingPreparation {
    request_hash: [u8; 32],
    info: PairRequestInfoV1,
    context: OuterContextV1,
    recipient: HpkePublicKey,
}

impl std::fmt::Debug for PairPendingPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairPendingPreparation")
            .field("binding", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PairPendingPreparation {
    #[must_use]
    pub(crate) const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub(crate) const fn info(&self) -> &PairRequestInfoV1 {
        &self.info
    }

    #[must_use]
    pub(crate) const fn context(&self) -> &OuterContextV1 {
        &self.context
    }

    #[must_use]
    pub(crate) const fn recipient(&self) -> &HpkePublicKey {
        &self.recipient
    }
}

impl std::fmt::Debug for PairingInviteRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingInviteRecord")
            .field("pairing_id", &self.pairing_id)
            .field("pair_route", &self.pair_route)
            .field("lifecycle", &self.lifecycle)
            .field("expires_at_ms", &self.expires_at_ms)
            .field(
                "invite_hpke_private_key_bytes",
                &self.invite_hpke_private_key.expose_secret().len(),
            )
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PairingInviteRecord {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> RuntimeId {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn pair_route(&self) -> RuntimeId {
        self.pair_route
    }

    #[must_use]
    pub(crate) const fn lifecycle(&self) -> PairingInviteLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub(crate) const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub(crate) fn canonical_invite(&self) -> &[u8] {
        self.canonical_invite.expose_secret()
    }

    pub(crate) fn into_invite_hpke_private_key(self) -> Result<HpkePrivateKey, RuntimeStoreError> {
        if self.lifecycle != PairingInviteLifecycle::Unused {
            return Err(RuntimeStoreError::PairingConflict);
        }
        HpkePrivateKey::from_bytes(self.invite_hpke_private_key.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    #[must_use]
    pub(crate) fn canonical_open_frame(&self) -> &[u8] {
        &self.canonical_open_frame
    }

    #[must_use]
    pub(crate) const fn request_hash(&self) -> Option<[u8; 32]> {
        self.request_hash
    }

    #[must_use]
    pub(crate) const fn device_sign_fingerprint(&self) -> Option<[u8; 32]> {
        self.device_sign_fingerprint
    }

    #[must_use]
    pub(crate) const fn request_received_at_ms(&self) -> Option<u64> {
        self.request_received_at_ms
    }

    #[must_use]
    pub(crate) fn canonical_pair_request(&self) -> Option<&[u8]> {
        self.canonical_pair_request
            .as_ref()
            .map(SecretBytes::expose_secret)
    }

    #[must_use]
    pub(crate) fn canonical_pending_frame(&self) -> Option<&[u8]> {
        self.canonical_pending_frame.as_deref()
    }

    pub(crate) fn pair_pending_preparation(
        &self,
    ) -> Result<Option<PairPendingPreparation>, RuntimeStoreError> {
        if self.lifecycle != PairingInviteLifecycle::Preparing {
            return Ok(None);
        }
        let request_hash = self
            .request_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let plaintext = PairRequestPlaintextV1::from_canonical_bytes(
            self.canonical_pair_request_plaintext
                .as_ref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .expose_secret(),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let invite = PairInviteV1::from_canonical_bytes(self.canonical_invite.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let recipient = HpkePublicKey::from_bytes(&plaintext.device_hpke_pubkey.0)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok(Some(PairPendingPreparation {
            request_hash,
            info: pair_request_info(&invite)?,
            context: pairing_context(&invite, OuterFrameKind::PairPending),
            recipient,
        }))
    }
}

#[derive(Debug)]
pub(crate) enum PreparePairingInviteOutcome {
    Prepared {
        invite: PairingInviteRecord,
    },
    Replayed {
        invite: PairingInviteRecord,
    },
    Terminal {
        receipt: PairingReceipt,
        state: PairingState,
    },
}

#[derive(Debug)]
pub(crate) enum AcceptPairRequestOutcome {
    Accepted { pairing: PairingInviteRecord },
    Replayed { pairing: PairingInviteRecord },
}

#[derive(Debug)]
pub(crate) enum CommitPairPendingOutcome {
    Committed { pairing: PairingInviteRecord },
    Replayed { pairing: PairingInviteRecord },
}

#[derive(Debug)]
pub(crate) struct AcknowledgePairRouteOpenOutcome {
    invite: PairingInviteRecord,
    replayed: bool,
}

impl AcknowledgePairRouteOpenOutcome {
    #[must_use]
    pub(crate) const fn invite(&self) -> &PairingInviteRecord {
        &self.invite
    }

    #[must_use]
    pub(crate) const fn replayed(&self) -> bool {
        self.replayed
    }
}

struct StoredPayload {
    owner: Vec<u8>,
    idempotency_key: String,
    invite: PairInviteV1,
    canonical_invite: SecretBytes,
    invite_hpke_private_key: SecretBytes,
    canonical_open_frame: Vec<u8>,
    expected_terminal: Vec<u8>,
    input_hash: [u8; 32],
    canonical_pair_request: Option<SecretBytes>,
    canonical_pair_request_plaintext: Option<SecretBytes>,
    request_received_at_ms: Option<u64>,
    canonical_pending_frame: Option<Vec<u8>>,
    grant_hash: Option<[u8; 32]>,
    response_hash: Option<[u8; 32]>,
    canonical_relay_grant: Option<Vec<u8>>,
    canonical_device_authorization: Option<SecretBytes>,
    canonical_key_directory_view: Option<SecretBytes>,
    canonical_pair_response: Option<SecretBytes>,
    canonical_install_frame: Option<Vec<u8>>,
    global_key_state_hash: Option<[u8; 32]>,
    delivery_receipt_hash: Option<[u8; 32]>,
}

pub(super) struct AuthenticatedPairingRow {
    pub(super) record: PairingInviteRecord,
    pub(super) owner: Vec<u8>,
    pub(super) idempotency_key: String,
    pub(super) expected_terminal: Vec<u8>,
    pub(super) input_hash: [u8; 32],
    pub(super) sealed_state_bytes: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) struct AuthenticatedOutboxRow {
    pub(super) outbox_id: RuntimeId,
    pub(super) pairing_id: RuntimeId,
    pub(super) operation_key: [u8; 32],
    pub(super) frame_hash: [u8; 32],
    pub(super) canonical_frame: Vec<u8>,
    pub(super) sealed_frame_bytes: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) struct PairingDirectory {
    pub(super) ledger: RuntimeLedger,
    pub(super) pairings: Vec<AuthenticatedPairingRow>,
    pub(super) outboxes: Vec<AuthenticatedOutboxRow>,
    pub(super) terminal: super::pairing_terminal::AuthenticatedTerminalDirectory,
    pub(super) grants: super::pairing_grant::AuthenticatedGrantDirectory,
}

type RawPairingRow = (
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Vec<u8>,
);
type RawOutboxRow = (
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
    i64,
    Vec<u8>,
);

pub(crate) fn prepare_write(
    input: PreparePairingInvite,
) -> Result<PreparedPairingInviteWrite, RuntimeStoreError> {
    if input.idempotency_key.is_empty() || input.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::InvalidConfig(
            "idempotency key must contain 1 to 1024 UTF-8 bytes",
        ));
    }
    let owner = super::journal::canonical_owner_v1(&input.owner);
    super::journal::decode_canonical_owner(&owner)?;
    let parsed = parse_invite_keypair(
        input.canonical_invite.expose_secret(),
        input.invite_hpke_private_key.expose_secret(),
    )
    .map_err(|()| RuntimeStoreError::PairingConflict)?;
    let input_hash = pairing_input_hash(&owner, &input.idempotency_key, &parsed)?;
    let retained_bytes = owner
        .len()
        .checked_add(input.idempotency_key.capacity())
        .and_then(|value| value.checked_add(input.canonical_invite.retained_capacity()))
        .and_then(|value| value.checked_add(input.invite_hpke_private_key.retained_capacity()))
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    Ok(PreparedPairingInviteWrite {
        owner,
        idempotency_key: input.idempotency_key,
        canonical_invite: input.canonical_invite,
        invite_hpke_private_key: input.invite_hpke_private_key,
        input_hash,
        retained_bytes,
    })
}

fn pairing_input_hash(
    owner: &[u8],
    idempotency_key: &str,
    invite: &PairInviteV1,
) -> Result<[u8; 32], RuntimeStoreError> {
    let canonical = Zeroizing::new(encode_fields(
        b"ADI2",
        &[
            owner,
            idempotency_key.as_bytes(),
            invite.machine_display_name.as_bytes(),
        ],
    )?);
    Ok(Sha256::digest(canonical.as_slice()).into())
}

pub(super) fn pairing_idempotency_token(
    key_bundle: &RuntimeKeyBundle,
    owner: &[u8],
    idempotency_key: &str,
) -> Result<[u8; 32], RuntimeStoreError> {
    let canonical = Zeroizing::new(encode_fields(
        b"ADIK",
        &[owner, idempotency_key.as_bytes()],
    )?);
    let token = *key_bundle
        .blind_index(PAIRING_IDEMPOTENCY_DOMAIN, canonical.as_slice())?
        .as_bytes();
    if token == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(token)
}

fn parse_invite_keypair(
    canonical_invite: &[u8],
    invite_hpke_private_key: &[u8],
) -> Result<PairInviteV1, ()> {
    if invite_hpke_private_key.len() != 32 || invite_hpke_private_key.iter().all(|byte| *byte == 0)
    {
        return Err(());
    }
    let invite = PairInviteV1::from_canonical_bytes(canonical_invite).map_err(|_| ())?;
    if invite.canonical_bytes().map_err(|_| ())? != canonical_invite {
        return Err(());
    }
    let private_key = HpkePrivateKey::from_bytes(invite_hpke_private_key).map_err(|_| ())?;
    if private_key.public_key().to_bytes() != invite.invite_hpke_pubkey.0 {
        return Err(());
    }
    Ok(invite)
}

fn encode_fields(magic: &[u8; 4], fields: &[&[u8]]) -> Result<Vec<u8>, RuntimeStoreError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(magic);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    Ok(encoded)
}

fn decode_fields<'a>(
    encoded: &'a [u8],
    magic: &[u8; 4],
    count: usize,
) -> Result<Vec<&'a [u8]>, RuntimeStoreError> {
    if encoded.get(..4) != Some(magic) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = 4_usize;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            encoded
                .get(cursor..length_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let end = cursor
            .checked_add(
                usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        fields.push(
            encoded
                .get(cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = end;
    }
    if cursor != encoded.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
}

fn encode_payload(
    prepared: &PreparedPairingInviteWrite,
    open_frame: &[u8],
    expected_terminal: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let encoded = Zeroizing::new(encode_fields(
        PAIRING_PAYLOAD_MAGIC_V1,
        &[
            &prepared.owner,
            prepared.idempotency_key.as_bytes(),
            prepared.canonical_invite.expose_secret(),
            prepared.invite_hpke_private_key.expose_secret(),
            open_frame,
            expected_terminal,
            &prepared.input_hash,
        ],
    )?);
    if encoded.len() > MAX_PAIRING_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
fn encode_payload_fields(
    owner: &[u8],
    idempotency_key: &str,
    canonical_invite: &[u8],
    invite_hpke_private_key: &[u8],
    open_frame: &[u8],
    expected_terminal: &[u8],
    input_hash: &[u8; 32],
    canonical_pair_request: Option<&[u8]>,
    canonical_pair_request_plaintext: Option<&[u8]>,
    request_received_at_ms: Option<u64>,
    canonical_pending_frame: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let (canonical_pair_request, canonical_pair_request_plaintext, request_received_at_ms) = match (
        canonical_pair_request,
        canonical_pair_request_plaintext,
        request_received_at_ms,
    ) {
        (Some(request), Some(plaintext), Some(received_at_ms)) => {
            (request, plaintext, received_at_ms)
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let received = request_received_at_ms.to_be_bytes();
    let encoded = Zeroizing::new(if let Some(pending_frame) = canonical_pending_frame {
        encode_fields(
            PAIRING_PAYLOAD_MAGIC_V3,
            &[
                owner,
                idempotency_key.as_bytes(),
                canonical_invite,
                invite_hpke_private_key,
                open_frame,
                expected_terminal,
                input_hash,
                canonical_pair_request,
                canonical_pair_request_plaintext,
                &received,
                pending_frame,
            ],
        )?
    } else {
        encode_fields(
            PAIRING_PAYLOAD_MAGIC_V2,
            &[
                owner,
                idempotency_key.as_bytes(),
                canonical_invite,
                invite_hpke_private_key,
                open_frame,
                expected_terminal,
                input_hash,
                canonical_pair_request,
                canonical_pair_request_plaintext,
                &received,
            ],
        )?
    });
    if encoded.len() > MAX_PAIRING_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

fn decode_payload(encoded: &[u8]) -> Result<StoredPayload, RuntimeStoreError> {
    let fields = if encoded.get(..4) == Some(&PAIRING_PAYLOAD_MAGIC_V1[..]) {
        decode_fields(encoded, PAIRING_PAYLOAD_MAGIC_V1, 7)?
    } else if encoded.get(..4) == Some(&PAIRING_PAYLOAD_MAGIC_V2[..]) {
        decode_fields(encoded, PAIRING_PAYLOAD_MAGIC_V2, 10)?
    } else if encoded.get(..4) == Some(&PAIRING_PAYLOAD_MAGIC_V3[..]) {
        decode_fields(encoded, PAIRING_PAYLOAD_MAGIC_V3, 11)?
    } else if encoded.get(..4) == Some(&PAIRING_PAYLOAD_MAGIC_V4[..]) {
        decode_fields(encoded, PAIRING_PAYLOAD_MAGIC_V4, 19)?
    } else {
        decode_fields(encoded, PAIRING_PAYLOAD_MAGIC_V5, 20)?
    };
    let owner = fields[0].to_vec();
    super::journal::decode_canonical_owner(&owner)?;
    let idempotency_key = std::str::from_utf8(fields[1])
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        .to_owned();
    if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let canonical_invite = SecretBytes::new(fields[2].to_vec());
    let invite_hpke_private_key = SecretBytes::new(fields[3].to_vec());
    let invite = parse_invite_keypair(
        canonical_invite.expose_secret(),
        invite_hpke_private_key.expose_secret(),
    )
    .map_err(|()| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_open_frame = fields[4].to_vec();
    let expected_terminal = fields[5].to_vec();
    let input_hash: [u8; 32] = fields[6]
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if pairing_input_hash(&owner, &idempotency_key, &invite)? != input_hash {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let (
        canonical_pair_request,
        canonical_pair_request_plaintext,
        request_received_at_ms,
        canonical_pending_frame,
    ) = if fields.len() == 7 {
        (None, None, None, None)
    } else {
        if fields[7].is_empty() || fields[8].is_empty() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let request = SecretBytes::new(fields[7].to_vec());
        let plaintext = SecretBytes::new(fields[8].to_vec());
        let received = u64::from_be_bytes(
            fields[9]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        let pending = (fields.len() >= 11).then(|| fields[10].to_vec());
        if pending.as_ref().is_some_and(Vec::is_empty) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        (Some(request), Some(plaintext), Some(received), pending)
    };
    let (
        grant_hash,
        response_hash,
        canonical_relay_grant,
        canonical_device_authorization,
        canonical_key_directory_view,
        canonical_pair_response,
        canonical_install_frame,
        global_key_state_hash,
    ) = if fields.len() >= 19 {
        let required = |index: usize| {
            let value = fields[index];
            (!value.is_empty())
                .then_some(value)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
        };
        (
            Some(
                required(11)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ),
            Some(
                required(12)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ),
            Some(required(13)?.to_vec()),
            Some(SecretBytes::new(required(14)?.to_vec())),
            Some(SecretBytes::new(required(15)?.to_vec())),
            Some(SecretBytes::new(required(16)?.to_vec())),
            Some(required(17)?.to_vec()),
            Some(
                required(18)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ),
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };
    let delivery_receipt_hash = if fields.len() == 20 {
        let hash: [u8; 32] = fields[19]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if hash == [0; 32] {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Some(hash)
    } else {
        None
    };
    Ok(StoredPayload {
        owner,
        idempotency_key,
        invite,
        canonical_invite,
        invite_hpke_private_key,
        canonical_open_frame,
        expected_terminal,
        input_hash,
        canonical_pair_request,
        canonical_pair_request_plaintext,
        request_received_at_ms,
        canonical_pending_frame,
        grant_hash,
        response_hash,
        canonical_relay_grant,
        canonical_device_authorization,
        canonical_key_directory_view,
        canonical_pair_response,
        canonical_install_frame,
        global_key_state_hash,
        delivery_receipt_hash,
    })
}

fn seal(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8; 16],
    column: &[u8],
    plaintext: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        plaintext,
        maximum,
    )?)
}

fn open(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8; 16],
    column: &[u8],
    ciphertext: &[u8],
    maximum: usize,
) -> Result<SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        ciphertext,
        maximum,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn pairing_row_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
    lifecycle: PairingInviteLifecycle,
    relay_server_id: [u8; 16],
    machine_route: [u8; 16],
    pair_route: RuntimeId,
    expires_at_ms: u64,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    request_hash: Option<[u8; 32]>,
    device_sign_fingerprint: Option<[u8; 32]>,
    grant_hash: Option<[u8; 32]>,
    response_hash: Option<[u8; 32]>,
    sealed_state: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed_state.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash: [u8; 32] = Sha256::digest(sealed_state).into();
    let lifecycle_tag = [lifecycle.tag()];
    let expires_at = expires_at_ms.to_be_bytes();
    let created_at = created_at_ms.to_be_bytes();
    let state_changed_at = state_changed_at_ms.to_be_bytes();
    let sealed_len = sealed_len.to_be_bytes();
    let common = [
        &database_id[..],
        &pairing_id.as_bytes()[..],
        &lifecycle_tag[..],
        &relay_server_id[..],
        &machine_route[..],
        &pair_route.as_bytes()[..],
        &expires_at[..],
        &created_at[..],
        &state_changed_at[..],
        &sealed_len[..],
        &sealed_hash[..],
    ];
    match (
        request_hash,
        device_sign_fingerprint,
        grant_hash,
        response_hash,
    ) {
        (None, None, None, None) => {
            super::stream::metadata_mac(key_bundle, PAIRING_METADATA_DOMAIN, &common)
        }
        (Some(request_hash), Some(device_sign_fingerprint), None, None) => {
            let mut fields = common.to_vec();
            fields.push(&request_hash);
            fields.push(&device_sign_fingerprint);
            super::stream::metadata_mac(key_bundle, PAIRING_REQUEST_METADATA_DOMAIN, &fields)
        }
        (
            Some(request_hash),
            Some(device_sign_fingerprint),
            Some(grant_hash),
            Some(response_hash),
        ) => {
            let mut fields = common.to_vec();
            fields.push(&request_hash);
            fields.push(&device_sign_fingerprint);
            fields.push(&grant_hash);
            fields.push(&response_hash);
            super::stream::metadata_mac(key_bundle, PAIRING_GRANT_METADATA_DOMAIN, &fields)
        }
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

#[allow(clippy::too_many_arguments)]
fn outbox_row_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    outbox_id: RuntimeId,
    operation_key: [u8; 32],
    pairing_id: RuntimeId,
    frame_hash: [u8; 32],
    sealed_frame: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed_frame.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash: [u8; 32] = Sha256::digest(sealed_frame).into();
    super::stream::metadata_mac(
        key_bundle,
        OUTBOX_METADATA_DOMAIN,
        &[
            &database_id,
            outbox_id.as_bytes(),
            b"openPairRoute",
            &operation_key,
            b"prepared",
            pairing_id.as_bytes(),
            &frame_hash,
            &sealed_len.to_be_bytes(),
            &sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

fn open_operation_key(
    key_bundle: &RuntimeKeyBundle,
    pairing_id: RuntimeId,
) -> Result<[u8; 32], RuntimeStoreError> {
    let token = key_bundle.blind_index(OPEN_OPERATION_DOMAIN, pairing_id.as_bytes())?;
    let value = *token.as_bytes();
    if value == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(value)
}

fn exact_frame(bytes: &[u8]) -> Result<OpaqueRouteFrame, RuntimeStoreError> {
    if bytes.len() > MAX_CONTROL_FRAME_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let frame = decode(bytes).map_err(|_| RuntimeStoreError::PairingConflict)?;
    if encode(&frame) != bytes {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(frame)
}

fn exact_pending_frame(
    bytes: &[u8],
    expected_pair_route: RuntimeId,
) -> Result<PairingControlEnvelopeV1, RuntimeStoreError> {
    let frame = exact_frame(bytes)?;
    let RelayFrameBody::PairData(PairData {
        pair_route,
        sealed_blob,
    }) = frame.body
    else {
        return Err(RuntimeStoreError::PairingConflict);
    };
    if pair_route.as_bytes() != expected_pair_route.as_bytes() {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let envelope = PairingControlEnvelopeV1::from_canonical_bytes(&sealed_blob.0)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if envelope
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::PairingConflict)?
        != sealed_blob.0
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(envelope)
}

fn frozen_frames(
    machine_route: [u8; 16],
    pair_route: [u8; 16],
    expires_at_ms: u64,
) -> (Vec<u8>, Vec<u8>) {
    let machine_route = MachineRouteId::from_bytes(machine_route);
    let pair_route = PairRouteId::from_bytes(pair_route);
    let open_frame = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::OpenPairRoute(OpenPairRoute {
            machine_route,
            pair_route,
            absolute_expiry_ms: expires_at_ms,
        }),
    });
    let terminal = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route,
            pair_route,
            absolute_expiry_ms: expires_at_ms,
        }),
    });
    (open_frame, terminal)
}

fn validate_invite_for_active_machine(
    prepared: &PreparedPairingInviteWrite,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
    now_ms: u64,
) -> Result<PairInviteV1, RuntimeStoreError> {
    let invite = PairInviteV1::from_canonical_bytes(prepared.canonical_invite.expose_secret())
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    invite
        .validate(now_ms)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    validate_invite_binding(&invite, active)?;
    Ok(invite)
}

fn validate_invite_binding(
    invite: &PairInviteV1,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
) -> Result<(), RuntimeStoreError> {
    invite
        .validate_static()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pins = &active.connection.spki_pins;
    let current_pin = pins
        .first()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let next_pin = pins.get(1).unwrap_or(current_pin);
    if invite.relay_server_id != active.connection.relay_server_id
        || invite.wss_url != active.connection.public_wss_url
        || invite.current_spki_pin != current_pin.0
        || invite.next_spki_pin != next_pin.0
        || invite.machine_root_pubkey.0 != active.binding.root_public_key
        || invite.machine_root_fingerprint != active.binding.root_fingerprint
        || invite.data_sign_cert != active.data_cert
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn pair_request_info(invite: &PairInviteV1) -> Result<PairRequestInfoV1, RuntimeStoreError> {
    Ok(PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite
            .canonical_sha256()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        expiry_ms: invite.expires_at_ms,
    })
}

fn pair_request_context(invite: &PairInviteV1) -> OuterContextV1 {
    pairing_context(invite, OuterFrameKind::PairRequest)
}

fn pairing_context(invite: &PairInviteV1, frame_kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(invite.pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn authenticate_request_material(
    invite: &PairInviteV1,
    invite_hpke_private_key: &[u8],
    canonical_request: &[u8],
    canonical_plaintext: &[u8],
    supplied_info: Option<&PairRequestInfoV1>,
    supplied_context: Option<&OuterContextV1>,
) -> Result<([u8; 32], [u8; 32]), RuntimeStoreError> {
    let request = PairRequestV1::from_canonical_bytes(canonical_request)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if request
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::PairingConflict)?
        != canonical_request
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let plaintext = PairRequestPlaintextV1::from_canonical_bytes(canonical_plaintext)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if plaintext
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::PairingConflict)?
        != canonical_plaintext
        || plaintext.invite_secret != invite.invite_secret
        || HpkePublicKey::from_bytes(&plaintext.device_hpke_pubkey.0).is_err()
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let expected_info = pair_request_info(invite)?;
    let expected_context = pair_request_context(invite);
    if supplied_info.is_some_and(|actual| actual != &expected_info)
        || supplied_context.is_some_and(|actual| actual != &expected_context)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let private_key = HpkePrivateKey::from_bytes(invite_hpke_private_key)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let verified = open_pair_request_verified(
        &private_key,
        &expected_info,
        &expected_context,
        &invite.invite_secret,
        &request,
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if verified.canonical_request() != canonical_request
        || verified.canonical_plaintext() != canonical_plaintext
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let request_hash = verified.request_hash();
    let fingerprint = plaintext.device_sign_fingerprint();
    if request_hash == [0; 32] || fingerprint == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok((request_hash, fingerprint))
}

pub(super) fn active_machine(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Box<crate::runtime::model::ActiveMachineEnrollmentState>, RuntimeStoreError> {
    match super::machine_remote::load_machine_enrollment_state(connection, key_bundle, database_id)?
    {
        Some(MachineEnrollmentState::Active(active)) => Ok(active),
        _ => Err(RuntimeStoreError::PairingConflict),
    }
}

fn authenticate_pairing_row(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawPairingRow,
) -> Result<AuthenticatedPairingRow, RuntimeStoreError> {
    let pairing_id = runtime_id(RuntimeIdKind::Pairing, raw.0)?;
    let lifecycle = PairingInviteLifecycle::parse(&raw.1)?;
    let database_id = fixed(raw.2)?;
    let relay_server_id = fixed(raw.3)?;
    let machine_route = fixed(raw.4)?;
    let pair_route = runtime_id(RuntimeIdKind::PairRoute, raw.5)?;
    let expires_at_ms = nonnegative(raw.6)?;
    let created_at_ms = nonnegative(raw.7)?;
    let state_changed_at_ms = nonnegative(raw.8)?;
    let request_hash = raw.9.map(fixed).transpose()?;
    let device_sign_fingerprint = raw.10.map(fixed).transpose()?;
    let grant_hash = raw.11.map(fixed).transpose()?;
    let response_hash = raw.12.map(fixed).transpose()?;
    let sealed_state_bytes = nonnegative(raw.14)?;
    let metadata_token = fixed(raw.15)?;
    if database_id != expected_database_id
        || sealed_state_bytes
            != u64::try_from(raw.13.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || created_at_ms >= expires_at_ms
        || state_changed_at_ms < created_at_ms
        || pairing_row_token(
            key_bundle,
            database_id,
            pairing_id,
            lifecycle,
            relay_server_id,
            machine_route,
            pair_route,
            expires_at_ms,
            created_at_ms,
            state_changed_at_ms,
            request_hash,
            device_sign_fingerprint,
            grant_hash,
            response_hash,
            &raw.13,
        )? != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open(
        key_bundle,
        database_id,
        PAIRING_TABLE,
        pairing_id.as_bytes(),
        PAIRING_COLUMN,
        &raw.13,
        MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let payload = decode_payload(plaintext.expose_secret())?;
    let invite = &payload.invite;
    if invite
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != payload.canonical_invite.expose_secret()
        || invite.pair_route.as_bytes() != pair_route.as_bytes()
        || invite.relay_server_id.as_bytes() != &relay_server_id
        || invite.expires_at_ms != expires_at_ms
        || !matches!(
            exact_frame(&payload.canonical_open_frame)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                .body,
            RelayFrameBody::OpenPairRoute(OpenPairRoute {
                machine_route: actual_machine,
                pair_route: actual_pair,
                absolute_expiry_ms: actual_expiry,
            }) if actual_machine.as_bytes() == &machine_route
                && actual_pair.as_bytes() == pair_route.as_bytes()
                && actual_expiry == expires_at_ms
        )
        || !matches!(
            exact_frame(&payload.expected_terminal)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                .body,
            RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: actual_machine,
                pair_route: actual_pair,
                absolute_expiry_ms: actual_expiry,
            }) if actual_machine.as_bytes() == &machine_route
                && actual_pair.as_bytes() == pair_route.as_bytes()
                && actual_expiry == expires_at_ms
        )
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let request_material = match (
        payload.canonical_pair_request.as_ref(),
        payload.canonical_pair_request_plaintext.as_ref(),
        payload.request_received_at_ms,
    ) {
        (None, None, None) => None,
        (Some(request), Some(request_plaintext), Some(received_at_ms)) => {
            if received_at_ms < created_at_ms
                || received_at_ms > state_changed_at_ms
                || received_at_ms >= expires_at_ms
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Some(
                authenticate_request_material(
                    invite,
                    payload.invite_hpke_private_key.expose_secret(),
                    request.expose_secret(),
                    request_plaintext.expose_secret(),
                    None,
                    None,
                )
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
        }
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let pending_is_exact = match payload.canonical_pending_frame.as_deref() {
        Some(frame) => exact_pending_frame(frame, pair_route).is_ok(),
        None => true,
    };
    let grant_payload_absent = payload.grant_hash.is_none()
        && payload.response_hash.is_none()
        && payload.canonical_relay_grant.is_none()
        && payload.canonical_device_authorization.is_none()
        && payload.canonical_key_directory_view.is_none()
        && payload.canonical_pair_response.is_none()
        && payload.canonical_install_frame.is_none()
        && payload.global_key_state_hash.is_none();
    let grant_payload_present = payload.grant_hash == grant_hash
        && payload.response_hash == response_hash
        && grant_hash.is_some_and(|hash| hash != [0; 32])
        && response_hash.is_some_and(|hash| hash != [0; 32])
        && payload.canonical_relay_grant.is_some()
        && payload.canonical_device_authorization.is_some()
        && payload.canonical_key_directory_view.is_some()
        && payload.canonical_pair_response.is_some()
        && payload.canonical_install_frame.is_some()
        && payload
            .global_key_state_hash
            .is_some_and(|hash| hash != [0; 32]);
    let lifecycle_shape_valid = match lifecycle {
        PairingInviteLifecycle::RouteOpening | PairingInviteLifecycle::Unused => {
            request_hash.is_none()
                && device_sign_fingerprint.is_none()
                && request_material.is_none()
                && payload.canonical_pending_frame.is_none()
                && grant_payload_absent
        }
        PairingInviteLifecycle::Preparing => {
            request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_none()
                && grant_payload_absent
        }
        PairingInviteLifecycle::AwaitingLocalConfirmation => {
            request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_some()
                && pending_is_exact
                && grant_payload_absent
        }
        PairingInviteLifecycle::GrantPreparing
        | PairingInviteLifecycle::GrantCommitted
        | PairingInviteLifecycle::OrphanRevoking => {
            request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_some()
                && pending_is_exact
                && grant_payload_present
                && payload.delivery_receipt_hash.is_none()
        }
        PairingInviteLifecycle::Delivered => {
            request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_some()
                && pending_is_exact
                && grant_payload_present
                && payload.delivery_receipt_hash.is_some()
        }
        PairingInviteLifecycle::Canceled => {
            let pregrant_canceled = state_changed_at_ms < expires_at_ms
                && grant_payload_absent
                && match request_material {
                    None => request_hash.is_none() && device_sign_fingerprint.is_none(),
                    Some(material) => Some(material) == request_hash.zip(device_sign_fingerprint),
                };
            let revoked_local_canceled = grant_payload_present
                && request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_some()
                && payload.delivery_receipt_hash.is_none();
            pending_is_exact && (pregrant_canceled || revoked_local_canceled)
        }
        PairingInviteLifecycle::Expired => {
            let pregrant_expired = grant_payload_absent
                && match request_material {
                    None => request_hash.is_none() && device_sign_fingerprint.is_none(),
                    Some(material) => Some(material) == request_hash.zip(device_sign_fingerprint),
                };
            let revoked_orphan_expired = grant_payload_present
                && request_material == request_hash.zip(device_sign_fingerprint)
                && payload.canonical_pending_frame.is_some()
                && payload.delivery_receipt_hash.is_none();
            state_changed_at_ms >= expires_at_ms
                && pending_is_exact
                && (pregrant_expired || revoked_orphan_expired)
        }
    };
    if !lifecycle_shape_valid {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedPairingRow {
        record: PairingInviteRecord {
            pairing_id,
            pair_route,
            lifecycle,
            relay_server_id,
            machine_route,
            expires_at_ms,
            created_at_ms,
            state_changed_at_ms,
            canonical_invite: payload.canonical_invite,
            invite_hpke_private_key: payload.invite_hpke_private_key,
            canonical_open_frame: payload.canonical_open_frame,
            request_hash,
            device_sign_fingerprint,
            request_received_at_ms: payload.request_received_at_ms,
            canonical_pair_request: payload.canonical_pair_request,
            canonical_pair_request_plaintext: payload.canonical_pair_request_plaintext,
            canonical_pending_frame: payload.canonical_pending_frame,
            grant_hash,
            response_hash,
            canonical_relay_grant: payload.canonical_relay_grant,
            canonical_device_authorization: payload.canonical_device_authorization,
            canonical_key_directory_view: payload.canonical_key_directory_view,
            canonical_pair_response: payload.canonical_pair_response,
            canonical_install_frame: payload.canonical_install_frame,
            global_key_state_hash: payload.global_key_state_hash,
            delivery_receipt_hash: payload.delivery_receipt_hash,
        },
        owner: payload.owner,
        idempotency_key: payload.idempotency_key,
        expected_terminal: payload.expected_terminal,
        input_hash: payload.input_hash,
        sealed_state_bytes,
        metadata_token,
    })
}

pub(super) fn load_pairing_rows(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedPairingRow>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT pairing_id, lifecycle, database_id, relay_server_id, machine_route,
                pair_route, expires_at_ms, created_at_ms, state_changed_at_ms,
                request_hash, device_sign_fingerprint, grant_hash, response_hash,
                sealed_state, sealed_state_bytes, metadata_token
         FROM remote_pairings ORDER BY pairing_id",
    )?;
    let raws = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
                row.get(15)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raws.into_iter()
        .map(|raw| authenticate_pairing_row(key_bundle, database_id, raw))
        .collect()
}

fn authenticate_outbox_row(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawOutboxRow,
) -> Result<AuthenticatedOutboxRow, RuntimeStoreError> {
    let outbox_id = runtime_id(RuntimeIdKind::RemoteOutbox, raw.0)?;
    let operation_key = fixed(raw.2)?;
    let database_id = fixed(raw.4)?;
    let pairing_id = runtime_id(
        RuntimeIdKind::Pairing,
        raw.5.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let frame_hash = fixed(raw.8)?;
    let sealed_frame_bytes = nonnegative(raw.10)?;
    let created_at_ms = nonnegative(raw.14)?;
    let state_changed_at_ms = nonnegative(raw.15)?;
    let metadata_token = fixed(raw.16)?;
    if raw.1 != "openPairRoute"
        || raw.3 != "prepared"
        || database_id != expected_database_id
        || raw.6.is_some()
        || raw.7.is_some()
        || raw.11.is_some()
        || raw.12.is_some()
        || raw.13.is_some()
        || state_changed_at_ms < created_at_ms
        || sealed_frame_bytes
            != u64::try_from(raw.9.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        || open_operation_key(key_bundle, pairing_id)? != operation_key
        || outbox_row_token(
            key_bundle,
            database_id,
            outbox_id,
            operation_key,
            pairing_id,
            frame_hash,
            &raw.9,
            created_at_ms,
            state_changed_at_ms,
        )? != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open(
        key_bundle,
        database_id,
        OUTBOX_TABLE,
        outbox_id.as_bytes(),
        OUTBOX_COLUMN,
        &raw.9,
        MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
    )?;
    let canonical_frame = plaintext.expose_secret().to_vec();
    let observed_hash: [u8; 32] = Sha256::digest(&canonical_frame).into();
    if observed_hash != frame_hash || exact_frame(&canonical_frame).is_err() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedOutboxRow {
        outbox_id,
        pairing_id,
        operation_key,
        frame_hash,
        canonical_frame,
        sealed_frame_bytes,
        metadata_token,
    })
}

fn load_outbox_rows(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedOutboxRow>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT outbox_id, operation_kind, operation_key, lifecycle, database_id,
                pairing_id, device_route, grant_serial, frame_hash, sealed_frame,
                sealed_frame_bytes, terminal_hash, sealed_terminal, sealed_terminal_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_control_outbox
         WHERE operation_kind = 'openPairRoute' ORDER BY outbox_id",
    )?;
    let raws = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
                row.get(15)?,
                row.get(16)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raws.into_iter()
        .map(|raw| authenticate_outbox_row(key_bundle, database_id, raw))
        .collect()
}

fn authenticate_directory(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<
    (
        Vec<AuthenticatedPairingRow>,
        Vec<AuthenticatedOutboxRow>,
        super::pairing_terminal::AuthenticatedTerminalDirectory,
        super::pairing_grant::AuthenticatedGrantDirectory,
    ),
    RuntimeStoreError,
> {
    let pairings = load_pairing_rows(connection, key_bundle, database_id)?;
    let outboxes = load_outbox_rows(connection, key_bundle, database_id)?;
    let terminal = super::pairing_terminal::authenticate_terminal_directory(
        connection,
        key_bundle,
        database_id,
        &pairings,
    )?;
    let grants = super::pairing_grant::authenticate_grant_directory(
        connection,
        key_bundle,
        database_id,
        &pairings,
        &terminal,
        ledger,
    )?;
    let pairing_bytes = pairings.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.sealed_state_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    let open_outbox_bytes = outboxes.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.sealed_frame_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    let outbox_count = u64::try_from(outboxes.len())
        .ok()
        .and_then(|count| count.checked_add(terminal.close_outbox_count()))
        .and_then(|count| count.checked_add(grants.install_count()))
        .and_then(|count| count.checked_add(grants.revocation_count()))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let outbox_bytes = open_outbox_bytes
        .checked_add(terminal.close_outbox_bytes())
        .and_then(|bytes| bytes.checked_add(grants.install_bytes()))
        .and_then(|bytes| bytes.checked_add(grants.revocation_bytes()))
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if u64::try_from(pairings.len()).ok() != Some(ledger.remote_pairing_count)
        || pairing_bytes != ledger.remote_pairing_sealed_bytes
        || terminal.receipt_count() != ledger.remote_pairing_receipt_count
        || terminal.receipt_bytes() != ledger.remote_pairing_receipt_bytes
        || outbox_count != ledger.remote_control_outbox_count
        || ledger.remote_control_outbox_pending_count != ledger.remote_control_outbox_count
        || ledger.remote_control_outbox_acknowledged_count != 0
        || outbox_bytes != ledger.remote_control_outbox_sealed_bytes
        || ledger.remote_pairing_count > MAX_ACTIVE_PAIRINGS
        || ledger.remote_pairing_sealed_bytes > MAX_PAIRING_SEALED_BYTES
        || ledger.remote_control_outbox_count > MAX_CONTROL_OUTBOX
        || ledger.remote_control_outbox_sealed_bytes > MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut pairing_ids = HashSet::new();
    let mut pair_routes = HashSet::new();
    let mut caller_keys = HashSet::new();
    let mut idempotency_tokens = HashSet::new();
    for pairing in &pairings {
        if !pairing_ids.insert(*pairing.record.pairing_id().as_bytes())
            || !pair_routes.insert(*pairing.record.pair_route().as_bytes())
            || !caller_keys.insert((pairing.owner.clone(), pairing.idempotency_key.clone()))
            || !idempotency_tokens.insert(pairing_idempotency_token(
                key_bundle,
                &pairing.owner,
                &pairing.idempotency_key,
            )?)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    for pairing in &pairings {
        let matching = outboxes
            .iter()
            .filter(|outbox| outbox.pairing_id == pairing.record.pairing_id())
            .collect::<Vec<_>>();
        match pairing.record.lifecycle() {
            PairingInviteLifecycle::RouteOpening
                if matching.len() == 1
                    && matching[0].canonical_frame == pairing.record.canonical_open_frame() => {}
            PairingInviteLifecycle::Unused
            | PairingInviteLifecycle::Preparing
            | PairingInviteLifecycle::AwaitingLocalConfirmation
            | PairingInviteLifecycle::GrantPreparing
            | PairingInviteLifecycle::GrantCommitted
            | PairingInviteLifecycle::Delivered
            | PairingInviteLifecycle::OrphanRevoking
                if matching.is_empty() => {}
            PairingInviteLifecycle::Canceled | PairingInviteLifecycle::Expired
                if matching.is_empty() => {}
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    if outboxes.iter().any(|outbox| {
        !pairings
            .iter()
            .any(|pairing| pairing.record.pairing_id() == outbox.pairing_id)
    }) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if !pairings.is_empty() {
        let active = active_machine(connection, key_bundle, database_id)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        for pairing in &pairings {
            let invite = PairInviteV1::from_canonical_bytes(pairing.record.canonical_invite())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            validate_invite_binding(&invite, &active)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if pairing.record.machine_route != active.record.machine_route {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
    }
    Ok((pairings, outboxes, terminal, grants))
}

pub(super) fn load_directory(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<PairingDirectory, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let (pairings, outboxes, terminal, grants) =
        authenticate_directory(connection, key_bundle, database_id, &ledger)?;
    Ok(PairingDirectory {
        ledger,
        pairings,
        outboxes,
        terminal,
        grants,
    })
}

pub(in crate::runtime::store) fn validate_v10_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    authenticate_directory(connection, key_bundle, database_id, ledger).map(|_| ())
}

fn replay_prepare(
    mut directory: PairingDirectory,
    key_bundle: &RuntimeKeyBundle,
    prepared: &PreparedPairingInviteWrite,
) -> Result<Option<PreparePairingInviteOutcome>, RuntimeStoreError> {
    let idempotency_token =
        pairing_idempotency_token(key_bundle, &prepared.owner, &prepared.idempotency_key)?;
    if let Some((receipt, state)) = directory.terminal.prepare_replay(
        &directory.pairings,
        idempotency_token,
        prepared.input_hash,
    )? {
        return Ok(Some(PreparePairingInviteOutcome::Terminal {
            receipt,
            state,
        }));
    }
    let matching = directory.pairings.iter().position(|row| {
        row.owner == prepared.owner && row.idempotency_key == prepared.idempotency_key
    });
    if let Some(index) = matching {
        let row = directory.pairings.swap_remove(index);
        if row.input_hash != prepared.input_hash {
            return Err(RuntimeStoreError::IdempotencyConflict);
        }
        return Ok(Some(PreparePairingInviteOutcome::Replayed {
            invite: row.record,
        }));
    }
    Ok(None)
}

pub(super) fn allocate_id(
    transaction: &Transaction<'_>,
    config: &RuntimeStoreConfig,
    kind: RuntimeIdKind,
) -> Result<RuntimeId, RuntimeStoreError> {
    let sql = match kind {
        RuntimeIdKind::Pairing => {
            "SELECT EXISTS(SELECT pairing_id FROM remote_pairings WHERE pairing_id = ?1
                           UNION ALL
                           SELECT pairing_id FROM remote_pairing_receipts WHERE pairing_id = ?1)"
        }
        RuntimeIdKind::RemoteOutbox => {
            "SELECT EXISTS(SELECT 1 FROM remote_control_outbox WHERE outbox_id = ?1)"
        }
        _ => {
            return Err(RuntimeStoreError::InvalidConfig(
                "pairing store cannot allocate this id kind",
            ));
        }
    };
    let mut source = config
        .id_source
        .lock()
        .map_err(|_| RuntimeStoreError::WorkerStopped)?;
    for _ in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
        let candidate = source.next_id(kind)?;
        if candidate.kind() != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: candidate.kind(),
            }
            .into());
        }
        let present: i64 =
            transaction.query_row(sql, [&candidate.as_bytes()[..]], |row| row.get(0))?;
        if present == 0 {
            return Ok(candidate);
        }
    }
    Err(RuntimeIdError::CollisionExhausted {
        kind,
        attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
    }
    .into())
}

fn route_exists(connection: &Connection, pair_route: RuntimeId) -> Result<bool, RuntimeStoreError> {
    let present: i64 = connection.query_row(
        "SELECT EXISTS(SELECT pair_route FROM remote_pairings WHERE pair_route = ?1
                       UNION ALL
                       SELECT pair_route FROM remote_pairing_receipts WHERE pair_route = ?1)",
        [&pair_route.as_bytes()[..]],
        |row| row.get(0),
    )?;
    Ok(present != 0)
}

fn validate_accept_input(
    current: &AuthenticatedPairingRow,
    input: &AcceptPairRequest,
) -> Result<([u8; 32], [u8; 32]), RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    let invite = PairInviteV1::from_canonical_bytes(current.record.canonical_invite())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let material = authenticate_request_material(
        &invite,
        current.record.invite_hpke_private_key.expose_secret(),
        input.verified.canonical_request(),
        input.verified.canonical_plaintext(),
        Some(input.verified.info()),
        Some(input.verified.context()),
    )?;
    if material.0 != input.verified.request_hash() {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(material)
}

fn accept_replay(
    current: AuthenticatedPairingRow,
    input: &AcceptPairRequest,
    material: ([u8; 32], [u8; 32]),
    now_ms: u64,
) -> Result<Option<PairingInviteRecord>, RuntimeStoreError> {
    validate_pairing_time(&current, now_ms)?;
    if current.record.request_hash.is_none() {
        return Ok(None);
    }
    let exact = current.record.request_hash == Some(material.0)
        && current.record.device_sign_fingerprint == Some(material.1)
        && current
            .record
            .canonical_pair_request
            .as_ref()
            .is_some_and(|bytes| bytes.expose_secret() == input.verified.canonical_request())
        && current
            .record
            .canonical_pair_request_plaintext
            .as_ref()
            .is_some_and(|bytes| bytes.expose_secret() == input.verified.canonical_plaintext());
    if exact
        && matches!(
            current.record.lifecycle,
            PairingInviteLifecycle::Preparing | PairingInviteLifecycle::AwaitingLocalConfirmation
        )
    {
        Ok(Some(current.record))
    } else {
        Err(RuntimeStoreError::PairingConflict)
    }
}

fn validate_first_request_transition(
    current: &AuthenticatedPairingRow,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if current.record.lifecycle != PairingInviteLifecycle::Unused {
        return Err(RuntimeStoreError::PairingConflict);
    }
    validate_pairing_time(current, now_ms)?;
    let invite = PairInviteV1::from_canonical_bytes(current.record.canonical_invite())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    invite
        .validate(now_ms)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    validate_invite_binding(&invite, active).map_err(|_| RuntimeStoreError::PairingConflict)
}

fn validate_pairing_time(
    current: &AuthenticatedPairingRow,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if now_ms < current.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: current.record.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
    if now_ms >= current.record.expires_at_ms {
        return Err(RuntimeStoreError::PairingExpired);
    }
    Ok(())
}

fn encode_request_payload(
    current: &AuthenticatedPairingRow,
    canonical_pair_request: &[u8],
    canonical_pair_request_plaintext: &[u8],
    request_received_at_ms: u64,
    canonical_pending_frame: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    encode_payload_fields(
        &current.owner,
        &current.idempotency_key,
        current.record.canonical_invite.expose_secret(),
        current.record.invite_hpke_private_key.expose_secret(),
        &current.record.canonical_open_frame,
        &current.expected_terminal,
        &current.input_hash,
        Some(canonical_pair_request),
        Some(canonical_pair_request_plaintext),
        Some(request_received_at_ms),
        canonical_pending_frame,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_grant_payload(
    current: &AuthenticatedPairingRow,
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    canonical_relay_grant: &[u8],
    canonical_device_authorization: &[u8],
    canonical_key_directory_view: &[u8],
    canonical_pair_response: &[u8],
    canonical_install_frame: &[u8],
    global_key_state_hash: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let request = current
        .record
        .canonical_pair_request
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let plaintext = current
        .record
        .canonical_pair_request_plaintext
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let received_at_ms = current
        .record
        .request_received_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending = current
        .record
        .canonical_pending_frame
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let encoded = Zeroizing::new(encode_fields(
        PAIRING_PAYLOAD_MAGIC_V4,
        &[
            &current.owner,
            current.idempotency_key.as_bytes(),
            current.record.canonical_invite.expose_secret(),
            current.record.invite_hpke_private_key.expose_secret(),
            &current.record.canonical_open_frame,
            &current.expected_terminal,
            &current.input_hash,
            request.expose_secret(),
            plaintext.expose_secret(),
            &received_at_ms.to_be_bytes(),
            pending,
            &grant_hash,
            &response_hash,
            canonical_relay_grant,
            canonical_device_authorization,
            canonical_key_directory_view,
            canonical_pair_response,
            canonical_install_frame,
            &global_key_state_hash,
        ],
    )?);
    if encoded.len() > MAX_PAIRING_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

pub(super) fn encode_delivered_payload(
    current: &AuthenticatedPairingRow,
    delivery_receipt_hash: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    if current.record.lifecycle != PairingInviteLifecycle::GrantCommitted
        || delivery_receipt_hash == [0; 32]
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let request = current
        .record
        .canonical_pair_request
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let plaintext = current
        .record
        .canonical_pair_request_plaintext
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let received_at_ms = current
        .record
        .request_received_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pending = current
        .record
        .canonical_pending_frame
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let grant_hash = current
        .record
        .grant_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let response_hash = current
        .record
        .response_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let global_key_state_hash = current
        .record
        .global_key_state_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_relay_grant = current
        .record
        .canonical_relay_grant
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_device_authorization = current
        .record
        .canonical_device_authorization
        .as_ref()
        .map(SecretBytes::expose_secret)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_key_directory_view = current
        .record
        .canonical_key_directory_view
        .as_ref()
        .map(SecretBytes::expose_secret)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_pair_response = current
        .record
        .canonical_pair_response
        .as_ref()
        .map(SecretBytes::expose_secret)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_install_frame = current
        .record
        .canonical_install_frame
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let encoded = Zeroizing::new(encode_fields(
        PAIRING_PAYLOAD_MAGIC_V5,
        &[
            &current.owner,
            current.idempotency_key.as_bytes(),
            current.record.canonical_invite.expose_secret(),
            current.record.invite_hpke_private_key.expose_secret(),
            &current.record.canonical_open_frame,
            &current.expected_terminal,
            &current.input_hash,
            request.expose_secret(),
            plaintext.expose_secret(),
            &received_at_ms.to_be_bytes(),
            pending,
            &grant_hash,
            &response_hash,
            canonical_relay_grant,
            canonical_device_authorization,
            canonical_key_directory_view,
            canonical_pair_response,
            canonical_install_frame,
            &global_key_state_hash,
            &delivery_receipt_hash,
        ],
    )?);
    if encoded.len() > MAX_PAIRING_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

fn update_pairing_sealed_bytes(
    ledger: &RuntimeLedger,
    previous_bytes: u64,
    next_bytes: usize,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let next_bytes = u64::try_from(next_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = ledger.clone();
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(previous_bytes)
        .and_then(|bytes| bytes.checked_add(next_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
        })?;
    if next.remote_pairing_sealed_bytes > MAX_PAIRING_SEALED_BYTES {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

fn frozen_pending_frame(
    pair_route: RuntimeId,
    envelope: &PairingControlEnvelopeV1,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let canonical_envelope = envelope
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let canonical_frame = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route: PairRouteId::from_bytes(*pair_route.as_bytes()),
            sealed_blob: SealedBlob(canonical_envelope),
        }),
    });
    exact_pending_frame(&canonical_frame, pair_route)?;
    Ok(canonical_frame)
}

pub(crate) fn prepare_pairing_invite(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedPairingInviteWrite,
    now_ms: u64,
) -> Result<PreparePairingInviteOutcome, RuntimeStoreError> {
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(outcome) = replay_prepare(directory, &state.key_bundle, &prepared)? {
        return Ok(outcome);
    }
    let active = active_machine(&state.connection, &state.key_bundle, state.database_id)?;
    let invite = validate_invite_for_active_machine(&prepared, &active, now_ms)?;
    if state
        .connection
        .query_row("SELECT COUNT(*) FROM remote_pairings", [], |row| {
            row.get::<_, i64>(0)
        })?
        >= i64::try_from(MAX_ACTIVE_PAIRINGS).expect("pairing limit fits i64")
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    let (projected_sealed_state_bytes, projected_sealed_frame_bytes, projected_write_bytes) = {
        let (open_frame, expected_terminal) = frozen_frames(
            active.record.machine_route,
            *invite.pair_route.as_bytes(),
            invite.expires_at_ms,
        );
        let payload = encode_payload(&prepared, &open_frame, &expected_terminal)?;
        let sealed_state_bytes = payload
            .len()
            .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        let sealed_frame_bytes = open_frame
            .len()
            .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
            .ok_or(RuntimeStoreError::PayloadTooLarge)?;
        let projected =
            super::journal::projected_write_bytes(&[sealed_state_bytes, sealed_frame_bytes])?;
        (sealed_state_bytes, sealed_frame_bytes, projected)
    };
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        super::sqlite::SafetyReserveProjection::CreatePairingInvite,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let directory = load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(outcome) = replay_prepare(directory, &state.key_bundle, &prepared)? {
        return Ok(outcome);
    }
    let active = active_machine(&transaction, &state.key_bundle, state.database_id)?;
    let invite = validate_invite_for_active_machine(&prepared, &active, now_ms)?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if ledger.remote_pairing_count >= MAX_ACTIVE_PAIRINGS {
        return Err(RuntimeStoreError::PairingLimit);
    }
    let pair_route = RuntimeId::from_bytes(RuntimeIdKind::PairRoute, *invite.pair_route.as_bytes())
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if route_exists(&transaction, pair_route)? {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let pairing_id = allocate_id(&transaction, config, RuntimeIdKind::Pairing)?;
    let outbox_id = allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
    let (open_frame, expected_terminal) = frozen_frames(
        active.record.machine_route,
        *invite.pair_route.as_bytes(),
        invite.expires_at_ms,
    );
    let payload = encode_payload(&prepared, &open_frame, &expected_terminal)?;
    let sealed_state = seal(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        pairing_id.as_bytes(),
        PAIRING_COLUMN,
        payload.as_slice(),
        MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    if sealed_state.len() != projected_sealed_state_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let pairing_token = pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing_id,
        PairingInviteLifecycle::RouteOpening,
        *invite.relay_server_id.as_bytes(),
        active.record.machine_route,
        pair_route,
        invite.expires_at_ms,
        now_ms,
        now_ms,
        None,
        None,
        None,
        None,
        &sealed_state,
    )?;
    transaction.execute(
        "INSERT INTO remote_pairings (
             pairing_id, lifecycle, database_id, relay_server_id, machine_route, pair_route,
             expires_at_ms, created_at_ms, state_changed_at_ms, request_hash,
             device_sign_fingerprint, grant_hash, response_hash, sealed_state,
             sealed_state_bytes, metadata_token
         ) VALUES (?1, 'routeOpening', ?2, ?3, ?4, ?5, ?6, ?7, ?7,
                   NULL, NULL, NULL, NULL, ?8, ?9, ?10)",
        params![
            &pairing_id.as_bytes()[..],
            &state.database_id[..],
            invite.relay_server_id.as_bytes(),
            &active.record.machine_route[..],
            &pair_route.as_bytes()[..],
            i64::try_from(invite.expires_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &sealed_state,
            i64::try_from(sealed_state.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &pairing_token[..],
        ],
    )?;
    let frame_hash: [u8; 32] = Sha256::digest(&open_frame).into();
    let sealed_frame = seal(
        &state.key_bundle,
        state.database_id,
        OUTBOX_TABLE,
        outbox_id.as_bytes(),
        OUTBOX_COLUMN,
        &open_frame,
        MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
    )?;
    if sealed_frame.len() != projected_sealed_frame_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let operation_key = open_operation_key(&state.key_bundle, pairing_id)?;
    let outbox_token = outbox_row_token(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        operation_key,
        pairing_id,
        frame_hash,
        &sealed_frame,
        now_ms,
        now_ms,
    )?;
    transaction.execute(
        "INSERT INTO remote_control_outbox (
             outbox_id, operation_kind, operation_key, lifecycle, database_id, pairing_id,
             device_route, grant_serial, frame_hash, sealed_frame, sealed_frame_bytes,
             terminal_hash, sealed_terminal, sealed_terminal_bytes, created_at_ms,
             state_changed_at_ms, metadata_token
         ) VALUES (?1, 'openPairRoute', ?2, 'prepared', ?3, ?4,
                   NULL, NULL, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8, ?9)",
        params![
            &outbox_id.as_bytes()[..],
            &operation_key[..],
            &state.database_id[..],
            &pairing_id.as_bytes()[..],
            &frame_hash[..],
            &sealed_frame,
            i64::try_from(sealed_frame.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &outbox_token[..],
        ],
    )?;
    let mut next = ledger.clone();
    next.remote_pairing_count = next.remote_pairing_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_count",
        },
    )?;
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_add(
            u64::try_from(sealed_state.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
        })?;
    next.remote_control_outbox_count = next.remote_control_outbox_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_count",
        },
    )?;
    next.remote_control_outbox_pending_count = next
        .remote_control_outbox_pending_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_pending_count",
        })?;
    next.remote_control_outbox_sealed_bytes = next
        .remote_control_outbox_sealed_bytes
        .checked_add(
            u64::try_from(sealed_frame.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        )
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_sealed_bytes",
        })?;
    if next.remote_pairing_sealed_bytes > MAX_PAIRING_SEALED_BYTES
        || next.remote_control_outbox_sealed_bytes > MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PreparePairingInviteBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::PreparePairingInvite)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PreparePairingInviteAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PreparePairingInvite,
        })?;
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let row = directory
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id() == pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(PreparePairingInviteOutcome::Prepared { invite: row.record })
}

pub(crate) fn accept_pair_request(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AcceptPairRequest,
    now_ms: u64,
) -> Result<AcceptPairRequestOutcome, RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let current = directory
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let material = validate_accept_input(&current, &input)?;
    if let Some(pairing) = accept_replay(current, &input, material, now_ms)? {
        return Ok(AcceptPairRequestOutcome::Replayed { pairing });
    }
    let active = active_machine(&state.connection, &state.key_bundle, state.database_id)?;
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let current = directory
        .pairings
        .iter()
        .find(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    validate_first_request_transition(current, &active, now_ms)?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut directory = load_directory(&transaction, &state.key_bundle, state.database_id)?;
    let index = directory
        .pairings
        .iter()
        .position(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let current = directory.pairings.swap_remove(index);
    let material = validate_accept_input(&current, &input)?;
    if let Some(pairing) = accept_replay(current, &input, material, now_ms)? {
        return Ok(AcceptPairRequestOutcome::Replayed { pairing });
    }
    let current = load_pairing_rows(&transaction, &state.key_bundle, state.database_id)?
        .into_iter()
        .find(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let active = active_machine(&transaction, &state.key_bundle, state.database_id)?;
    validate_first_request_transition(&current, &active, now_ms)?;
    let payload = encode_request_payload(
        &current,
        input.verified.canonical_request(),
        input.verified.canonical_plaintext(),
        now_ms,
        None,
    )?;
    let sealed_state = seal(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        input.pairing_id.as_bytes(),
        PAIRING_COLUMN,
        payload.as_slice(),
        MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let next_token = pairing_row_token(
        &state.key_bundle,
        state.database_id,
        input.pairing_id,
        PairingInviteLifecycle::Preparing,
        current.record.relay_server_id,
        current.record.machine_route,
        current.record.pair_route,
        current.record.expires_at_ms,
        current.record.created_at_ms,
        now_ms,
        Some(material.0),
        Some(material.1),
        None,
        None,
        &sealed_state,
    )?;
    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'preparing', state_changed_at_ms = ?1,
             request_hash = ?2, device_sign_fingerprint = ?3,
             sealed_state = ?4, sealed_state_bytes = ?5, metadata_token = ?6
         WHERE pairing_id = ?7 AND lifecycle = 'unused'
           AND request_hash IS NULL AND device_sign_fingerprint IS NULL
           AND metadata_token = ?8",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &material.0[..],
            &material.1[..],
            &sealed_state,
            i64::try_from(sealed_state.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &next_token[..],
            &input.pairing_id.as_bytes()[..],
            &current.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let next = update_pairing_sealed_bytes(
        &directory.ledger,
        current.sealed_state_bytes,
        sealed_state.len(),
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcceptPairRequestBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::AcceptPairRequest)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcceptPairRequestAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcceptPairRequest,
        })?;
    let pairing = load_pairing_invite(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        input.pairing_id,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AcceptPairRequestOutcome::Accepted { pairing })
}

pub(crate) fn commit_pair_pending(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: CommitPairPending,
    now_ms: u64,
) -> Result<CommitPairPendingOutcome, RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    if input.request_hash == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let current = directory
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if current.record.request_hash != Some(input.request_hash) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    validate_pairing_time(&current, now_ms)?;
    let canonical_frame = frozen_pending_frame(current.record.pair_route, &input.envelope)?;
    if current.record.lifecycle == PairingInviteLifecycle::AwaitingLocalConfirmation {
        return if current.record.canonical_pending_frame.as_deref() == Some(&canonical_frame) {
            Ok(CommitPairPendingOutcome::Replayed {
                pairing: current.record,
            })
        } else {
            Err(RuntimeStoreError::PairingConflict)
        };
    }
    if current.record.lifecycle != PairingInviteLifecycle::Preparing {
        return Err(RuntimeStoreError::PairingConflict);
    }
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut directory = load_directory(&transaction, &state.key_bundle, state.database_id)?;
    let index = directory
        .pairings
        .iter()
        .position(|row| row.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let current = directory.pairings.swap_remove(index);
    if current.record.request_hash != Some(input.request_hash) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    validate_pairing_time(&current, now_ms)?;
    let canonical_frame = frozen_pending_frame(current.record.pair_route, &input.envelope)?;
    if current.record.lifecycle == PairingInviteLifecycle::AwaitingLocalConfirmation {
        return if current.record.canonical_pending_frame.as_deref() == Some(&canonical_frame) {
            Ok(CommitPairPendingOutcome::Replayed {
                pairing: current.record,
            })
        } else {
            Err(RuntimeStoreError::PairingConflict)
        };
    }
    if current.record.lifecycle != PairingInviteLifecycle::Preparing {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let request_received_at_ms = current
        .record
        .request_received_at_ms
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_request = current
        .record
        .canonical_pair_request
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical_plaintext = current
        .record
        .canonical_pair_request_plaintext
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let payload = encode_request_payload(
        &current,
        canonical_request.expose_secret(),
        canonical_plaintext.expose_secret(),
        request_received_at_ms,
        Some(&canonical_frame),
    )?;
    let sealed_state = seal(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        input.pairing_id.as_bytes(),
        PAIRING_COLUMN,
        payload.as_slice(),
        MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let fingerprint = current
        .record
        .device_sign_fingerprint
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let next_token = pairing_row_token(
        &state.key_bundle,
        state.database_id,
        input.pairing_id,
        PairingInviteLifecycle::AwaitingLocalConfirmation,
        current.record.relay_server_id,
        current.record.machine_route,
        current.record.pair_route,
        current.record.expires_at_ms,
        current.record.created_at_ms,
        now_ms,
        Some(input.request_hash),
        Some(fingerprint),
        None,
        None,
        &sealed_state,
    )?;
    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'awaitingLocalConfirmation', state_changed_at_ms = ?1,
             sealed_state = ?2, sealed_state_bytes = ?3, metadata_token = ?4
         WHERE pairing_id = ?5 AND lifecycle = 'preparing'
           AND request_hash = ?6 AND device_sign_fingerprint = ?7
           AND metadata_token = ?8",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &sealed_state,
            i64::try_from(sealed_state.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &next_token[..],
            &input.pairing_id.as_bytes()[..],
            &input.request_hash[..],
            &fingerprint[..],
            &current.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let next = update_pairing_sealed_bytes(
        &directory.ledger,
        current.sealed_state_bytes,
        sealed_state.len(),
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CommitPairPendingBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::CommitPairPending)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CommitPairPendingAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::CommitPairPending,
        })?;
    let pairing = load_pairing_invite(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        input.pairing_id,
    )?
    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(CommitPairPendingOutcome::Committed { pairing })
}

pub(crate) fn acknowledge_pair_route_open(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pairing_id: RuntimeId,
    canonical_terminal: Vec<u8>,
    now_ms: u64,
) -> Result<AcknowledgePairRouteOpenOutcome, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    exact_frame(&canonical_terminal)?;
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let current = directory
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id() == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if current.expected_terminal != canonical_terminal {
        return Err(RuntimeStoreError::PairingConflict);
    }
    validate_pairing_time(&current, now_ms)?;
    if current.record.lifecycle() != PairingInviteLifecycle::RouteOpening {
        return Ok(AcknowledgePairRouteOpenOutcome {
            invite: current.record,
            replayed: true,
        });
    }
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut directory = load_directory(&transaction, &state.key_bundle, state.database_id)?;
    let index = directory
        .pairings
        .iter()
        .position(|row| row.record.pairing_id() == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let current = directory.pairings.swap_remove(index);
    if current.expected_terminal != canonical_terminal {
        return Err(RuntimeStoreError::PairingConflict);
    }
    validate_pairing_time(&current, now_ms)?;
    if current.record.lifecycle() != PairingInviteLifecycle::RouteOpening {
        return Ok(AcknowledgePairRouteOpenOutcome {
            invite: current.record,
            replayed: true,
        });
    }
    let outbox_index = directory
        .outboxes
        .iter()
        .position(|row| row.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let outbox = directory.outboxes.swap_remove(outbox_index);
    if transaction.execute(
        "DELETE FROM remote_control_outbox
         WHERE outbox_id = ?1 AND operation_kind = 'openPairRoute'
           AND pairing_id = ?2 AND operation_key = ?3 AND frame_hash = ?4
           AND metadata_token = ?5",
        params![
            &outbox.outbox_id.as_bytes()[..],
            &pairing_id.as_bytes()[..],
            &outbox.operation_key[..],
            &outbox.frame_hash[..],
            &outbox.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let sealed_state: Vec<u8> = transaction.query_row(
        "SELECT sealed_state FROM remote_pairings WHERE pairing_id = ?1",
        [&pairing_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let next_token = pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing_id,
        PairingInviteLifecycle::Unused,
        current.record.relay_server_id,
        current.record.machine_route,
        current.record.pair_route(),
        current.record.expires_at_ms(),
        current.record.created_at_ms,
        now_ms,
        None,
        None,
        None,
        None,
        &sealed_state,
    )?;
    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'unused', state_changed_at_ms = ?1, metadata_token = ?2
         WHERE pairing_id = ?3 AND lifecycle = 'routeOpening' AND metadata_token = ?4",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &next_token[..],
            &pairing_id.as_bytes()[..],
            &current.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let ledger = directory.ledger;
    let mut next = ledger.clone();
    next.remote_control_outbox_count = next
        .remote_control_outbox_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_pending_count = next
        .remote_control_outbox_pending_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_sealed_bytes = next
        .remote_control_outbox_sealed_bytes
        .checked_sub(outbox.sealed_frame_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgePairRouteOpenBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgePairRouteOpen,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgePairRouteOpenAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgePairRouteOpen,
        })?;
    let directory = load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let invite = directory
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id() == pairing_id)
        .map(|row| row.record)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AcknowledgePairRouteOpenOutcome {
        invite,
        replayed: false,
    })
}

pub(crate) fn load_pairing_invite(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
) -> Result<Option<PairingInviteRecord>, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    Ok(load_directory(connection, key_bundle, database_id)?
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id() == pairing_id)
        .map(|row| row.record))
}

pub(crate) fn replay_pair_request(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
    canonical_request: SecretBytes,
    now_ms: u64,
) -> Result<PairingInviteRecord, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    let current = load_directory(connection, key_bundle, database_id)?
        .pairings
        .into_iter()
        .find(|row| row.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    validate_pairing_time(&current, now_ms)?;
    if !matches!(
        current.record.lifecycle,
        PairingInviteLifecycle::Preparing | PairingInviteLifecycle::AwaitingLocalConfirmation
    ) || current
        .record
        .canonical_pair_request
        .as_ref()
        .is_none_or(|frozen| frozen.expose_secret() != canonical_request.expose_secret())
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(current.record)
}

pub(crate) fn list_pairing_recovery(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<PairingInviteRecord>, RuntimeStoreError> {
    Ok(load_directory(connection, key_bundle, database_id)?
        .pairings
        .into_iter()
        .map(|row| row.record)
        .collect())
}

pub(crate) fn list_pending_pairings(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<PendingPairing>, RuntimeStoreError> {
    load_directory(connection, key_bundle, database_id)?
        .pairings
        .into_iter()
        .filter(|row| row.record.lifecycle == PairingInviteLifecycle::AwaitingLocalConfirmation)
        .map(|row| {
            Ok(PendingPairing {
                pairing_id: PairingId::new(row.record.pairing_id.to_canonical_string()),
                request_hash: row
                    .record
                    .request_hash
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                device_sign_fingerprint: row
                    .record
                    .device_sign_fingerprint
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                requested_at_ms: row
                    .record
                    .request_received_at_ms
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                expires_at_ms: row.record.expires_at_ms,
            })
        })
        .collect()
}

fn runtime_id(kind: RuntimeIdKind, value: Vec<u8>) -> Result<RuntimeId, RuntimeStoreError> {
    RuntimeId::from_bytes(
        kind,
        value
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}
