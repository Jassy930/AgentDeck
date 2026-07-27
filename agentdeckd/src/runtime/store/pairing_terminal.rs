//! Pairing terminal receipt、ClosePairRoute outbox 与 ACK 后 secret scrub。

use std::collections::HashSet;

use agentdeck_crypto::HpkePublicKey;
use agentdeck_protocol::e2ee::{
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairInviteV1, PairRequestInfoV1,
    PairRequestPlaintextV1, PairTerminalOutcomeV1, PairTerminalV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::auth::Ed25519Signature;
use agentdeck_protocol::relay_v2::frame::{
    ClosePairRoute, OpaqueRouteFrame, PairData, PairRouteCloseOutcome, PairRouteClosed,
    RelayFrameBody, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    MachineRouteId, PairRouteId, RELAY_PROTOCOL_VERSION, SignedCertificate, decode, encode,
};
use agentdeck_protocol::runtime::identity::PairingId;
use agentdeck_protocol::runtime::{PairingReceipt, PairingState};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::{AuthenticatedPairingRow, PairingInviteLifecycle};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::RuntimeSqlite;

const RECEIPT_METADATA_DOMAIN: &[u8] = b"remote.pairing.receipt.metadata.v2";
const CLOSE_OPERATION_DOMAIN: &[u8] = b"remote.control.close-pair-route.operation.v1";
const PAIR_TERMINAL_HPKE_SEED_DOMAIN: &[u8] = b"remote.pairing.terminal.hpke-seed.v1";
const OUTBOX_METADATA_DOMAIN: &[u8] = b"remote.control.outbox.metadata.v1";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
pub(super) const RECEIPT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_RECEIPT_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalAction {
    Confirm,
    Cancel,
    Expire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PairingTerminalAction {
    Cancel,
    Expire,
}

impl PairingTerminalAction {
    const fn internal(self) -> TerminalAction {
        match self {
            Self::Cancel => TerminalAction::Cancel,
            Self::Expire => TerminalAction::Expire,
        }
    }
}

impl TerminalAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirmed",
            Self::Cancel => "canceled",
            Self::Expire => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "confirmed" => Ok(Self::Confirm),
            "canceled" => Ok(Self::Cancel),
            "expired" => Ok(Self::Expire),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

pub(crate) struct PairingCloseProjection {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    canonical_frame: Vec<u8>,
}

impl std::fmt::Debug for PairingCloseProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingCloseProjection")
            .field("pairing_id", &self.pairing_id)
            .field("route", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PairingCloseProjection {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> RuntimeId {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }

    #[must_use]
    pub(crate) fn canonical_frame(&self) -> &[u8] {
        &self.canonical_frame
    }

    pub(super) fn duplicate(&self) -> Self {
        Self {
            pairing_id: self.pairing_id,
            pair_route: self.pair_route,
            canonical_frame: self.canonical_frame.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PairingTerminalizeOutcome {
    Transitioned {
        receipt: PairingReceipt,
        close: PairingCloseProjection,
    },
    Replayed {
        receipt: PairingReceipt,
        state: PairingState,
        close: Option<PairingCloseProjection>,
    },
    AlreadyHandled {
        receipt: PairingReceipt,
        state: PairingState,
        close: Option<PairingCloseProjection>,
    },
}

pub(super) struct ConfirmedReceiptWrite {
    pairing_id: RuntimeId,
    database_id: [u8; 16],
    relay_server_id: [u8; 16],
    machine_route: [u8; 16],
    pair_route: RuntimeId,
    idempotency_token: [u8; 32],
    input_hash: [u8; 32],
    request_hash: [u8; 32],
    receipt: PairingReceipt,
    receipt_hash: [u8; 32],
    canonical_receipt: Vec<u8>,
    receipt_bytes: u64,
    created_at_ms: u64,
    retain_until_ms: u64,
    metadata_token: [u8; 32],
}

impl ConfirmedReceiptWrite {
    #[must_use]
    pub(super) const fn receipt(&self) -> &PairingReceipt {
        &self.receipt
    }

    #[must_use]
    pub(super) const fn receipt_bytes(&self) -> u64 {
        self.receipt_bytes
    }
}

#[derive(Debug)]
pub(crate) struct PairingTerminalRecovery {
    receipt: PairingReceipt,
    close: PairingCloseProjection,
    preparation: Option<PairTerminalPreparation>,
    carrier: Option<PairTerminalCarrierProjection>,
}

impl PairingTerminalRecovery {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &PairingReceipt {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn close(&self) -> &PairingCloseProjection {
        &self.close
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn preparation(&self) -> Option<&PairTerminalPreparation> {
        self.preparation.as_ref()
    }

    /// 将恢复记录持有的唯一 HPKE seed owner 移交给上层 coordinator。
    ///
    /// preparation 只能 move，不能从只读投影复制；carrier 已持久化时该值固定为 `None`。
    #[must_use]
    pub(crate) fn take_preparation(&mut self) -> Option<PairTerminalPreparation> {
        self.preparation.take()
    }

    #[must_use]
    pub(crate) const fn carrier(&self) -> Option<&PairTerminalCarrierProjection> {
        self.carrier.as_ref()
    }
}

pub(crate) struct PairTerminalPreparation {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    machine_route: MachineRouteId,
    request_hash: [u8; 32],
    outcome: PairTerminalOutcomeV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    recipient: HpkePublicKey,
    data_sign_certificate: SignedCertificate,
    hpke_seed_commitment: [u8; 32],
    hpke_seed: Option<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for PairTerminalPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairTerminalPreparation([REDACTED])")
    }
}

impl PairTerminalPreparation {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> RuntimeId {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }

    #[must_use]
    pub(crate) const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub(crate) const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> PairTerminalOutcomeV1 {
        self.outcome
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

    #[must_use]
    pub(crate) const fn data_sign_certificate(&self) -> &SignedCertificate {
        &self.data_sign_certificate
    }

    /// 只允许交给同一 generation 的 `PairingMachineAuthority` 作为 HPKE CSPRNG seed。
    ///
    /// 该 seed 由 Runtime DB 密钥对 exact terminal identity 做用途隔离 PRF 得到；同一
    /// durable winner 在 carrier COMMIT 前崩溃后会逐字节重放，其他 pairing、outcome、
    /// recipient 或签名 credential 都不能复用。
    #[must_use]
    #[cfg(test)]
    pub(crate) fn hpke_seed(&self) -> Option<&[u8; 32]> {
        self.hpke_seed.as_deref()
    }

    /// 将唯一 seed owner 交给 transport。取出后 preparation 仍保留非 secret identity，
    /// 可继续用于 carrier COMMIT；重复 seal 固定 fail-close，不能退化为零 seed。
    pub(crate) fn take_hpke_seed(&mut self) -> Option<Zeroizing<[u8; 32]>> {
        self.hpke_seed.take()
    }

    /// 只复制已经消费 seed 的非 secret terminal identity，供 COMMIT-unknown 精确重试。
    ///
    /// seal 前的 preparation 是唯一 secret owner；任何仍持有 seed 的值都必须 fail-close，
    /// 不能借由 retry artifact 复制。
    fn duplicate_after_seed_consumed(&self) -> Result<Self, RuntimeStoreError> {
        if self.hpke_seed.is_some() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self {
            pairing_id: self.pairing_id,
            pair_route: self.pair_route,
            machine_route: self.machine_route,
            request_hash: self.request_hash,
            outcome: self.outcome,
            info: self.info.clone(),
            context: self.context.clone(),
            recipient: self.recipient.clone(),
            data_sign_certificate: self.data_sign_certificate.clone(),
            hpke_seed_commitment: self.hpke_seed_commitment,
            hpke_seed: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        pairing_id: RuntimeId,
        machine_route: MachineRouteId,
        request_hash: [u8; 32],
        outcome: PairTerminalOutcomeV1,
        canonical_invite: &[u8],
        canonical_request_plaintext: &[u8],
        hpke_seed: [u8; 32],
    ) -> Result<Self, RuntimeStoreError> {
        let invite = PairInviteV1::from_canonical_bytes(canonical_invite)
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
        let plaintext = PairRequestPlaintextV1::from_canonical_bytes(canonical_request_plaintext)
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
        let recipient = HpkePublicKey::from_bytes(&plaintext.device_hpke_pubkey.0)
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
        let info = super::pairing::pair_request_info(&invite)?;
        let context = super::pairing::pairing_context(&invite, OuterFrameKind::PairTerminal);
        let hpke_seed_commitment = terminal_hpke_seed_commitment(&hpke_seed);
        Ok(Self {
            pairing_id,
            pair_route: invite.pair_route,
            machine_route,
            request_hash,
            outcome,
            info,
            context,
            recipient,
            data_sign_certificate: invite.data_sign_cert,
            hpke_seed_commitment,
            hpke_seed: Some(Zeroizing::new(hpke_seed)),
        })
    }
}

pub(crate) struct CommitPairTerminal {
    preparation: PairTerminalPreparation,
    canonical_frame: Vec<u8>,
}

impl std::fmt::Debug for CommitPairTerminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommitPairTerminal([REDACTED])")
    }
}

impl CommitPairTerminal {
    pub(crate) fn new(
        preparation: PairTerminalPreparation,
        envelope: PairingControlEnvelopeV1,
    ) -> Result<Self, RuntimeStoreError> {
        envelope
            .validate()
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
        let canonical_envelope = envelope
            .canonical_bytes()
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
        if PairingControlEnvelopeV1::from_canonical_bytes(&canonical_envelope)
            .map_err(|_| RuntimeStoreError::PairingConflict)?
            != envelope
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let canonical_frame = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairData(PairData {
                pair_route: preparation.pair_route,
                sealed_blob: SealedBlob(canonical_envelope),
            }),
        });
        super::pairing::exact_pair_terminal_frame(&canonical_frame, preparation.pair_route)?;
        Ok(Self {
            preparation,
            canonical_frame,
        })
    }

    #[must_use]
    pub(crate) fn canonical_frame(&self) -> &[u8] {
        &self.canonical_frame
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.canonical_frame.capacity()
    }

    /// 构造仅含非 secret metadata 与 frozen carrier 的 COMMIT-unknown 重试副本。
    pub(crate) fn retry_copy(&self) -> Result<Self, RuntimeStoreError> {
        Ok(Self {
            preparation: self.preparation.duplicate_after_seed_consumed()?,
            canonical_frame: self.canonical_frame.clone(),
        })
    }
}

#[derive(Clone)]
pub(crate) struct PairTerminalCarrierProjection {
    pair_route: PairRouteId,
    canonical_frame: Vec<u8>,
}

impl std::fmt::Debug for PairTerminalCarrierProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairTerminalCarrierProjection([REDACTED])")
    }
}

impl PairTerminalCarrierProjection {
    #[must_use]
    pub(crate) const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }

    #[must_use]
    pub(crate) fn canonical_frame(&self) -> &[u8] {
        &self.canonical_frame
    }
}

#[derive(Debug)]
pub(crate) enum CommitPairTerminalOutcome {
    Committed { recovery: PairingTerminalRecovery },
    Replayed { recovery: PairingTerminalRecovery },
}

#[derive(Debug)]
pub(crate) struct AcknowledgePairRouteCloseOutcome {
    receipt: PairingReceipt,
    replayed: bool,
}

impl AcknowledgePairRouteCloseOutcome {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &PairingReceipt {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// 已通过完整 pairing directory 认证的 first-valid winner 与当前 durable state。
///
/// 该投影只读，不触发 terminal CAS、Close 重发或 receipt retention 变更。
#[derive(Debug)]
pub(crate) struct PairingWinnerProjection {
    receipt: PairingReceipt,
    state: PairingState,
}

impl PairingWinnerProjection {
    #[must_use]
    pub(crate) const fn receipt(&self) -> &PairingReceipt {
        &self.receipt
    }

    #[must_use]
    pub(crate) const fn state(&self) -> PairingState {
        self.state
    }
}

struct AuthenticatedReceipt {
    pairing_id: RuntimeId,
    relay_server_id: [u8; 16],
    machine_route: [u8; 16],
    pair_route: RuntimeId,
    idempotency_token: [u8; 32],
    input_hash: [u8; 32],
    action: TerminalAction,
    request_hash: Option<[u8; 32]>,
    receipt: PairingReceipt,
    receipt_bytes: u64,
    created_at_ms: u64,
    retain_until_ms: u64,
    metadata_token: [u8; 32],
}

struct AuthenticatedCloseOutbox {
    outbox_id: RuntimeId,
    pairing_id: RuntimeId,
    operation_key: [u8; 32],
    frame_hash: [u8; 32],
    projection: PairingCloseProjection,
    sealed_frame_bytes: u64,
    created_at_ms: u64,
    state_changed_at_ms: u64,
    metadata_token: [u8; 32],
}

pub(super) struct AuthenticatedTerminalDirectory {
    receipts: Vec<AuthenticatedReceipt>,
    close_outboxes: Vec<AuthenticatedCloseOutbox>,
    receipt_bytes: u64,
    close_outbox_bytes: u64,
}

impl AuthenticatedTerminalDirectory {
    pub(super) fn receipt_count(&self) -> u64 {
        u64::try_from(self.receipts.len()).unwrap_or(u64::MAX)
    }

    pub(super) const fn receipt_bytes(&self) -> u64 {
        self.receipt_bytes
    }

    pub(super) fn close_outbox_count(&self) -> u64 {
        u64::try_from(self.close_outboxes.len()).unwrap_or(u64::MAX)
    }

    pub(super) const fn close_outbox_bytes(&self) -> u64 {
        self.close_outbox_bytes
    }

    fn receipt(&self, pairing_id: RuntimeId) -> Option<&AuthenticatedReceipt> {
        self.receipts
            .iter()
            .find(|receipt| receipt.pairing_id == pairing_id)
    }

    pub(super) fn receipt_value(&self, pairing_id: RuntimeId) -> Option<&PairingReceipt> {
        self.receipt(pairing_id).map(|receipt| &receipt.receipt)
    }

    pub(super) fn prepare_replay(
        &self,
        pairings: &[AuthenticatedPairingRow],
        idempotency_token: [u8; 32],
        input_hash: [u8; 32],
    ) -> Result<Option<(PairingReceipt, PairingState)>, RuntimeStoreError> {
        let Some(receipt) = self
            .receipts
            .iter()
            .find(|receipt| receipt.idempotency_token == idempotency_token)
        else {
            return Ok(None);
        };
        if receipt.input_hash != input_hash {
            return Err(RuntimeStoreError::IdempotencyConflict);
        }
        let state = pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == receipt.pairing_id)
            .map_or(PairingState::ClosedTombstone, |pairing| {
                pairing_state(pairing.record.lifecycle)
            });
        Ok(Some((receipt.receipt.clone(), state)))
    }

    fn close(&self, pairing_id: RuntimeId) -> Option<&AuthenticatedCloseOutbox> {
        self.close_outboxes
            .iter()
            .find(|close| close.pairing_id == pairing_id)
    }

    pub(super) fn close_projection(&self, pairing_id: RuntimeId) -> Option<PairingCloseProjection> {
        self.close(pairing_id)
            .map(|close| close.projection.duplicate())
    }
}

type RawReceiptRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
);

type RawCloseOutboxRow = (
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

#[allow(clippy::too_many_arguments)]
fn receipt_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
    relay_server_id: [u8; 16],
    machine_route: [u8; 16],
    pair_route: RuntimeId,
    idempotency_token: [u8; 32],
    input_hash: [u8; 32],
    action: TerminalAction,
    request_hash: Option<[u8; 32]>,
    receipt_hash: [u8; 32],
    receipt_bytes: u64,
    created_at_ms: u64,
    retain_until_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let presence = [u8::from(request_hash.is_some())];
    let request_hash = request_hash.unwrap_or([0; 32]);
    super::stream::metadata_mac(
        key_bundle,
        RECEIPT_METADATA_DOMAIN,
        &[
            &database_id,
            pairing_id.as_bytes(),
            &relay_server_id,
            &machine_route,
            pair_route.as_bytes(),
            &idempotency_token,
            &input_hash,
            action.as_str().as_bytes(),
            &presence,
            &request_hash,
            &receipt_hash,
            &receipt_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
            &retain_until_ms.to_be_bytes(),
        ],
    )
}

fn refresh_receipt_retention(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    receipt: &AuthenticatedReceipt,
    acknowledged_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if acknowledged_at_ms < receipt.created_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: receipt.created_at_ms,
            observed_ms: acknowledged_at_ms,
        });
    }
    let canonical_receipt = serde_json::to_vec(&receipt.receipt)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let receipt_bytes =
        u64::try_from(canonical_receipt.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let receipt_hash: [u8; 32] = Sha256::digest(&canonical_receipt).into();
    if receipt_bytes != receipt.receipt_bytes || receipt_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let retain_until_ms = acknowledged_at_ms
        .checked_add(RECEIPT_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let metadata_token = receipt_token(
        key_bundle,
        database_id,
        receipt.pairing_id,
        receipt.relay_server_id,
        receipt.machine_route,
        receipt.pair_route,
        receipt.idempotency_token,
        receipt.input_hash,
        receipt.action,
        receipt.request_hash,
        receipt_hash,
        receipt_bytes,
        receipt.created_at_ms,
        retain_until_ms,
    )?;
    if transaction.execute(
        "UPDATE remote_pairing_receipts
         SET retain_until_ms = ?1, metadata_token = ?2
         WHERE pairing_id = ?3 AND created_at_ms = ?4 AND retain_until_ms = ?5
           AND metadata_token = ?6",
        params![
            i64::try_from(retain_until_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &metadata_token[..],
            &receipt.pairing_id.as_bytes()[..],
            i64::try_from(receipt.created_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(receipt.retain_until_ms)
                .map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &receipt.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

pub(super) fn close_operation_key(
    key_bundle: &RuntimeKeyBundle,
    pairing_id: RuntimeId,
) -> Result<[u8; 32], RuntimeStoreError> {
    let value = *key_bundle
        .blind_index(CLOSE_OPERATION_DOMAIN, pairing_id.as_bytes())?
        .as_bytes();
    if value == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn close_outbox_token(
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
            b"closePairRoute",
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

fn open_close_frame(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    outbox_id: RuntimeId,
    ciphertext: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle
        .row_cipher()
        .open_bounded(
            &RowAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &database_id,
                table: OUTBOX_TABLE,
                primary_key: outbox_id.as_bytes(),
                column: OUTBOX_COLUMN,
            },
            ciphertext,
            super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
        )?
        .expose_secret()
        .to_vec())
}

pub(super) fn exact_close_frame(
    canonical: &[u8],
    pairing_id: RuntimeId,
) -> Result<PairingCloseProjection, RuntimeStoreError> {
    let frame: OpaqueRouteFrame =
        decode(canonical).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if encode(&frame) != canonical || frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let RelayFrameBody::ClosePairRoute(ClosePairRoute {
        machine_route: _,
        pair_route,
    }) = frame.body
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    Ok(PairingCloseProjection {
        pairing_id,
        pair_route,
        canonical_frame: canonical.to_vec(),
    })
}

fn canonical_receipt(
    encoded: &[u8],
) -> Result<(PairingReceipt, TerminalAction, String), RuntimeStoreError> {
    if encoded.is_empty() || encoded.len() > MAX_RECEIPT_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let receipt: PairingReceipt =
        serde_json::from_slice(encoded).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if serde_json::to_vec(&receipt).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != encoded
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let (action, pairing_id) = match &receipt {
        PairingReceipt::Confirmed { pairing_id } => {
            (TerminalAction::Confirm, pairing_id.as_str().to_owned())
        }
        PairingReceipt::Canceled { pairing_id } => {
            (TerminalAction::Cancel, pairing_id.as_str().to_owned())
        }
        PairingReceipt::Expired { pairing_id } => {
            (TerminalAction::Expire, pairing_id.as_str().to_owned())
        }
        PairingReceipt::Replayed { .. }
        | PairingReceipt::AlreadyHandled { .. }
        | PairingReceipt::Failed { .. } => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    Ok((receipt, action, pairing_id))
}

fn authenticate_receipt(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawReceiptRow,
) -> Result<AuthenticatedReceipt, RuntimeStoreError> {
    let pairing_id = runtime_id(RuntimeIdKind::Pairing, raw.0)?;
    let database_id = fixed(raw.1)?;
    let relay_server_id = fixed(raw.2)?;
    let machine_route = fixed(raw.3)?;
    let pair_route = runtime_id(RuntimeIdKind::PairRoute, raw.4)?;
    let idempotency_token = fixed(raw.5)?;
    let input_hash = fixed(raw.6)?;
    let action = TerminalAction::parse(&raw.7)?;
    let request_hash = raw.8.map(fixed).transpose()?;
    let receipt_hash: [u8; 32] = fixed(raw.9)?;
    let receipt_bytes = nonnegative(raw.11)?;
    let created_at_ms = nonnegative(raw.12)?;
    let retain_until_ms = nonnegative(raw.13)?;
    let metadata_token = fixed(raw.14)?;
    let (receipt, encoded_action, encoded_id) = canonical_receipt(&raw.10)?;
    let observed_receipt_hash: [u8; 32] = Sha256::digest(&raw.10).into();
    if database_id != expected_database_id
        || action != encoded_action
        || encoded_id != pairing_id.to_canonical_string()
        || receipt_hash != observed_receipt_hash
        || receipt_hash == [0; 32]
        || idempotency_token == [0; 32]
        || input_hash == [0; 32]
        || receipt_bytes != u64::try_from(raw.10.len()).unwrap_or(u64::MAX)
        || created_at_ms
            .checked_add(RECEIPT_RETENTION_MS)
            .is_none_or(|minimum| retain_until_ms < minimum)
        || receipt_token(
            key_bundle,
            database_id,
            pairing_id,
            relay_server_id,
            machine_route,
            pair_route,
            idempotency_token,
            input_hash,
            action,
            request_hash,
            receipt_hash,
            receipt_bytes,
            created_at_ms,
            retain_until_ms,
        )? != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedReceipt {
        pairing_id,
        relay_server_id,
        machine_route,
        pair_route,
        idempotency_token,
        input_hash,
        action,
        request_hash,
        receipt,
        receipt_bytes,
        created_at_ms,
        retain_until_ms,
        metadata_token,
    })
}

fn load_receipts(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedReceipt>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT pairing_id, database_id, relay_server_id, machine_route, pair_route,
                idempotency_token, input_hash, action, request_hash, receipt_hash,
                canonical_receipt, receipt_bytes,
                created_at_ms, retain_until_ms, metadata_token
         FROM remote_pairing_receipts ORDER BY pairing_id",
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
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raws.into_iter()
        .map(|raw| authenticate_receipt(key_bundle, database_id, raw))
        .collect()
}

fn authenticate_close_outbox(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawCloseOutboxRow,
) -> Result<AuthenticatedCloseOutbox, RuntimeStoreError> {
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
    if raw.1 != "closePairRoute"
        || raw.3 != "prepared"
        || database_id != expected_database_id
        || raw.6.is_some()
        || raw.7.is_some()
        || raw.11.is_some()
        || raw.12.is_some()
        || raw.13.is_some()
        || state_changed_at_ms != created_at_ms
        || sealed_frame_bytes != u64::try_from(raw.9.len()).unwrap_or(u64::MAX)
        || close_operation_key(key_bundle, pairing_id)? != operation_key
        || close_outbox_token(
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
    let canonical = open_close_frame(key_bundle, database_id, outbox_id, &raw.9)?;
    let observed_frame_hash: [u8; 32] = Sha256::digest(&canonical).into();
    if frame_hash != observed_frame_hash || frame_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AuthenticatedCloseOutbox {
        outbox_id,
        pairing_id,
        operation_key,
        frame_hash,
        projection: exact_close_frame(&canonical, pairing_id)?,
        sealed_frame_bytes,
        created_at_ms,
        state_changed_at_ms,
        metadata_token,
    })
}

fn load_close_outboxes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedCloseOutbox>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT outbox_id, operation_kind, operation_key, lifecycle, database_id,
                pairing_id, device_route, grant_serial, frame_hash, sealed_frame,
                sealed_frame_bytes, terminal_hash, sealed_terminal, sealed_terminal_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_control_outbox
         WHERE operation_kind = 'closePairRoute' ORDER BY outbox_id",
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
        .map(|raw| authenticate_close_outbox(key_bundle, database_id, raw))
        .collect()
}

pub(super) fn authenticate_terminal_directory(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairings: &[AuthenticatedPairingRow],
) -> Result<AuthenticatedTerminalDirectory, RuntimeStoreError> {
    let receipts = load_receipts(connection, key_bundle, database_id)?;
    let close_outboxes = load_close_outboxes(connection, key_bundle, database_id)?;
    let mut receipt_ids = HashSet::new();
    let mut receipt_routes = HashSet::new();
    let mut receipt_idempotency_tokens = HashSet::new();
    for receipt in &receipts {
        if !receipt_ids.insert(*receipt.pairing_id.as_bytes())
            || !receipt_routes.insert(*receipt.pair_route.as_bytes())
            || !receipt_idempotency_tokens.insert(receipt.idempotency_token)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        if receipt.action == TerminalAction::Confirm && receipt.request_hash.is_none() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        match pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == receipt.pairing_id)
        {
            Some(pairing)
                if pairing.record.pair_route == receipt.pair_route
                    && pairing.record.relay_server_id == receipt.relay_server_id
                    && pairing.record.machine_route == receipt.machine_route
                    && super::pairing::pairing_idempotency_token(
                        key_bundle,
                        &pairing.owner,
                        &pairing.idempotency_key,
                    )? == receipt.idempotency_token
                    && pairing.input_hash == receipt.input_hash
                    && pairing.record.request_hash == receipt.request_hash
                    && match (pairing.record.lifecycle, receipt.action) {
                        (PairingInviteLifecycle::Canceled, TerminalAction::Cancel)
                        | (PairingInviteLifecycle::Expired, TerminalAction::Expire)
                        | (PairingInviteLifecycle::GrantPreparing, TerminalAction::Confirm) => {
                            pairing.record.state_changed_at_ms == receipt.created_at_ms
                        }
                        (
                            PairingInviteLifecycle::GrantCommitted
                            | PairingInviteLifecycle::Delivered
                            | PairingInviteLifecycle::OrphanRevoking
                            | PairingInviteLifecycle::Expired
                            | PairingInviteLifecycle::Canceled,
                            TerminalAction::Confirm,
                        ) => receipt.created_at_ms <= pairing.record.state_changed_at_ms,
                        _ => false,
                    } => {}
            Some(_) => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            None if pairings
                .iter()
                .all(|pairing| pairing.record.pair_route != receipt.pair_route) => {}
            None => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    let mut close_pairings = HashSet::new();
    for close in &close_outboxes {
        if !close_pairings.insert(*close.pairing_id.as_bytes()) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let pairing = pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == close.pairing_id)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if !matches!(
            pairing.record.lifecycle,
            PairingInviteLifecycle::Canceled
                | PairingInviteLifecycle::Expired
                | PairingInviteLifecycle::Delivered
        ) || pairing.record.pair_route.as_bytes() != close.projection.pair_route.as_bytes()
            || pairing.record.state_changed_at_ms != close.created_at_ms
            || close.state_changed_at_ms != close.created_at_ms
            || !matches!(
                decode(close.projection.canonical_frame())
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                    .body,
                RelayFrameBody::ClosePairRoute(ClosePairRoute { machine_route, pair_route })
                    if machine_route.as_bytes() == &pairing.record.machine_route
                        && pair_route.as_bytes() == pairing.record.pair_route.as_bytes()
            )
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    for pairing in pairings {
        let idempotency_token = super::pairing::pairing_idempotency_token(
            key_bundle,
            &pairing.owner,
            &pairing.idempotency_key,
        )?;
        if receipts.iter().any(|receipt| {
            receipt.idempotency_token == idempotency_token
                && receipt.pairing_id != pairing.record.pairing_id
        }) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let receipt_count = receipts
            .iter()
            .filter(|receipt| receipt.pairing_id == pairing.record.pairing_id)
            .count();
        let close_count = close_outboxes
            .iter()
            .filter(|close| close.pairing_id == pairing.record.pairing_id)
            .count();
        match pairing.record.lifecycle {
            PairingInviteLifecycle::Canceled | PairingInviteLifecycle::Expired
                if receipt_count == 1 && close_count == 1 => {}
            PairingInviteLifecycle::GrantPreparing | PairingInviteLifecycle::GrantCommitted
                if receipt_count == 1 && close_count == 0 => {}
            PairingInviteLifecycle::OrphanRevoking if receipt_count == 1 && close_count == 0 => {}
            PairingInviteLifecycle::Delivered if receipt_count == 1 && close_count == 1 => {}
            PairingInviteLifecycle::RouteOpening
            | PairingInviteLifecycle::Unused
            | PairingInviteLifecycle::Preparing
            | PairingInviteLifecycle::AwaitingLocalConfirmation
                if receipt_count == 0 && close_count == 0 => {}
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    let receipt_bytes = receipts.iter().try_fold(0_u64, |total, receipt| {
        total
            .checked_add(receipt.receipt_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    let close_outbox_bytes = close_outboxes.iter().try_fold(0_u64, |total, close| {
        total
            .checked_add(close.sealed_frame_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    Ok(AuthenticatedTerminalDirectory {
        receipts,
        close_outboxes,
        receipt_bytes,
        close_outbox_bytes,
    })
}

fn pairing_state(lifecycle: PairingInviteLifecycle) -> PairingState {
    match lifecycle {
        PairingInviteLifecycle::RouteOpening => PairingState::RouteOpening,
        PairingInviteLifecycle::Unused => PairingState::Unused,
        PairingInviteLifecycle::Preparing => PairingState::Preparing,
        PairingInviteLifecycle::AwaitingLocalConfirmation => {
            PairingState::AwaitingLocalConfirmation
        }
        PairingInviteLifecycle::GrantPreparing => PairingState::GrantPreparing,
        PairingInviteLifecycle::GrantCommitted => PairingState::GrantCommitted,
        PairingInviteLifecycle::Delivered => PairingState::Delivered,
        PairingInviteLifecycle::OrphanRevoking => PairingState::OrphanRevoking,
        PairingInviteLifecycle::Canceled => PairingState::Canceled,
        PairingInviteLifecycle::Expired => PairingState::Expired,
    }
}

pub(crate) fn load_pairing_winner(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
) -> Result<Option<PairingWinnerProjection>, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let Some(receipt) = directory.terminal.receipt(pairing_id) else {
        return Ok(None);
    };
    let state = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == pairing_id)
        .map_or(PairingState::ClosedTombstone, |pairing| {
            pairing_state(pairing.record.lifecycle)
        });
    Ok(Some(PairingWinnerProjection {
        receipt: receipt.receipt.clone(),
        state,
    }))
}

fn classify_existing(
    directory: &super::pairing::PairingDirectory,
    pairing_id: RuntimeId,
    requested: TerminalAction,
) -> Option<PairingTerminalizeOutcome> {
    let receipt = directory.terminal.receipt(pairing_id)?;
    let state = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == pairing_id)
        .map_or(PairingState::ClosedTombstone, |pairing| {
            pairing_state(pairing.record.lifecycle)
        });
    let close = directory
        .terminal
        .close(pairing_id)
        .map(|outbox| outbox.projection.duplicate());
    let fields = (receipt.receipt.clone(), state, close);
    Some(if receipt.action == requested {
        PairingTerminalizeOutcome::Replayed {
            receipt: fields.0,
            state: fields.1,
            close: fields.2,
        }
    } else {
        PairingTerminalizeOutcome::AlreadyHandled {
            receipt: fields.0,
            state: fields.1,
            close: fields.2,
        }
    })
}

fn winner_receipt(
    pairing_id: RuntimeId,
    action: TerminalAction,
) -> Result<(PairingReceipt, Vec<u8>, [u8; 32]), RuntimeStoreError> {
    let pairing_id = PairingId::new(pairing_id.to_canonical_string());
    let receipt = match action {
        TerminalAction::Cancel => PairingReceipt::Canceled { pairing_id },
        TerminalAction::Expire => PairingReceipt::Expired { pairing_id },
        TerminalAction::Confirm => return Err(RuntimeStoreError::PairingConflict),
    };
    let canonical =
        serde_json::to_vec(&receipt).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if canonical.is_empty() || canonical.len() > MAX_RECEIPT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let hash: [u8; 32] = Sha256::digest(&canonical).into();
    if hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((receipt, canonical, hash))
}

pub(super) fn prepare_confirmed_receipt(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing: &AuthenticatedPairingRow,
    now_ms: u64,
) -> Result<ConfirmedReceiptWrite, RuntimeStoreError> {
    if pairing.record.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation
        || now_ms < pairing.record.state_changed_at_ms
        || now_ms >= pairing.record.expires_at_ms
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let request_hash = pairing
        .record
        .request_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pairing_id = pairing.record.pairing_id;
    let receipt = PairingReceipt::Confirmed {
        pairing_id: PairingId::new(pairing_id.to_canonical_string()),
    };
    let canonical_receipt =
        serde_json::to_vec(&receipt).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if canonical_receipt.is_empty() || canonical_receipt.len() > MAX_RECEIPT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let receipt_hash: [u8; 32] = Sha256::digest(&canonical_receipt).into();
    if receipt_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let receipt_bytes =
        u64::try_from(canonical_receipt.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let retain_until_ms = now_ms
        .checked_add(RECEIPT_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let idempotency_token = super::pairing::pairing_idempotency_token(
        key_bundle,
        &pairing.owner,
        &pairing.idempotency_key,
    )?;
    let metadata_token = receipt_token(
        key_bundle,
        database_id,
        pairing_id,
        pairing.record.relay_server_id,
        pairing.record.machine_route,
        pairing.record.pair_route,
        idempotency_token,
        pairing.input_hash,
        TerminalAction::Confirm,
        Some(request_hash),
        receipt_hash,
        receipt_bytes,
        now_ms,
        retain_until_ms,
    )?;
    Ok(ConfirmedReceiptWrite {
        pairing_id,
        database_id,
        relay_server_id: pairing.record.relay_server_id,
        machine_route: pairing.record.machine_route,
        pair_route: pairing.record.pair_route,
        idempotency_token,
        input_hash: pairing.input_hash,
        request_hash,
        receipt,
        receipt_hash,
        canonical_receipt,
        receipt_bytes,
        created_at_ms: now_ms,
        retain_until_ms,
        metadata_token,
    })
}

pub(super) fn insert_confirmed_receipt(
    transaction: &Transaction<'_>,
    pairing: &AuthenticatedPairingRow,
    write: &ConfirmedReceiptWrite,
) -> Result<(), RuntimeStoreError> {
    if pairing.record.pairing_id != write.pairing_id
        || pairing.record.relay_server_id != write.relay_server_id
        || pairing.record.machine_route != write.machine_route
        || pairing.record.pair_route != write.pair_route
        || pairing.record.request_hash != Some(write.request_hash)
        || pairing.input_hash != write.input_hash
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "INSERT INTO remote_pairing_receipts (
             pairing_id, database_id, relay_server_id, machine_route, pair_route,
             idempotency_token, input_hash, action, request_hash, receipt_hash,
             canonical_receipt, receipt_bytes, created_at_ms, retain_until_ms, metadata_token
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'confirmed', ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            &write.pairing_id.as_bytes()[..],
            &write.database_id[..],
            &write.relay_server_id[..],
            &write.machine_route[..],
            &write.pair_route.as_bytes()[..],
            &write.idempotency_token[..],
            &write.input_hash[..],
            &write.request_hash[..],
            &write.receipt_hash[..],
            &write.canonical_receipt,
            i64::try_from(write.receipt_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(write.created_at_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(write.retain_until_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &write.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

pub(super) fn frozen_close_frame(pairing: &AuthenticatedPairingRow) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::ClosePairRoute(ClosePairRoute {
            machine_route: agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(
                pairing.record.machine_route,
            ),
            pair_route: PairRouteId::from_bytes(*pairing.record.pair_route.as_bytes()),
        }),
    })
}

pub(super) fn seal_close_frame(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    outbox_id: RuntimeId,
    canonical: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: OUTBOX_TABLE,
            primary_key: outbox_id.as_bytes(),
            column: OUTBOX_COLUMN,
        },
        canonical,
        super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
    )?)
}

fn effective_action(
    pairing: &AuthenticatedPairingRow,
    requested: TerminalAction,
    now_ms: u64,
) -> Result<TerminalAction, RuntimeStoreError> {
    if now_ms < pairing.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: pairing.record.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
    if !matches!(
        pairing.record.lifecycle,
        PairingInviteLifecycle::RouteOpening
            | PairingInviteLifecycle::Unused
            | PairingInviteLifecycle::Preparing
            | PairingInviteLifecycle::AwaitingLocalConfirmation
    ) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    match requested {
        TerminalAction::Cancel if now_ms >= pairing.record.expires_at_ms => {
            Ok(TerminalAction::Expire)
        }
        TerminalAction::Cancel => Ok(TerminalAction::Cancel),
        TerminalAction::Expire if now_ms >= pairing.record.expires_at_ms => {
            Ok(TerminalAction::Expire)
        }
        TerminalAction::Expire | TerminalAction::Confirm => Err(RuntimeStoreError::PairingConflict),
    }
}

fn delete_open_outbox(
    transaction: &rusqlite::Transaction<'_>,
    pairing_id: RuntimeId,
    outbox: &super::pairing::AuthenticatedOutboxRow,
) -> Result<(), RuntimeStoreError> {
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
    Ok(())
}

fn update_terminal_ledger(
    ledger: &super::sqlite::RuntimeLedger,
    receipt_bytes: usize,
    close_bytes: usize,
    replaced_open_bytes: Option<u64>,
) -> Result<super::sqlite::RuntimeLedger, RuntimeStoreError> {
    let receipt_bytes =
        u64::try_from(receipt_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let close_bytes = u64::try_from(close_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = ledger.clone();
    next.remote_pairing_receipt_count = next.remote_pairing_receipt_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_receipt_count",
        },
    )?;
    next.remote_pairing_receipt_bytes = next
        .remote_pairing_receipt_bytes
        .checked_add(receipt_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_receipt_bytes",
        })?;
    match replaced_open_bytes {
        Some(open_bytes) => {
            next.remote_control_outbox_sealed_bytes = next
                .remote_control_outbox_sealed_bytes
                .checked_sub(open_bytes)
                .and_then(|bytes| bytes.checked_add(close_bytes))
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_control_outbox_sealed_bytes",
                })?;
        }
        None => {
            next.remote_control_outbox_count = next
                .remote_control_outbox_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_control_outbox_count",
                })?;
            next.remote_control_outbox_pending_count = next
                .remote_control_outbox_pending_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_control_outbox_pending_count",
                })?;
            next.remote_control_outbox_sealed_bytes = next
                .remote_control_outbox_sealed_bytes
                .checked_add(close_bytes)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_control_outbox_sealed_bytes",
                })?;
        }
    }
    if next.remote_pairing_receipt_count > 65_536
        || next.remote_pairing_receipt_bytes > 64 * 1024 * 1024
        || next.remote_control_outbox_count > super::pairing::MAX_CONTROL_OUTBOX
        || next.remote_control_outbox_sealed_bytes > super::pairing::MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

pub(crate) fn terminalize_pairing(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pairing_id: RuntimeId,
    requested: PairingTerminalAction,
    now_ms: u64,
) -> Result<PairingTerminalizeOutcome, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    let requested = requested.internal();
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(outcome) = classify_existing(&directory, pairing_id, requested) {
        return Ok(outcome);
    }
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let _ = effective_action(pairing, requested, now_ms)?;
    let (_, canonical_receipt, _) = winner_receipt(pairing_id, requested)?;
    let close_frame = frozen_close_frame(pairing);
    let _ = exact_close_frame(&close_frame, pairing_id)?;
    let _ = canonical_receipt
        .len()
        .checked_add(close_frame.len())
        .ok_or(RuntimeStoreError::PayloadTooLarge)?;
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
    let mut directory =
        super::pairing::load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(outcome) = classify_existing(&directory, pairing_id, requested) {
        return Ok(outcome);
    }
    let index = directory
        .pairings
        .iter()
        .position(|pairing| pairing.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let pairing = directory.pairings.swap_remove(index);
    let winner = effective_action(&pairing, requested, now_ms)?;
    let (receipt, canonical_receipt, receipt_hash) = winner_receipt(pairing_id, winner)?;
    let close_frame = frozen_close_frame(&pairing);
    let frame_hash: [u8; 32] = Sha256::digest(&close_frame).into();
    if frame_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let retain_until_ms = now_ms
        .checked_add(RECEIPT_RETENTION_MS)
        .ok_or(RuntimeStoreError::TimeOutOfRange)?;
    let outbox_id = super::pairing::allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
    let sealed_close = seal_close_frame(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        &close_frame,
    )?;
    let operation_key = close_operation_key(&state.key_bundle, pairing_id)?;
    let idempotency_token = super::pairing::pairing_idempotency_token(
        &state.key_bundle,
        &pairing.owner,
        &pairing.idempotency_key,
    )?;
    let receipt_metadata = receipt_token(
        &state.key_bundle,
        state.database_id,
        pairing_id,
        pairing.record.relay_server_id,
        pairing.record.machine_route,
        pairing.record.pair_route,
        idempotency_token,
        pairing.input_hash,
        winner,
        pairing.record.request_hash,
        receipt_hash,
        u64::try_from(canonical_receipt.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        now_ms,
        retain_until_ms,
    )?;
    let close_metadata = close_outbox_token(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        operation_key,
        pairing_id,
        frame_hash,
        &sealed_close,
        now_ms,
        now_ms,
    )?;
    let open_outbox = directory
        .outboxes
        .iter()
        .find(|outbox| outbox.pairing_id == pairing_id);
    match pairing.record.lifecycle {
        PairingInviteLifecycle::RouteOpening => {
            delete_open_outbox(
                &transaction,
                pairing_id,
                open_outbox.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
            )?;
        }
        _ if open_outbox.is_none() => {}
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
    transaction.execute(
        "INSERT INTO remote_pairing_receipts (
             pairing_id, database_id, relay_server_id, machine_route, pair_route,
             idempotency_token, input_hash, action, request_hash, receipt_hash,
             canonical_receipt, receipt_bytes, created_at_ms, retain_until_ms, metadata_token
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            &pairing_id.as_bytes()[..],
            &state.database_id[..],
            &pairing.record.relay_server_id[..],
            &pairing.record.machine_route[..],
            &pairing.record.pair_route.as_bytes()[..],
            &idempotency_token[..],
            &pairing.input_hash[..],
            winner.as_str(),
            pairing
                .record
                .request_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            &receipt_hash[..],
            &canonical_receipt,
            i64::try_from(canonical_receipt.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            i64::try_from(retain_until_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &receipt_metadata[..],
        ],
    )?;
    transaction.execute(
        "INSERT INTO remote_control_outbox (
             outbox_id, operation_kind, operation_key, lifecycle, database_id, pairing_id,
             device_route, grant_serial, frame_hash, sealed_frame, sealed_frame_bytes,
             terminal_hash, sealed_terminal, sealed_terminal_bytes, created_at_ms,
             state_changed_at_ms, metadata_token
         ) VALUES (?1, 'closePairRoute', ?2, 'prepared', ?3, ?4,
                   NULL, NULL, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8, ?9)",
        params![
            &outbox_id.as_bytes()[..],
            &operation_key[..],
            &state.database_id[..],
            &pairing_id.as_bytes()[..],
            &frame_hash[..],
            &sealed_close,
            i64::try_from(sealed_close.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &close_metadata[..],
        ],
    )?;
    let sealed_state: Vec<u8> = transaction.query_row(
        "SELECT sealed_state FROM remote_pairings WHERE pairing_id = ?1",
        [&pairing_id.as_bytes()[..]],
        |row| row.get(0),
    )?;
    let lifecycle = match winner {
        TerminalAction::Cancel => PairingInviteLifecycle::Canceled,
        TerminalAction::Expire => PairingInviteLifecycle::Expired,
        TerminalAction::Confirm => return Err(RuntimeStoreError::PairingConflict),
    };
    let pairing_metadata = super::pairing::pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing_id,
        lifecycle,
        pairing.record.relay_server_id,
        pairing.record.machine_route,
        pairing.record.pair_route,
        pairing.record.expires_at_ms,
        pairing.record.created_at_ms,
        now_ms,
        pairing.record.request_hash,
        pairing.record.device_sign_fingerprint,
        None,
        None,
        &sealed_state,
    )?;
    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = ?1, state_changed_at_ms = ?2, metadata_token = ?3
         WHERE pairing_id = ?4 AND lifecycle = ?5 AND metadata_token = ?6",
        params![
            winner.as_str(),
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &pairing_metadata[..],
            &pairing_id.as_bytes()[..],
            match pairing.record.lifecycle {
                PairingInviteLifecycle::RouteOpening => "routeOpening",
                PairingInviteLifecycle::Unused => "unused",
                PairingInviteLifecycle::Preparing => "preparing",
                PairingInviteLifecycle::AwaitingLocalConfirmation => "awaitingLocalConfirmation",
                PairingInviteLifecycle::GrantPreparing
                | PairingInviteLifecycle::GrantCommitted
                | PairingInviteLifecycle::Delivered
                | PairingInviteLifecycle::OrphanRevoking
                | PairingInviteLifecycle::Canceled
                | PairingInviteLifecycle::Expired => {
                    return Err(RuntimeStoreError::PairingConflict);
                }
            },
            &pairing.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let next_ledger = update_terminal_ledger(
        &directory.ledger,
        canonical_receipt.len(),
        sealed_close.len(),
        open_outbox.map(|outbox| outbox.sealed_frame_bytes),
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next_ledger,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::TerminalizePairingBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::TerminalizePairing)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::TerminalizePairingAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::TerminalizePairing,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let close = directory
        .terminal
        .close(pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .projection
        .duplicate();
    Ok(if winner == requested {
        PairingTerminalizeOutcome::Transitioned { receipt, close }
    } else {
        PairingTerminalizeOutcome::AlreadyHandled {
            receipt,
            state: PairingState::Expired,
            close: Some(close),
        }
    })
}

pub(crate) fn terminalize_due_pairings(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    now_ms: u64,
) -> Result<Vec<PairingTerminalizeOutcome>, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let due = directory
        .pairings
        .iter()
        .filter(|pairing| {
            pairing.record.expires_at_ms <= now_ms
                && matches!(
                    pairing.record.lifecycle,
                    PairingInviteLifecycle::RouteOpening
                        | PairingInviteLifecycle::Unused
                        | PairingInviteLifecycle::Preparing
                        | PairingInviteLifecycle::AwaitingLocalConfirmation
                )
        })
        .map(|pairing| pairing.record.pairing_id)
        .collect::<Vec<_>>();
    if due.len() > usize::try_from(super::pairing::MAX_ACTIVE_PAIRINGS).unwrap_or(usize::MAX) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    due.into_iter()
        .map(|pairing_id| {
            terminalize_pairing(
                state,
                config,
                pairing_id,
                PairingTerminalAction::Expire,
                now_ms,
            )
        })
        .collect()
}

pub(crate) fn list_pairing_terminal_recovery(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<PairingTerminalRecovery>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    directory
        .terminal
        .close_outboxes
        .iter()
        .map(|close| terminal_recovery(&directory, close, key_bundle, database_id))
        .collect()
}

fn terminal_preparation(
    pairing: &AuthenticatedPairingRow,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<PairTerminalPreparation>, RuntimeStoreError> {
    let outcome = match pairing.record.lifecycle {
        PairingInviteLifecycle::Canceled => PairTerminalOutcomeV1::Canceled,
        PairingInviteLifecycle::Expired => PairTerminalOutcomeV1::Expired,
        PairingInviteLifecycle::Delivered => return Ok(None),
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let Some(request_hash) = pairing.record.request_hash else {
        if pairing.record.canonical_pair_request.is_some()
            || pairing.record.canonical_pair_request_plaintext.is_some()
            || pairing.record.request_received_at_ms.is_some()
            || pairing.record.canonical_pair_terminal_frame.is_some()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(None);
    };
    let invite =
        PairInviteV1::from_canonical_bytes(pairing.record.canonical_invite.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if invite
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != pairing.record.canonical_invite.expose_secret()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let canonical_plaintext = pairing
        .record
        .canonical_pair_request_plaintext
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .expose_secret();
    let plaintext = PairRequestPlaintextV1::from_canonical_bytes(canonical_plaintext)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if plaintext
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != canonical_plaintext
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let recipient = HpkePublicKey::from_bytes(&plaintext.device_hpke_pubkey.0)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let info = super::pairing::pair_request_info(&invite)?;
    let context = super::pairing::pairing_context(&invite, OuterFrameKind::PairTerminal);
    context
        .validate()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if info.pair_route.as_bytes() != pairing.record.pair_route.as_bytes()
        || info.relay_server_id.as_bytes() != &pairing.record.relay_server_id
        || info.expiry_ms != pairing.record.expires_at_ms
        || request_hash == [0; 32]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let terminal = PairTerminalV1 {
        machine_route: MachineRouteId::from_bytes(pairing.record.machine_route),
        request_hash,
        outcome,
        signature: Ed25519Signature([0; 64]),
    };
    let signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let terminal_tbs = terminal
        .signature_tbs(&info, &context, &signer)
        .and_then(|tbs| tbs.encode())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let terminal_tbs_sha256: [u8; 32] = Sha256::digest(&terminal_tbs).into();
    let mut seed_binding = Zeroizing::new(Vec::with_capacity(16 + 16 + 32 + 32));
    seed_binding.extend_from_slice(&database_id);
    seed_binding.extend_from_slice(pairing.record.pairing_id.as_bytes());
    seed_binding.extend_from_slice(&recipient.to_bytes());
    seed_binding.extend_from_slice(&terminal_tbs_sha256);
    let derived = key_bundle.blind_index(PAIR_TERMINAL_HPKE_SEED_DOMAIN, seed_binding.as_ref())?;
    let mut hpke_seed = Zeroizing::new([0_u8; 32]);
    hpke_seed.copy_from_slice(derived.as_bytes());
    let hpke_seed_commitment = terminal_hpke_seed_commitment(&hpke_seed);
    Ok(Some(PairTerminalPreparation {
        pairing_id: pairing.record.pairing_id,
        pair_route: invite.pair_route,
        machine_route: MachineRouteId::from_bytes(pairing.record.machine_route),
        request_hash,
        outcome,
        info,
        context,
        recipient,
        data_sign_certificate: invite.data_sign_cert,
        hpke_seed_commitment,
        hpke_seed: Some(hpke_seed),
    }))
}

fn terminal_recovery(
    directory: &super::pairing::PairingDirectory,
    close: &AuthenticatedCloseOutbox,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<PairingTerminalRecovery, RuntimeStoreError> {
    let receipt = directory
        .terminal
        .receipt(close.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == close.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let preparation = terminal_preparation(pairing, key_bundle, database_id)?;
    let carrier = pairing
        .record
        .canonical_pair_terminal_frame
        .as_ref()
        .map(|canonical| {
            super::pairing::exact_pair_terminal_frame(canonical, close.projection.pair_route)?;
            Ok::<_, RuntimeStoreError>(PairTerminalCarrierProjection {
                pair_route: close.projection.pair_route,
                canonical_frame: canonical.clone(),
            })
        })
        .transpose()?;
    if carrier.is_some() && preparation.is_none() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(PairingTerminalRecovery {
        receipt: receipt.receipt.clone(),
        close: close.projection.duplicate(),
        preparation: carrier.is_none().then_some(preparation).flatten(),
        carrier,
    })
}

fn validate_commit_preparation(
    expected: &PairTerminalPreparation,
    supplied: &PairTerminalPreparation,
) -> Result<(), RuntimeStoreError> {
    if expected.pairing_id != supplied.pairing_id
        || expected.pair_route != supplied.pair_route
        || expected.machine_route != supplied.machine_route
        || expected.request_hash != supplied.request_hash
        || expected.outcome != supplied.outcome
        || expected.info != supplied.info
        || expected.context != supplied.context
        || expected.recipient.to_bytes() != supplied.recipient.to_bytes()
        || expected.data_sign_certificate != supplied.data_sign_certificate
        || expected.hpke_seed_commitment != supplied.hpke_seed_commitment
        || expected.hpke_seed.is_none()
        || supplied.hpke_seed.is_some()
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn terminal_hpke_seed_commitment(seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"agentdeck.runtime.pair-terminal.hpke-seed-commitment.v1");
    hasher.update(seed);
    hasher.finalize().into()
}

fn classify_terminal_carrier(
    directory: &super::pairing::PairingDirectory,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    input: &CommitPairTerminal,
) -> Result<Option<PairingTerminalRecovery>, RuntimeStoreError> {
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.preparation.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let expected = terminal_preparation(pairing, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    validate_commit_preparation(&expected, &input.preparation)?;
    super::pairing::exact_pair_terminal_frame(
        input.canonical_frame(),
        input.preparation.pair_route,
    )?;
    let close = directory
        .terminal
        .close(input.preparation.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    match pairing.record.canonical_pair_terminal_frame.as_deref() {
        Some(canonical) if canonical == input.canonical_frame() => {
            terminal_recovery(directory, close, key_bundle, database_id).map(Some)
        }
        Some(_) => Err(RuntimeStoreError::PairingConflict),
        None => Ok(None),
    }
}

pub(crate) fn commit_pair_terminal(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: CommitPairTerminal,
) -> Result<CommitPairTerminalOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(recovery) =
        classify_terminal_carrier(&directory, &state.key_bundle, state.database_id, &input)?
    {
        return Ok(CommitPairTerminalOutcome::Replayed { recovery });
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
    let directory =
        super::pairing::load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(recovery) =
        classify_terminal_carrier(&directory, &state.key_bundle, state.database_id, &input)?
    {
        return Ok(CommitPairTerminalOutcome::Replayed { recovery });
    }
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.preparation.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let payload = super::pairing::encode_pair_terminal_payload(pairing, input.canonical_frame())?;
    let sealed_state = super::pairing::seal(
        &state.key_bundle,
        state.database_id,
        super::pairing::PAIRING_TABLE,
        pairing.record.pairing_id.as_bytes(),
        super::pairing::PAIRING_COLUMN,
        payload.as_slice(),
        super::pairing::MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let metadata_token = super::pairing::pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing.record.pairing_id,
        pairing.record.lifecycle,
        pairing.record.relay_server_id,
        pairing.record.machine_route,
        pairing.record.pair_route,
        pairing.record.expires_at_ms,
        pairing.record.created_at_ms,
        pairing.record.state_changed_at_ms,
        pairing.record.request_hash,
        pairing.record.device_sign_fingerprint,
        pairing.record.grant_hash,
        pairing.record.response_hash,
        &sealed_state,
    )?;
    let mut next = directory.ledger.clone();
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(pairing.sealed_state_bytes)
        .and_then(|bytes| bytes.checked_add(u64::try_from(sealed_state.len()).unwrap_or(u64::MAX)))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
        })?;
    if next.remote_pairing_sealed_bytes > super::pairing::MAX_PAIRING_SEALED_BYTES {
        return Err(RuntimeStoreError::PairingLimit);
    }
    if transaction.execute(
        "UPDATE remote_pairings
         SET sealed_state = ?1, sealed_state_bytes = ?2, metadata_token = ?3
         WHERE pairing_id = ?4 AND lifecycle = ?5 AND state_changed_at_ms = ?6
           AND request_hash = ?7 AND metadata_token = ?8",
        params![
            &sealed_state,
            i64::try_from(sealed_state.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            &pairing.record.pairing_id.as_bytes()[..],
            match pairing.record.lifecycle {
                PairingInviteLifecycle::Canceled => "canceled",
                PairingInviteLifecycle::Expired => "expired",
                _ => return Err(RuntimeStoreError::InvalidStateTransition),
            },
            i64::try_from(pairing.record.state_changed_at_ms)
                .map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            pairing
                .record
                .request_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            &pairing.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CommitPairTerminalBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::CommitPairTerminal)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::CommitPairTerminalAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::CommitPairTerminal,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let recovery =
        classify_terminal_carrier(&directory, &state.key_bundle, state.database_id, &input)?
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(CommitPairTerminalOutcome::Committed { recovery })
}

fn exact_close_terminal(
    canonical: &[u8],
    expected_pair_route: RuntimeId,
) -> Result<(), RuntimeStoreError> {
    let frame: OpaqueRouteFrame =
        decode(canonical).map_err(|_| RuntimeStoreError::PairingConflict)?;
    if encode(&frame) != canonical || frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RuntimeStoreError::PairingConflict);
    }
    match frame.body {
        RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed | PairRouteCloseOutcome::AlreadyAbsent,
        }) if pair_route.as_bytes() == expected_pair_route.as_bytes() => Ok(()),
        _ => Err(RuntimeStoreError::PairingConflict),
    }
}

fn replayed_close_ack(
    directory: &super::pairing::PairingDirectory,
    pairing_id: RuntimeId,
    canonical_terminal: &[u8],
) -> Result<Option<AcknowledgePairRouteCloseOutcome>, RuntimeStoreError> {
    let Some(receipt) = directory.terminal.receipt(pairing_id) else {
        return Ok(None);
    };
    exact_close_terminal(canonical_terminal, receipt.pair_route)?;
    if directory
        .pairings
        .iter()
        .any(|pairing| pairing.record.pairing_id == pairing_id)
    {
        return Ok(None);
    }
    if directory.terminal.close(pairing_id).is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(AcknowledgePairRouteCloseOutcome {
        receipt: receipt.receipt.clone(),
        replayed: true,
    }))
}

fn require_terminal_carrier_before_close(
    pairing: &AuthenticatedPairingRow,
) -> Result<(), RuntimeStoreError> {
    if matches!(
        pairing.record.lifecycle,
        PairingInviteLifecycle::Canceled | PairingInviteLifecycle::Expired
    ) && pairing.record.request_hash.is_some()
        && pairing.record.canonical_pair_terminal_frame.is_none()
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    Ok(())
}

pub(crate) fn acknowledge_pair_route_close(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pairing_id: RuntimeId,
    canonical_terminal: Vec<u8>,
) -> Result<AcknowledgePairRouteCloseOutcome, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(replayed) = replayed_close_ack(&directory, pairing_id, &canonical_terminal)? {
        return Ok(replayed);
    }
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if !matches!(
        pairing.record.lifecycle,
        PairingInviteLifecycle::Canceled
            | PairingInviteLifecycle::Expired
            | PairingInviteLifecycle::Delivered
    ) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    require_terminal_carrier_before_close(pairing)?;
    exact_close_terminal(&canonical_terminal, pairing.record.pair_route)?;
    if directory.terminal.close(pairing_id).is_none()
        || directory.terminal.receipt(pairing_id).is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if pairing.record.lifecycle == PairingInviteLifecycle::Delivered {
        super::pairing_delivery::ensure_durable_bootstrap_install_proof(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            pairing,
        )?;
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
    let mut directory =
        super::pairing::load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(replayed) = replayed_close_ack(&directory, pairing_id, &canonical_terminal)? {
        return Ok(replayed);
    }
    // 两个 exact replay 分支都必须保持只读且不依赖 wall clock；只有确定进入
    // fresh Close 事务后才读取 receipt retention 的新起点。
    let acknowledged_at_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
    let pairing_index = directory
        .pairings
        .iter()
        .position(|pairing| pairing.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let pairing = directory.pairings.swap_remove(pairing_index);
    require_terminal_carrier_before_close(&pairing)?;
    if pairing.record.lifecycle == PairingInviteLifecycle::Delivered {
        super::pairing_delivery::ensure_durable_bootstrap_install_proof(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &pairing,
        )?;
    }
    let close_index = directory
        .terminal
        .close_outboxes
        .iter()
        .position(|close| close.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let close = directory.terminal.close_outboxes.swap_remove(close_index);
    let receipt_row = directory
        .terminal
        .receipt(pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let persisted_ms = pairing
        .record
        .state_changed_at_ms
        .max(close.state_changed_at_ms)
        .max(receipt_row.created_at_ms);
    if acknowledged_at_ms < persisted_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms,
            observed_ms: acknowledged_at_ms,
        });
    }
    let receipt = receipt_row.receipt.clone();
    exact_close_terminal(&canonical_terminal, pairing.record.pair_route)?;
    // Fresh Close ACK 重新起算 receipt tombstone 的完整保留窗口。刷新、secret scrub
    // 与 Close outbox 删除同事务提交；commit-unknown 后 exact replay 不再刷新。
    refresh_receipt_retention(
        &transaction,
        &state.key_bundle,
        state.database_id,
        receipt_row,
        acknowledged_at_ms,
    )?;
    if transaction.execute(
        "DELETE FROM remote_control_outbox
         WHERE outbox_id = ?1 AND operation_kind = 'closePairRoute'
           AND pairing_id = ?2 AND operation_key = ?3 AND frame_hash = ?4
           AND metadata_token = ?5",
        params![
            &close.outbox_id.as_bytes()[..],
            &pairing_id.as_bytes()[..],
            &close.operation_key[..],
            &close.frame_hash[..],
            &close.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "DELETE FROM remote_pairings WHERE pairing_id = ?1 AND metadata_token = ?2",
        params![&pairing_id.as_bytes()[..], &pairing.metadata_token[..],],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let mut next = directory.ledger.clone();
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
        .checked_sub(close.sealed_frame_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_pairing_count = next
        .remote_pairing_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(pairing.sealed_state_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgePairRouteCloseBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgePairRouteClose,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgePairRouteCloseAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgePairRouteClose,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if directory.terminal.receipt(pairing_id).is_none()
        || directory
            .pairings
            .iter()
            .any(|pairing| pairing.record.pairing_id == pairing_id)
        || directory.terminal.close(pairing_id).is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AcknowledgePairRouteCloseOutcome {
        receipt,
        replayed: false,
    })
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
