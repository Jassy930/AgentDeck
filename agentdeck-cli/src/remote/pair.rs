//! Persistent `remote pair` 的 durable transaction 与受限 Relay pairing transport。
//!
//! 完整 PairInvite 是 bearer secret。本模块只从 stdin 或 current-UID exact-0600、
//! no-follow 文件读取 canonical URI；Relay endpoint projection 明确排除 invite secret。
//! PairRequest 在任何网络发送前由 [`PendingPairingCoordinator`] immutable 持久化，未知
//! outcome 只能复用同一 pending marker、同一 invite 与同一 canonical carrier 重连。

#![cfg(unix)]

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    E2EE_FORMAT_VERSION, PairInviteV1, PairingError,
};
use agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_NOT_FOUND;
use agentdeck_protocol::relay_v2::frame::{PairData, PairRouteCloseOutcome, SealedBlob};
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, PairRouteId, PairingHello, RELAY_PROTOCOL_VERSION, RelayFrameBody,
    RelayServerId, encode,
};
use agentdeck_protocol::runtime::MachineRootFingerprint;
use agentdeck_relay_client::{
    PairingEvent, RelayClientConfig, RelayClientError, RelayPairingClient, RelayTlsPolicy,
};
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::keychain::RemoteKeyStore;
use super::paired_machine::{PairedPromotionCoordinator, PairedPromotionError};
use super::pending::{PendingPairingCoordinator, PendingPairingError, VerifiedPendingPairData};
use super::production::PersistentRemoteComposition;

const MAX_INVITE_URI_BYTES: usize = 8 * 1_024;
const MAX_INVITE_INPUT_BYTES: usize = MAX_INVITE_URI_BYTES + 2;
const RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_UNKNOWN_RECONNECTS: usize = 64;
const PERSISTENT_REMOTE_CLI_DISPLAY_NAME: &str = "Persistent Remote CLI";

/// 不含 bearer 的 Relay pairing endpoint。CLI/env 不能覆盖其中任一坐标。
pub struct PairEndpoint {
    wss_url: String,
    relay_server_id: RelayServerId,
    pair_route: PairRouteId,
    spki_pins: Vec<[u8; 32]>,
}

impl std::fmt::Debug for PairEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairEndpoint")
            .field("wss_url", &"<redacted>")
            .field("relay_server", &"<redacted>")
            .field("pair_route", &"<redacted>")
            .field("pin_count", &self.spki_pins.len())
            .finish()
    }
}

impl PairEndpoint {
    fn from_invite(invite: &PairInviteV1) -> Self {
        let spki_pins = if invite.current_spki_pin == invite.next_spki_pin {
            vec![invite.current_spki_pin]
        } else {
            vec![invite.current_spki_pin, invite.next_spki_pin]
        };
        Self {
            wss_url: invite.wss_url.clone(),
            relay_server_id: invite.relay_server_id,
            pair_route: invite.pair_route,
            spki_pins,
        }
    }

    #[must_use]
    pub const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }
}

/// 单条受限 pairing connection；接口没有 principal `send`。
#[async_trait]
pub trait DurablePairConnection: Send {
    async fn send_pair_data_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError>;

    async fn next_event(&mut self) -> Result<Option<PairingEvent>, RelayClientError>;

    async fn shutdown(&mut self) {}
}

#[async_trait]
impl DurablePairConnection for RelayPairingClient {
    async fn send_pair_data_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError> {
        RelayPairingClient::send_pair_data_encoded(self, bytes).await
    }

    async fn next_event(&mut self) -> Result<Option<PairingEvent>, RelayClientError> {
        RelayPairingClient::next_event(self).await
    }

    async fn shutdown(&mut self) {
        RelayPairingClient::shutdown(self).await;
    }
}

/// Unknown outcome 的唯一重连 seam。endpoint 不含 bearer，也没有 relay override。
#[async_trait]
pub trait DurablePairConnector: Send {
    type Connection: DurablePairConnection;

    async fn connect(
        &mut self,
        endpoint: &PairEndpoint,
    ) -> Result<Self::Connection, RelayClientError>;

    async fn wait_before_retry(&mut self);
}

/// Production connector 固定使用 PairInvite 的 WSS、Relay identity 与 current/next SPKI。
#[derive(Debug, Default)]
struct ProductionPairConnector;

#[async_trait]
impl DurablePairConnector for ProductionPairConnector {
    type Connection = RelayPairingClient;

    async fn connect(
        &mut self,
        endpoint: &PairEndpoint,
    ) -> Result<Self::Connection, RelayClientError> {
        let tls = RelayTlsPolicy::pinned_spki(endpoint.spki_pins.clone())?;
        let config = RelayClientConfig::new(&endpoint.wss_url, endpoint.relay_server_id, tls)?;
        RelayPairingClient::connect_pairing(
            config,
            PairingHello {
                relay_server_id: endpoint.relay_server_id,
                pair_route: endpoint.pair_route,
            },
        )
        .await
    }

    async fn wait_before_retry(&mut self) {
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

/// 只有 matching `PairRouteClosed::Closed` 之后才会产生的成功结果。
#[derive(Debug)]
pub struct DurablePairOutcome {
    pair_route: PairRouteId,
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: agentdeck_protocol::relay_v2::MachineRouteId,
    device_route: agentdeck_protocol::relay_v2::DeviceRouteId,
    route_accepted_observed: bool,
    recovered_paired_marker: bool,
}

impl DurablePairOutcome {
    #[must_use]
    pub const fn pair_route(&self) -> PairRouteId {
        self.pair_route
    }

    #[must_use]
    pub const fn machine_root_fingerprint(&self) -> MachineRootFingerprint {
        self.machine_root_fingerprint
    }

    #[must_use]
    pub const fn machine_route(&self) -> agentdeck_protocol::relay_v2::MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub const fn device_route(&self) -> agentdeck_protocol::relay_v2::DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub const fn route_accepted_observed(&self) -> bool {
        self.route_accepted_observed
    }

    #[must_use]
    pub const fn recovered_paired_marker(&self) -> bool {
        self.recovered_paired_marker
    }
}

/// Pair 命令失败；任何 variant 都不是 pairing success。
#[derive(Debug, Error)]
pub enum DurablePairError {
    #[error("pair invite input is unavailable or unsafe")]
    Input(#[source] io::Error),
    #[error("pair invite URI is not canonical or valid")]
    InvalidInvite(#[source] PairingError),
    #[error("pair authorization request is invalid")]
    InvalidAuthorization(#[source] PairingError),
    #[error("confirmed MachineRoot fingerprint does not exactly match the PairInvite")]
    RootFingerprintMismatch,
    #[error("durable pending pairing state failed")]
    Pending(#[from] PendingPairingError),
    #[error("durable paired promotion failed")]
    Promotion(#[from] PairedPromotionError),
    #[error("pairing outcome is unknown without a durable Closed acknowledgement")]
    OutcomeUnknown,
    #[error("Relay pairing transport failed a non-retryable security check: {0}")]
    TransportSecurity(String),
    #[error("Relay rejected pairing with {0}")]
    RelayRejected(String),
    #[error("PairRouteClosed::Closed arrived before the receipt was sent")]
    ClosedBeforeReceipt,
    #[error("Relay pairing event does not match the invite pair route")]
    RouteMismatch,
}

impl DurablePairError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Input(_) => "remote.pairing.input_unsafe",
            Self::InvalidInvite(_) => "remote.pairing.invite_invalid",
            Self::InvalidAuthorization(_) => "remote.pairing.authorization_invalid",
            Self::RootFingerprintMismatch => "remote.pairing.root_fingerprint_mismatch",
            Self::Pending(error) => error.code(),
            Self::Promotion(error) => error.code(),
            Self::OutcomeUnknown => "remote.pairing.outcome_unknown",
            Self::TransportSecurity(_) => "remote.pairing.transport_security",
            Self::RelayRejected(_) => "remote.pairing.relay_rejected",
            Self::ClosedBeforeReceipt | Self::RouteMismatch => "remote.pairing.frame_invalid",
        }
    }
}

/// 组合 durable pending 与 paired promotion；自身不持有 canonical 业务 state。
pub struct DurablePairingCoordinator<'a> {
    pending: PendingPairingCoordinator<'a>,
    promotion: PairedPromotionCoordinator<'a>,
}

impl std::fmt::Debug for DurablePairingCoordinator<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurablePairingCoordinator([REDACTED])")
    }
}

impl<'a> DurablePairingCoordinator<'a> {
    #[must_use]
    pub fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid, state_root: &Path) -> Self {
        Self {
            pending: PendingPairingCoordinator::new(store, installation_id),
            promotion: PairedPromotionCoordinator::new(store, installation_id, state_root),
        }
    }

    /// 完成 durable pair。每次连接的第一帧都是 prepare exact readback 后的同一 PairRequest；
    /// ServerRestarting 继续 drain，只有 EOF/transport error 才让同 transaction 重连，绝不重 seal。
    pub async fn pair<R, C, N>(
        &self,
        invite: PairInviteV1,
        authorization: &AuthorizationRequestV1,
        connector: &mut C,
        mut now_ms: N,
        rng: &mut R,
    ) -> Result<DurablePairOutcome, DurablePairError>
    where
        R: CryptoRng,
        C: DurablePairConnector,
        N: FnMut() -> u64,
    {
        let sensitive_invite = SensitivePairInvite(invite);
        let invite = &sensitive_invite.0;
        authorization
            .validate()
            .map_err(DurablePairError::InvalidAuthorization)?;
        let prepared = self.pending.prepare(invite, authorization, now_ms(), rng)?;
        let exact_request = exact_pair_data(invite.pair_route, prepared.canonical_request());
        let endpoint = PairEndpoint::from_invite(invite);
        let mut route_accepted_observed = false;
        let mut unknown_reconnects = 0_usize;

        loop {
            if now_ms() >= invite.expires_at_ms {
                return Err(DurablePairError::OutcomeUnknown);
            }
            let mut connection = match connector.connect(&endpoint).await {
                Ok(connection) => connection,
                Err(error) if retryable_transport_error(&error) => {
                    unknown_reconnects += 1;
                    if unknown_reconnects >= MAX_UNKNOWN_RECONNECTS {
                        return Err(DurablePairError::OutcomeUnknown);
                    }
                    connector.wait_before_retry().await;
                    continue;
                }
                Err(error) => return Err(transport_security_error(error)),
            };
            match self
                .run_attempt(
                    invite,
                    authorization,
                    &exact_request,
                    &mut connection,
                    &mut now_ms,
                    rng,
                    &mut route_accepted_observed,
                )
                .await
            {
                Ok(AttemptResult::Complete(mut outcome)) => {
                    outcome.route_accepted_observed = route_accepted_observed;
                    connection.shutdown().await;
                    return Ok(outcome);
                }
                Ok(AttemptResult::OutcomeUnknown) => {
                    connection.shutdown().await;
                    unknown_reconnects += 1;
                    if unknown_reconnects >= MAX_UNKNOWN_RECONNECTS {
                        return Err(DurablePairError::OutcomeUnknown);
                    }
                    connector.wait_before_retry().await;
                }
                Err(error) => {
                    connection.shutdown().await;
                    return Err(error);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_attempt<R, C, N>(
        &self,
        invite: &PairInviteV1,
        authorization: &AuthorizationRequestV1,
        exact_request: &[u8],
        connection: &mut C,
        now_ms: &mut N,
        rng: &mut R,
        route_accepted_observed: &mut bool,
    ) -> Result<AttemptResult, DurablePairError>
    where
        R: CryptoRng,
        C: DurablePairConnection,
        N: FnMut() -> u64,
    {
        if let Err(error) = connection
            .send_pair_data_encoded(exact_request.to_vec())
            .await
        {
            return transport_attempt_error(error);
        }

        let mut promoted = None;
        loop {
            let observed_now_ms = now_ms();
            if observed_now_ms >= invite.expires_at_ms {
                return Err(DurablePairError::OutcomeUnknown);
            }
            let remaining = Duration::from_millis(invite.expires_at_ms - observed_now_ms);
            let next_event = match tokio::time::timeout(remaining, connection.next_event()).await {
                Ok(next_event) => next_event,
                Err(_) => return Ok(AttemptResult::OutcomeUnknown),
            };
            let event = match next_event {
                Ok(Some(event)) => event,
                Ok(None) => return Ok(AttemptResult::OutcomeUnknown),
                Err(error) => return transport_attempt_error(error),
            };
            match event {
                PairingEvent::Data(data) => {
                    if data.pair_route != invite.pair_route {
                        return Err(DurablePairError::RouteMismatch);
                    }
                    match self
                        .pending
                        .classify_pair_data(invite, authorization, now_ms(), &data)?
                    {
                        VerifiedPendingPairData::Waiting(_) => {}
                        VerifiedPendingPairData::Response(response) => {
                            let paired = self.promotion.promote(*response, rng)?;
                            let outcome = DurablePairOutcome {
                                pair_route: invite.pair_route,
                                machine_root_fingerprint: MachineRootFingerprint::from_bytes(
                                    invite.machine_root_fingerprint,
                                ),
                                machine_route: paired.machine_route(),
                                device_route: paired.device_route(),
                                route_accepted_observed: false,
                                recovered_paired_marker: paired.was_already_committed(),
                            };
                            let exact_receipt = exact_pair_data(
                                invite.pair_route,
                                paired.canonical_receipt_carrier(),
                            );
                            if let Err(error) =
                                connection.send_pair_data_encoded(exact_receipt).await
                            {
                                return transport_attempt_error(error);
                            }
                            promoted = Some(outcome);
                        }
                    }
                }
                PairingEvent::RouteAccepted(accepted) => {
                    if !matches!(
                        accepted.accepted,
                        agentdeck_protocol::relay_v2::frame::AcceptedRef::PairFrame { pair_route }
                            if pair_route == invite.pair_route
                    ) {
                        return Err(DurablePairError::RouteMismatch);
                    }
                    *route_accepted_observed = true;
                }
                PairingEvent::RouteClosed(closed) => {
                    if closed.pair_route != invite.pair_route {
                        return Err(DurablePairError::RouteMismatch);
                    }
                    match closed.outcome {
                        PairRouteCloseOutcome::Closed => {
                            return promoted.map_or_else(
                                || Err(DurablePairError::ClosedBeforeReceipt),
                                |outcome| Ok(AttemptResult::Complete(outcome)),
                            );
                        }
                        PairRouteCloseOutcome::AlreadyAbsent => {
                            return Err(DurablePairError::OutcomeUnknown);
                        }
                    }
                }
                PairingEvent::Failure(failure) => {
                    let code = if failure.has_safe_code() {
                        failure.code
                    } else {
                        "relay.failure.invalid".to_owned()
                    };
                    if retryable_pairing_failure_code(&code) {
                        return Ok(AttemptResult::OutcomeUnknown);
                    }
                    return Err(DurablePairError::RelayRejected(code));
                }
                // ServerRestarting 只是 urgent drain hint；当前 writer 仍可能交付 durable
                // Closed。继续读到 terminal 或真实 EOF/error，不能主动丢弃成功证明。
                PairingEvent::ServerRestarting(_) => {}
            }
        }
    }
}

enum AttemptResult {
    Complete(DurablePairOutcome),
    OutcomeUnknown,
}

struct SensitivePairInvite(PairInviteV1);

impl Drop for SensitivePairInvite {
    fn drop(&mut self) {
        self.0.invite_secret.zeroize();
    }
}

fn transport_attempt_error(error: RelayClientError) -> Result<AttemptResult, DurablePairError> {
    if retryable_transport_error(&error) {
        Ok(AttemptResult::OutcomeUnknown)
    } else {
        Err(transport_security_error(error))
    }
}

fn retryable_transport_error(error: &RelayClientError) -> bool {
    matches!(
        error.code(),
        "relay.client.backpressure"
            | "relay.client.connect_failed"
            | "relay.client.connect_timeout"
            | "relay.client.connection_closed"
            | "relay.client.handshake_rejected"
            | "relay.client.handshake_timeout"
            | "relay.client.lagged"
            | "relay.client.not_connected"
            | "relay.client.receive_timeout"
            | "relay.client.send_outcome_unknown"
            | "relay.client.send_timeout"
    ) || retryable_pairing_failure_code(error.code())
}

fn retryable_pairing_failure_code(code: &str) -> bool {
    matches!(code, RELAY_ROUTE_NOT_FOUND | "relay.server.draining")
}

fn transport_security_error(error: RelayClientError) -> DurablePairError {
    DurablePairError::TransportSecurity(error.code().to_owned())
}

fn exact_pair_data(pair_route: PairRouteId, carrier: &[u8]) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairData(PairData {
            pair_route,
            sealed_blob: SealedBlob(carrier.to_vec()),
        }),
    })
}

/// 全量 P4 MVP authorization；remote pairing 不包含 machine/pairing admin 权限。
pub fn mvp_authorization() -> Result<AuthorizationRequestV1, PairingError> {
    let request = AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: PERSISTENT_REMOTE_CLI_DISPLAY_NAME.to_owned(),
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

/// 已完成人工 MachineRoot fingerprint 确认的 move-only production capability。
/// 字段私有且 Debug 全量脱敏；唯一构造入口是 [`confirm_machine_root_fingerprint`]。
pub struct ConfirmedPairInvite(Option<PairInviteV1>);

impl std::fmt::Debug for ConfirmedPairInvite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfirmedPairInvite([REDACTED])")
    }
}

impl ConfirmedPairInvite {
    fn into_invite(mut self) -> PairInviteV1 {
        self.0
            .take()
            .expect("confirmed PairInvite is consumed exactly once")
    }
}

impl Drop for ConfirmedPairInvite {
    fn drop(&mut self) {
        if let Some(invite) = self.0.as_mut() {
            invite.invite_secret.zeroize();
        }
    }
}

/// 要求用户确认的值必须与 canonical invite 的完整 MachineRoot fingerprint 逐字相同。
/// confirmation 本身不是 bearer，可安全作为 CLI 参数；错误不回显输入或期望值。
/// 成功会消费 raw invite 并返回 production pair 唯一接受的 capability。
pub fn confirm_machine_root_fingerprint(
    mut invite: PairInviteV1,
    confirmation: &str,
) -> Result<ConfirmedPairInvite, DurablePairError> {
    if confirmation == invite.machine_root_fingerprint_display() {
        Ok(ConfirmedPairInvite(Some(invite)))
    } else {
        invite.invite_secret.zeroize();
        Err(DurablePairError::RootFingerprintMismatch)
    }
}

/// 从 bounded stdin/read pipe 读取一条 canonical PairInvite URI。只容许一个 LF 或 CRLF
/// record terminator；不使用 `trim()`，避免接受被改写的 bearer 文本。
pub fn load_pair_invite_from_reader(
    reader: impl Read,
    now_ms: u64,
) -> Result<PairInviteV1, DurablePairError> {
    decode_pair_invite_input(read_bounded(reader)?, now_ms)
}

/// 从 current-UID、single-link、exact-0600 regular file 读取 canonical invite。
pub fn load_pair_invite_from_private_file(
    path: &Path,
    now_ms: u64,
) -> Result<PairInviteV1, DurablePairError> {
    let mut options = File::options();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|error| DurablePairError::Input(redacted_io(error.kind())))?;
    let metadata = file
        .metadata()
        .map_err(|error| DurablePairError::Input(redacted_io(error.kind())))?;
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.uid() != current_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_INVITE_INPUT_BYTES as u64
    {
        return Err(DurablePairError::Input(redacted_io(
            io::ErrorKind::PermissionDenied,
        )));
    }
    decode_pair_invite_input(read_bounded(file)?, now_ms)
}

fn read_bounded(reader: impl Read) -> Result<Zeroizing<Vec<u8>>, DurablePairError> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_INVITE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| DurablePairError::Input(redacted_io(error.kind())))?;
    if bytes.is_empty() || bytes.len() > MAX_INVITE_INPUT_BYTES {
        return Err(DurablePairError::Input(redacted_io(
            io::ErrorKind::InvalidData,
        )));
    }
    Ok(bytes)
}

fn decode_pair_invite_input(
    mut bytes: Zeroizing<Vec<u8>>,
    now_ms: u64,
) -> Result<PairInviteV1, DurablePairError> {
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if bytes.is_empty() || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(DurablePairError::InvalidInvite(
            PairingError::InvalidEncoding("pair invite input record"),
        ));
    }
    let encoded = std::str::from_utf8(&bytes).map_err(|_| {
        DurablePairError::InvalidInvite(PairingError::InvalidEncoding("pair invite URI UTF-8"))
    })?;
    PairInviteV1::decode_uri(encoded, now_ms).map_err(DurablePairError::InvalidInvite)
}

fn redacted_io(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "pair invite input rejected")
}

/// Production composition convenience。签名/entitlement、Keychain 与 passwd-derived root
/// 均来自既有封闭 composition；本入口不接受替代 store、relay URL 或 TLS policy。
pub async fn pair_production<R: CryptoRng>(
    composition: &PersistentRemoteComposition,
    invite: ConfirmedPairInvite,
    rng: &mut R,
) -> Result<DurablePairOutcome, DurablePairError> {
    let coordinator = DurablePairingCoordinator::new(
        composition.key_store(),
        composition.installation_id().as_uuid(),
        composition.state_root(),
    );
    let authorization = mvp_authorization().map_err(DurablePairError::InvalidAuthorization)?;
    let mut connector = ProductionPairConnector;
    coordinator
        .pair(
            invite.into_invite(),
            &authorization,
            &mut connector,
            unix_now_ms,
            rng,
        )
        .await
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
