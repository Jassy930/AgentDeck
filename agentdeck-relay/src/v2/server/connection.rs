//! Relay v2 WebSocket 连接状态机。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticated, Hello, PairingHello as WirePairingHello,
};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, MAX_FRAME_BYTES, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFailure,
    RelayFrameBody, decode,
};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::v2::auth::{
    AccessContext, AuthenticationOutcome, AuthorizationCoordinator, ChallengeRegistry,
    ChallengeRoute, ChallengeSource, PairingHello as AuthorizationPairingHello,
    authorize_pairing_route,
};
use crate::v2::core::writer::WriterCloseResult;
use crate::v2::core::{RelayCore, WriterCloseReason, WriterHandle, WriterReceiver};

/// HTTP/WS listener 与 codec 共用的硬上限。listener 必须在聚合分片时也应用该值。
pub const MAX_WS_MESSAGE_BYTES: usize = MAX_FRAME_BYTES;
pub const GLOBAL_WS_INGRESS_BYTES: usize = 64 * 1024 * 1024;
const WS_INGRESS_RESERVATION_PER_MESSAGE: usize = 2 * MAX_WS_MESSAGE_BYTES;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
// 8 个并发预读槽、4,096 连接上限下，一次最坏公平轮转约 5.12 秒，低于 20 秒
// heartbeat interval 与 30 秒握手上限；idle peer 不能永久霸占全局预读 permit。
const INGRESS_POLL_SLICE: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundFrameError {
    UnsupportedData,
    TooLarge,
    Protocol,
}

/// 只接受 canonical Relay v2 binary；WS control frame 不进入协议层。
pub(crate) fn decode_message(
    message: Message,
) -> Result<Option<OpaqueRouteFrame>, InboundFrameError> {
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > MAX_WS_MESSAGE_BYTES {
                return Err(InboundFrameError::TooLarge);
            }
            decode(bytes.as_ref())
                .map(Some)
                .map_err(|_| InboundFrameError::Protocol)
        }
        Message::Text(_) => Err(InboundFrameError::UnsupportedData),
        Message::Ping(_) | Message::Pong(_) | Message::Close(_) => Ok(None),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ConnectionMode {
    Principal,
    Pairing,
}

pub(crate) struct AcceptedConnection {
    pub socket: WebSocket,
    pub source: SocketAddr,
    pub mode: ConnectionMode,
}

#[derive(Clone)]
pub(crate) struct ConnectionServices {
    pub core: RelayCore,
    pub authorization: AuthorizationCoordinator,
    pub challenges: Arc<ChallengeRegistry>,
    pub relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
    pub source_hash_key: [u8; 32],
    pub book: Arc<ConnectionBook>,
    pub draining: Arc<AtomicBool>,
    pub network_ingress: Arc<Semaphore>,
    pub shutdown: CancellationToken,
}

/// server 自己持有 writer clone，用于先发 `ServerRestarting` 再 drain。
#[derive(Default)]
pub(crate) struct ConnectionBook {
    state: Mutex<ConnectionBookState>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct ConnectionBookState {
    writers: HashMap<ConnectionInstanceId, WriterHandle>,
    draining: bool,
}

impl ConnectionBook {
    fn lock(&self) -> MutexGuard<'_, ConnectionBookState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn insert(&self, connection: ConnectionInstanceId, writer: WriterHandle) -> bool {
        let mut state = self.lock();
        if state.draining {
            return false;
        }
        let inserted = state.writers.insert(connection, writer).is_none();
        drop(state);
        self.changed.notify_waiters();
        inserted
    }

    pub fn remove(&self, connection: ConnectionInstanceId) {
        self.lock().writers.remove(&connection);
        self.changed.notify_waiters();
    }

    pub fn writers(&self) -> Vec<WriterHandle> {
        self.lock().writers.values().cloned().collect()
    }

    /// 与 insert 使用同一 mutex：返回的 snapshot 包含 drain fence 前全部 writer，
    /// fence 后 insert 一律失败，避免漏发 ServerRestarting。
    pub fn begin_drain(&self) -> Vec<WriterHandle> {
        let mut state = self.lock();
        state.draining = true;
        state.writers.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lock().writers.len()
    }

    pub async fn wait_empty(&self) {
        loop {
            let changed = self.changed.notified();
            if self.len() == 0 {
                return;
            }
            changed.await;
        }
    }
}

pub(super) fn source_hash(key: &[u8; 32], source: IpAddr) -> ChallengeSource {
    let mut hash = Sha256::new();
    hash.update(b"AgentDeck/RelayChallengeSourceV1\0");
    hash.update(key);
    match source {
        IpAddr::V4(ip) => hash.update(ip.octets()),
        IpAddr::V6(ip) => hash.update(ip.octets()),
    }
    ChallengeSource::from_bytes(hash.finalize().into())
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

fn frame(body: RelayFrameBody) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    }
}

fn draining_failure() -> RelayFailure {
    RelayFailure::new(
        "relay.server.draining",
        "Relay server is draining and no longer accepts authentication",
    )
}

fn challenge_route(proof: &AuthProof) -> ChallengeRoute {
    match proof {
        AuthProof::MachineLink { machine_route, .. } => ChallengeRoute::Machine(*machine_route),
        AuthProof::Device { relay_grant } => ChallengeRoute::Device {
            machine_route: relay_grant.machine_route,
            device_route: relay_grant.device_route,
        },
    }
}

async fn next_application_frame(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    ingress: &Arc<Semaphore>,
) -> Result<Option<(OpaqueRouteFrame, OwnedSemaphorePermit)>, InboundFrameError> {
    loop {
        // 在 poll WebSocket stream（从而允许 tungstenite 聚合/分配消息）之前先占满
        // raw WS bytes + canonical decode 后的 owned payload 各预留一个单帧上界。
        // 最多只有 64MiB / 8MiB 个连接可同时物化最坏输入。
        let permits = u32::try_from(WS_INGRESS_RESERVATION_PER_MESSAGE)
            .map_err(|_| InboundFrameError::TooLarge)?;
        let mut permit = Arc::clone(ingress)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| InboundFrameError::Protocol)?;
        let message = match tokio::time::timeout(INGRESS_POLL_SLICE, stream.next()).await {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(None),
            Err(_) => {
                drop(permit);
                tokio::task::yield_now().await;
                continue;
            }
        };
        let message = message.map_err(|_| InboundFrameError::Protocol)?;
        let encoded_len = match &message {
            Message::Binary(bytes) => bytes.len(),
            Message::Text(text) => text.len(),
            Message::Ping(bytes) | Message::Pong(bytes) => bytes.len(),
            Message::Close(_) => 0,
        };
        if matches!(message, Message::Close(_)) {
            return Ok(None);
        }
        if let Some(frame) = decode_message(message)? {
            let retained = encoded_len.saturating_mul(2).max(1);
            let excess = permit.num_permits().saturating_sub(retained);
            if excess > 0 {
                drop(permit.split(excess));
            }
            return Ok(Some((frame, permit)));
        }
    }
}

async fn writer_loop(
    mut sink: futures_util::stream::SplitSink<WebSocket, Message>,
    mut receiver: WriterReceiver,
    shutdown: CancellationToken,
) {
    loop {
        let delivery = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            delivery = receiver.recv() => delivery,
        };
        let Some(delivery) = delivery else {
            break;
        };
        let bytes = axum::body::Bytes::from_owner(delivery.shared_encoded());
        let sent = tokio::select! {
            biased;
            _ = receiver.closed() => false,
            _ = shutdown.cancelled() => false,
            result = sink.send(Message::Binary(bytes)) => result.is_ok(),
        };
        if !sent {
            break;
        }
        delivery.mark_flushed();
    }
    let _ = tokio::time::timeout(Duration::from_millis(250), sink.close()).await;
}

async fn principal_handshake(
    services: &ConnectionServices,
    connection: ConnectionInstanceId,
    source: ChallengeSource,
    writer: &WriterHandle,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Result<Option<AccessContext>, RelayFailure> {
    if services.draining.load(Ordering::Acquire) {
        return Err(draining_failure());
    }
    let challenge = services.challenges.issue(connection, source)?;
    writer
        .try_enqueue_control(frame(RelayFrameBody::Challenge(challenge)))
        .map_err(|_| {
            RelayFailure::new("relay.connection.backpressure", "connection unavailable")
        })?;

    let authenticate = match next_application_frame(stream, &services.network_ingress).await {
        Ok(Some((
            OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Authenticate(authenticate),
            },
            _network_permit,
        ))) => authenticate,
        Ok(_) | Err(_) => {
            return Err(RelayFailure::new(
                "relay.auth.handshake_invalid",
                "expected Authenticate",
            ));
        }
    };
    if services.draining.load(Ordering::Acquire) {
        return Err(draining_failure());
    }
    let route = challenge_route(&authenticate.proof);
    let consumed = services.challenges.consume(connection, source, route)?;
    let outcome = services
        .authorization
        .authenticate_outcome(authenticate, consumed, unix_now_ms())
        .await?;
    let access = match &outcome {
        AuthenticationOutcome::Activated(activation) => Some(activation.access.clone()),
        AuthenticationOutcome::RevokedTerminal(_) | AuthenticationOutcome::RetiredTerminal(_) => {
            None
        }
    };
    services.core.activate_authentication(outcome).await?;
    if access.is_some() {
        writer
            .try_enqueue_control(frame(RelayFrameBody::Authenticated(Authenticated {
                heartbeat_interval_secs: 20,
            })))
            .map_err(|_| {
                RelayFailure::new("relay.connection.backpressure", "connection unavailable")
            })?;
    }
    Ok(access)
}

async fn pairing_handshake(
    services: &ConnectionServices,
    connection: ConnectionInstanceId,
    writer: &WriterHandle,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Result<AccessContext, RelayFailure> {
    if services.draining.load(Ordering::Acquire) {
        return Err(draining_failure());
    }
    let pairing_hello = match next_application_frame(stream, &services.network_ingress).await {
        Ok(Some((
            OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairingHello(pairing_hello),
            },
            _network_permit,
        ))) => pairing_hello,
        Ok(_) | Err(_) => {
            return Err(RelayFailure::new(
                "relay.auth.handshake_invalid",
                "expected PairingHello",
            ));
        }
    };
    let WirePairingHello {
        relay_server_id,
        pair_route,
    } = pairing_hello;
    if relay_server_id != services.relay_server_id {
        return Err(RelayFailure::new(
            agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_NOT_FOUND,
            "pair route is unavailable or expired",
        ));
    }
    let view = services.core.pair_route_view(pair_route).await?;
    let access = authorize_pairing_route(
        AuthorizationPairingHello {
            protocol_version: RELAY_PROTOCOL_VERSION,
            relay_server_id,
            connection_instance: connection,
            pair_route,
        },
        &view,
    )?;
    let access = AccessContext::Pairing(access);
    services.core.activate(access.clone()).await?;
    writer
        .try_enqueue_control(frame(RelayFrameBody::Authenticated(Authenticated {
            heartbeat_interval_secs: 20,
        })))
        .map_err(|_| {
            RelayFailure::new("relay.connection.backpressure", "connection unavailable")
        })?;
    Ok(access)
}

async fn reader_loop(
    services: &ConnectionServices,
    connection: ConnectionInstanceId,
    mode: ConnectionMode,
    source: ChallengeSource,
    writer: &WriterHandle,
    mut stream: futures_util::stream::SplitStream<WebSocket>,
) -> Result<(), RelayFailure> {
    let access = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        match next_application_frame(&mut stream, &services.network_ingress).await {
            Ok(Some((
                OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body:
                        RelayFrameBody::Hello(Hello {
                            protocol_version: RELAY_PROTOCOL_VERSION,
                        }),
                },
                _network_permit,
            ))) => {}
            Ok(_) | Err(_) => {
                return Err(RelayFailure::new(
                    "relay.auth.handshake_invalid",
                    "expected Relay v2 Hello",
                ));
            }
        }

        if services.draining.load(Ordering::Acquire) {
            return Err(draining_failure());
        }

        match mode {
            ConnectionMode::Principal => {
                principal_handshake(services, connection, source, writer, &mut stream).await
            }
            ConnectionMode::Pairing => pairing_handshake(services, connection, writer, &mut stream)
                .await
                .map(Some),
        }
    })
    .await
    .map_err(|_| {
        RelayFailure::new(
            "relay.auth.handshake_timeout",
            "Relay authentication handshake timed out",
        )
    })??;
    let Some(access) = access else {
        return Ok(());
    };

    loop {
        let Some((inbound, _network_permit)) =
            next_application_frame(&mut stream, &services.network_ingress)
                .await
                .map_err(|error| match error {
                    InboundFrameError::TooLarge => RelayFailure::new(
                        agentdeck_protocol::relay_v2::failure::RELAY_FRAME_TOO_LARGE,
                        "Relay frame exceeds the public limit",
                    ),
                    InboundFrameError::UnsupportedData | InboundFrameError::Protocol => {
                        RelayFailure::new("relay.frame.invalid", "invalid Relay binary frame")
                    }
                })?
        else {
            return Ok(());
        };
        // shutdown linearization：触发 drain 前已经进入 Core 的命令允许完成；此检查后
        // 到达的 frame 只被丢弃，不再产生 Store/Core mutation。reader 继续读取 Close，
        // 让 prompt client 可在收到 ServerRestarting 后自然退出。
        if services.draining.load(Ordering::Acquire) {
            continue;
        }
        if let Err(error) = services.core.handle(&access, inbound).await {
            writer
                .try_enqueue_control(frame(RelayFrameBody::Error(error)))
                .map_err(|_| {
                    RelayFailure::new("relay.connection.backpressure", "connection unavailable")
                })?;
        }
    }
}

pub(crate) async fn run_connection(accepted: AcceptedConnection, services: ConnectionServices) {
    if services.draining.load(Ordering::Acquire) {
        return;
    }
    let connection = ConnectionInstanceId::random();
    let source = source_hash(&services.source_hash_key, accepted.source.ip());
    let (writer, receiver) = WriterHandle::channel();
    if services
        .core
        .attach_pending(connection, writer.clone())
        .await
        .is_err()
    {
        writer.close(WriterCloseReason::Disconnected);
        return;
    }
    if !services.book.insert(connection, writer.clone()) {
        writer.close(WriterCloseReason::Disconnected);
        let _ = services.core.disconnect(connection).await;
        return;
    }

    let connection_shutdown = services.shutdown.child_token();
    let (sink, stream) = accepted.socket.split();
    let reader = reader_loop(
        &services,
        connection,
        accepted.mode,
        source,
        &writer,
        stream,
    );
    let socket_writer = writer_loop(sink, receiver, connection_shutdown.clone());
    tokio::pin!(reader);
    tokio::pin!(socket_writer);
    tokio::select! {
        result = &mut reader => {
            if let Err(error) = result {
                tracing::warn!(
                    event = "relay.frame.rejected",
                    failure_code = %error.code,
                    "Relay v2 connection rejected an inbound frame"
                );
            }
            if matches!(
                writer.close_unless_terminalizing(WriterCloseReason::Disconnected),
                WriterCloseResult::TerminalInProgress
            ) {
                // terminal-only reauth / revoke race：reader 退出不能覆盖 terminal。
                // receiver 继续独占写出，直到 flush 自动 close 或 Core 2s deadline。
                (&mut socket_writer).await;
            }
        }
        _ = &mut socket_writer => {}
        _ = services.shutdown.cancelled() => {}
    }
    connection_shutdown.cancel();
    let _ = writer.close_unless_terminalizing(WriterCloseReason::Disconnected);
    let _ = services.core.disconnect(connection).await;
    services.book.remove(connection);
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::frame::Hello;
    use agentdeck_protocol::relay_v2::{
        MAX_FRAME_BYTES, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, encode,
    };
    use axum::extract::ws::Message;

    use super::{InboundFrameError, decode_message};

    fn hello() -> OpaqueRouteFrame {
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::Hello(Hello {
                protocol_version: RELAY_PROTOCOL_VERSION,
            }),
        }
    }

    #[test]
    fn binary_only_decoder_accepts_canonical_v2_frame() {
        let frame = hello();
        assert_eq!(
            decode_message(Message::Binary(encode(&frame).into())).unwrap(),
            Some(frame)
        );
    }

    #[test]
    fn text_is_rejected_before_protocol_decode() {
        assert_eq!(
            decode_message(Message::Text("sensitive-payload".into())).unwrap_err(),
            InboundFrameError::UnsupportedData
        );
    }

    #[test]
    fn oversize_binary_is_rejected_before_protocol_decode() {
        assert_eq!(
            decode_message(Message::Binary(vec![0_u8; MAX_FRAME_BYTES + 1].into())).unwrap_err(),
            InboundFrameError::TooLarge
        );
    }

    #[test]
    fn malformed_binary_is_protocol_error_and_ws_control_is_not_application_data() {
        assert_eq!(
            decode_message(Message::Binary(vec![1, 2, 3].into())).unwrap_err(),
            InboundFrameError::Protocol
        );
        assert_eq!(decode_message(Message::Ping(vec![1].into())).unwrap(), None);
        assert_eq!(decode_message(Message::Pong(vec![2].into())).unwrap(), None);
        assert_eq!(decode_message(Message::Close(None)).unwrap(), None);
    }
}
