//! Principal / enrollment / pairing 互斥状态机与 active connection supervisor。

use std::collections::VecDeque;
use std::sync::Arc;

use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Authenticated, ClosePairRoute, Hello, PairData,
    PairRouteClosed, Pong, RouteAccepted, ServerRestarting,
};
use agentdeck_protocol::relay_v2::{
    MAX_FRAME_BYTES, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, OpaqueRouteFrame,
    PairRouteId, PairingHello, RELAY_PROTOCOL_VERSION, RelayFailure, RelayFrameBody,
    enrollment_receipt_hash,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::transport::{
    BinarySocket, Socket, encode_checked, is_protocol_ping, post_enrollment, protocol_pong,
};
use super::{
    EnrollmentClientConfig, HANDSHAKE_TIMEOUT, IO_TIMEOUT, LinkAuthenticator, RelayClientConfig,
    RelayClientError,
};

const APPLICATION_QUEUE_FRAMES: usize = 512;
const APPLICATION_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const URGENT_QUEUE_FRAMES: usize = 4;
const OUTBOUND_DATA_FRAMES: usize = 4;
const OUTBOUND_CONTROL_FRAMES: usize = 8;
const OUTBOUND_DATA_BYTES: usize = 15 * 1024 * 1024;
const OUTBOUND_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub enum PairingEvent {
    Data(PairData),
    RouteAccepted(RouteAccepted),
    RouteClosed(PairRouteClosed),
    Failure(RelayFailure),
    ServerRestarting(ServerRestarting),
}

impl std::fmt::Debug for PairingEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(_) => formatter.write_str("PairingEvent::Data(<redacted>)"),
            Self::RouteAccepted(_) => {
                formatter.write_str("PairingEvent::RouteAccepted(<redacted>)")
            }
            Self::RouteClosed(_) => formatter.write_str("PairingEvent::RouteClosed(<redacted>)"),
            Self::Failure(failure) => formatter
                .debug_struct("PairingEvent::Failure")
                .field("failure", failure)
                .finish(),
            Self::ServerRestarting(_) => {
                formatter.write_str("PairingEvent::ServerRestarting(<redacted>)")
            }
        }
    }
}

enum OutboundPayload {
    Binary(Vec<u8>),
    WebSocketPong(Vec<u8>),
}

struct Outbound {
    payload: OutboundPayload,
    _budget: OwnedSemaphorePermit,
    completion: Option<oneshot::Sender<Result<(), RelayClientError>>>,
}

struct Inbound {
    frame: OpaqueRouteFrame,
    _budget: OwnedSemaphorePermit,
}

struct ActiveConnection {
    data_tx: mpsc::Sender<Outbound>,
    outbound_budget: Arc<Semaphore>,
    inbound_rx: mpsc::Receiver<Inbound>,
    urgent_rx: mpsc::Receiver<OpaqueRouteFrame>,
    status_tx: watch::Sender<Option<RelayClientError>>,
    status_rx: watch::Receiver<Option<RelayClientError>>,
    cancel: CancellationToken,
    reader_task: Option<JoinHandle<()>>,
    writer_task: Option<JoinHandle<()>>,
}

impl ActiveConnection {
    fn start(socket: Socket) -> Self {
        let (sink, stream) = socket.split();
        let (data_tx, data_rx) = mpsc::channel(OUTBOUND_DATA_FRAMES);
        let (control_tx, control_rx) = mpsc::channel(OUTBOUND_CONTROL_FRAMES);
        let (inbound_tx, inbound_rx) = mpsc::channel(APPLICATION_QUEUE_FRAMES);
        let (urgent_tx, urgent_rx) = mpsc::channel(URGENT_QUEUE_FRAMES);
        let (status_tx, status_rx) = watch::channel(None);
        let outbound_budget = Arc::new(Semaphore::new(OUTBOUND_DATA_BYTES));
        let control_budget = Arc::new(Semaphore::new(OUTBOUND_CONTROL_BYTES));
        let inbound_budget = Arc::new(Semaphore::new(APPLICATION_QUEUE_BYTES));
        let cancel = CancellationToken::new();
        let writer_task = tokio::spawn(writer_loop(
            sink,
            control_rx,
            data_rx,
            status_tx.clone(),
            cancel.clone(),
        ));
        let reader_task = tokio::spawn(reader_loop(
            stream,
            control_tx.clone(),
            control_budget,
            inbound_tx,
            inbound_budget,
            urgent_tx,
            status_tx.clone(),
            cancel.clone(),
        ));
        Self {
            data_tx,
            outbound_budget,
            inbound_rx,
            urgent_rx,
            status_tx,
            status_rx,
            cancel,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
        }
    }

    async fn send(&self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
        let bytes = encode_checked(&frame)?;
        let budget = reserve_bytes(
            &self.outbound_budget,
            bytes.len(),
            "relay.client.backpressure",
        )?;
        let (completion, flushed) = oneshot::channel();
        self.data_tx
            .try_send(Outbound {
                payload: OutboundPayload::Binary(bytes),
                _budget: budget,
                completion: Some(completion),
            })
            .map_err(|_| RelayClientError::new("relay.client.backpressure"))?;
        await_flush(flushed, IO_TIMEOUT, &self.status_tx, &self.cancel).await
    }

    async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        loop {
            if let Ok(frame) = self.urgent_rx.try_recv() {
                return Ok(Some(frame));
            }
            if let Ok(inbound) = self.inbound_rx.try_recv() {
                return Ok(Some(inbound.frame));
            }
            if let Some(error) = self.status_rx.borrow().clone() {
                return Err(error);
            }
            tokio::select! {
                biased;
                urgent = self.urgent_rx.recv() => {
                    if let Some(frame) = urgent { return Ok(Some(frame)); }
                }
                inbound = self.inbound_rx.recv() => {
                    if let Some(inbound) = inbound { return Ok(Some(inbound.frame)); }
                }
                changed = self.status_rx.changed() => {
                    if changed.is_err() && self.inbound_rx.is_closed() && self.urgent_rx.is_closed() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    async fn shutdown(&mut self) {
        self.cancel.cancel();
        join_or_abort_owned(&mut self.reader_task).await;
        join_or_abort_owned(&mut self.writer_task).await;
    }
}

async fn await_flush(
    flushed: oneshot::Receiver<Result<(), RelayClientError>>,
    timeout: std::time::Duration,
    status: &watch::Sender<Option<RelayClientError>>,
    cancel: &CancellationToken,
) -> Result<(), RelayClientError> {
    match tokio::time::timeout(timeout, flushed).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(RelayClientError::new("relay.client.connection_closed")),
        Err(_) => {
            let error = RelayClientError::new("relay.client.send_outcome_unknown");
            let _ = status.send(Some(error.clone()));
            cancel.cancel();
            Err(error)
        }
    }
}

async fn join_or_abort_owned(task: &mut Option<JoinHandle<()>>) {
    let Some(task_handle) = task.as_mut() else {
        return;
    };
    join_or_abort_with_timeout(task_handle, IO_TIMEOUT).await;
    *task = None;
}

async fn join_or_abort_with_timeout(task: &mut JoinHandle<()>, timeout: std::time::Duration) {
    if tokio::time::timeout(timeout, &mut *task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Some(task) = self.writer_task.take() {
            task.abort();
        }
    }
}

fn reserve_bytes(
    budget: &Arc<Semaphore>,
    bytes: usize,
    code: &'static str,
) -> Result<OwnedSemaphorePermit, RelayClientError> {
    let permits = u32::try_from(bytes.max(1)).map_err(|_| RelayClientError::new(code))?;
    Arc::clone(budget)
        .try_acquire_many_owned(permits)
        .map_err(|_| RelayClientError::new(code))
}

async fn writer_loop<S>(
    mut sink: S,
    mut control_rx: mpsc::Receiver<Outbound>,
    mut data_rx: mpsc::Receiver<Outbound>,
    status: watch::Sender<Option<RelayClientError>>,
    cancel: CancellationToken,
) where
    S: futures_util::Sink<Message> + Unpin,
{
    loop {
        let outbound = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            control = control_rx.recv() => match control {
                Some(control) => control,
                None => match data_rx.recv().await { Some(data) => data, None => break },
            },
            data = data_rx.recv() => match data {
                Some(data) => data,
                None => match control_rx.recv().await { Some(control) => control, None => break },
            },
        };
        let message = match outbound.payload {
            OutboundPayload::Binary(bytes) => Message::Binary(bytes.into()),
            OutboundPayload::WebSocketPong(bytes) => Message::Pong(bytes.into()),
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(RelayClientError::new("relay.client.send_outcome_unknown")),
            result = sink.send(message) => result
                .map_err(|_| RelayClientError::new("relay.client.send_outcome_unknown")),
        };
        if let Some(completion) = outbound.completion {
            let _ = completion.send(result.clone());
        }
        if let Err(error) = result {
            let _ = status.send(Some(error));
            cancel.cancel();
            break;
        }
    }
    let _ = tokio::time::timeout(std::time::Duration::from_millis(250), sink.close()).await;
}

#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    mut stream: futures_util::stream::SplitStream<Socket>,
    control_tx: mpsc::Sender<Outbound>,
    outbound_budget: Arc<Semaphore>,
    inbound_tx: mpsc::Sender<Inbound>,
    inbound_budget: Arc<Semaphore>,
    urgent_tx: mpsc::Sender<OpaqueRouteFrame>,
    status: watch::Sender<Option<RelayClientError>>,
    cancel: CancellationToken,
) {
    let outcome = loop {
        let message = tokio::select! {
            biased;
            _ = cancel.cancelled() => break None,
            message = stream.next() => message,
        };
        let Some(message) = message else {
            break Some(RelayClientError::new("relay.client.connection_closed"));
        };
        match message {
            Ok(Message::Binary(bytes)) => {
                if bytes.len() > MAX_FRAME_BYTES {
                    break Some(RelayClientError::new("relay.client.frame_too_large"));
                }
                let frame = match agentdeck_protocol::relay_v2::decode(&bytes) {
                    Ok(frame) => frame,
                    Err(_) => break Some(RelayClientError::new("relay.client.frame_invalid")),
                };
                if matches!(&frame.body, RelayFrameBody::Error(error) if !error.has_safe_code()) {
                    break Some(RelayClientError::new("relay.client.frame_invalid"));
                }
                if let Some(nonce) = is_protocol_ping(&frame) {
                    if queue_control_frame(&control_tx, &outbound_budget, protocol_pong(nonce))
                        .is_err()
                    {
                        break Some(RelayClientError::new("relay.client.backpressure"));
                    }
                    continue;
                }
                if is_urgent(&frame) {
                    if urgent_tx.try_send(frame).is_err() {
                        break Some(RelayClientError::new("relay.client.lagged"));
                    }
                    continue;
                }
                let budget =
                    match reserve_bytes(&inbound_budget, bytes.len(), "relay.client.lagged") {
                        Ok(budget) => budget,
                        Err(error) => break Some(error),
                    };
                if inbound_tx
                    .try_send(Inbound {
                        frame,
                        _budget: budget,
                    })
                    .is_err()
                {
                    break Some(RelayClientError::new("relay.client.lagged"));
                }
            }
            Ok(Message::Ping(bytes)) => {
                let budget =
                    match reserve_bytes(&outbound_budget, bytes.len(), "relay.client.backpressure")
                    {
                        Ok(budget) => budget,
                        Err(error) => break Some(error),
                    };
                if control_tx
                    .try_send(Outbound {
                        payload: OutboundPayload::WebSocketPong(bytes.to_vec()),
                        _budget: budget,
                        completion: None,
                    })
                    .is_err()
                {
                    break Some(RelayClientError::new("relay.client.backpressure"));
                }
            }
            Ok(Message::Pong(_)) => {}
            Ok(Message::Close(_)) => {
                break Some(RelayClientError::new("relay.client.connection_closed"));
            }
            Ok(Message::Text(_) | Message::Frame(_)) => {
                break Some(RelayClientError::new("relay.client.frame_invalid"));
            }
            Err(_) => break Some(RelayClientError::new("relay.client.connection_closed")),
        }
    };
    if let Some(error) = outcome {
        let _ = status.send(Some(error));
    }
    cancel.cancel();
}

fn queue_control_frame(
    control_tx: &mpsc::Sender<Outbound>,
    budget: &Arc<Semaphore>,
    frame: OpaqueRouteFrame,
) -> Result<(), RelayClientError> {
    let bytes = encode_checked(&frame)?;
    let budget = reserve_bytes(budget, bytes.len(), "relay.client.backpressure")?;
    control_tx
        .try_send(Outbound {
            payload: OutboundPayload::Binary(bytes),
            _budget: budget,
            completion: None,
        })
        .map_err(|_| RelayClientError::new("relay.client.backpressure"))
}

fn is_urgent(frame: &OpaqueRouteFrame) -> bool {
    matches!(
        frame.body,
        RelayFrameBody::RevocationCommitted(_)
            | RelayFrameBody::RetirementCommitted(_)
            | RelayFrameBody::ServerRestarting(_)
            | RelayFrameBody::PairRouteClosed(_)
    )
}

fn hello() -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
    }
}

async fn principal_connection(
    config: &RelayClientConfig,
    authenticator: &Arc<dyn LinkAuthenticator>,
) -> Result<ActiveConnection, RelayClientError> {
    let mut socket = BinarySocket::connect(config, "/v2/connect").await?;
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        socket.send_frame(&hello()).await?;
        let Some((challenge_frame, _)) = socket.recv_frame().await? else {
            return Err(RelayClientError::new("relay.client.handshake_rejected"));
        };
        let RelayFrameBody::Challenge(challenge) = challenge_frame.body else {
            return Err(RelayClientError::new("relay.client.handshake_rejected"));
        };
        if challenge.relay_server_id != config.expected_relay_server_id {
            return Err(RelayClientError::new(
                "relay.client.server_identity_mismatch",
            ));
        }
        let expected_proof = authenticator.proof();
        let authenticate = authenticator.authenticate(&challenge).await?;
        if authenticate.proof != expected_proof {
            return Err(RelayClientError::new("relay.client.authenticator_invalid"));
        }
        socket
            .send_frame(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Authenticate(authenticate),
            })
            .await?;
        let Some((outcome, raw)) = socket.recv_frame().await? else {
            return Err(RelayClientError::new("relay.client.handshake_rejected"));
        };
        match outcome.body {
            RelayFrameBody::Authenticated(Authenticated { .. }) => Ok(()),
            RelayFrameBody::RevocationCommitted(_) | RelayFrameBody::RetirementCommitted(_) => {
                Err(RelayClientError::authentication_terminal(outcome, raw))
            }
            RelayFrameBody::Error(error) if error.has_safe_code() => {
                Err(RelayClientError::new(error.code))
            }
            RelayFrameBody::Error(_) => Err(RelayClientError::new("relay.client.frame_invalid")),
            _ => Err(RelayClientError::new("relay.client.handshake_rejected")),
        }
    })
    .await
    .map_err(|_| RelayClientError::new("relay.client.handshake_timeout"))?;
    result?;
    Ok(ActiveConnection::start(socket.into_inner()))
}

async fn pairing_connection(
    config: &RelayClientConfig,
    pairing_hello: PairingHello,
) -> Result<ActiveConnection, RelayClientError> {
    if pairing_hello.relay_server_id != config.expected_relay_server_id {
        return Err(RelayClientError::new(
            "relay.client.server_identity_mismatch",
        ));
    }
    let mut socket = BinarySocket::connect(config, "/v2/pair").await?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        socket.send_frame(&hello()).await?;
        socket
            .send_frame(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairingHello(pairing_hello),
            })
            .await?;
        let Some((outcome, _)) = socket.recv_frame().await? else {
            return Err(RelayClientError::new("relay.client.handshake_rejected"));
        };
        match outcome.body {
            RelayFrameBody::Authenticated(_) => Ok(()),
            RelayFrameBody::Error(error) if error.has_safe_code() => {
                Err(RelayClientError::new(error.code))
            }
            RelayFrameBody::Error(_) => Err(RelayClientError::new("relay.client.frame_invalid")),
            _ => Err(RelayClientError::new("relay.client.handshake_rejected")),
        }
    })
    .await
    .map_err(|_| RelayClientError::new("relay.client.handshake_timeout"))??;
    Ok(ActiveConnection::start(socket.into_inner()))
}

pub struct RelayClient {
    config: RelayClientConfig,
    authenticator: Arc<dyn LinkAuthenticator>,
    connection: Option<ActiveConnection>,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayClient")
            .field("config", &"<redacted>")
            .field("authenticator", &"<redacted>")
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl RelayClient {
    pub async fn connect(
        config: RelayClientConfig,
        authenticator: Arc<dyn LinkAuthenticator>,
    ) -> Result<Self, RelayClientError> {
        let connection = principal_connection(&config, &authenticator).await?;
        Ok(Self {
            config,
            authenticator,
            connection: Some(connection),
        })
    }

    pub async fn send(&self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
        self.connection
            .as_ref()
            .ok_or_else(|| RelayClientError::new("relay.client.not_connected"))?
            .send(frame)
            .await
    }

    pub async fn recv(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        self.connection
            .as_mut()
            .ok_or_else(|| RelayClientError::new("relay.client.not_connected"))?
            .recv()
            .await
    }

    pub async fn reconnect_and_authenticate(&mut self) -> Result<(), RelayClientError> {
        self.shutdown().await;
        let connection = principal_connection(&self.config, &self.authenticator).await?;
        self.connection = Some(connection);
        Ok(())
    }

    /// 正常关闭当前 generation，并在清空 owner 前等待 reader/writer task 收口。
    ///
    /// 重复调用是零副作用的 no-op；`Drop` 只保留取消/abort 的最后兜底语义。
    pub async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            connection.shutdown().await;
        }
        self.connection = None;
    }
}

pub struct RelayEnrollmentClient;

impl RelayEnrollmentClient {
    pub async fn enroll_machine(
        config: EnrollmentClientConfig,
        request: MachineEnrollmentRequestV1,
    ) -> Result<MachineEnrollmentResponseV1, RelayClientError> {
        let request_bytes = Zeroizing::new(
            serde_json::to_vec(&request)
                .map_err(|_| RelayClientError::new("relay.client.enrollment_request_invalid"))?,
        );
        let response_bytes = post_enrollment(&config.relay, &request_bytes).await?;
        let response: MachineEnrollmentResponseV1 = serde_json::from_slice(&response_bytes)
            .map_err(|_| RelayClientError::new("relay.client.enrollment_response_invalid"))?;
        if response.relay_server_id != config.relay.expected_relay_server_id
            || response.machine_route != request.machine_route
            || response.trust_epoch != request.link_cert.trust_epoch.value()
            || request.link_cert.trust_epoch != request.data_cert.trust_epoch
            || response.receipt_hash
                != enrollment_receipt_hash(
                    response.relay_server_id,
                    response.machine_route,
                    response.trust_epoch,
                    request.canonical_sha256(),
                )
        {
            return Err(RelayClientError::new(
                "relay.client.enrollment_response_invalid",
            ));
        }
        Ok(response)
    }
}

/// 受限 pairing client 不公开 raw principal `send`：
///
/// ```compile_fail
/// use agentdeck_protocol::relay_v2::OpaqueRouteFrame;
/// use agentdeck_relay_client::RelayPairingClient;
/// async fn forbidden(client: &RelayPairingClient, frame: OpaqueRouteFrame) {
///     client.send(frame).await;
/// }
/// ```
pub struct RelayPairingClient {
    pair_route: PairRouteId,
    connection: ActiveConnection,
    pending_events: VecDeque<PairingEvent>,
}

impl std::fmt::Debug for RelayPairingClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayPairingClient")
            .field("pair_route", &"<redacted>")
            .finish()
    }
}

impl RelayPairingClient {
    pub async fn connect_pairing(
        config: RelayClientConfig,
        pairing_hello: PairingHello,
    ) -> Result<Self, RelayClientError> {
        let pair_route = pairing_hello.pair_route;
        let connection = pairing_connection(&config, pairing_hello).await?;
        Ok(Self {
            pair_route,
            connection,
            pending_events: VecDeque::new(),
        })
    }

    pub async fn send_pair_data(&self, frame: PairData) -> Result<(), RelayClientError> {
        if frame.pair_route != self.pair_route {
            return Err(RelayClientError::new("relay.client.pair_route_mismatch"));
        }
        self.connection
            .send(OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::PairData(frame),
            })
            .await
    }

    pub async fn request_close(&self, frame: ClosePairRoute) -> Result<(), RelayClientError> {
        if frame.pair_route != self.pair_route {
            return Err(RelayClientError::new("relay.client.pair_route_mismatch"));
        }
        self.connection
            .send(OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::ClosePairRoute(frame),
            })
            .await
    }

    pub async fn next_event(&mut self) -> Result<Option<PairingEvent>, RelayClientError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }
        let Some(frame) = self.connection.recv().await? else {
            return Ok(None);
        };
        let event = match frame.body {
            RelayFrameBody::PairData(data) if data.pair_route == self.pair_route => {
                PairingEvent::Data(data)
            }
            RelayFrameBody::RouteAccepted(accepted)
                if matches!(
                    accepted.accepted,
                    AcceptedRef::PairFrame { pair_route } if pair_route == self.pair_route
                ) =>
            {
                PairingEvent::RouteAccepted(accepted)
            }
            RelayFrameBody::PairRouteClosed(closed) if closed.pair_route == self.pair_route => {
                PairingEvent::RouteClosed(closed)
            }
            RelayFrameBody::Error(failure) => PairingEvent::Failure(failure),
            RelayFrameBody::ServerRestarting(restarting) => {
                PairingEvent::ServerRestarting(restarting)
            }
            _ => return Err(RelayClientError::new("relay.client.pair_frame_forbidden")),
        };
        Ok(Some(event))
    }

    pub async fn recv_pair_data(&mut self) -> Result<Option<PairData>, RelayClientError> {
        match self.next_event().await? {
            Some(PairingEvent::Data(data)) => Ok(Some(data)),
            Some(event) => {
                self.pending_events.push_front(event);
                Err(RelayClientError::new("relay.client.pair_event_pending"))
            }
            None => Ok(None),
        }
    }

    pub async fn close_pair_route(&self, frame: ClosePairRoute) -> Result<(), RelayClientError> {
        self.request_close(frame).await
    }
}

// 保留这些类型在本文件可见，防止接口演进时误把 principal Challenge/Pong 当业务事件。
#[allow(dead_code)]
fn handshake_markers(
    _proof: AuthProof,
    _authenticate: Authenticate,
    _pong: Pong,
    _failure: RelayFailure,
) {
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    struct PendingSink {
        entered: Arc<tokio::sync::Notify>,
    }

    impl futures_util::Sink<Message> for PendingSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.entered.notify_one();
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn control_byte_reserve_is_independent_from_exhausted_data_budget() {
        let data = Arc::new(Semaphore::new(OUTBOUND_DATA_BYTES));
        let control = Arc::new(Semaphore::new(OUTBOUND_CONTROL_BYTES));
        let _all_data = reserve_bytes(&data, OUTBOUND_DATA_BYTES, "relay.client.backpressure")
            .expect("reserve all data bytes");
        assert!(
            reserve_bytes(&data, 1, "relay.client.backpressure").is_err(),
            "data budget must really be exhausted"
        );
        let _control = reserve_bytes(&control, 1024, "relay.client.backpressure")
            .expect("heartbeat control reserve survives full data budget");
    }

    #[tokio::test]
    async fn send_timeout_is_outcome_unknown_and_cancels_the_generation() {
        let (_completion, flushed) = oneshot::channel::<Result<(), RelayClientError>>();
        let (status_tx, status_rx) = watch::channel(None);
        let cancel = CancellationToken::new();
        let error = await_flush(
            flushed,
            std::time::Duration::from_millis(1),
            &status_tx,
            &cancel,
        )
        .await
        .expect_err("stalled flush is outcome unknown");
        assert_eq!(error.code(), "relay.client.send_outcome_unknown");
        assert!(cancel.is_cancelled());
        assert_eq!(
            status_rx.borrow().as_ref().map(RelayClientError::code),
            Some("relay.client.send_outcome_unknown")
        );
    }

    #[tokio::test]
    async fn cancelling_an_in_flight_writer_reports_outcome_unknown() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let (control_tx, control_rx) = mpsc::channel(1);
        let (data_tx, data_rx) = mpsc::channel(1);
        let (status_tx, _status_rx) = watch::channel(None);
        let cancel = CancellationToken::new();
        let writer = tokio::spawn(writer_loop(
            PendingSink {
                entered: Arc::clone(&entered),
            },
            control_rx,
            data_rx,
            status_tx,
            cancel.clone(),
        ));
        let budget = reserve_bytes(
            &Arc::new(Semaphore::new(1024)),
            1,
            "relay.client.backpressure",
        )
        .expect("writer test budget");
        let (completion, flushed) = oneshot::channel();
        data_tx
            .send(Outbound {
                payload: OutboundPayload::Binary(vec![1]),
                _budget: budget,
                completion: Some(completion),
            })
            .await
            .expect("queue writer test frame");
        entered.notified().await;
        cancel.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), flushed)
            .await
            .expect("in-flight completion timeout")
            .expect("in-flight completion channel")
            .expect_err("cancelled in-flight send is uncertain");
        assert_eq!(error.code(), "relay.client.send_outcome_unknown");
        drop(control_tx);
        drop(data_tx);
        writer.await.expect("writer task joins");
    }

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    #[tokio::test]
    async fn stalled_child_is_aborted_instead_of_detached_after_join_timeout() {
        let (signal, dropped) = oneshot::channel();
        let mut task = tokio::spawn(async move {
            let _guard = DropSignal(Some(signal));
            std::future::pending::<()>().await;
        });
        join_or_abort_with_timeout(&mut task, std::time::Duration::from_millis(1)).await;
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .expect("aborted task drop timeout")
            .expect("drop signal");
        assert!(task.is_finished());
    }

    struct ActiveTaskCounter(Arc<AtomicUsize>);

    impl Drop for ActiveTaskCounter {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn caller_cancellation_preserves_join_ownership_for_retry_shutdown() {
        let (data_tx, _data_rx) = mpsc::channel(1);
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_urgent_tx, urgent_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = watch::channel(None);
        let active_tasks = Arc::new(AtomicUsize::new(2));
        let cancel = CancellationToken::new();
        let (release, released) = oneshot::channel::<()>();
        let child_counter = Arc::clone(&active_tasks);
        let reader_task = tokio::spawn(async move {
            let _guard = ActiveTaskCounter(child_counter);
            let _ = released.await;
        });
        let child_counter = Arc::clone(&active_tasks);
        let writer_cancel = cancel.clone();
        let writer_task = tokio::spawn(async move {
            let _guard = ActiveTaskCounter(child_counter);
            writer_cancel.cancelled().await;
        });
        let mut connection = ActiveConnection {
            data_tx,
            outbound_budget: Arc::new(Semaphore::new(1)),
            inbound_rx,
            urgent_rx,
            status_tx,
            status_rx,
            cancel,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
        };

        let mut first_shutdown = Box::pin(connection.shutdown());
        tokio::select! {
            result = &mut first_shutdown => panic!("blocked child unexpectedly joined: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
        drop(first_shutdown);

        assert!(
            connection.reader_task.is_some(),
            "caller cancellation must not detach the in-flight reader JoinHandle"
        );
        assert!(connection.writer_task.is_some());
        release.send(()).expect("release blocked reader");
        connection.shutdown().await;
        assert!(connection.reader_task.is_none());
        assert!(connection.writer_task.is_none());
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn close_ack_is_reserved_and_pairing_debug_never_renders_ciphertext() {
        let pair_route = PairRouteId::from_bytes([0xaa; 16]);
        let closed = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
                pair_route,
                outcome: agentdeck_protocol::relay_v2::frame::PairRouteCloseOutcome::Closed,
            }),
        };
        assert!(is_urgent(&closed));
        let event = PairingEvent::Data(PairData {
            pair_route,
            sealed_blob: agentdeck_protocol::relay_v2::frame::SealedBlob(
                b"ciphertext-sentinel".to_vec(),
            ),
        });
        let rendered = format!("{event:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ciphertext-sentinel"));
    }
}
