//! `WsTransport`: `agentdeck_protocol::Transport` 的字节层 WS 实现
//! （`String` ↔ WS text frame，`reconnect` 真重连）。
//! `WsRelayClient`：在 `WsTransport` 之上编解码 `RemoteFrame`（serde_json
//! text），实现 `RelayLink`；记录已发的 `Subscribe` 帧，`reconnect` 后重放。

use agentdeck_protocol::remote::{ClientRole, RelayControlMsg, RemoteFrame};
use agentdeck_protocol::{AuthContext, Transport, TransportError};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

#[derive(thiserror::Error, Debug)]
pub enum WsError {
    #[error("ws connect: {0}")]
    Connect(String),
    #[error("ws io: {0}")]
    Io(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("closed")]
    Closed,
}

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;

/// 字节层 transport：`Transport::send/recv` 收发一整行 `String`，映射到 WS
/// text frame。`reconnect` 用保存的 `url`/`bearer` 重建整条连接（新的
/// sink/stream 替换旧的，Subscribe 重放由更上层的 `WsRelayClient` 负责）。
pub struct WsTransport {
    url: String,
    bearer: String,
    auth: AuthContext,
    sink: Mutex<WsSink>,
    stream: Mutex<SplitStream<WsStream>>,
}

fn role_label(role: &ClientRole) -> String {
    match role {
        ClientRole::Relay => "relay".to_string(),
        ClientRole::Machine { machine_id } => format!("machine:{machine_id}"),
        ClientRole::Device { device_id } => format!("device:{device_id}"),
    }
}

fn build_request(
    url: &str,
    bearer: &str,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, WsError> {
    let mut request = url
        .into_client_request()
        .map_err(|e| WsError::Connect(e.to_string()))?;
    let value = format!("Bearer {bearer}")
        .parse()
        .map_err(|e: tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue| {
            WsError::Connect(e.to_string())
        })?;
    request.headers_mut().insert(AUTHORIZATION, value);
    Ok(request)
}

async fn dial(url: &str, bearer: &str) -> Result<(WsSink, SplitStream<WsStream>), WsError> {
    let request = build_request(url, bearer)?;
    let (ws_stream, _response) = connect_async(request)
        .await
        .map_err(|e| WsError::Connect(e.to_string()))?;
    Ok(ws_stream.split())
}

impl WsTransport {
    /// `auth_label` 只用于 `auth_context()` 诊断展示（例如 `"device:D1"`），
    /// 不参与握手；握手鉴权走 `bearer` 生成的 `Authorization` header。
    pub async fn connect(url: &str, bearer: &str, auth_label: String) -> Result<Self, WsError> {
        let (sink, stream) = dial(url, bearer).await?;
        Ok(Self {
            url: url.to_string(),
            bearer: bearer.to_string(),
            auth: AuthContext::Bearer { token: bearer.to_string(), device_id: auth_label },
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
        })
    }
}

#[async_trait::async_trait]
impl Transport for WsTransport {
    async fn send(&self, line: String) -> Result<(), TransportError> {
        let mut sink = self.sink.lock().await;
        sink.send(Message::text(line))
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e.to_string())))
    }

    async fn recv(&self) -> Result<Option<String>, TransportError> {
        let mut stream = self.stream.lock().await;
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => return Ok(Some(text.to_string())),
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_))) => {
                    continue;
                }
                Some(Err(e)) => {
                    return Err(TransportError::Io(std::io::Error::other(e.to_string())));
                }
            }
        }
    }

    async fn reconnect(&self) -> Result<(), TransportError> {
        let (new_sink, new_stream) = dial(&self.url, &self.bearer)
            .await
            .map_err(|e| TransportError::AuthFailed(e.to_string()))?;
        *self.sink.lock().await = new_sink;
        *self.stream.lock().await = new_stream;
        Ok(())
    }

    fn auth_context(&self) -> &AuthContext {
        &self.auth
    }
}

/// `RelayLink` 的 WS 实现：在 `WsTransport` 上做 `RemoteFrame` 的 JSON 编解码，
/// 并记录发出的 `Subscribe` 帧，`reconnect()` 后按记录顺序重放，使 relay 端
/// 恢复此连接此前建立的所有订阅。
pub struct WsRelayClient {
    transport: WsTransport,
    subscriptions: Mutex<Vec<RemoteFrame>>,
}

impl WsRelayClient {
    pub async fn connect(url: &str, bearer: &str, from: ClientRole) -> Result<Self, WsError> {
        let transport = WsTransport::connect(url, bearer, role_label(&from)).await?;
        Ok(Self { transport, subscriptions: Mutex::new(Vec::new()) })
    }

    /// 重连底层 WS 连接，并按记录顺序重放此前发出的所有 `Subscribe` 帧。
    pub async fn reconnect(&self) -> Result<(), WsError> {
        self.transport
            .reconnect()
            .await
            .map_err(|e| WsError::Connect(e.to_string()))?;
        let subs = self.subscriptions.lock().await.clone();
        for frame in subs {
            let line = serde_json::to_string(&frame)
                .map_err(|e| WsError::InvalidFrame(e.to_string()))?;
            self.transport.send(line).await.map_err(|e| WsError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl agentdeck_relay::RelayLink for WsRelayClient {
    async fn send(&self, frame: RemoteFrame) {
        if matches!(frame.msg, RelayControlMsg::Subscribe { .. }) {
            self.subscriptions.lock().await.push(frame.clone());
        }
        let Ok(line) = serde_json::to_string(&frame) else { return };
        let _ = self.transport.send(line).await;
    }

    async fn recv(&mut self) -> Option<RemoteFrame> {
        loop {
            match self.transport.recv().await {
                Ok(Some(line)) => match serde_json::from_str::<RemoteFrame>(&line) {
                    Ok(frame) => return Some(frame),
                    Err(_) => continue,
                },
                Ok(None) | Err(_) => return None,
            }
        }
    }
}
