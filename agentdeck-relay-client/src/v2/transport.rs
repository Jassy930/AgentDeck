//! 私有 binary WebSocket/TLS transport；业务调用方不能取得 raw socket。

use agentdeck_protocol::relay_v2::failure::REMOTE_TRANSPORT_TLS_PIN_MISMATCH;
use agentdeck_protocol::relay_v2::{
    MAX_FRAME_BYTES, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, decode, encode,
};
use futures_util::{SinkExt, StreamExt};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use url::Position;

use super::{
    CONNECT_TIMEOUT, IO_TIMEOUT, MAX_ENROLLMENT_BYTES, RelayClientConfig, RelayClientError,
};

const MAX_HTTP_HEADERS: usize = 16 * 1024;

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct BinarySocket {
    socket: Socket,
}

impl BinarySocket {
    pub(crate) async fn connect(
        config: &RelayClientConfig,
        path: &'static str,
    ) -> Result<Self, RelayClientError> {
        let mut endpoint = config.origin.clone();
        endpoint.set_path(path);
        let request = endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| RelayClientError::new("relay.client.origin_invalid"))?;
        let tls = config.tls.client_config()?;
        let mut websocket = WebSocketConfig::default();
        websocket.read_buffer_size = 64 * 1024;
        websocket.write_buffer_size = 64 * 1024;
        websocket.max_write_buffer_size = MAX_FRAME_BYTES.saturating_add(64 * 1024);
        websocket.max_message_size = Some(MAX_FRAME_BYTES);
        websocket.max_frame_size = Some(MAX_FRAME_BYTES);
        websocket.accept_unmasked_frames = false;
        let (socket, response) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_async_tls_with_config(
                request,
                Some(websocket),
                false,
                Some(Connector::Rustls(tls)),
            ),
        )
        .await
        .map_err(|_| RelayClientError::new("relay.client.connect_timeout"))?
        .map_err(|error| map_connect_error(&error))?;
        if response.status().as_u16() != 101 {
            return Err(RelayClientError::new("relay.client.handshake_rejected"));
        }
        Ok(Self { socket })
    }

    pub(crate) async fn send_frame(
        &mut self,
        frame: &OpaqueRouteFrame,
    ) -> Result<(), RelayClientError> {
        let bytes = encode_checked(frame)?;
        tokio::time::timeout(IO_TIMEOUT, self.socket.send(Message::Binary(bytes.into())))
            .await
            .map_err(|_| RelayClientError::new("relay.client.send_timeout"))?
            .map_err(|_| RelayClientError::new("relay.client.connection_closed"))
    }

    pub(crate) async fn recv_frame(
        &mut self,
    ) -> Result<Option<(OpaqueRouteFrame, Vec<u8>)>, RelayClientError> {
        loop {
            let message = tokio::time::timeout(IO_TIMEOUT, self.socket.next())
                .await
                .map_err(|_| RelayClientError::new("relay.client.receive_timeout"))?;
            match message {
                Some(Ok(Message::Binary(bytes))) => {
                    let raw = bytes.to_vec();
                    let frame = decode(&raw)
                        .map_err(|_| RelayClientError::new("relay.client.frame_invalid"))?;
                    return Ok(Some((frame, raw)));
                }
                Some(Ok(Message::Ping(bytes))) => {
                    self.socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| RelayClientError::new("relay.client.connection_closed"))?;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Text(_) | Message::Frame(_))) => {
                    return Err(RelayClientError::new("relay.client.frame_invalid"));
                }
                Some(Err(_)) => {
                    return Err(RelayClientError::new("relay.client.connection_closed"));
                }
            }
        }
    }

    pub(crate) fn into_inner(self) -> Socket {
        self.socket
    }
}

pub(crate) fn encode_checked(frame: &OpaqueRouteFrame) -> Result<Vec<u8>, RelayClientError> {
    if frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RelayClientError::new("relay.client.version_unsupported"));
    }
    let bytes = encode(frame);
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(RelayClientError::new("relay.client.frame_too_large"));
    }
    Ok(bytes)
}

/// 校验调用方已经冻结的 Relay codec bytes，但不重建或替换待发送字节。
pub(crate) fn validate_encoded(bytes: &[u8]) -> Result<(), RelayClientError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(RelayClientError::new("relay.client.frame_too_large"));
    }
    decode(bytes)
        .map(|_| ())
        .map_err(|_| RelayClientError::new("relay.client.frame_invalid"))
}

pub(crate) fn is_protocol_ping(frame: &OpaqueRouteFrame) -> Option<u64> {
    match frame.body {
        RelayFrameBody::Ping(ref ping) => Some(ping.nonce),
        _ => None,
    }
}

pub(crate) async fn post_enrollment(
    config: &RelayClientConfig,
    body: &[u8],
) -> Result<Vec<u8>, RelayClientError> {
    if body.len() > MAX_ENROLLMENT_BYTES {
        return Err(RelayClientError::new(
            "relay.client.enrollment_request_too_large",
        ));
    }
    let host = config
        .origin
        .host_str()
        .ok_or_else(|| RelayClientError::new("relay.client.origin_invalid"))?
        .to_owned();
    let port = config
        .origin
        .port_or_known_default()
        .ok_or_else(|| RelayClientError::new("relay.client.origin_invalid"))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| RelayClientError::new("relay.client.connect_timeout"))?
        .map_err(|_| RelayClientError::new("relay.client.connect_failed"))?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| RelayClientError::new("relay.client.origin_invalid"))?;
    // TLS handshake 必须在构造/写入任何含 enrollment material 的 HTTP bytes 之前完成。
    let mut tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config.tls.client_config()?).connect(server_name, tcp),
    )
    .await
    .map_err(|_| RelayClientError::new("relay.client.connect_timeout"))?
    .map_err(|error| map_tls_error(&error))?;

    let authority = config.origin[Position::BeforeHost..Position::AfterPort].to_owned();
    let header = format!(
        "POST /v2/machine-enroll HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        tls.write_all(header.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await
    })
    .await
    .map_err(|_| RelayClientError::new("relay.client.send_timeout"))?
    .map_err(|_| RelayClientError::new("relay.client.connection_closed"))?;

    let response = tokio::time::timeout(IO_TIMEOUT, read_http_response(&mut tls))
        .await
        .map_err(|_| RelayClientError::new("relay.client.receive_timeout"))??;
    parse_http_response(response)
}

async fn read_http_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, RelayClientError> {
    let read_limit = MAX_HTTP_HEADERS
        .saturating_add(MAX_ENROLLMENT_BYTES)
        .saturating_add(1);
    let mut response = Vec::with_capacity(8 * 1024);
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| RelayClientError::new("relay.client.connection_closed"))?;
        if count == 0 {
            return Err(RelayClientError::new("relay.client.http_invalid"));
        }
        if response.len().saturating_add(count) > read_limit {
            return Err(RelayClientError::new(
                "relay.client.enrollment_response_too_large",
            ));
        }
        response.extend_from_slice(&buffer[..count]);
        let Some(header_end) = response.windows(4).position(|part| part == b"\r\n\r\n") else {
            if response.len() > MAX_HTTP_HEADERS {
                return Err(RelayClientError::new("relay.client.http_invalid"));
            }
            continue;
        };
        let header_len = header_end + 4;
        if header_len > MAX_HTTP_HEADERS {
            return Err(RelayClientError::new("relay.client.http_invalid"));
        }
        let content_length = parse_content_length(&response[..header_len])?;
        let total = header_len
            .checked_add(content_length)
            .ok_or_else(|| RelayClientError::new("relay.client.http_invalid"))?;
        if total > MAX_HTTP_HEADERS + MAX_ENROLLMENT_BYTES {
            return Err(RelayClientError::new(
                "relay.client.enrollment_response_too_large",
            ));
        }
        if response.len() >= total {
            return Ok(response);
        }
    }
}

fn parse_content_length(headers_bytes: &[u8]) -> Result<usize, RelayClientError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    if !matches!(
        parsed
            .parse(headers_bytes)
            .map_err(|_| RelayClientError::new("relay.client.http_invalid"))?,
        httparse::Status::Complete(_)
    ) {
        return Err(RelayClientError::new("relay.client.http_invalid"));
    }
    if parsed
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(RelayClientError::new("relay.client.http_invalid"));
    }
    let mut lengths = parsed.headers.iter().filter_map(|header| {
        header
            .name
            .eq_ignore_ascii_case("content-length")
            .then_some(header.value)
    });
    let content_length = lengths
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| RelayClientError::new("relay.client.http_invalid"))?;
    if lengths.next().is_some() || content_length > MAX_ENROLLMENT_BYTES {
        return Err(RelayClientError::new("relay.client.http_invalid"));
    }
    Ok(content_length)
}

fn parse_http_response(response: Vec<u8>) -> Result<Vec<u8>, RelayClientError> {
    if response.len() > MAX_HTTP_HEADERS + MAX_ENROLLMENT_BYTES {
        return Err(RelayClientError::new(
            "relay.client.enrollment_response_too_large",
        ));
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    let header_len = match parsed
        .parse(&response)
        .map_err(|_| RelayClientError::new("relay.client.http_invalid"))?
    {
        httparse::Status::Complete(length) if length <= MAX_HTTP_HEADERS => length,
        _ => return Err(RelayClientError::new("relay.client.http_invalid")),
    };
    let status = parsed
        .code
        .ok_or_else(|| RelayClientError::new("relay.client.http_invalid"))?;
    let content_length = parse_content_length(&response[..header_len])?;
    if (300..400).contains(&status) {
        return Err(RelayClientError::new("relay.client.redirect_rejected"));
    }
    let body = response[header_len..].to_vec();
    if body.len() != content_length || body.len() > MAX_ENROLLMENT_BYTES {
        return Err(RelayClientError::new(
            "relay.client.enrollment_response_too_large",
        ));
    }
    if status != 200 {
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("code")?.as_str().map(ToOwned::to_owned))
            .filter(|code| valid_failure_code(code))
            .unwrap_or_else(|| "relay.client.enrollment_rejected".to_owned());
        return Err(RelayClientError::new(code));
    }
    Ok(body)
}

fn valid_failure_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code.starts_with("relay.")
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn map_connect_error(error: &tokio_tungstenite::tungstenite::Error) -> RelayClientError {
    let rendered = error.to_string();
    if rendered.contains(REMOTE_TRANSPORT_TLS_PIN_MISMATCH) {
        RelayClientError::new(REMOTE_TRANSPORT_TLS_PIN_MISMATCH)
    } else if rendered.contains("relay.client.tls_certificate_invalid")
        || rendered.contains("InvalidCertificate")
        || rendered.contains("certificate")
    {
        RelayClientError::new("relay.client.tls_verification_failed")
    } else if matches!(error, tokio_tungstenite::tungstenite::Error::Http(_)) {
        RelayClientError::new("relay.client.handshake_rejected")
    } else {
        RelayClientError::new("relay.client.connect_failed")
    }
}

fn map_tls_error(error: &std::io::Error) -> RelayClientError {
    if error
        .to_string()
        .contains(REMOTE_TRANSPORT_TLS_PIN_MISMATCH)
    {
        RelayClientError::new(REMOTE_TRANSPORT_TLS_PIN_MISMATCH)
    } else {
        RelayClientError::new("relay.client.tls_verification_failed")
    }
}

pub(crate) fn protocol_pong(nonce: u64) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Pong(agentdeck_protocol::relay_v2::frame::Pong { nonce }),
    }
}
