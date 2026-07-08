// agentdeck-relay/src/server/conn.rs
//! per-conn task：WS frame <-> `RemoteFrame`，经 `RelayClient` 与 relay core 交互。
//!
//! `RelayClient::send(&self, ..)`/`recv(&mut self)`（`router.rs`，本 task 不可
//! 改）没有 split API，`tx`/`rx` 字段私有——无法安全地把读/写各自 move 进两个独立
//! `tokio::spawn` 任务（用 `Arc<Mutex<RelayClient>>` 包裹也不行：`recv()` 会长时间
//! 挂起等待下一帧，若持锁 await 会把并发的 `send()` 一并锁死）。故这里用单个任务内
//! `tokio::select!` 达成读/写并发，语义等价于两个协作任务。

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};

use agentdeck_protocol::remote::RemoteFrame;

use crate::router::{ConnIdentity, FakeRelay};

pub(crate) async fn handle_conn(socket: WebSocket, relay: Arc<FakeRelay>, identity: ConnIdentity) {
    let device_id = identity.device_id.clone();
    let mut link = relay.connect_with_identity(identity).await;
    let (mut sink, mut stream) = socket.split();

    loop {
        tokio::select! {
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<RemoteFrame>(&text) {
                            Ok(frame) => link.send(frame).await,
                            Err(err) => {
                                tracing::warn!(device_id = %device_id, error = %err, "relay: dropping invalid inbound WS frame");
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    // Ping/Pong 由 axum 底层已自动应答；Binary/Frame 不是本协议的载体，忽略。
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        tracing::warn!(device_id = %device_id, error = %err, "relay: ws read error, closing connection");
                        break;
                    }
                }
            }
            outgoing = link.recv() => {
                match outgoing {
                    Some(frame) => match serde_json::to_string(&frame) {
                        Ok(text) => {
                            if sink.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(device_id = %device_id, error = %err, "relay: failed to encode outbound frame");
                        }
                    },
                    // relay core 关闭了此连接（例如 revoke）——结束本任务。
                    None => break,
                }
            }
        }
    }
    tracing::info!(device_id = %device_id, "relay: connection closed");
}
