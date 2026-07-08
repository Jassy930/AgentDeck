// agentdeck-relay/src/server/mod.rs
//! server 骨架：axum `Router` 装配（REST enroll + WS 握手）+ `serve` 入口。
//! `server` feature 门内——default（无 server feature）构建不含本模块，
//! 不拉入 axum/tokio-net。

mod conn;
mod pair;
mod ws;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::{get, post};

use crate::auth::store::InMemoryRelayStore;
use crate::config::RelayConfig;
use crate::router::FakeRelay;

/// Handler 依赖注入：`Arc`/`Mutex` 包裹以便在 axum `State` extractor 里 `Clone` 共享。
#[derive(Clone)]
pub(crate) struct AppState {
    store: Arc<Mutex<InMemoryRelayStore>>,
    relay: Arc<FakeRelay>,
    bootstrap_secret: String,
    challenge_ttl_ms: u64,
}

/// `serve` 启动/运行失败原因。
#[derive(thiserror::Error, Debug)]
pub enum ServeError {
    #[error("relay bind failed: {0}")]
    Bind(std::io::Error),
    #[error("relay server io error: {0}")]
    Io(std::io::Error),
}

/// 装配 axum `Router`（REST enroll + WS 握手）并起监听——阻塞直到进程终止或出错。
pub async fn serve(
    config: RelayConfig,
    store: InMemoryRelayStore,
    relay: FakeRelay,
) -> Result<(), ServeError> {
    let bind = config.bind;
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        relay: Arc::new(relay),
        bootstrap_secret: config.bootstrap_secret,
        challenge_ttl_ms: 60_000,
    };
    let app = Router::new()
        .route("/v1/pair/challenge", post(pair::challenge))
        .route("/v1/pair/complete", post(pair::complete))
        .route("/v1/connect", get(ws::connect))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await.map_err(ServeError::Bind)?;
    axum::serve(listener, app).await.map_err(ServeError::Io)?;
    Ok(())
}
