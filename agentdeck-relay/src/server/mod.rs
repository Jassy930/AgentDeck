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

use crate::auth::store::{InMemoryRelayStore, RelayStore};
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
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(ServeError::Bind)?;
    serve_with_listener(config, Arc::new(Mutex::new(store)), relay, listener).await
}

/// `serve` 的可测试变体：接受一个已就绪的 `TcpListener`（e2e 测试用
/// `127.0.0.1:0` 绑定后读回实际端口）与外部持有的共享 store 句柄（e2e 测试
/// 用它在 REST enroll 之外直接操纵 store，例如驱动 revoke 场景）。`serve()`
/// 内部构造 `Arc<Mutex<_>>` 后委托本函数，行为等价，仅多出可观测性。
pub async fn serve_with_listener(
    config: RelayConfig,
    store: Arc<Mutex<InMemoryRelayStore>>,
    relay: FakeRelay,
    listener: tokio::net::TcpListener,
) -> Result<(), ServeError> {
    let state = AppState {
        store,
        relay: Arc::new(relay),
        bootstrap_secret: config.bootstrap_secret,
        challenge_ttl_ms: 60_000,
    };
    let app = Router::new()
        .route("/v1/pair/challenge", post(pair::challenge))
        .route("/v1/pair/complete", post(pair::complete))
        .route("/v1/connect", get(ws::connect))
        .with_state(state);

    axum::serve(listener, app).await.map_err(ServeError::Io)?;
    Ok(())
}

/// 直接标记一个设备/机器凭据被撤销（不经 REST——R1a 尚无 revoke 端点，留给
/// 后续 task）。供 e2e 测试驱动"凭据已撤销后连接被拒"场景：`RelayStore` trait
/// 本身是 `pub(crate)`（只供 crate 内部按 trait 方法使用），外部 crate 无法直接
/// 调用 `InMemoryRelayStore` 上的 `mark_revoked`——这里以最小 `pub fn` 包装暴露
/// 出去，不改变 store/auth 模块本身的可见性。
pub fn revoke_device(store: &Arc<Mutex<InMemoryRelayStore>>, device_id: &str) {
    store.lock().expect("relay store mutex poisoned").mark_revoked(device_id);
}
