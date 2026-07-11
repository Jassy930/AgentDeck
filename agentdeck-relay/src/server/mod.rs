// agentdeck-relay/src/server/mod.rs
//! server 骨架：axum `Router` 装配（REST enroll + WS 握手）+ `serve` 入口。
//! `server` feature 门内——default（无 server feature）构建不含本模块，
//! 不拉入 axum/tokio-net。

mod conn;
mod pair;
mod ws;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::auth::store::RelayStore;
use crate::config::RelayConfig;
use crate::router::FakeRelay;
use crate::store::SqliteRelayStore;

/// Handler 依赖注入：`SqliteRelayStore` 自带内部 `Arc<Mutex<Connection>>` +
/// `Clone`（Task 3），不需要外层再包一层 `Arc<Mutex<_>>`——`AppState` 的
/// `#[derive(Clone)]`（axum `State` extractor 需要）天然满足。
#[derive(Clone)]
pub(crate) struct AppState {
    store: SqliteRelayStore,
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
    /// `--tls-cert`/`--tls-key` 指向的文件读取或 PEM 解析失败（`tls` feature
    /// 打开时才会真正构造：证书/私钥装载只发生在 `serve()` 的 TLS 分支）。
    #[cfg(feature = "tls")]
    #[error("relay tls cert/key load failed: {0}")]
    TlsLoad(String),
}

/// 装配共享的 axum `Router`（REST enroll + WS 握手）——明文/TLS 两条 serve
/// 路径共用同一份路由与 handler，只是外层监听套不套 TLS 终结不同。
fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/pair/challenge", post(pair::challenge))
        .route("/v1/pair/complete", post(pair::complete))
        .route("/v1/connect", get(ws::connect))
        .with_state(state)
}

/// 装配 axum `Router`（REST enroll + WS 握手）并起监听——阻塞直到进程终止或出错。
///
/// TLS 分支：`config.tls`（`--tls-cert`/`--tls-key`）非空且二进制编译了 `tls`
/// feature 时，装载证书/私钥并走 `serve_with_listener_tls`（真 TLS 终结，
/// `axum-server` + `rustls`）；否则（含"配了 `--tls-cert`/`--tls-key` 但二进制
/// 未编译 `tls` feature"这一边缘情形——`RelayConfig::validate_transport_gate`
/// 只校验路径是否配置，不知道当前二进制是否真的编译了 `tls` feature）回退明文
/// `serve_with_listener`，并在后一种情形下打一条 `tracing::warn!`——不静默。
pub async fn serve(
    config: RelayConfig,
    store: SqliteRelayStore,
    relay: FakeRelay,
) -> Result<(), ServeError> {
    let bind = config.bind;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(ServeError::Bind)?;

    if let Some(tls_paths) = config.tls.clone() {
        if cfg!(feature = "tls") {
            #[cfg(feature = "tls")]
            {
                let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tls_paths.cert,
                    &tls_paths.key,
                )
                .await
                .map_err(|e| ServeError::TlsLoad(e.to_string()))?;
                return serve_with_listener_tls(config, store, relay, listener, tls_config).await;
            }
            #[cfg(not(feature = "tls"))]
            unreachable!("cfg!(feature = \"tls\") 上面已判为 false 才会走到这个分支")
        } else {
            tracing::warn!(
                cert = %tls_paths.cert,
                key = %tls_paths.key,
                "config.tls 已配置（--tls-cert/--tls-key）但本二进制未编译 tls feature——\
                 回退明文服务；请用 `cargo build -p agentdeck-relay --features server,tls` 重新构建以启用真 TLS 终结"
            );
        }
    }

    serve_with_listener(config, store, relay, listener).await
}

/// `serve` 的可测试变体：接受一个已就绪的 `TcpListener`（e2e 测试用
/// `127.0.0.1:0` 绑定后读回实际端口）与外部持有的共享 store 句柄（e2e 测试
/// 用它在 REST enroll 之外直接操纵 store，例如驱动 revoke 场景）。`serve()`
/// 内部构造 `Arc<Mutex<_>>` 后委托本函数，行为等价，仅多出可观测性。
pub async fn serve_with_listener(
    config: RelayConfig,
    store: SqliteRelayStore,
    relay: FakeRelay,
    listener: tokio::net::TcpListener,
) -> Result<(), ServeError> {
    let state = AppState {
        store,
        relay: Arc::new(relay),
        bootstrap_secret: config.bootstrap_secret,
        challenge_ttl_ms: 60_000,
    };
    let app = build_app(state);

    axum::serve(listener, app).await.map_err(ServeError::Io)?;
    Ok(())
}

/// `serve_with_listener` 的 TLS 变体：`tls_config`（证书/私钥已从磁盘装载并
/// 解析好的 `RustlsConfig`）驱动 `axum-server` 的 rustls acceptor 完成真
/// TLS 终结，而不是明文 `axum::serve`。`listener` 与明文版一样是外部已经
/// `bind` 好的 `tokio::net::TcpListener`（e2e 测试同样可以 `127.0.0.1:0` 绑定
/// 后读回动态端口）——`axum-server` 的 `from_tcp_rustls` 要的是
/// `std::net::TcpListener`，`into_std()` 转换后它自己会重新置为非阻塞模式
/// （见 `axum-server` 内部 `Listener::Std` 分支），调用方不需要关心。
#[cfg(feature = "tls")]
pub async fn serve_with_listener_tls(
    config: RelayConfig,
    store: SqliteRelayStore,
    relay: FakeRelay,
    listener: tokio::net::TcpListener,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) -> Result<(), ServeError> {
    let state = AppState {
        store,
        relay: Arc::new(relay),
        bootstrap_secret: config.bootstrap_secret,
        challenge_ttl_ms: 60_000,
    };
    let app = build_app(state);

    let std_listener = listener.into_std().map_err(ServeError::Io)?;
    axum_server::tls_rustls::from_tcp_rustls(std_listener, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(ServeError::Io)?;
    Ok(())
}

/// 直接标记一个设备/机器凭据被撤销（不经 REST——R1a 尚无 revoke 端点，留给
/// 后续 task）。供 e2e 测试驱动"凭据已撤销后连接被拒"场景：`RelayStore` trait
/// 本身是 `pub(crate)`（只供 crate 内部按 trait 方法使用），外部 crate 无法直接
/// 调用 `SqliteRelayStore` 上的 `mark_revoked`——这里以最小 `pub fn` 包装暴露
/// 出去，不改变 store/auth 模块本身的可见性。`SqliteRelayStore` 内部
/// `Arc<Mutex<Connection>>` 共享连接，`clone()` 后在克隆上调用 `&mut self`
/// trait 方法即可作用于同一份底层数据，调用方无需持有 `mut` 绑定。
pub fn revoke_device(store: &SqliteRelayStore, device_id: &str) {
    store.clone().mark_revoked(device_id);
}
