// agentdeck-relay/src/server/ws.rs
//! `GET /v1/connect`：WS 握手鉴权——Bearer credential + 版本参数 → 查设备 →
//! 派生 `ConnIdentity` → upgrade 后交给 `conn::handle_conn`。

use axum::Json;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use agentdeck_protocol::remote::{RELAY_PROTOCOL_VERSION, failure};

use crate::auth::crypto::hash_credential;
use crate::auth::store::{DeviceRole, RelayStore};
use crate::router::{ConnIdentity, ConnRole};

use super::AppState;
use super::conn::handle_conn;

/// per-conn 上限（inbound/outbound 单帧）；brief 未钉死具体值，4MiB 足够覆盖
/// R0 控制面帧（不含 DataEnvelope 大 payload 的场景）又不至于让单连接无限吃内存。
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// 版本协商参数：query string `?v=<u16>`（brief 未钉死 query 还是 header，取
/// query 更简单——不需要为它另起一个自定义 header 名）。缺省当作与本 relay 版本
/// 一致（兼容不显式传版本的客户端）。
#[derive(Debug, Deserialize)]
pub(crate) struct ConnectQuery {
    v: Option<u16>,
}

#[derive(Debug, Serialize)]
struct ConnectErrorBody {
    code: &'static str,
    message: String,
}

fn reject(status: StatusCode, code: &'static str, message: &str) -> Response {
    (status, Json(ConnectErrorBody { code, message: message.to_string() })).into_response()
}

/// 从 header 取 `Authorization: Bearer <cred>`。header 名比对由 `HeaderMap`/
/// `HeaderName` 天然大小写不敏感（`get` 按 `HeaderName` 相等性查找，不区分大小
/// 写）；这里额外对 `Bearer` scheme 关键字也做大小写不敏感比对。
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

pub(crate) async fn connect(
    State(state): State<AppState>,
    Query(query): Query<ConnectQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let version = query.v.unwrap_or(RELAY_PROTOCOL_VERSION);
    if version != RELAY_PROTOCOL_VERSION {
        return reject(
            StatusCode::BAD_REQUEST,
            failure::VERSION_UNSUPPORTED,
            "unsupported relay protocol version",
        );
    }

    let Some(bearer) = extract_bearer(&headers) else {
        return reject(
            StatusCode::UNAUTHORIZED,
            failure::AUTH_INVALID_DEVICE,
            "missing or malformed Authorization header",
        );
    };
    let credential_hash = hash_credential(&bearer);

    let device = {
        let store = state.store.lock().expect("relay store mutex poisoned");
        // R1b Task 3：trait 签名改为 owned return（SQL backend 无法返 borrow），
        // 值已 owned，`.cloned()` 移除。
        store.device_by_credential_hash(&credential_hash)
    };
    let Some(device) = device else {
        return reject(
            StatusCode::UNAUTHORIZED,
            failure::AUTH_INVALID_DEVICE,
            "unknown device credential",
        );
    };
    if device.revoked {
        return reject(
            StatusCode::UNAUTHORIZED,
            failure::AUTH_REVOKED_DEVICE,
            "device credential revoked",
        );
    }

    // Device 的角色本身就是 machine/device 概念的来源；R1a 未额外传 machine_id
    // 元数据，用 device_id 兼作 machine_id（同一实体的两个视角）。
    let role = match device.role {
        DeviceRole::Machine => ConnRole::Machine { machine_id: device.device_id.clone() },
        DeviceRole::Device => ConnRole::Device,
    };
    let identity = ConnIdentity { account_id: device.account_id, device_id: device.device_id, role };

    let relay = state.relay.clone();
    ws.max_message_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_conn(socket, relay, identity))
}
