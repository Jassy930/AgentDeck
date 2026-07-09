// agentdeck-relay/src/server/pair.rs
//! REST enroll：`POST /v1/pair/challenge`、`POST /v1/pair/complete`——
//! 包 Task 6 `auth::enroll` 纯函数（这两个 handler 只做 JSON DTO 转换 + 依赖注入 +
//! 错误映射，不含任何 enroll 业务逻辑）。
//!
//! Task 6 的 `ChallengeReq`/`CompleteReq`/`ChallengeResp`/`CompleteResp` 是
//! `pub(crate)` 且未派生 `Serialize`/`Deserialize`（本 task 允许改动的文件不含
//! `auth/enroll.rs`），故这里定义结构对等的本地 wire DTO，在 handler 内与
//! enroll 类型互转，不改动 enroll.rs。

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use agentdeck_protocol::remote::failure;

use crate::auth::enroll::{self, ChallengeReq, CompleteReq, EnrollError, NewDevice};
use crate::auth::store::DeviceRole;

use super::AppState;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChallengeReqBody {
    pub device_sign_pubkey: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChallengeRespBody {
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NewDeviceBody {
    pub device_id: String,
    /// `"machine"` | `"device"`（大小写不敏感）；未知值当作 `"device"`。
    pub role: String,
    pub sign_pubkey: String,
    pub box_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CompleteReqBody {
    pub bootstrap_secret: String,
    pub nonce_sig: String,
    pub device: NewDeviceBody,
    pub owner_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CompleteRespBody {
    pub account_id: String,
    pub credential: String,
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct EnrollErrorBody {
    pub code: &'static str,
    pub message: String,
}

fn map_enroll_error(err: EnrollError) -> (StatusCode, Json<EnrollErrorBody>) {
    let (status, code) = match &err {
        EnrollError::BadSecret => (StatusCode::UNAUTHORIZED, failure::PAIR_BAD_SECRET),
        EnrollError::ChallengeExpired => (StatusCode::BAD_REQUEST, failure::PAIR_CHALLENGE_EXPIRED),
        EnrollError::BadSignature => (StatusCode::UNAUTHORIZED, failure::PAIR_BAD_SIGNATURE),
        EnrollError::MissingOwnerPubkey => {
            (StatusCode::BAD_REQUEST, failure::PAIR_MISSING_OWNER_PUBKEY)
        }
    };
    (status, Json(EnrollErrorBody { code, message: err.to_string() }))
}

pub(crate) async fn challenge(
    State(state): State<AppState>,
    Json(body): Json<ChallengeReqBody>,
) -> Json<ChallengeRespBody> {
    let mut store = state.store.lock().expect("relay store mutex poisoned");
    let resp = enroll::start_challenge(
        &mut *store,
        ChallengeReq { device_sign_pubkey: body.device_sign_pubkey },
        state.challenge_ttl_ms as i64,
        now_ms() as i64,
    );
    Json(ChallengeRespBody { nonce: resp.nonce })
}

pub(crate) async fn complete(
    State(state): State<AppState>,
    Json(body): Json<CompleteReqBody>,
) -> Result<Json<CompleteRespBody>, (StatusCode, Json<EnrollErrorBody>)> {
    let role = if body.device.role.eq_ignore_ascii_case("machine") {
        DeviceRole::Machine
    } else {
        DeviceRole::Device
    };
    let req = CompleteReq {
        bootstrap_secret: body.bootstrap_secret,
        nonce_sig: body.nonce_sig,
        device: NewDevice {
            device_id: body.device.device_id,
            role,
            sign_pubkey: body.device.sign_pubkey,
            box_pubkey: body.device.box_pubkey,
        },
        owner_pubkey: body.owner_pubkey,
    };

    let mut store = state.store.lock().expect("relay store mutex poisoned");
    let resp = enroll::complete(&mut *store, req, &state.bootstrap_secret, now_ms() as i64)
        .map_err(map_enroll_error)?;
    Ok(Json(CompleteRespBody {
        account_id: resp.account_id,
        credential: resp.credential,
        device_id: resp.device.device_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_owner_pubkey_uses_registered_failure_code() {
        assert_eq!(
            map_enroll_error(EnrollError::MissingOwnerPubkey).1.0.code,
            agentdeck_protocol::remote::failure::PAIR_MISSING_OWNER_PUBKEY
        );
    }
}
