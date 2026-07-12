//! Relay v2 独立 loopback health/readiness 服务。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
struct ReadinessSnapshot {
    ready: bool,
    code: &'static str,
}

/// 周期探针写、HTTP只读的 readiness cache；HTTP 洪泛不能占用 Store actor 队列。
#[derive(Clone)]
pub(crate) struct ReadinessCache {
    inner: Arc<RwLock<ReadinessSnapshot>>,
}

impl ReadinessCache {
    pub fn ready() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ReadinessSnapshot {
                ready: true,
                code: "relay.ready",
            })),
        }
    }

    pub fn mark_ready(&self) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ReadinessSnapshot {
            ready: true,
            code: "relay.ready",
        };
    }

    pub fn mark_not_ready(&self, code: &'static str) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            ReadinessSnapshot { ready: false, code };
    }

    fn snapshot(&self) -> ReadinessSnapshot {
        *self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone)]
pub(crate) struct HealthState {
    readiness: ReadinessCache,
    draining: Arc<AtomicBool>,
}

impl HealthState {
    pub fn new(readiness: ReadinessCache, draining: Arc<AtomicBool>) -> Self {
        Self {
            readiness,
            draining,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthBody {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

async fn healthz() -> impl IntoResponse {
    Json(HealthBody {
        status: "ok",
        code: None,
    })
}

async fn readyz(State(state): State<HealthState>) -> Response {
    if state.draining.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthBody {
                status: "notReady",
                code: Some("relay.server.draining"),
            }),
        )
            .into_response();
    }
    let readiness = state.readiness.snapshot();
    if readiness.ready {
        Json(HealthBody {
            status: "ready",
            code: None,
        })
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthBody {
                status: "notReady",
                code: Some(readiness.code),
            }),
        )
            .into_response()
    }
}

pub(crate) fn router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}
