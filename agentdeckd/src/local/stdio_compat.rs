//! 显式 ephemeral/no-remote stdio compatibility 入口。
//!
//! 威胁场景：legacy stdio 若能在 recovery 前启动，或重新构造完整 execution hub，
//! 本地调用方会绕过 RuntimeEnvelope/Core 与 exec gate；因此本入口按值消费 recovery
//! permit，并且只能构造固定 admin/read allowlist。

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{DaemonConfig, LocalIngressMode};
use crate::runtime::namespace::DaemonMode;
use crate::runtime::recovery::RecoveryReadyPermit;
use crate::runtime::{RuntimeCore, RuntimeHub};

#[derive(Debug, thiserror::Error)]
pub enum StdioCompatError {
    #[error("recovery readiness permit does not belong to this RuntimeCore")]
    RecoveryPermitMismatch,
    #[error("stdio compatibility requires an ephemeral, no-remote stdio config")]
    InvalidConfig,
    #[error("stdio compatibility I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl StdioCompatError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RecoveryPermitMismatch => "daemon.local.recovery_permit_mismatch",
            Self::InvalidConfig => "daemon.local.stdio_config_invalid",
            Self::Io(_) => "daemon.local.stdio_io_failed",
        }
    }
}

/// recovery 后唯一的 stdio compatibility 构造路径。
pub async fn run_after_recovery<R, W>(
    config: &DaemonConfig,
    recovery_ready: RecoveryReadyPermit,
    core: &RuntimeCore,
    stdin: R,
    stdout: W,
) -> Result<(), StdioCompatError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if !core.owns_recovery_ready_permit(&recovery_ready) {
        return Err(StdioCompatError::RecoveryPermitMismatch);
    }
    if config.local_ingress_mode() != LocalIngressMode::StdioCompat
        || !matches!(config.mode(), DaemonMode::Ephemeral { .. })
        || config.remote_enabled()
    {
        return Err(StdioCompatError::InvalidConfig);
    }
    RuntimeHub::admin_only(core.stdio_compatibility_router())
        .run(stdin, stdout)
        .await
        .map_err(StdioCompatError::Io)
}
