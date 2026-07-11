//! Relay 配置层：加载（dotenvy + clap + env）+ 传输安全门禁（非 loopback 无 TLS 拒启动）。
//!
//! 本模块只产出配置数据结构与门禁校验逻辑，不含任何网络监听/绑定动作（Task 9 消费）。

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::v2::store::{
    MAX_ENROLLMENT_CODES, RelayV2StoreConfig, RetentionLimits, StoreError, validate_store_path,
};

/// Relay 运行时配置。
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub bootstrap_secret: String,
    pub tls: Option<TlsPaths>,
    pub allow_plaintext: bool,
    pub log_level: String,
    /// Task 9：`SqliteRelayStore` 落盘文件路径（相对 CWD 或绝对路径）。
    /// `--selfcheck` 不使用此字段——走 `SqliteRelayStore::open_in_memory()`。
    pub storage_path: PathBuf,
    /// Task 9：`Core.conv_buffer` 每 conversation 保留的最近事件数硬上界。
    pub conv_buffer_cap: usize,
    /// Task 9：`req_origin` 条目 TTL（毫秒）。
    pub req_origin_ttl_ms: u64,
}

/// 默认落盘路径：相对 CWD，可被 `--storage`/`AGENTDECK_RELAY_STORAGE` 覆盖。
const DEFAULT_STORAGE_PATH: &str = "./agentdeck-relay-data/relay.db";
/// 默认 `conv_buffer` 硬上界（每 conversation，假设约 10 events/s、100s 缓冲窗口）。
const DEFAULT_CONV_BUFFER_CAP: usize = 1000;
/// 默认 `req_origin` TTL（5 分钟，对齐典型 RPC timeout）。
const DEFAULT_REQ_ORIGIN_TTL_MS: u64 = 300_000;

/// 供 test 用的默认值 helper（保持默认值单一来源）。
pub(crate) fn default_conv_buffer_cap() -> usize {
    DEFAULT_CONV_BUFFER_CAP
}
pub(crate) fn default_req_origin_ttl_ms() -> u64 {
    DEFAULT_REQ_ORIGIN_TTL_MS
}
pub(crate) fn default_storage_path() -> PathBuf {
    PathBuf::from(DEFAULT_STORAGE_PATH)
}

/// Relay v2 Store 的独立运行配置面。
///
/// P2.1 只建立与 v1 并列的 Store library，因此此类型不嵌入上方的 v1
/// `RelayConfig`，也不会让当前 binary 提前切到 v2。P2.6 会把这些字段接入
/// CLI / env / config file；无论来源如何，启动 Store 前都必须通过本类型到
/// `RelayV2StoreConfig` 的显式转换。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayV2StoreSettings {
    pub storage_path: PathBuf,
    pub max_frames_per_stream: u64,
    pub max_bytes_per_stream: u64,
    pub max_age_ms: u64,
    pub max_bytes_per_machine: u64,
    pub max_bytes_global: u64,
    pub replay_page_max_frames: u64,
    pub replay_page_max_bytes: u64,
    pub disk_reserve_bytes: u64,
    pub disk_reserve_percent: u8,
    pub max_enrollment_codes: u64,
}

impl RelayV2StoreSettings {
    /// 使用设计 §11.4 的配额默认值；调用方必须显式给出生产绝对路径。
    pub fn new(storage_path: PathBuf) -> Self {
        let retention = RetentionLimits::default();
        Self {
            storage_path,
            max_frames_per_stream: retention.max_frames_per_stream,
            max_bytes_per_stream: retention.max_bytes_per_stream,
            max_age_ms: retention.max_age_ms,
            max_bytes_per_machine: retention.max_bytes_per_machine,
            max_bytes_global: retention.max_bytes_global,
            replay_page_max_frames: retention.replay_page_max_frames,
            replay_page_max_bytes: retention.replay_page_max_bytes,
            disk_reserve_bytes: retention.disk_reserve_bytes,
            disk_reserve_percent: retention.disk_reserve_percent,
            max_enrollment_codes: MAX_ENROLLMENT_CODES,
        }
    }

    pub fn retention_limits(&self) -> RetentionLimits {
        RetentionLimits {
            max_frames_per_stream: self.max_frames_per_stream,
            max_bytes_per_stream: self.max_bytes_per_stream,
            max_age_ms: self.max_age_ms,
            max_bytes_per_machine: self.max_bytes_per_machine,
            max_bytes_global: self.max_bytes_global,
            replay_page_max_frames: self.replay_page_max_frames,
            replay_page_max_bytes: self.replay_page_max_bytes,
            disk_reserve_bytes: self.disk_reserve_bytes,
            disk_reserve_percent: self.disk_reserve_percent,
        }
    }

    /// 在 worker 或 SQLite 文件创建前验证路径和所有配额。
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_store_path(&self.storage_path)?;
        self.retention_limits().validate()?;
        if self.max_enrollment_codes == 0 || self.max_enrollment_codes > MAX_ENROLLMENT_CODES {
            return Err(StoreError::InvalidValue {
                field: "max_enrollment_codes",
                reason: "enrollment code bound must be in 1...4096",
            });
        }
        Ok(())
    }

    pub fn into_store_config(self) -> Result<RelayV2StoreConfig, StoreError> {
        RelayV2StoreConfig::try_from(self)
    }
}

impl TryFrom<RelayV2StoreSettings> for RelayV2StoreConfig {
    type Error = StoreError;

    fn try_from(settings: RelayV2StoreSettings) -> Result<Self, Self::Error> {
        settings.validate()?;
        let retention = settings.retention_limits();
        Ok(RelayV2StoreConfig::new(settings.storage_path)
            .with_retention(retention)
            .with_max_enrollment_codes(settings.max_enrollment_codes))
    }
}

/// TLS 证书/私钥文件路径。
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: String,
    pub key: String,
}

/// 配置加载 / 门禁校验失败原因。
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("非 loopback 绑定必须启用 TLS 或显式 --allow-plaintext")]
    PlaintextNonLoopback,
    #[error("命令行/环境变量解析失败: {0}")]
    Cli(#[from] clap::error::Error),
    #[error("仅提供了 --tls-cert 或 --tls-key 其中之一，两者必须同时提供")]
    TlsPartial,
    #[error("缺少 bootstrap secret（--bootstrap-secret 或 AGENTDECK_RELAY_BOOTSTRAP_SECRET）")]
    MissingBootstrapSecret,
    #[error("bind 地址解析失败: {0}")]
    InvalidBind(String),
}

impl ConfigError {
    /// 稳定错误码，供跨进程/日志比对。
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::PlaintextNonLoopback => {
                agentdeck_protocol::remote::failure::CONFIG_PLAINTEXT_NON_LOOPBACK
            }
            ConfigError::Cli(_) => "relay.config.cli_parse",
            ConfigError::TlsPartial => "relay.config.tls_partial",
            ConfigError::MissingBootstrapSecret => "relay.config.missing_bootstrap_secret",
            ConfigError::InvalidBind(_) => "relay.config.invalid_bind",
        }
    }
}

/// 命令行原始入参（内部使用，`RelayConfig::load` 组装为 `RelayConfig`）。
///
/// 本 crate 只钉版 `clap` 的 `derive` feature（不引 `env` feature），因此命令行标志
/// 均为 `Option`，环境变量 fallback（`AGENTDECK_RELAY_*`）由 `load()` 手动读取
/// `std::env::var` 完成，两者优先级：CLI 显式传入 > 环境变量 > 硬编码默认值。
#[derive(clap::Parser, Debug)]
struct RawArgs {
    #[arg(long)]
    bind: Option<String>,

    #[arg(long)]
    bootstrap_secret: Option<String>,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long)]
    allow_plaintext: bool,

    #[arg(long)]
    log_level: Option<String>,

    #[arg(long)]
    storage: Option<String>,

    #[arg(long)]
    conv_buffer_cap: Option<usize>,

    #[arg(long)]
    req_origin_ttl_ms: Option<u64>,

    /// `agentdeck-relay` 二进制（main.rs，Task 9）的 `--selfcheck` 标志——本模块
    /// 不消费它（不映射进 `RelayConfig` 任何字段），只声明它以便 clap 不把它当
    /// unknown argument 拒绝解析；真正的 selfcheck 分支逻辑在 main.rs。
    #[arg(long)]
    #[allow(dead_code)]
    selfcheck: bool,
}

impl RelayConfig {
    /// 加载配置：先尽力加载 `.env`（不存在不报错，写入 process env），
    /// 再用 clap 解析命令行参数，未显式传入的字段回落到 `AGENTDECK_RELAY_*`
    /// 环境变量，最后回落到硬编码默认值，组装为 `RelayConfig`。
    pub fn load() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv();
        let raw = RawArgs::try_parse()?;

        let bind_str = raw
            .bind
            .or_else(|| std::env::var("AGENTDECK_RELAY_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8443".to_string());
        let bind: SocketAddr = bind_str
            .parse()
            .map_err(|_| ConfigError::InvalidBind(bind_str))?;

        let bootstrap_secret = raw
            .bootstrap_secret
            .or_else(|| std::env::var("AGENTDECK_RELAY_BOOTSTRAP_SECRET").ok())
            .ok_or(ConfigError::MissingBootstrapSecret)?;

        let tls_cert = raw
            .tls_cert
            .or_else(|| std::env::var("AGENTDECK_RELAY_TLS_CERT").ok());
        let tls_key = raw
            .tls_key
            .or_else(|| std::env::var("AGENTDECK_RELAY_TLS_KEY").ok());
        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsPaths { cert, key }),
            (None, None) => None,
            _ => return Err(ConfigError::TlsPartial),
        };

        let allow_plaintext = raw.allow_plaintext
            || std::env::var("AGENTDECK_RELAY_ALLOW_PLAINTEXT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

        let log_level = raw
            .log_level
            .or_else(|| std::env::var("AGENTDECK_RELAY_LOG").ok())
            .unwrap_or_else(|| "info".to_string());

        let storage_path = raw
            .storage
            .or_else(|| std::env::var("AGENTDECK_RELAY_STORAGE").ok())
            .map(PathBuf::from)
            .unwrap_or_else(default_storage_path);

        let conv_buffer_cap = raw
            .conv_buffer_cap
            .or_else(|| {
                std::env::var("AGENTDECK_RELAY_CONV_BUFFER_CAP")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(DEFAULT_CONV_BUFFER_CAP);

        let req_origin_ttl_ms = raw
            .req_origin_ttl_ms
            .or_else(|| {
                std::env::var("AGENTDECK_RELAY_REQ_ORIGIN_TTL_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(DEFAULT_REQ_ORIGIN_TTL_MS);

        Ok(RelayConfig {
            bind,
            bootstrap_secret,
            tls,
            allow_plaintext,
            log_level,
            storage_path,
            conv_buffer_cap,
            req_origin_ttl_ms,
        })
    }

    /// 传输安全门禁：非 loopback 绑定且无 TLS 且未显式 allow-plaintext → 拒启动。
    pub fn validate_transport_gate(&self) -> Result<(), ConfigError> {
        let is_loopback = self.bind.ip().is_loopback();
        let has_tls = self.tls.is_some();
        let allow = self.allow_plaintext;
        if is_loopback || has_tls || allow {
            Ok(())
        } else {
            Err(ConfigError::PlaintextNonLoopback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::{RelayV2StoreConfig, StoreError};
    #[allow(unused_imports)]
    use std::net::SocketAddr;
    fn cfg(bind: &str, tls: bool, allow: bool) -> RelayConfig {
        RelayConfig {
            bind: bind.parse().unwrap(),
            bootstrap_secret: "s".into(),
            tls: if tls {
                Some(TlsPaths {
                    cert: "c".into(),
                    key: "k".into(),
                })
            } else {
                None
            },
            allow_plaintext: allow,
            log_level: "info".into(),
            storage_path: default_storage_path(),
            conv_buffer_cap: default_conv_buffer_cap(),
            req_origin_ttl_ms: default_req_origin_ttl_ms(),
        }
    }
    #[test]
    fn loopback_plaintext_ok() {
        assert!(
            cfg("127.0.0.1:8080", false, false)
                .validate_transport_gate()
                .is_ok()
        );
    }
    #[test]
    fn non_loopback_plaintext_rejected() {
        let e = cfg("0.0.0.0:8080", false, false)
            .validate_transport_gate()
            .unwrap_err();
        assert_eq!(
            e.code(),
            agentdeck_protocol::remote::failure::CONFIG_PLAINTEXT_NON_LOOPBACK
        );
    }
    #[test]
    fn non_loopback_with_tls_ok() {
        assert!(
            cfg("0.0.0.0:8080", true, false)
                .validate_transport_gate()
                .is_ok()
        );
    }
    #[test]
    fn non_loopback_allow_plaintext_ok() {
        assert!(
            cfg("0.0.0.0:8080", false, true)
                .validate_transport_gate()
                .is_ok()
        );
    }

    #[test]
    fn defaults_match_documented_values() {
        assert_eq!(default_conv_buffer_cap(), 1000);
        assert_eq!(default_req_origin_ttl_ms(), 300_000);
        assert_eq!(
            default_storage_path().to_str().unwrap(),
            "./agentdeck-relay-data/relay.db"
        );
    }

    #[test]
    fn v2_store_settings_preserve_every_runtime_limit_during_conversion() {
        let mut settings =
            RelayV2StoreSettings::new(PathBuf::from("/var/lib/agentdeck-relay/v2.db"));
        settings.max_frames_per_stream = 111;
        settings.max_bytes_per_stream = 222;
        settings.max_age_ms = 333;
        settings.max_bytes_per_machine = 444;
        settings.max_bytes_global = 555;
        settings.replay_page_max_frames = 12;
        settings.replay_page_max_bytes = 4 * 1024 * 1024 + 666;
        settings.disk_reserve_bytes = 777;
        settings.disk_reserve_percent = 8;
        settings.max_enrollment_codes = 999;

        let store_config = RelayV2StoreConfig::try_from(settings).unwrap();

        assert_eq!(
            store_config.storage_path,
            PathBuf::from("/var/lib/agentdeck-relay/v2.db")
        );
        assert_eq!(store_config.retention.max_frames_per_stream, 111);
        assert_eq!(store_config.retention.max_bytes_per_stream, 222);
        assert_eq!(store_config.retention.max_age_ms, 333);
        assert_eq!(store_config.retention.max_bytes_per_machine, 444);
        assert_eq!(store_config.retention.max_bytes_global, 555);
        assert_eq!(store_config.retention.replay_page_max_frames, 12);
        assert_eq!(
            store_config.retention.replay_page_max_bytes,
            4 * 1024 * 1024 + 666
        );
        assert_eq!(store_config.retention.disk_reserve_bytes, 777);
        assert_eq!(store_config.retention.disk_reserve_percent, 8);
        assert_eq!(store_config.max_enrollment_codes, 999);
    }

    #[test]
    fn v2_store_settings_use_the_approved_retention_defaults() {
        let settings =
            RelayV2StoreSettings::new(PathBuf::from("/var/lib/agentdeck-relay/relay.db"));

        assert_eq!(settings.max_frames_per_stream, 2_000);
        assert_eq!(settings.max_bytes_per_stream, 64 * 1024 * 1024);
        assert_eq!(settings.max_age_ms, 24 * 60 * 60 * 1_000);
        assert_eq!(settings.max_bytes_per_machine, 512 * 1024 * 1024);
        assert_eq!(settings.max_bytes_global, 4 * 1024 * 1024 * 1024);
        assert_eq!(settings.replay_page_max_frames, 64);
        assert_eq!(settings.replay_page_max_bytes, 8 * 1024 * 1024);
        assert_eq!(settings.disk_reserve_bytes, 512 * 1024 * 1024);
        assert_eq!(settings.disk_reserve_percent, 5);
        assert_eq!(settings.max_enrollment_codes, 4_096);
    }

    #[test]
    fn v2_store_settings_reject_relative_storage_before_store_start() {
        let error = RelayV2StoreConfig::try_from(RelayV2StoreSettings::new(PathBuf::from(
            "relative/relay.db",
        )))
        .unwrap_err();

        assert!(matches!(error, StoreError::PathNotAbsolute));

        let noncanonical =
            RelayV2StoreSettings::new(PathBuf::from("/var/lib/agentdeck-relay/../relay.db"));
        let error = RelayV2StoreConfig::try_from(noncanonical).unwrap_err();
        assert!(matches!(error, StoreError::PathNotCanonical));

        for alias in [
            "/var/lib/./agentdeck-relay/relay.db",
            "/var//lib/agentdeck-relay/relay.db",
            "/var/lib/agentdeck-relay/relay.db/",
        ] {
            let error =
                RelayV2StoreConfig::try_from(RelayV2StoreSettings::new(PathBuf::from(alias)))
                    .unwrap_err();
            assert!(
                matches!(error, StoreError::PathNotCanonical),
                "lexical alias must be rejected: {alias}"
            );
        }
    }

    #[test]
    fn v2_store_settings_reject_invalid_replay_and_retention_limits() {
        let mut settings =
            RelayV2StoreSettings::new(PathBuf::from("/var/lib/agentdeck-relay/relay.db"));
        settings.replay_page_max_frames = 65;

        let error = RelayV2StoreConfig::try_from(settings).unwrap_err();

        assert!(matches!(
            error,
            StoreError::InvalidValue {
                field: "retention",
                ..
            }
        ));

        let mut enrollment =
            RelayV2StoreSettings::new(PathBuf::from("/var/lib/agentdeck-relay/relay.db"));
        enrollment.max_enrollment_codes = 4_097;
        let error = RelayV2StoreConfig::try_from(enrollment).unwrap_err();
        assert!(matches!(
            error,
            StoreError::InvalidValue {
                field: "max_enrollment_codes",
                ..
            }
        ));
    }
}
