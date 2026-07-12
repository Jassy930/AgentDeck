//! Relay 配置层：加载（dotenvy + clap + env）+ 传输安全门禁（非 loopback 无 TLS 拒启动）。
//!
//! 本模块只产出配置数据结构与门禁校验逻辑，不含任何网络监听/绑定动作（Task 9 消费）。

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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

/// Relay v2 公开 listener 的三种、且仅三种传输模式。
///
/// `InsecureLoopback` 只供显式本机开发；`ProxyLoopback` 表示 TLS 在反向代理终止，
/// Relay 自身仍只能监听 loopback；生产直连必须使用 `DirectTls`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayV2TransportMode {
    DirectTls(RelayV2TlsPaths),
    InsecureLoopback,
    ProxyLoopback,
}

/// Relay v2 TLS preflight 的输入路径。证书存在性、PEM 解析与 keypair 匹配由
/// `v2::server::tls` 在 bind 前校验；配置层只负责来源合并与 feature fail-closed。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayV2TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// P2.6 并列 v2 server 配置。
///
/// 本类型刻意不复用 v1 的 bootstrap secret、`allow_plaintext`、conversation buffer
/// 或 `req_origin`；v1 binary 在 P2.9 原子切换前继续使用上方 [`RelayConfig`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayV2ServerConfig {
    pub bind: SocketAddr,
    pub health_bind: SocketAddr,
    pub store: RelayV2StoreSettings,
    pub transport: RelayV2TransportMode,
    pub admin: Option<RelayV2AdminConfig>,
    pub log_level: String,
}

/// 仅供 Relay host 本机 UDS 与公开 enrollment bundle 使用的配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayV2AdminConfig {
    pub socket_path: PathBuf,
    pub public_wss_url: String,
    /// 当前证书 pin 在前，可选下一证书 pin 在后。
    pub spki_pins: Vec<[u8; 32]>,
}

impl RelayV2AdminConfig {
    pub fn validate(&self) -> Result<(), RelayV2ConfigError> {
        if !self.socket_path.is_absolute() || self.socket_path.file_name().is_none() {
            return Err(RelayV2ConfigError::AdminInvalid {
                field: "admin_socket",
            });
        }
        let url = url::Url::parse(&self.public_wss_url).map_err(|_| {
            RelayV2ConfigError::AdminInvalid {
                field: "public_wss_url",
            }
        })?;
        if url.scheme() != "wss"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(RelayV2ConfigError::AdminInvalid {
                field: "public_wss_url",
            });
        }
        if !(1..=2).contains(&self.spki_pins.len())
            || (self.spki_pins.len() == 2 && self.spki_pins[0] == self.spki_pins[1])
        {
            return Err(RelayV2ConfigError::AdminInvalid { field: "spki_pins" });
        }
        Ok(())
    }
}

const V2_DEFAULT_BIND: &str = "127.0.0.1:8443";
const V2_DEFAULT_HEALTH_BIND: &str = "127.0.0.1:8444";
const V2_DEFAULT_STORAGE_RELATIVE: &str = "agentdeck-relay-data/relay-v2.db";

#[derive(clap::Parser, Debug)]
struct RelayV2RawArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    bind: Option<String>,
    #[arg(long)]
    health_bind: Option<String>,
    #[arg(long)]
    storage: Option<PathBuf>,
    #[arg(long)]
    max_frames_per_stream: Option<u64>,
    #[arg(long)]
    max_bytes_per_stream: Option<u64>,
    #[arg(long)]
    max_age_ms: Option<u64>,
    #[arg(long)]
    max_bytes_per_machine: Option<u64>,
    #[arg(long)]
    max_bytes_global: Option<u64>,
    #[arg(long)]
    replay_page_max_frames: Option<u64>,
    #[arg(long)]
    replay_page_max_bytes: Option<u64>,
    #[arg(long)]
    disk_reserve_bytes: Option<u64>,
    #[arg(long)]
    disk_reserve_percent: Option<u8>,
    #[arg(long)]
    max_enrollment_codes: Option<u64>,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    allow_insecure_loopback: bool,
    #[arg(long)]
    proxy_mode: bool,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long)]
    admin_socket: Option<PathBuf>,
    #[arg(long)]
    public_wss_url: Option<String>,
    #[arg(long = "spki-pin")]
    spki_pins: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayV2FileConfig {
    bind: Option<String>,
    health_bind: Option<String>,
    storage: Option<PathBuf>,
    max_frames_per_stream: Option<u64>,
    max_bytes_per_stream: Option<u64>,
    max_age_ms: Option<u64>,
    max_bytes_per_machine: Option<u64>,
    max_bytes_global: Option<u64>,
    replay_page_max_frames: Option<u64>,
    replay_page_max_bytes: Option<u64>,
    disk_reserve_bytes: Option<u64>,
    disk_reserve_percent: Option<u8>,
    max_enrollment_codes: Option<u64>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    allow_insecure_loopback: Option<bool>,
    proxy_mode: Option<bool>,
    log_level: Option<String>,
    admin_socket: Option<PathBuf>,
    public_wss_url: Option<String>,
    spki_pins: Option<Vec<String>>,
}

/// Relay v2 配置加载和传输门禁失败。
#[derive(thiserror::Error, Debug)]
pub enum RelayV2ConfigError {
    #[error("Relay v2 command-line parse failed: {0}")]
    Cli(#[from] clap::error::Error),
    #[error("Relay v2 config path from {key} is invalid")]
    InvalidEnvironment { key: &'static str },
    #[error("failed to read Relay v2 config file {path}: {source}")]
    ConfigFileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse Relay v2 config file {path}: {source}")]
    ConfigFileParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("Relay v2 config value is invalid: {field}")]
    InvalidValue { field: &'static str },
    #[error("Relay v2 storage configuration is invalid: {0}")]
    StorageInvalid(#[source] StoreError),
    #[error("TLS certificate and key must be configured together")]
    TlsPartial,
    #[error("configured TLS requires the binary tls feature")]
    TlsFeatureMissing,
    #[error("non-loopback Relay v2 listener requires direct TLS")]
    TlsRequired,
    #[error("loopback plaintext requires explicit --allow-insecure-loopback")]
    InsecureLoopbackOptInRequired,
    #[error("proxy mode requires a loopback Relay listener")]
    ProxyNonLoopback,
    #[error("Relay v2 transport modes are mutually exclusive")]
    TransportConflict,
    #[error("Relay health listener must bind loopback")]
    HealthNonLoopback,
    #[error("admin socket, public WSS URL and SPKI pins must be configured together")]
    AdminPartial,
    #[error("Relay admin/enrollment requires direct TLS or trusted loopback proxy mode")]
    AdminRequiresSecureTransport,
    #[error("Relay admin configuration is invalid: {field}")]
    AdminInvalid { field: &'static str },
}

impl RelayV2ConfigError {
    /// 稳定诊断码；不得包含路径、证书或配置内容。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cli(_) => "relay.config.cli_parse",
            Self::InvalidEnvironment { .. } => "relay.config.env_invalid",
            Self::ConfigFileRead { .. } => "relay.config.file_read",
            Self::ConfigFileParse { .. } => "relay.config.file_parse",
            Self::InvalidValue { .. } => "relay.config.invalid_value",
            Self::StorageInvalid(_) => "relay.config.storage_invalid",
            Self::TlsPartial => "relay.config.tls_partial",
            Self::TlsFeatureMissing => "relay.transport.tls_feature_missing",
            Self::TlsRequired => "relay.transport.tls_required",
            Self::InsecureLoopbackOptInRequired => {
                "relay.transport.insecure_loopback_opt_in_required"
            }
            Self::ProxyNonLoopback => "relay.transport.proxy_requires_loopback",
            Self::TransportConflict => "relay.transport.mode_conflict",
            Self::HealthNonLoopback => "relay.config.health_non_loopback",
            Self::AdminPartial => "relay.admin.config_partial",
            Self::AdminRequiresSecureTransport => "relay.admin.secure_transport_required",
            Self::AdminInvalid { .. } => "relay.admin.config_invalid",
        }
    }
}

impl RelayV2ServerConfig {
    /// 复核所有可由公共字段手工构造绕过的启动门禁。
    ///
    /// server preflight 必须在读取 TLS identity 或绑定任何 listener 前调用；loader
    /// 同样在返回前调用，保证两条构造路径共享相同不变量。
    pub fn validate(&self) -> Result<(), RelayV2ConfigError> {
        if !self.health_bind.ip().is_loopback() {
            return Err(RelayV2ConfigError::HealthNonLoopback);
        }
        self.store
            .validate()
            .map_err(RelayV2ConfigError::StorageInvalid)?;
        if self.log_level.trim().is_empty()
            || self.log_level.len() > 128
            || self.log_level.contains(['\r', '\n'])
        {
            return Err(RelayV2ConfigError::InvalidValue { field: "log_level" });
        }
        match &self.transport {
            RelayV2TransportMode::DirectTls(_) => {
                if !cfg!(feature = "tls") {
                    return Err(RelayV2ConfigError::TlsFeatureMissing);
                }
            }
            RelayV2TransportMode::InsecureLoopback => {
                if !self.bind.ip().is_loopback() {
                    return Err(RelayV2ConfigError::TlsRequired);
                }
            }
            RelayV2TransportMode::ProxyLoopback => {
                if !self.bind.ip().is_loopback() {
                    return Err(RelayV2ConfigError::ProxyNonLoopback);
                }
            }
        }
        if let Some(admin) = &self.admin {
            admin.validate()?;
            if matches!(self.transport, RelayV2TransportMode::InsecureLoopback) {
                return Err(RelayV2ConfigError::AdminRequiresSecureTransport);
            }
        }
        Ok(())
    }

    /// 生产入口：只读取真实 argv/env/cwd，不加载 `.env`，避免额外隐式优先级和
    /// process-global 环境突变。
    pub fn load() -> Result<Self, RelayV2ConfigError> {
        let environment = std::env::vars().collect::<BTreeMap<_, _>>();
        let cwd = std::env::current_dir().map_err(|_| RelayV2ConfigError::InvalidValue {
            field: "current_dir",
        })?;
        Self::load_from(std::env::args_os(), &environment, &cwd)
    }

    /// 可测试的确定性加载入口：逐字段执行 CLI > env > TOML > dev defaults。
    pub fn load_from<I, T>(
        args: I,
        environment: &BTreeMap<String, String>,
        cwd: &Path,
    ) -> Result<Self, RelayV2ConfigError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        if !cwd.is_absolute() {
            return Err(RelayV2ConfigError::InvalidValue {
                field: "current_dir",
            });
        }
        let raw = RelayV2RawArgs::try_parse_from(args)?;
        let config_path = match raw.config {
            Some(path) => Some(resolve_from_cwd(path, cwd)),
            None => environment
                .get("AGENTDECK_RELAY_CONFIG")
                .map(|value| {
                    if value.trim().is_empty() {
                        Err(RelayV2ConfigError::InvalidEnvironment {
                            key: "AGENTDECK_RELAY_CONFIG",
                        })
                    } else {
                        Ok(resolve_from_cwd(PathBuf::from(value), cwd))
                    }
                })
                .transpose()?,
        };
        let file = load_v2_file_config(config_path.as_deref())?;

        let bind = parse_socket_addr(
            raw.bind
                .or_else(|| environment.get("AGENTDECK_RELAY_BIND").cloned())
                .or(file.bind)
                .unwrap_or_else(|| V2_DEFAULT_BIND.to_owned()),
            "bind",
        )?;
        let health_bind = parse_socket_addr(
            raw.health_bind
                .or_else(|| environment.get("AGENTDECK_RELAY_HEALTH_BIND").cloned())
                .or(file.health_bind)
                .unwrap_or_else(|| V2_DEFAULT_HEALTH_BIND.to_owned()),
            "health_bind",
        )?;
        if !health_bind.ip().is_loopback() {
            return Err(RelayV2ConfigError::HealthNonLoopback);
        }

        let storage_path = raw
            .storage
            .or_else(|| {
                environment
                    .get("AGENTDECK_RELAY_STORAGE")
                    .map(PathBuf::from)
            })
            .or(file.storage)
            .unwrap_or_else(|| cwd.join(V2_DEFAULT_STORAGE_RELATIVE));
        let mut store = RelayV2StoreSettings::new(storage_path);
        store.max_frames_per_stream = layered_numeric(
            raw.max_frames_per_stream,
            environment,
            "AGENTDECK_RELAY_MAX_FRAMES_PER_STREAM",
            file.max_frames_per_stream,
            store.max_frames_per_stream,
        )?;
        store.max_bytes_per_stream = layered_numeric(
            raw.max_bytes_per_stream,
            environment,
            "AGENTDECK_RELAY_MAX_BYTES_PER_STREAM",
            file.max_bytes_per_stream,
            store.max_bytes_per_stream,
        )?;
        store.max_age_ms = layered_numeric(
            raw.max_age_ms,
            environment,
            "AGENTDECK_RELAY_MAX_AGE_MS",
            file.max_age_ms,
            store.max_age_ms,
        )?;
        store.max_bytes_per_machine = layered_numeric(
            raw.max_bytes_per_machine,
            environment,
            "AGENTDECK_RELAY_MAX_BYTES_PER_MACHINE",
            file.max_bytes_per_machine,
            store.max_bytes_per_machine,
        )?;
        store.max_bytes_global = layered_numeric(
            raw.max_bytes_global,
            environment,
            "AGENTDECK_RELAY_MAX_BYTES_GLOBAL",
            file.max_bytes_global,
            store.max_bytes_global,
        )?;
        store.replay_page_max_frames = layered_numeric(
            raw.replay_page_max_frames,
            environment,
            "AGENTDECK_RELAY_REPLAY_PAGE_MAX_FRAMES",
            file.replay_page_max_frames,
            store.replay_page_max_frames,
        )?;
        store.replay_page_max_bytes = layered_numeric(
            raw.replay_page_max_bytes,
            environment,
            "AGENTDECK_RELAY_REPLAY_PAGE_MAX_BYTES",
            file.replay_page_max_bytes,
            store.replay_page_max_bytes,
        )?;
        store.disk_reserve_bytes = layered_numeric(
            raw.disk_reserve_bytes,
            environment,
            "AGENTDECK_RELAY_DISK_RESERVE_BYTES",
            file.disk_reserve_bytes,
            store.disk_reserve_bytes,
        )?;
        store.disk_reserve_percent = layered_numeric(
            raw.disk_reserve_percent,
            environment,
            "AGENTDECK_RELAY_DISK_RESERVE_PERCENT",
            file.disk_reserve_percent,
            store.disk_reserve_percent,
        )?;
        store.max_enrollment_codes = layered_numeric(
            raw.max_enrollment_codes,
            environment,
            "AGENTDECK_RELAY_MAX_ENROLLMENT_CODES",
            file.max_enrollment_codes,
            store.max_enrollment_codes,
        )?;
        store
            .validate()
            .map_err(RelayV2ConfigError::StorageInvalid)?;

        let tls = select_v2_tls_paths(
            (raw.tls_cert, raw.tls_key),
            (
                environment
                    .get("AGENTDECK_RELAY_TLS_CERT")
                    .map(PathBuf::from),
                environment
                    .get("AGENTDECK_RELAY_TLS_KEY")
                    .map(PathBuf::from),
            ),
            (file.tls_cert, file.tls_key),
        )?;

        let allow_insecure_loopback = if raw.allow_insecure_loopback {
            true
        } else {
            parse_optional_env_bool(environment, "AGENTDECK_RELAY_ALLOW_INSECURE_LOOPBACK")?
                .or(file.allow_insecure_loopback)
                .unwrap_or(false)
        };
        let proxy_mode = if raw.proxy_mode {
            true
        } else {
            parse_optional_env_bool(environment, "AGENTDECK_RELAY_PROXY_MODE")?
                .or(file.proxy_mode)
                .unwrap_or(false)
        };

        let transport = select_v2_transport(bind, tls, allow_insecure_loopback, proxy_mode)?;

        let cli_spki_pins = (!raw.spki_pins.is_empty()).then_some(raw.spki_pins);
        let env_spki_pins = environment
            .get("AGENTDECK_RELAY_SPKI_PINS")
            .map(|value| split_pin_list(value, "AGENTDECK_RELAY_SPKI_PINS"))
            .transpose()?;
        let admin = select_v2_admin(
            (raw.admin_socket, raw.public_wss_url, cli_spki_pins),
            (
                environment
                    .get("AGENTDECK_RELAY_ADMIN_SOCKET")
                    .map(PathBuf::from),
                environment.get("AGENTDECK_RELAY_PUBLIC_WSS_URL").cloned(),
                env_spki_pins,
            ),
            (file.admin_socket, file.public_wss_url, file.spki_pins),
        )?;

        let log_level = raw
            .log_level
            .or_else(|| environment.get("AGENTDECK_RELAY_LOG").cloned())
            .or(file.log_level)
            .unwrap_or_else(|| "info".to_owned());
        if log_level.trim().is_empty() || log_level.len() > 128 || log_level.contains(['\r', '\n'])
        {
            return Err(RelayV2ConfigError::InvalidValue { field: "log_level" });
        }

        let config = Self {
            bind,
            health_bind,
            store,
            transport,
            admin,
            log_level,
        };
        config.validate()?;
        Ok(config)
    }
}

fn resolve_from_cwd(path: PathBuf, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn load_v2_file_config(path: Option<&Path>) -> Result<RelayV2FileConfig, RelayV2ConfigError> {
    let Some(path) = path else {
        return Ok(RelayV2FileConfig::default());
    };
    let source =
        std::fs::read_to_string(path).map_err(|source| RelayV2ConfigError::ConfigFileRead {
            path: path.to_path_buf(),
            source,
        })?;
    let mut config: RelayV2FileConfig =
        toml::from_str(&source).map_err(|source| RelayV2ConfigError::ConfigFileParse {
            path: path.to_path_buf(),
            source,
        })?;
    let parent = path.parent().ok_or(RelayV2ConfigError::InvalidValue {
        field: "config_path",
    })?;
    config.tls_cert = config.tls_cert.map(|value| resolve_from_cwd(value, parent));
    config.tls_key = config.tls_key.map(|value| resolve_from_cwd(value, parent));
    config.admin_socket = config
        .admin_socket
        .map(|value| resolve_from_cwd(value, parent));
    Ok(config)
}

type RawAdminConfig = (Option<PathBuf>, Option<String>, Option<Vec<String>>);

fn select_v2_admin(
    cli: RawAdminConfig,
    environment: RawAdminConfig,
    file: RawAdminConfig,
) -> Result<Option<RelayV2AdminConfig>, RelayV2ConfigError> {
    let socket_path = cli.0.or(environment.0).or(file.0);
    let public_wss_url = cli.1.or(environment.1).or(file.1);
    let raw_pins = cli.2.or(environment.2).or(file.2);
    if socket_path.is_none() && public_wss_url.is_none() && raw_pins.is_none() {
        return Ok(None);
    }
    let (Some(socket_path), Some(public_wss_url), Some(raw_pins)) =
        (socket_path, public_wss_url, raw_pins)
    else {
        return Err(RelayV2ConfigError::AdminPartial);
    };
    let pins = raw_pins
        .iter()
        .map(|pin| parse_spki_pin(pin))
        .collect::<Result<Vec<_>, _>>()?;
    let admin = RelayV2AdminConfig {
        socket_path,
        public_wss_url,
        spki_pins: pins,
    };
    admin.validate()?;
    Ok(Some(admin))
}

fn split_pin_list(value: &str, key: &'static str) -> Result<Vec<String>, RelayV2ConfigError> {
    let pins = value
        .split(',')
        .map(str::trim)
        .filter(|pin| !pin.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if pins.is_empty() {
        return Err(RelayV2ConfigError::InvalidEnvironment { key });
    }
    Ok(pins)
}

fn parse_spki_pin(value: &str) -> Result<[u8; 32], RelayV2ConfigError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| RelayV2ConfigError::AdminInvalid { field: "spki_pins" })?;
    decoded
        .try_into()
        .map_err(|_| RelayV2ConfigError::AdminInvalid { field: "spki_pins" })
}

fn select_v2_tls_paths(
    cli: (Option<PathBuf>, Option<PathBuf>),
    environment: (Option<PathBuf>, Option<PathBuf>),
    file: (Option<PathBuf>, Option<PathBuf>),
) -> Result<Option<RelayV2TlsPaths>, RelayV2ConfigError> {
    for (cert, key) in [cli, environment, file] {
        match (cert, key) {
            (Some(cert), Some(key)) => return Ok(Some(RelayV2TlsPaths { cert, key })),
            (None, None) => {}
            _ => return Err(RelayV2ConfigError::TlsPartial),
        }
    }
    Ok(None)
}

fn parse_socket_addr(value: String, field: &'static str) -> Result<SocketAddr, RelayV2ConfigError> {
    value
        .parse()
        .map_err(|_| RelayV2ConfigError::InvalidValue { field })
}

fn layered_numeric<T>(
    cli: Option<T>,
    environment: &BTreeMap<String, String>,
    key: &'static str,
    file: Option<T>,
    default: T,
) -> Result<T, RelayV2ConfigError>
where
    T: Copy + std::str::FromStr,
{
    if let Some(value) = cli {
        return Ok(value);
    }
    if let Some(value) = environment.get(key) {
        return value
            .parse::<T>()
            .map_err(|_| RelayV2ConfigError::InvalidEnvironment { key });
    }
    Ok(file.unwrap_or(default))
}

fn parse_optional_env_bool(
    environment: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Option<bool>, RelayV2ConfigError> {
    let Some(value) = environment.get(key) else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(Some(true)),
        "0" | "false" => Ok(Some(false)),
        _ => Err(RelayV2ConfigError::InvalidEnvironment { key }),
    }
}

fn select_v2_transport(
    bind: SocketAddr,
    tls: Option<RelayV2TlsPaths>,
    allow_insecure_loopback: bool,
    proxy_mode: bool,
) -> Result<RelayV2TransportMode, RelayV2ConfigError> {
    if allow_insecure_loopback && proxy_mode {
        return Err(RelayV2ConfigError::TransportConflict);
    }
    if let Some(tls) = tls {
        if allow_insecure_loopback || proxy_mode {
            return Err(RelayV2ConfigError::TransportConflict);
        }
        if !cfg!(feature = "tls") {
            return Err(RelayV2ConfigError::TlsFeatureMissing);
        }
        return Ok(RelayV2TransportMode::DirectTls(tls));
    }
    if proxy_mode {
        return if bind.ip().is_loopback() {
            Ok(RelayV2TransportMode::ProxyLoopback)
        } else {
            Err(RelayV2ConfigError::ProxyNonLoopback)
        };
    }
    if allow_insecure_loopback {
        return if bind.ip().is_loopback() {
            Ok(RelayV2TransportMode::InsecureLoopback)
        } else {
            Err(RelayV2ConfigError::TlsRequired)
        };
    }
    if bind.ip().is_loopback() {
        Err(RelayV2ConfigError::InsecureLoopbackOptInRequired)
    } else {
        Err(RelayV2ConfigError::TlsRequired)
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
