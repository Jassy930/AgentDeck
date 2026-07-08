//! Relay 配置层：加载（dotenvy + clap + env）+ 传输安全门禁（非 loopback 无 TLS 拒启动）。
//!
//! 本模块只产出配置数据结构与门禁校验逻辑，不含任何网络监听/绑定动作（Task 9 消费）。

use clap::Parser;
use std::net::SocketAddr;

/// Relay 运行时配置。
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub bootstrap_secret: String,
    pub tls: Option<TlsPaths>,
    pub allow_plaintext: bool,
    pub log_level: String,
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

        Ok(RelayConfig {
            bind,
            bootstrap_secret,
            tls,
            allow_plaintext,
            log_level,
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
    #[allow(unused_imports)]
    use std::net::SocketAddr;
    fn cfg(bind: &str, tls: bool, allow: bool) -> RelayConfig {
        RelayConfig { bind: bind.parse().unwrap(), bootstrap_secret: "s".into(),
            tls: if tls { Some(TlsPaths { cert: "c".into(), key: "k".into() }) } else { None },
            allow_plaintext: allow, log_level: "info".into() }
    }
    #[test]
    fn loopback_plaintext_ok() { assert!(cfg("127.0.0.1:8080", false, false).validate_transport_gate().is_ok()); }
    #[test]
    fn non_loopback_plaintext_rejected() {
        let e = cfg("0.0.0.0:8080", false, false).validate_transport_gate().unwrap_err();
        assert_eq!(e.code(), agentdeck_protocol::remote::failure::CONFIG_PLAINTEXT_NON_LOOPBACK);
    }
    #[test]
    fn non_loopback_with_tls_ok() { assert!(cfg("0.0.0.0:8080", true, false).validate_transport_gate().is_ok()); }
    #[test]
    fn non_loopback_allow_plaintext_ok() { assert!(cfg("0.0.0.0:8080", false, true).validate_transport_gate().is_ok()); }
}
