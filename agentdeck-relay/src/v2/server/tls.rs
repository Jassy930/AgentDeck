//! Relay v2 TLS identity 的 bind 前装载与校验。
//!
//! 本模块只接受一对本地 PEM 文件，并在调用方绑定公网 listener 之前完成：
//! 读取上界、PEM 解析、私钥解析以及 leaf certificate / private key SPKI 一致性校验。
//! 没有编译 `tls` feature 时，同一入口稳定返回 [`TlsIdentityError::FeatureMissing`]；
//! 绝不把“配置了 TLS”降级成明文 listener。

use std::fmt;
use std::io;
#[cfg(feature = "tls")]
use std::io::Read;
#[cfg(feature = "tls")]
use std::path::Path;
use std::path::PathBuf;

/// 单个 certificate chain / private-key PEM 的启动期硬上界。
///
/// 正常 leaf + short chain 远小于 1 MiB；本上界避免本地错误配置在 listener bind 前
/// 造成无界内存分配。它不是 WebSocket frame 上限。
pub const MAX_TLS_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentityPaths {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

impl TlsIdentityPaths {
    pub fn new(certificate_chain: impl Into<PathBuf>, private_key: impl Into<PathBuf>) -> Self {
        Self {
            certificate_chain: certificate_chain.into(),
            private_key: private_key.into(),
        }
    }
}

/// bind 前 TLS identity 校验失败。
///
/// 错误本身不保存路径或 PEM bytes；日志只应记录 [`TlsIdentityError::code`]。
#[derive(Debug, thiserror::Error)]
pub enum TlsIdentityError {
    #[error("Relay binary was built without TLS support")]
    FeatureMissing,
    #[error("failed to read TLS certificate chain")]
    CertificateRead {
        #[source]
        source: io::Error,
    },
    #[error("failed to read TLS private key")]
    PrivateKeyRead {
        #[source]
        source: io::Error,
    },
    #[error("TLS certificate chain exceeds the startup limit")]
    CertificateTooLarge,
    #[error("TLS private key exceeds the startup limit")]
    PrivateKeyTooLarge,
    #[error("TLS certificate chain or private key is invalid or mismatched")]
    InvalidIdentity {
        #[source]
        source: io::Error,
    },
    #[error("configured enrollment SPKI pin does not match the active TLS leaf certificate")]
    PinMismatch,
}

impl TlsIdentityError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FeatureMissing => "relay.transport.tls_feature_missing",
            Self::CertificateRead { .. } => "relay.tls.certificate_read",
            Self::PrivateKeyRead { .. } => "relay.tls.private_key_read",
            Self::CertificateTooLarge => "relay.tls.certificate_too_large",
            Self::PrivateKeyTooLarge => "relay.tls.private_key_too_large",
            Self::InvalidIdentity { .. } => "relay.tls.identity_invalid",
            Self::PinMismatch => "relay.tls.spki_pin_mismatch",
        }
    }
}

/// 已完成 PEM 与 certificate/private-key 一致性校验的 server identity。
///
/// wrapper 让 `load_tls_identity` 在有/无 `tls` feature 时保持相同签名；真正的
/// rustls 配置只在 `tls` feature 下可取出。
pub struct LoadedTlsIdentity {
    #[cfg(feature = "tls")]
    config: axum_server::tls_rustls::RustlsConfig,
    #[cfg(feature = "tls")]
    leaf_spki_sha256: [u8; 32],
    #[cfg(not(feature = "tls"))]
    _private: (),
}

impl fmt::Debug for LoadedTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedTlsIdentity")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tls")]
impl LoadedTlsIdentity {
    pub fn rustls_config(&self) -> axum_server::tls_rustls::RustlsConfig {
        self.config.clone()
    }

    pub fn into_rustls_config(self) -> axum_server::tls_rustls::RustlsConfig {
        self.config
    }

    pub fn server_config(&self) -> std::sync::Arc<rustls::ServerConfig> {
        self.config.get_inner()
    }

    pub fn leaf_spki_sha256(&self) -> [u8; 32] {
        self.leaf_spki_sha256
    }
}

/// 在任何 listener bind 之前装载并验证 TLS server identity。
pub async fn load_tls_identity(
    paths: &TlsIdentityPaths,
) -> Result<LoadedTlsIdentity, TlsIdentityError> {
    #[cfg(not(feature = "tls"))]
    {
        let _ = paths;
        Err(TlsIdentityError::FeatureMissing)
    }

    #[cfg(feature = "tls")]
    {
        ensure_crypto_provider();
        // 启动期同步读取发生在 bind 前，且被 1 MiB 硬上界约束；随后
        // `RustlsConfig::from_pem` 在 blocking task 中完成 PEM/key 解析。
        let certificate_chain = read_bounded(
            &paths.certificate_chain,
            TlsIdentityError::CertificateTooLarge,
            |source| TlsIdentityError::CertificateRead { source },
        )?;
        let private_key = read_bounded(
            &paths.private_key,
            TlsIdentityError::PrivateKeyTooLarge,
            |source| TlsIdentityError::PrivateKeyRead { source },
        )?;
        let leaf_spki_sha256 = parse_leaf_spki_sha256(&certificate_chain)?;
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem(certificate_chain, private_key)
                .await
                .map_err(|source| TlsIdentityError::InvalidIdentity { source })?;
        Ok(LoadedTlsIdentity {
            config,
            leaf_spki_sha256,
        })
    }
}

#[cfg(feature = "tls")]
fn parse_leaf_spki_sha256(pem: &[u8]) -> Result<[u8; 32], TlsIdentityError> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::{FromDer, X509Certificate};

    let mut reader = std::io::Cursor::new(pem);
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .map_err(|source| TlsIdentityError::InvalidIdentity { source })?
        .ok_or_else(|| TlsIdentityError::InvalidIdentity {
            source: io::Error::new(io::ErrorKind::InvalidData, "certificate chain is empty"),
        })?;
    let (remainder, certificate) = X509Certificate::from_der(leaf.as_ref()).map_err(|_| {
        TlsIdentityError::InvalidIdentity {
            source: io::Error::new(io::ErrorKind::InvalidData, "leaf certificate is invalid"),
        }
    })?;
    if !remainder.is_empty() {
        return Err(TlsIdentityError::InvalidIdentity {
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "leaf certificate has trailing data",
            ),
        });
    }
    Ok(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}

#[cfg(feature = "tls")]
fn ensure_crypto_provider() {
    // 当前 workspace 的 TLS client/server 依赖可能同时启用 rustls 的多个 provider，
    // 此时 rustls 无法自动选取并会在 ServerConfig::builder() 内 panic。若进程尚未
    // 安装 provider，显式选择随 rustls 默认 feature 编译进来的 AWS-LC；并发调用时
    // 只有一个赢家，失败方观察到的只是“已有全局 provider”，可安全继续。
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(feature = "tls")]
fn read_bounded(
    path: &Path,
    too_large: TlsIdentityError,
    read_error: impl Fn(io::Error) -> TlsIdentityError,
) -> Result<Vec<u8>, TlsIdentityError> {
    let file = std::fs::File::open(path).map_err(&read_error)?;
    let limit = u64::try_from(MAX_TLS_PEM_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut reader = file.take(limit);
    let mut bytes = Vec::with_capacity(16 * 1024);
    reader.read_to_end(&mut bytes).map_err(read_error)?;
    if bytes.len() > MAX_TLS_PEM_BYTES {
        return Err(too_large);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tls")]
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[cfg(feature = "tls")]
    fn valid_paths() -> TlsIdentityPaths {
        TlsIdentityPaths::new(fixture("test_cert.pem"), fixture("test_key.pem"))
    }

    #[cfg(not(feature = "tls"))]
    #[tokio::test]
    async fn configured_tls_without_feature_is_a_stable_failure_before_file_io() {
        let missing = TlsIdentityPaths::new("/definitely/missing/cert", "/definitely/missing/key");
        let error = load_tls_identity(&missing)
            .await
            .expect_err("TLS feature missing must never fall back to plaintext");
        assert!(matches!(error, TlsIdentityError::FeatureMissing));
        assert_eq!(error.code(), "relay.transport.tls_feature_missing");
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn matching_certificate_and_key_produce_server_config() {
        let identity = load_tls_identity(&valid_paths())
            .await
            .expect("fixture identity is valid");
        let config = identity.rustls_config();
        let _server_config = config.get_inner();
        assert_ne!(identity.leaf_spki_sha256(), [0; 32]);
        let _owned = identity.into_rustls_config();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn mismatched_private_key_is_rejected_before_bind() {
        let paths =
            TlsIdentityPaths::new(fixture("test_cert.pem"), fixture("test_mismatch_key.pem"));
        let error = load_tls_identity(&paths)
            .await
            .expect_err("certificate/private-key mismatch must fail closed");
        assert!(matches!(error, TlsIdentityError::InvalidIdentity { .. }));
        assert_eq!(error.code(), "relay.tls.identity_invalid");
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn malformed_pem_is_rejected_before_bind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert = temp.path().join("cert.pem");
        std::fs::write(&cert, b"not a certificate").expect("write fixture");
        let paths = TlsIdentityPaths::new(cert, fixture("test_key.pem"));
        let error = load_tls_identity(&paths)
            .await
            .expect_err("malformed PEM must fail closed");
        assert!(matches!(error, TlsIdentityError::InvalidIdentity { .. }));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn missing_files_are_typed_without_leaking_paths() {
        let paths = TlsIdentityPaths::new(
            "/definitely/missing/agentdeck-cert-secret.pem",
            "/definitely/missing/agentdeck-key-secret.pem",
        );
        let error = load_tls_identity(&paths)
            .await
            .expect_err("missing certificate must fail closed");
        assert!(matches!(error, TlsIdentityError::CertificateRead { .. }));
        assert_eq!(error.code(), "relay.tls.certificate_read");
        assert!(!error.to_string().contains("agentdeck-cert-secret"));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn oversized_pem_is_rejected_before_full_allocation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert = temp.path().join("oversized.pem");
        std::fs::write(&cert, vec![b'A'; MAX_TLS_PEM_BYTES + 1]).expect("write fixture");
        let paths = TlsIdentityPaths::new(cert, fixture("test_key.pem"));
        let error = load_tls_identity(&paths)
            .await
            .expect_err("oversized PEM must fail closed");
        assert!(matches!(error, TlsIdentityError::CertificateTooLarge));
        assert_eq!(error.code(), "relay.tls.certificate_too_large");
    }
}
