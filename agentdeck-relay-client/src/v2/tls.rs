//! 显式 public-CA / CA+pin / pinned-SPKI TLS policy。

use std::fmt;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::RelayClientError;
use agentdeck_protocol::relay_v2::failure::REMOTE_TRANSPORT_TLS_PIN_MISMATCH;

const MAX_EXTRA_ROOTS: usize = 16;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustMode {
    PublicCa,
    PublicCaAndPins,
    PinnedSpki,
}

/// TLS 信任策略。三种模式不会在运行期互相降级。
#[derive(Clone)]
pub struct RelayTlsPolicy {
    mode: TrustMode,
    pins: Vec<[u8; 32]>,
    extra_roots: Vec<Vec<u8>>,
}

impl RelayTlsPolicy {
    pub fn public_ca() -> Result<Self, RelayClientError> {
        Ok(Self {
            mode: TrustMode::PublicCa,
            pins: Vec::new(),
            extra_roots: Vec::new(),
        })
    }

    pub fn public_ca_and_pins(pins: Vec<[u8; 32]>) -> Result<Self, RelayClientError> {
        validate_pins(&pins)?;
        Ok(Self {
            mode: TrustMode::PublicCaAndPins,
            pins,
            extra_roots: Vec::new(),
        })
    }

    pub fn pinned_spki(pins: Vec<[u8; 32]>) -> Result<Self, RelayClientError> {
        validate_pins(&pins)?;
        Ok(Self {
            mode: TrustMode::PinnedSpki,
            pins,
            extra_roots: Vec::new(),
        })
    }

    /// 仅用于私有 CA/测试 CA；证书仍走 WebPKI 的链、时间与 hostname 验证。
    pub fn with_additional_root_der(
        mut self,
        certificate_der: Vec<u8>,
    ) -> Result<Self, RelayClientError> {
        if self.extra_roots.len() >= MAX_EXTRA_ROOTS
            || certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_BYTES
        {
            return Err(RelayClientError::new("relay.client.tls_policy_invalid"));
        }
        self.extra_roots.push(certificate_der);
        Ok(self)
    }

    pub(crate) fn client_config(&self) -> Result<Arc<rustls::ClientConfig>, RelayClientError> {
        let provider = crypto_provider();
        let roots = Arc::new(self.root_store()?);
        let public_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::clone(&roots), Arc::clone(&provider))
                .build()
                .map_err(|_| RelayClientError::new("relay.client.tls_policy_invalid"))?;
        let verifier = StrictServerVerifier {
            mode: self.mode,
            pins: self.pins.clone(),
            public_verifier,
            provider: Arc::clone(&provider),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| RelayClientError::new("relay.client.tls_policy_invalid"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.enable_early_data = false;
        Ok(Arc::new(config))
    }

    fn root_store(&self) -> Result<RootCertStore, RelayClientError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for certificate in &self.extra_roots {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| RelayClientError::new("relay.client.tls_policy_invalid"))?;
        }
        Ok(roots)
    }
}

impl fmt::Debug for RelayTlsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayTlsPolicy")
            .field("mode", &self.mode)
            .field("pins", &"<redacted>")
            .field("pin_count", &self.pins.len())
            .field("extra_root_count", &self.extra_roots.len())
            .finish()
    }
}

fn validate_pins(pins: &[[u8; 32]]) -> Result<(), RelayClientError> {
    if !(1..=2).contains(&pins.len()) || (pins.len() == 2 && pins[0] == pins[1]) {
        return Err(RelayClientError::new("relay.client.tls_policy_invalid"));
    }
    Ok(())
}

fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[derive(Debug)]
struct StrictServerVerifier {
    mode: TrustMode,
    pins: Vec<[u8; 32]>,
    public_verifier: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
}

impl StrictServerVerifier {
    fn require_pin(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let (_, certificate) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("relay.client.tls_certificate_invalid".into()))?;
        let fingerprint: [u8; 32] =
            Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into();
        if self.pins.iter().any(|candidate| candidate == &fingerprint) {
            Ok(())
        } else {
            Err(rustls::Error::General(
                REMOTE_TRANSPORT_TLS_PIN_MISMATCH.into(),
            ))
        }
    }

    fn pinned_webpki(
        &self,
        end_entity: &CertificateDer<'_>,
    ) -> Result<Arc<WebPkiServerVerifier>, rustls::Error> {
        let mut roots = RootCertStore::empty();
        roots
            .add(end_entity.clone().into_owned())
            .map_err(|_| rustls::Error::General("relay.client.tls_certificate_invalid".into()))?;
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&self.provider))
            .build()
            .map_err(|_| rustls::Error::General("relay.client.tls_certificate_invalid".into()))
    }
}

impl ServerCertVerifier for StrictServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.mode {
            TrustMode::PublicCa => self.public_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            TrustMode::PublicCaAndPins => {
                let verified = self.public_verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )?;
                self.require_pin(end_entity)?;
                Ok(verified)
            }
            TrustMode::PinnedSpki => {
                self.require_pin(end_entity)?;
                self.pinned_webpki(end_entity)?.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public_verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public_verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.public_verifier.supported_verify_schemes()
    }
}
