//! 首次 machine enrollment 的唯一公网 HTTP endpoint。

use agentdeck_crypto::{SignatureBytes, VerifyingKey, sha256, verify_tbs};
use agentdeck_protocol::relay_v2::{
    CertRole, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, RelayServerId,
    enrollment_receipt_hash,
};

use crate::v2::auth::AuthorizationCoordinator;
use crate::v2::store::{RegisterMachine, StoreError};

pub const MAX_ENROLLMENT_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("machine enrollment was rejected")]
    Rejected,
    #[error("machine enrollment service is unavailable")]
    Unavailable,
}

impl EnrollmentError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Rejected => "relay.enrollment.rejected",
            Self::Unavailable => "relay.enrollment.unavailable",
        }
    }
}

#[derive(Clone)]
pub struct EnrollmentService {
    authorization: AuthorizationCoordinator,
    relay_server_id: RelayServerId,
}

impl std::fmt::Debug for EnrollmentService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentService")
            .field("relay_server", &self.relay_server_id.redacted())
            .finish_non_exhaustive()
    }
}

impl EnrollmentService {
    pub fn new(authorization: AuthorizationCoordinator, relay_server_id: RelayServerId) -> Self {
        Self {
            authorization,
            relay_server_id,
        }
    }

    /// 返回冻结的 exact JSON response bytes。SQLite COMMIT 后即使首次 HTTP response
    /// 丢失，同 code + 同 canonical request 在 TTL 内也逐字节返回这份 bytes。
    pub async fn enroll(
        &self,
        request: MachineEnrollmentRequestV1,
    ) -> Result<Vec<u8>, EnrollmentError> {
        validate_request(&request, self.relay_server_id)?;
        let request_hash = request.canonical_sha256();
        let receipt_hash = enrollment_receipt_hash(
            self.relay_server_id,
            request.machine_route,
            request.link_cert.trust_epoch.value(),
            request_hash,
        );
        let response = MachineEnrollmentResponseV1 {
            relay_server_id: self.relay_server_id,
            machine_route: request.machine_route,
            trust_epoch: request.link_cert.trust_epoch.value(),
            receipt_hash,
        };
        let response_blob =
            serde_json::to_vec(&response).map_err(|_| EnrollmentError::Unavailable)?;
        let code_hash = sha256(&request.code.0);
        let mutation = self
            .authorization
            .register_machine(RegisterMachine {
                code_hash,
                request_hash,
                response_blob,
                receipt_hash,
                machine_route: request.machine_route,
                root_pubkey: request.root_pubkey,
                link_cert_hash: request.link_cert.canonical_sha256(),
                data_cert_hash: request.data_cert.canonical_sha256(),
                link_cert: request.link_cert,
                data_cert: request.data_cert,
            })
            .await
            .map_err(map_store_error)?;
        let (record, _) = mutation.into_parts();
        Ok(record.response_blob)
    }
}

fn validate_request(
    request: &MachineEnrollmentRequestV1,
    relay_server_id: RelayServerId,
) -> Result<(), EnrollmentError> {
    if request.link_cert.cert_role != CertRole::Link
        || request.data_cert.cert_role != CertRole::Data
        || request.link_cert.root_key_id != request.data_cert.root_key_id
        || request.link_cert.trust_epoch != request.data_cert.trust_epoch
        || request.link_cert.generation.value() == 0
        || request.data_cert.generation.value() == 0
        || request.link_cert.trust_epoch.value() == 0
    {
        return Err(EnrollmentError::Rejected);
    }
    let root =
        VerifyingKey::from_bytes(&request.root_pubkey.0).map_err(|_| EnrollmentError::Rejected)?;
    VerifyingKey::from_bytes(&request.link_cert.subject_pubkey.0)
        .map_err(|_| EnrollmentError::Rejected)?;
    VerifyingKey::from_bytes(&request.data_cert.subject_pubkey.0)
        .map_err(|_| EnrollmentError::Rejected)?;
    let root_fingerprint = sha256(&request.root_pubkey.0);
    verify_tbs(
        &root,
        &request.link_cert.to_be_signed_v1(
            relay_server_id,
            request.machine_route,
            root_fingerprint,
        ),
        &SignatureBytes::from(request.link_cert.signature),
    )
    .map_err(|_| EnrollmentError::Rejected)?;
    verify_tbs(
        &root,
        &request.data_cert.to_be_signed_v1(
            relay_server_id,
            request.machine_route,
            root_fingerprint,
        ),
        &SignatureBytes::from(request.data_cert.signature),
    )
    .map_err(|_| EnrollmentError::Rejected)
}

fn map_store_error(error: StoreError) -> EnrollmentError {
    match error {
        StoreError::EnrollmentCodeNotFound
        | StoreError::EnrollmentCodeExpired
        | StoreError::EnrollmentCodeConflict
        | StoreError::AuthenticationMismatch { .. }
        | StoreError::IdempotencyConflict { .. }
        | StoreError::MonotonicRollback { .. }
        | StoreError::MachineNotFound
        | StoreError::RootFingerprintMismatch
        | StoreError::InvalidValue { .. } => EnrollmentError::Rejected,
        _ => EnrollmentError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_hash_binds_server_route_epoch_and_request() {
        let server = RelayServerId::from_bytes([1; 16]);
        let route = agentdeck_protocol::relay_v2::MachineRouteId::from_bytes([2; 16]);
        let baseline = enrollment_receipt_hash(server, route, 1, [3; 32]);
        assert_ne!(baseline, enrollment_receipt_hash(server, route, 2, [3; 32]));
        assert_ne!(baseline, enrollment_receipt_hash(server, route, 1, [4; 32]));
    }
}
