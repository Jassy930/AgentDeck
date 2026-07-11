//! MachineLink / DeviceLink 的真实 Ed25519 验签与 Store 单调确认。

use std::fmt;

use agentdeck_crypto::{
    SignatureBytes, VerifyingKey, sha256, verify_authentication_transcript, verify_tbs,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_AUTH_REVOKED, RELAY_STORE_UNAVAILABLE,
};
use agentdeck_protocol::relay_v2::frame::{AuthProof, Authenticate};
use agentdeck_protocol::relay_v2::{RELAY_PROTOCOL_VERSION, RelayFailure};

use super::access::{AccessContext, Activation, DeviceAccess, MachineAccess};
use super::challenge::{ChallengeRoute, ConsumedChallenge};
use crate::v2::store::{
    AuthorizationOwner, CommitMachineLinkAuth, ConfirmDeviceAuth, DeviceTrustView, GrantCommit,
    InstallGrantRecord, MachineRecord, MachineTrustView, PersistRevocation, PurgeMachine,
    PurgeReadback, RegisterMachine, RelayStoreHandle, RevocationCommit, StoreError,
};

#[derive(Clone, PartialEq, Eq)]
pub enum AuthenticationTrust {
    Machine(MachineTrustView),
    Device(DeviceTrustView),
}

/// `now_ms` 是证书 absolute expiry 的 wall-clock 读数；challenge TTL 单独使用
/// ChallengeRegistry 的 monotonic clock，二者不可混用。
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationTrustView {
    pub now_ms: u64,
    pub trust: AuthenticationTrust,
}

impl fmt::Debug for AuthenticationTrustView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.trust {
            AuthenticationTrust::Machine(_) => "machine",
            AuthenticationTrust::Device(_) => "device",
        };
        formatter
            .debug_struct("AuthenticationTrustView")
            .field("kind", &kind)
            .field("now_ms", &self.now_ms)
            .field("trust_material", &"<redacted>")
            .finish()
    }
}

pub fn verify_authentication(
    frame: &Authenticate,
    challenge: &ConsumedChallenge,
    trust: &AuthenticationTrustView,
) -> Result<AccessContext, RelayFailure> {
    match (&frame.proof, &trust.trust) {
        (
            AuthProof::MachineLink {
                machine_route,
                link_cert,
            },
            AuthenticationTrust::Machine(machine),
        ) => {
            let expected_route = ChallengeRoute::Machine(*machine_route);
            if challenge.route() != expected_route
                || *machine_route != machine.machine_route
                || challenge.challenge().relay_server_id != machine.relay_server_id
                || link_cert.cert_role != CertRole::Link
                || link_cert.root_key_id != machine.root_key_id
                || link_cert.trust_epoch != machine.trust_epoch
                || link_cert
                    .not_after_ms
                    .is_some_and(|expiry| trust.now_ms >= expiry)
            {
                return Err(invalid_grant());
            }

            let cert_hash = link_cert.canonical_sha256();
            if link_cert.generation < machine.highest_link_generation
                || (link_cert.generation == machine.highest_link_generation
                    && cert_hash != machine.link_cert_hash)
            {
                return Err(invalid_grant());
            }

            let root_key = verifying_key(machine.root_pubkey.0)?;
            let root_fingerprint = sha256(&machine.root_pubkey.0);
            let certificate_tbs = link_cert.to_be_signed_v1(
                machine.relay_server_id,
                machine.machine_route,
                root_fingerprint,
            );
            verify_tbs(
                &root_key,
                &certificate_tbs,
                &SignatureBytes::from(link_cert.signature),
            )
            .map_err(|_| invalid_grant())?;

            let transcript = AuthenticationTranscriptV1 {
                role: AuthenticationRole::MachineLink,
                challenge_nonce: challenge.challenge().challenge_nonce,
                connection_instance: challenge.challenge().connection_instance,
                relay_server_id: challenge.challenge().relay_server_id,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                machine_route: *machine_route,
                device_route: None,
                serial_or_generation: link_cert.generation.value(),
                credential_sha256: cert_hash,
            };
            let link_key = verifying_key(link_cert.subject_pubkey.0)?;
            verify_authentication_transcript(
                &link_key,
                &transcript,
                &SignatureBytes::from(frame.signature),
            )
            .map_err(|_| invalid_grant())?;

            Ok(AccessContext::Machine(MachineAccess {
                machine_route: *machine_route,
                connection_instance: challenge.challenge().connection_instance,
                trust_epoch: machine.trust_epoch,
                link_generation: link_cert.generation,
                cert_hash,
            }))
        }
        (AuthProof::Device { relay_grant }, AuthenticationTrust::Device(device)) => {
            let expected_route = ChallengeRoute::Device {
                machine_route: relay_grant.machine_route,
                device_route: relay_grant.device_route,
            };
            let grant_hash = relay_grant.canonical_sha256();
            let device_fingerprint = sha256(&relay_grant.device_sign_pubkey.0);
            if challenge.route() != expected_route
                || challenge.challenge().relay_server_id != device.machine.relay_server_id
                || relay_grant.machine_route != device.machine.machine_route
                || relay_grant.device_route != device.device_route
                || relay_grant.root_key_id != device.machine.root_key_id
                || relay_grant.trust_epoch != device.machine.trust_epoch
                || relay_grant.grant_serial != device.grant_serial
                || grant_hash != device.grant_hash
                || relay_grant.device_sign_pubkey != device.auth_pubkey
                || device_fingerprint != device.auth_fingerprint
            {
                return Err(invalid_grant());
            }

            let root_key = verifying_key(device.machine.root_pubkey.0)?;
            let root_fingerprint = sha256(&device.machine.root_pubkey.0);
            verify_tbs(
                &root_key,
                &relay_grant.to_be_signed_v1(device.machine.relay_server_id, root_fingerprint),
                &SignatureBytes::from(relay_grant.signature),
            )
            .map_err(|_| invalid_grant())?;

            let transcript = AuthenticationTranscriptV1 {
                role: AuthenticationRole::Device,
                challenge_nonce: challenge.challenge().challenge_nonce,
                connection_instance: challenge.challenge().connection_instance,
                relay_server_id: challenge.challenge().relay_server_id,
                relay_protocol_version: RELAY_PROTOCOL_VERSION,
                machine_route: relay_grant.machine_route,
                device_route: Some(relay_grant.device_route),
                serial_or_generation: relay_grant.grant_serial.value(),
                credential_sha256: grant_hash,
            };
            let device_key = verifying_key(relay_grant.device_sign_pubkey.0)?;
            verify_authentication_transcript(
                &device_key,
                &transcript,
                &SignatureBytes::from(frame.signature),
            )
            .map_err(|_| invalid_grant())?;

            // 只有能证明持有当前、MachineRoot-signed grant 与 DeviceSign 私钥的 endpoint
            // 才能观察 terminal revoked 状态；伪造 route/proof 仍统一折叠为 invalid_grant。
            if device.revoked {
                return Err(revoked());
            }

            Ok(AccessContext::Device(DeviceAccess {
                machine_route: relay_grant.machine_route,
                device_route: relay_grant.device_route,
                connection_instance: challenge.challenge().connection_instance,
                grant_serial: relay_grant.grant_serial,
                grant_hash,
                device_sign_fingerprint: device_fingerprint,
            }))
        }
        _ => Err(invalid_grant()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationActivation {
    pub access: AccessContext,
    pub activation: Activation,
}

pub(super) struct PreparedAuthentication {
    pub(super) access: AccessContext,
    trust: AuthenticationTrust,
}

pub(super) struct AuthenticationService {
    store: RelayStoreHandle,
    owner: AuthorizationOwner,
}

impl fmt::Debug for AuthenticationService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationService")
            .finish_non_exhaustive()
    }
}

impl AuthenticationService {
    pub(super) fn new(store: RelayStoreHandle, owner: AuthorizationOwner) -> Self {
        Self { store, owner }
    }

    /// 只读取 trust 并完成真实验签；没有持久 mutation，因此这一段尚不需要 fence active。
    pub(super) async fn prepare(
        &self,
        frame: &Authenticate,
        challenge: &ConsumedChallenge,
        now_ms: u64,
    ) -> Result<PreparedAuthentication, RelayFailure> {
        let trust = match &frame.proof {
            AuthProof::MachineLink { machine_route, .. } => AuthenticationTrustView {
                now_ms,
                trust: AuthenticationTrust::Machine(
                    self.store
                        .machine_trust(*machine_route)
                        .await
                        .map_err(map_store_error)?,
                ),
            },
            AuthProof::Device { relay_grant } => AuthenticationTrustView {
                now_ms,
                trust: AuthenticationTrust::Device(
                    self.store
                        .device_trust(relay_grant.machine_route, relay_grant.device_route)
                        .await
                        .map_err(map_store_error)?,
                ),
            },
        };
        let access = verify_authentication(frame, challenge, &trust)?;
        Ok(PreparedAuthentication {
            access,
            trust: trust.trust,
        })
    }

    /// Caller 必须先把 principal route fence 为 Transitioning；本方法返回 Ready 后到 active
    /// commit 之间不得再有 await。
    pub(super) async fn commit(
        &self,
        prepared: &PreparedAuthentication,
    ) -> Result<(), RelayFailure> {
        match &prepared.access {
            AccessContext::Machine(access) => {
                self.store
                    .commit_machine_link_auth_authorized(
                        &self.owner,
                        CommitMachineLinkAuth {
                            machine_route: access.machine_route,
                            root_key_id: match &prepared.trust {
                                AuthenticationTrust::Machine(machine) => machine.root_key_id,
                                AuthenticationTrust::Device(_) => return Err(invalid_grant()),
                            },
                            trust_epoch: access.trust_epoch,
                            generation: access.link_generation,
                            cert_hash: access.cert_hash,
                        },
                    )
                    .await
                    .map_err(map_store_error)?;
            }
            AccessContext::Device(access) => {
                let device = match &prepared.trust {
                    AuthenticationTrust::Device(device) => device,
                    AuthenticationTrust::Machine(_) => return Err(invalid_grant()),
                };
                self.store
                    .confirm_device_auth_authorized(
                        &self.owner,
                        ConfirmDeviceAuth {
                            machine_route: access.machine_route,
                            device_route: access.device_route,
                            grant_serial: access.grant_serial,
                            grant_hash: access.grant_hash,
                            auth_pubkey: device.auth_pubkey,
                            auth_fingerprint: access.device_sign_fingerprint,
                        },
                    )
                    .await
                    .map_err(map_store_error)?;
            }
            AccessContext::Pairing(_) => return Err(invalid_grant()),
        }
        Ok(())
    }

    pub(super) async fn register_machine(
        &self,
        request: RegisterMachine,
    ) -> Result<MachineRecord, StoreError> {
        self.store
            .register_machine_authorized(&self.owner, request)
            .await
    }

    pub(super) async fn install_grant(
        &self,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        self.store
            .install_grant_authorized(&self.owner, request)
            .await
    }

    pub(super) async fn revoke(
        &self,
        request: PersistRevocation,
    ) -> Result<RevocationCommit, StoreError> {
        self.store.revoke_authorized(&self.owner, request).await
    }

    pub(super) async fn purge_machine(
        &self,
        request: PurgeMachine,
    ) -> Result<PurgeReadback, StoreError> {
        self.store
            .purge_machine_authorized(&self.owner, request)
            .await
    }
}

fn verifying_key(bytes: [u8; 32]) -> Result<VerifyingKey, RelayFailure> {
    VerifyingKey::from_bytes(&bytes).map_err(|_| invalid_grant())
}

fn map_store_error(error: StoreError) -> RelayFailure {
    match error {
        StoreError::Revoked => revoked(),
        StoreError::MachineNotFound
        | StoreError::GrantNotFound
        | StoreError::MonotonicRollback { .. }
        | StoreError::IdempotencyConflict { .. }
        | StoreError::AuthenticationMismatch { .. } => invalid_grant(),
        _ => RelayFailure::new(
            RELAY_STORE_UNAVAILABLE,
            "authentication state is unavailable",
        ),
    }
}

fn invalid_grant() -> RelayFailure {
    RelayFailure::new(
        RELAY_AUTH_INVALID_GRANT,
        "authentication credential is invalid",
    )
}

fn revoked() -> RelayFailure {
    RelayFailure::new(RELAY_AUTH_REVOKED, "authentication credential is revoked")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::FaultPoint;

    #[test]
    fn store_errors_only_expose_expected_credential_failures() {
        for error in [
            StoreError::MachineNotFound,
            StoreError::GrantNotFound,
            StoreError::MonotonicRollback {
                field: "link_generation",
            },
            StoreError::IdempotencyConflict {
                field: "link_generation",
            },
            StoreError::AuthenticationMismatch {
                field: "grant_hash",
            },
        ] {
            assert_eq!(map_store_error(error).code, RELAY_AUTH_INVALID_GRANT);
        }
        assert_eq!(
            map_store_error(StoreError::Revoked).code,
            RELAY_AUTH_REVOKED
        );

        for error in [
            StoreError::InvalidValue {
                field: "grant_hash",
                reason: "corrupt persisted bytes",
            },
            StoreError::WorkerBusy,
            StoreError::InjectedFault(FaultPoint::MachineLinkAuthBeforeCommit),
        ] {
            assert_eq!(map_store_error(error).code, RELAY_STORE_UNAVAILABLE);
        }
    }
}
