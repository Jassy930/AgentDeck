//! MachineLink / DeviceLink 的真实 Ed25519 验签与 Store 单调确认。

use std::fmt;

use agentdeck_crypto::{
    SignatureBytes, VerifyingKey, sha256, verify_authentication_transcript, verify_tbs,
};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, CertRole, DeviceRevocation, RelayGrant,
};
use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_AUTH_REVOKED, RELAY_STORE_UNAVAILABLE,
};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, OpaqueRouteFrame, RetireMachine, RetirementCommitted,
    RevocationCommitted,
};
use agentdeck_protocol::relay_v2::{
    RELAY_PROTOCOL_VERSION, RelayFailure, RelayFrameBody, decode, encode,
};

use super::access::{AccessContext, Activation, DeviceAccess, MachineAccess};
use super::challenge::{ChallengeRoute, ConsumedChallenge};
use crate::v2::store::{
    AuthorizationOwner, CommitMachineLinkAuth, ConfirmDeviceAuth, DeviceTrustView,
    EnrollmentCodeSeed, GrantCommit, InstallGrantRecord, MachineRecord, MachineTrustView,
    PersistRetirement, PersistRevocation, PurgeMachine, PurgeReadback, RegisterMachine,
    RelayStoreHandle, RetirementCommit, RevocationCommit, StoreError,
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

enum VerifiedAuthentication {
    Active(AccessContext),
    Revoked {
        access: DeviceAccess,
        terminal: OpaqueRouteFrame,
    },
    Retired {
        access: MachineAccess,
        terminal: OpaqueRouteFrame,
    },
}

pub fn verify_authentication(
    frame: &Authenticate,
    challenge: &ConsumedChallenge,
    trust: &AuthenticationTrustView,
) -> Result<AccessContext, RelayFailure> {
    match verify_authentication_endpoint(frame, challenge, trust)? {
        VerifiedAuthentication::Active(access) => Ok(access),
        VerifiedAuthentication::Revoked { .. } => Err(revoked()),
        VerifiedAuthentication::Retired { .. } => Err(invalid_grant()),
    }
}

fn verify_authentication_endpoint(
    frame: &Authenticate,
    challenge: &ConsumedChallenge,
    trust: &AuthenticationTrustView,
) -> Result<VerifiedAuthentication, RelayFailure> {
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
            let credential_rolls_back = link_cert.generation < machine.highest_link_generation
                || (link_cert.generation == machine.highest_link_generation
                    && cert_hash != machine.link_cert_hash);
            let retired_credential_mismatch = machine.retired
                && (link_cert.generation != machine.highest_link_generation
                    || cert_hash != machine.link_cert_hash);
            if credential_rolls_back || retired_credential_mismatch {
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

            let access = MachineAccess {
                machine_route: *machine_route,
                connection_instance: challenge.challenge().connection_instance,
                trust_epoch: machine.trust_epoch,
                link_generation: link_cert.generation,
                cert_hash,
                absolute_expiry_ms: link_cert.not_after_ms,
            };
            if machine.retired {
                let terminal = decode_retirement_terminal(machine)?;
                return Ok(VerifiedAuthentication::Retired { access, terminal });
            }
            Ok(VerifiedAuthentication::Active(AccessContext::Machine(
                access,
            )))
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
            let access = DeviceAccess {
                machine_route: relay_grant.machine_route,
                device_route: relay_grant.device_route,
                connection_instance: challenge.challenge().connection_instance,
                grant_serial: relay_grant.grant_serial,
                grant_hash,
                device_sign_fingerprint: device_fingerprint,
            };
            if device.revoked {
                let terminal = decode_revocation_terminal(device, &root_key)?;
                return Ok(VerifiedAuthentication::Revoked { access, terminal });
            }

            Ok(VerifiedAuthentication::Active(AccessContext::Device(
                access,
            )))
        }
        _ => Err(invalid_grant()),
    }
}

fn decode_revocation_terminal(
    device: &DeviceTrustView,
    root_key: &VerifyingKey,
) -> Result<OpaqueRouteFrame, RelayFailure> {
    let persisted = device
        .revocation_terminal
        .as_ref()
        .ok_or_else(invalid_grant)?;
    let terminal = decode(&persisted.signed_revocation_blob).map_err(|_| invalid_grant())?;
    if encode(&terminal) != persisted.signed_revocation_blob {
        return Err(invalid_grant());
    }
    let RelayFrameBody::RevocationCommitted(committed) = &terminal.body else {
        return Err(invalid_grant());
    };
    let revocation = &committed.signed_revocation;
    if committed.device_route != device.device_route
        || committed.grant_serial != device.grant_serial
        || revocation.machine_route != device.machine.machine_route
        || revocation.device_route != device.device_route
        || revocation.grant_serial != device.grant_serial
        || revocation.root_key_id != device.machine.root_key_id
        || revocation.trust_epoch != device.machine.trust_epoch
        || revocation.canonical_sha256() != persisted.revocation_hash
    {
        return Err(invalid_grant());
    }
    verify_tbs(
        root_key,
        &revocation.to_be_signed_v1(
            device.machine.relay_server_id,
            sha256(&device.machine.root_pubkey.0),
        ),
        &SignatureBytes::from(revocation.signature),
    )
    .map_err(|_| invalid_grant())?;
    Ok(terminal)
}

fn decode_retirement_terminal(
    machine: &MachineTrustView,
) -> Result<OpaqueRouteFrame, RelayFailure> {
    let persisted = machine
        .retirement_terminal
        .as_ref()
        .ok_or_else(invalid_grant)?;
    let terminal = decode(&persisted.retirement_terminal_blob).map_err(|_| invalid_grant())?;
    if encode(&terminal) != persisted.retirement_terminal_blob {
        return Err(invalid_grant());
    }
    match &terminal.body {
        RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route,
            trust_epoch,
            retire_hash,
        }) if *machine_route == machine.machine_route
            && *trust_epoch == machine.trust_epoch
            && *retire_hash == persisted.retirement_hash =>
        {
            Ok(terminal)
        }
        _ => Err(invalid_grant()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationActivation {
    pub access: AccessContext,
    pub activation: Activation,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RevokedAuthentication {
    pub(crate) access: DeviceAccess,
    pub(crate) terminal: OpaqueRouteFrame,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RetiredAuthentication {
    pub(crate) access: MachineAccess,
    pub(crate) terminal: OpaqueRouteFrame,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthenticationOutcome {
    Activated(AuthenticationActivation),
    RevokedTerminal(RevokedAuthentication),
    RetiredTerminal(RetiredAuthentication),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PreparedTerminal {
    Revoked(RevokedAuthentication),
    Retired(RetiredAuthentication),
}

pub(super) struct PreparedAuthentication {
    pub(super) access: AccessContext,
    trust: AuthenticationTrust,
    pub(super) terminal: Option<PreparedTerminal>,
}

pub(super) struct AuthenticationService {
    store: RelayStoreHandle,
    owner: AuthorizationOwner,
}

#[derive(Debug)]
pub(super) enum AuthenticationCommitError {
    Rollback(RelayFailure),
    OutcomeUnknown(RelayFailure),
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
        let verified = verify_authentication_endpoint(frame, challenge, &trust)?;
        let (access, terminal) = match verified {
            VerifiedAuthentication::Active(access) => (access, None),
            VerifiedAuthentication::Revoked { access, terminal } => {
                let context = AccessContext::Device(access.clone());
                (
                    context,
                    Some(PreparedTerminal::Revoked(RevokedAuthentication {
                        access,
                        terminal,
                    })),
                )
            }
            VerifiedAuthentication::Retired { access, terminal } => {
                let context = AccessContext::Machine(access.clone());
                (
                    context,
                    Some(PreparedTerminal::Retired(RetiredAuthentication {
                        access,
                        terminal,
                    })),
                )
            }
        };
        Ok(PreparedAuthentication {
            access,
            trust: trust.trust,
            terminal,
        })
    }

    /// Caller 必须先把 principal route fence 为 Transitioning；本方法返回 Ready 后到 active
    /// commit 之间不得再有 await。
    pub(super) async fn commit(
        &self,
        prepared: &PreparedAuthentication,
    ) -> Result<(), AuthenticationCommitError> {
        if prepared.terminal.is_some() {
            return Err(AuthenticationCommitError::Rollback(invalid_grant()));
        }
        match &prepared.access {
            AccessContext::Machine(access) => {
                let request = CommitMachineLinkAuth {
                    machine_route: access.machine_route,
                    root_key_id: match &prepared.trust {
                        AuthenticationTrust::Machine(machine) => machine.root_key_id,
                        AuthenticationTrust::Device(_) => {
                            return Err(AuthenticationCommitError::Rollback(invalid_grant()));
                        }
                    },
                    trust_epoch: access.trust_epoch,
                    generation: access.link_generation,
                    cert_hash: access.cert_hash,
                };
                match self
                    .store
                    .commit_machine_link_auth_authorized(&self.owner, request.clone())
                    .await
                {
                    Ok(_) => {}
                    Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => {
                        if self
                            .store
                            .commit_machine_link_auth_authorized(&self.owner, request)
                            .await
                            .is_err()
                        {
                            return Err(AuthenticationCommitError::OutcomeUnknown(
                                map_store_error(unknown),
                            ));
                        }
                    }
                    Err(error) => {
                        return Err(AuthenticationCommitError::Rollback(map_store_error(error)));
                    }
                }
            }
            AccessContext::Device(access) => {
                let device = match &prepared.trust {
                    AuthenticationTrust::Device(device) => device,
                    AuthenticationTrust::Machine(_) => {
                        return Err(AuthenticationCommitError::Rollback(invalid_grant()));
                    }
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
                    .map_err(|error| AuthenticationCommitError::Rollback(map_store_error(error)))?;
            }
            AccessContext::Pairing(_) => {
                return Err(AuthenticationCommitError::Rollback(invalid_grant()));
            }
        }
        Ok(())
    }

    pub(super) async fn register_machine(
        &self,
        request: RegisterMachine,
    ) -> Result<MachineRecord, StoreError> {
        let retry = request.clone();
        match self
            .store
            .register_machine_authorized(&self.owner, request)
            .await
        {
            Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => self
                .store
                .register_machine_authorized(&self.owner, retry)
                .await
                .map_err(|_| unknown),
            result => result,
        }
    }

    pub(super) async fn seed_enrollment_code(
        &self,
        request: EnrollmentCodeSeed,
    ) -> Result<(), StoreError> {
        self.store.seed_enrollment_code(request).await
    }

    pub(super) async fn purge_machine_admin(
        &self,
        request: PurgeMachine,
    ) -> Result<PurgeReadback, StoreError> {
        let retry = request.clone();
        match self
            .store
            .purge_machine_authorized(&self.owner, request)
            .await
        {
            Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => self
                .store
                .purge_machine_authorized(&self.owner, retry)
                .await
                .map_err(|_| unknown),
            result => result,
        }
    }

    pub(super) async fn prepare_install_grant(
        &self,
        grant: RelayGrant,
    ) -> Result<InstallGrantRecord, RelayFailure> {
        let machine = self
            .store
            .machine_trust(grant.machine_route)
            .await
            .map_err(map_store_error)?;
        verify_machine_root_object(
            &machine,
            grant.root_key_id,
            grant.trust_epoch,
            &grant.to_be_signed_v1(machine.relay_server_id, sha256(&machine.root_pubkey.0)),
            grant.signature,
        )?;
        Ok(InstallGrantRecord {
            grant_hash: grant.canonical_sha256(),
            grant,
        })
    }

    pub(super) async fn prepare_revocation(
        &self,
        revocation: DeviceRevocation,
    ) -> Result<PersistRevocation, RelayFailure> {
        let machine = self
            .store
            .machine_trust(revocation.machine_route)
            .await
            .map_err(map_store_error)?;
        verify_machine_root_object(
            &machine,
            revocation.root_key_id,
            revocation.trust_epoch,
            &revocation.to_be_signed_v1(machine.relay_server_id, sha256(&machine.root_pubkey.0)),
            revocation.signature,
        )?;
        let revocation_hash = revocation.canonical_sha256();
        let terminal = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
                device_route: revocation.device_route,
                grant_serial: revocation.grant_serial,
                signed_revocation: revocation.clone(),
            }),
        };
        Ok(PersistRevocation {
            revocation,
            revocation_hash,
            signed_revocation_blob: encode(&terminal),
        })
    }

    pub(super) async fn prepare_retirement(
        &self,
        retirement: RetireMachine,
    ) -> Result<PersistRetirement, RelayFailure> {
        let machine = self
            .store
            .machine_trust(retirement.machine_route)
            .await
            .map_err(map_store_error)?;
        verify_machine_root_object(
            &machine,
            retirement.root_key_id,
            retirement.trust_epoch,
            &retirement.to_be_signed_v1(machine.relay_server_id, sha256(&machine.root_pubkey.0)),
            retirement.signature,
        )?;
        let retirement_hash = retirement.canonical_sha256();
        let terminal = OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
                machine_route: retirement.machine_route,
                trust_epoch: retirement.trust_epoch,
                retire_hash: retirement_hash,
            }),
        };
        Ok(PersistRetirement {
            retirement,
            retirement_hash,
            retirement_terminal_blob: encode(&terminal),
        })
    }

    pub(super) async fn install_grant(
        &self,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        let retry = request.clone();
        match self
            .store
            .install_grant_authorized(&self.owner, request)
            .await
        {
            Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => {
                match self
                    .store
                    .install_grant_authorized(&self.owner, retry)
                    .await
                {
                    Ok(mut commit) => {
                        // 第一次 COMMIT 可能已经提升 grant；即使精确重试读回 duplicate，
                        // coordinator 也必须按 mutation 失效旧 device generation。
                        commit.duplicate = false;
                        Ok(commit)
                    }
                    Err(_) => Err(unknown),
                }
            }
            result => result,
        }
    }

    pub(super) async fn revoke(
        &self,
        request: PersistRevocation,
    ) -> Result<RevocationCommit, StoreError> {
        let retry = request.clone();
        match self.store.revoke_authorized(&self.owner, request).await {
            Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => self
                .store
                .revoke_authorized(&self.owner, retry)
                .await
                .map_err(|_| unknown),
            result => result,
        }
    }

    pub(super) async fn retire_machine(
        &self,
        request: PersistRetirement,
    ) -> Result<RetirementCommit, StoreError> {
        let retry = request.clone();
        match self
            .store
            .retire_machine_authorized(&self.owner, request)
            .await
        {
            Err(unknown @ StoreError::CommitOutcomeUnknown { .. }) => self
                .store
                .retire_machine_authorized(&self.owner, retry)
                .await
                .map_err(|_| unknown),
            result => result,
        }
    }
}

fn verify_machine_root_object(
    machine: &MachineTrustView,
    root_key_id: agentdeck_protocol::relay_v2::RootKeyId,
    trust_epoch: agentdeck_protocol::relay_v2::TrustEpoch,
    tbs: &agentdeck_protocol::e2ee::ToBeSignedV1,
    signature: agentdeck_protocol::relay_v2::Ed25519Signature,
) -> Result<(), RelayFailure> {
    if machine.retired || root_key_id != machine.root_key_id || trust_epoch != machine.trust_epoch {
        return Err(invalid_grant());
    }
    verify_tbs(
        &verifying_key(machine.root_pubkey.0)?,
        tbs,
        &SignatureBytes::from(signature),
    )
    .map_err(|_| invalid_grant())
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
