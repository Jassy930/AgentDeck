//! 本机确认后、durable CAS 前的 DeviceGrant 冻结边界。
//!
//! 本模块只在内存中生成并验证一组不可变的 grant artifacts；它不写 Store、不发送
//! `InstallGrant`，也不推进 pairing lifecycle。production 入口只使用可失败 OS 熵，测试入口
//! 才允许注入固定熵源。

use std::fmt;

use agentdeck_crypto::{
    HpkePublicKey, SecretAeadKey, SignatureBytes, VerifyingKey, sha256,
    verify_device_authorization, verify_key_directory, verify_pair_response_envelope, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectorySignatureContextV1,
    KeyDirectoryV1, KeyPurpose, KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1,
    OuterFrameKind, PairInviteV1, PairRequestPlaintextV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseV1,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision, LinkGeneration,
    MachineRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayGrant, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::runtime::store::pairing_grant::{
    ConfirmPairingGrant, GlobalKeyStateV1, PairingGrantPreparation,
};
use crate::runtime::store::{GrantAllocationProjection, RuntimeId};
use crate::security::SecretBytes;

use super::bootstrap::validate_pairing_device_sign_key;
use super::transport::{PairingInviteAnchor, PairingMachineAuthority, RemoteTransportError};

const ENTROPY_ATTEMPTS: usize = 8;
const FIRST_KEY_EPOCH: u64 = 1;

/// Grant freeze 的稳定、无敏感材料 failure taxonomy。
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum GrantFreezeError {
    #[error("authenticated pairing request is not valid for grant freeze")]
    InvalidFrozenRequest,
    #[error("pairing grant authority does not match the frozen invite")]
    AuthorityMismatch,
    #[error("pairing grant serial is not the checked allocation serial")]
    InvalidGrantSerial,
    #[error("pairing grant allocation does not match the authenticated device history")]
    InvalidGrantAllocation,
    #[cfg(test)]
    #[error("the authenticated device route is revoked and cannot be reused")]
    GrantRouteRevoked,
    #[error("pairing grant serial reached u64::MAX and requires trust reset")]
    GrantSerialTrustResetRequired,
    #[error("key-directory revision is not the checked next revision")]
    InvalidKeyDirectoryRevision,
    #[error("operating-system entropy is unavailable")]
    EntropyUnavailable,
    #[error("grant cryptographic operation failed")]
    CryptoFailure,
    #[error("daemon global key state rejected the grant transition")]
    KeyStateConflict,
}

impl GrantFreezeError {
    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidFrozenRequest => "daemon.pairing.grant_request_invalid",
            Self::AuthorityMismatch => "daemon.pairing.grant_authority_mismatch",
            Self::InvalidGrantSerial => "daemon.pairing.grant_serial_invalid",
            Self::InvalidGrantAllocation => "daemon.pairing.grant_allocation_invalid",
            #[cfg(test)]
            Self::GrantRouteRevoked => "daemon.pairing.grant_route_revoked",
            Self::GrantSerialTrustResetRequired => {
                "daemon.pairing.grant_serial_trust_reset_required"
            }
            Self::InvalidKeyDirectoryRevision => "daemon.pairing.key_revision_invalid",
            Self::EntropyUnavailable => "daemon.pairing.entropy_unavailable",
            Self::CryptoFailure => "daemon.pairing.grant_crypto_failed",
            Self::KeyStateConflict => "daemon.pairing.key_state_conflict",
        }
    }
}

/// Store authenticated authorization history 的窄投影；不携带 key material。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrantAllocationState {
    NewFingerprint,
    #[cfg(test)]
    Active {
        device_route: DeviceRouteId,
        current_serial: GrantSerial,
    },
    #[cfg(test)]
    Revoked {
        device_route: DeviceRouteId,
        last_serial: GrantSerial,
    },
}

/// 绑定 DeviceSign fingerprint 的 checked grant route/serial allocation。
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct GrantAllocation {
    device_sign_fingerprint: [u8; 32],
    device_route: Option<DeviceRouteId>,
    previous_serial: Option<GrantSerial>,
    grant_serial: GrantSerial,
}

impl fmt::Debug for GrantAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantAllocation([REDACTED])")
    }
}

impl GrantAllocation {
    pub(crate) fn from_authenticated(
        device_sign_fingerprint: [u8; 32],
        state: GrantAllocationState,
    ) -> Result<Self, GrantFreezeError> {
        if device_sign_fingerprint == [0; 32] {
            return Err(GrantFreezeError::InvalidGrantAllocation);
        }
        let allocation = match state {
            GrantAllocationState::NewFingerprint => Self {
                device_sign_fingerprint,
                device_route: None,
                previous_serial: None,
                grant_serial: GrantSerial::ZERO
                    .next()
                    .map_err(|_| GrantFreezeError::InvalidGrantSerial)?,
            },
            #[cfg(test)]
            GrantAllocationState::Active {
                device_route,
                current_serial,
            } => Self {
                device_sign_fingerprint,
                device_route: Some(device_route),
                previous_serial: Some(current_serial),
                grant_serial: current_serial
                    .next()
                    .map_err(|_| GrantFreezeError::GrantSerialTrustResetRequired)?,
            },
            #[cfg(test)]
            GrantAllocationState::Revoked {
                device_route,
                last_serial,
            } => {
                if device_route.as_bytes() == &[0; 16] || last_serial.value() == 0 {
                    return Err(GrantFreezeError::InvalidGrantAllocation);
                }
                return Err(GrantFreezeError::GrantRouteRevoked);
            }
        };
        allocation.validate(device_sign_fingerprint)?;
        Ok(allocation)
    }

    fn from_projection(
        projection: GrantAllocationProjection,
    ) -> Result<(Self, Option<GlobalKeyStateV1>), GrantFreezeError> {
        let (allocation, current_global_keys) = match projection {
            GrantAllocationProjection::New {
                device_sign_fingerprint,
                current_global_keys,
            } => (
                Self::from_authenticated(
                    device_sign_fingerprint,
                    GrantAllocationState::NewFingerprint,
                )?,
                current_global_keys,
            ),
            GrantAllocationProjection::Renew {
                device_sign_fingerprint,
                device_route,
                current_serial,
                next_serial,
                current_global_keys,
            } => {
                let allocation = Self {
                    device_sign_fingerprint,
                    device_route: Some(device_route),
                    previous_serial: Some(current_serial),
                    grant_serial: next_serial,
                };
                allocation.validate(device_sign_fingerprint)?;
                (allocation, Some(current_global_keys))
            }
        };
        Ok((allocation, current_global_keys))
    }

    #[cfg(test)]
    fn fresh_candidate(device_sign_fingerprint: [u8; 32], grant_serial: GrantSerial) -> Self {
        Self {
            device_sign_fingerprint,
            device_route: None,
            previous_serial: None,
            grant_serial,
        }
    }

    fn validate(&self, expected_device_sign_fingerprint: [u8; 32]) -> Result<(), GrantFreezeError> {
        if self.device_sign_fingerprint == [0; 32]
            || self.device_sign_fingerprint != expected_device_sign_fingerprint
        {
            return Err(GrantFreezeError::InvalidGrantAllocation);
        }
        match (self.device_route, self.previous_serial) {
            (None, None) => {
                let first = GrantSerial::ZERO
                    .next()
                    .map_err(|_| GrantFreezeError::InvalidGrantSerial)?;
                if self.grant_serial != first {
                    return Err(GrantFreezeError::InvalidGrantSerial);
                }
            }
            (Some(device_route), Some(previous_serial)) => {
                if device_route.as_bytes() == &[0; 16] || previous_serial.value() == 0 {
                    return Err(GrantFreezeError::InvalidGrantAllocation);
                }
                let next = previous_serial
                    .next()
                    .map_err(|_| GrantFreezeError::GrantSerialTrustResetRequired)?;
                if self.grant_serial != next {
                    return Err(GrantFreezeError::InvalidGrantSerial);
                }
            }
            _ => return Err(GrantFreezeError::InvalidGrantAllocation),
        }
        Ok(())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn device_sign_fingerprint(&self) -> [u8; 32] {
        self.device_sign_fingerprint
    }

    #[must_use]
    pub(crate) const fn device_route(&self) -> Option<DeviceRouteId> {
        self.device_route
    }

    #[must_use]
    pub(crate) const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    #[must_use]
    const fn is_renewal(&self) -> bool {
        self.device_route.is_some()
    }
}

/// 单次 grant 的内存冻结器。它消费 optional global-key singleton，且故意不实现 Clone。
pub(crate) struct GrantFreezeBuilder<'a> {
    preparation: &'a PairingGrantPreparation,
    invite_anchor: &'a PairingInviteAnchor,
    authority: &'a PairingMachineAuthority,
    current_global_keys: Option<GlobalKeyStateV1>,
    allocation: GrantAllocation,
    next_key_directory_revision: KeyDirectoryRevision,
}

impl fmt::Debug for GrantFreezeBuilder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantFreezeBuilder([REDACTED])")
    }
}

impl<'a> GrantFreezeBuilder<'a> {
    pub(crate) fn from_projection(
        preparation: &'a PairingGrantPreparation,
        invite_anchor: &'a PairingInviteAnchor,
        authority: &'a PairingMachineAuthority,
        projection: GrantAllocationProjection,
    ) -> Result<Self, GrantFreezeError> {
        let expected_fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
        let (allocation, current_global_keys) = GrantAllocation::from_projection(projection)?;
        allocation.validate(expected_fingerprint)?;
        let current_revision = current_global_keys
            .as_ref()
            .map_or(KeyDirectoryRevision::ZERO, GlobalKeyStateV1::revision);
        let next_key_directory_revision = current_revision
            .next()
            .map_err(|_| GrantFreezeError::InvalidKeyDirectoryRevision)?;
        Ok(Self {
            preparation,
            invite_anchor,
            authority,
            current_global_keys,
            allocation,
            next_key_directory_revision,
        })
    }

    /// 使用可失败 OS 熵冻结完整 artifacts。任何错误都发生在 durable mutation 之前。
    pub(crate) fn freeze(self) -> Result<FrozenGrantArtifacts, GrantFreezeError> {
        let expected_anchor = AuthorityBinding::from_invite_anchor(self.invite_anchor);
        let authority = ProductionGrantAuthority {
            authority: self.authority,
        };
        let material = FrozenRequestMaterial {
            pairing_id: self.preparation.pairing_id(),
            invite: self.preparation.invite(),
            request_hash: self.preparation.request_hash(),
            request: self.preparation.request(),
        };
        freeze_with_allocation(
            material,
            expected_anchor,
            self.current_global_keys,
            self.allocation,
            self.next_key_directory_revision,
            &authority,
            |bytes| getrandom::fill(bytes).map_err(|_| GrantFreezeError::EntropyUnavailable),
        )
    }
}

/// 已冻结且可由 Store 再验证的 exact artifacts。秘密 key 只存在于 global key state；
/// Debug 不展开任何 route、hash、密文、授权或 key material。
pub(crate) struct FrozenGrantArtifacts {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    relay_grant: RelayGrant,
    device_authorization: DeviceAuthorizationV1,
    key_directory: KeyDirectoryV1,
    pair_response: PairResponseV1,
    global_key_state: GlobalKeyStateV1,
    #[cfg(test)]
    response_info: PairResponseInfoV1,
    #[cfg(test)]
    response_context: OuterContextV1,
    #[cfg(test)]
    grant_hash: [u8; 32],
    #[cfg(test)]
    authorization_hash: [u8; 32],
    #[cfg(test)]
    key_directory_hash: [u8; 32],
    #[cfg(test)]
    response_hash: [u8; 32],
}

impl fmt::Debug for FrozenGrantArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenGrantArtifacts([REDACTED])")
    }
}

impl FrozenGrantArtifacts {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn relay_grant(&self) -> &RelayGrant {
        &self.relay_grant
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn device_authorization(&self) -> &DeviceAuthorizationV1 {
        &self.device_authorization
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn key_directory(&self) -> &KeyDirectoryV1 {
        &self.key_directory
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn pair_response(&self) -> &PairResponseV1 {
        &self.pair_response
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn response_info(&self) -> &PairResponseInfoV1 {
        &self.response_info
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn response_context(&self) -> &OuterContextV1 {
        &self.response_context
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn grant_hash(&self) -> [u8; 32] {
        self.grant_hash
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn authorization_hash(&self) -> [u8; 32] {
        self.authorization_hash
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn key_directory_hash(&self) -> [u8; 32] {
        self.key_directory_hash
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }

    /// 消费 frozen bundle，直接形成 Store 的 typed confirm 输入；这里不执行事务。
    #[must_use]
    pub(crate) fn into_store_input(self) -> ConfirmPairingGrant {
        ConfirmPairingGrant::new(
            self.pairing_id,
            self.request_hash,
            self.relay_grant,
            self.device_authorization,
            self.key_directory,
            self.pair_response,
            self.global_key_state,
        )
    }
}

struct FrozenRequestMaterial<'a> {
    pairing_id: RuntimeId,
    invite: &'a PairInviteV1,
    request_hash: [u8; 32],
    request: &'a PairRequestPlaintextV1,
}

#[derive(Clone, Eq, PartialEq)]
struct AuthorityBinding {
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_public_key: PublicKeyBytes,
    root_fingerprint: [u8; 32],
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    data_generation: LinkGeneration,
    data_certificate: SignedCertificate,
}

impl AuthorityBinding {
    fn from_invite_anchor(anchor: &PairingInviteAnchor) -> Self {
        Self {
            relay_server_id: anchor.relay_server_id(),
            machine_route: anchor.machine_route(),
            root_public_key: anchor.root_public_key(),
            root_fingerprint: anchor.root_fingerprint(),
            root_key_id: anchor.root_key_id(),
            trust_epoch: anchor.trust_epoch(),
            data_generation: anchor.data_generation(),
            data_certificate: anchor.data_sign_certificate().clone(),
        }
    }
}

impl fmt::Debug for AuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityBinding([REDACTED])")
    }
}

trait GrantCryptographicAuthority {
    fn active_binding(&self) -> Result<AuthorityBinding, GrantFreezeError>;

    fn sign_relay_grant(&self, grant: RelayGrant) -> Result<RelayGrant, GrantFreezeError>;

    fn sign_device_authorization(
        &self,
        grant: &RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, GrantFreezeError>;

    fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, GrantFreezeError>;

    fn sign_key_directory(
        &self,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, GrantFreezeError>;

    fn seal_pair_response(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
    ) -> Result<PairResponseV1, GrantFreezeError>;
}

struct ProductionGrantAuthority<'a> {
    authority: &'a PairingMachineAuthority,
}

impl GrantCryptographicAuthority for ProductionGrantAuthority<'_> {
    fn active_binding(&self) -> Result<AuthorityBinding, GrantFreezeError> {
        self.authority
            .invite_anchor()
            .map(|anchor| AuthorityBinding::from_invite_anchor(&anchor))
            .map_err(|_| GrantFreezeError::AuthorityMismatch)
    }

    fn sign_relay_grant(&self, grant: RelayGrant) -> Result<RelayGrant, GrantFreezeError> {
        self.authority
            .sign_relay_grant(grant)
            .map_err(map_authority_error)
    }

    fn sign_device_authorization(
        &self,
        grant: &RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, GrantFreezeError> {
        self.authority
            .sign_device_authorization(grant, authorization)
            .map_err(map_authority_error)
    }

    fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, GrantFreezeError> {
        self.authority
            .seal_key_directory_entry(recipient, info, context, key)
            .map_err(map_authority_error)
    }

    fn sign_key_directory(
        &self,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, GrantFreezeError> {
        self.authority
            .sign_key_directory(context, directory)
            .map_err(map_authority_error)
    }

    fn seal_pair_response(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
    ) -> Result<PairResponseV1, GrantFreezeError> {
        self.authority
            .seal_pair_response(recipient, info, context, plaintext)
            .map_err(map_authority_error)
    }
}

fn map_authority_error(error: RemoteTransportError) -> GrantFreezeError {
    if matches!(&error, RemoteTransportError::PairingEntropyUnavailable) {
        GrantFreezeError::EntropyUnavailable
    } else if matches!(&error, RemoteTransportError::Closed)
        || error.code() == "remote.transport.pairing_authority_mismatch"
    {
        GrantFreezeError::AuthorityMismatch
    } else {
        GrantFreezeError::CryptoFailure
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn freeze_with<F>(
    material: FrozenRequestMaterial<'_>,
    expected_anchor: AuthorityBinding,
    current_global_keys: Option<GlobalKeyStateV1>,
    grant_serial: GrantSerial,
    next_revision: KeyDirectoryRevision,
    authority: &impl GrantCryptographicAuthority,
    entropy: F,
) -> Result<FrozenGrantArtifacts, GrantFreezeError>
where
    F: FnMut(&mut [u8]) -> Result<(), GrantFreezeError>,
{
    let allocation = GrantAllocation::fresh_candidate(
        sha256(&material.request.device_sign_pubkey.0),
        grant_serial,
    );
    freeze_with_allocation(
        material,
        expected_anchor,
        current_global_keys,
        allocation,
        next_revision,
        authority,
        entropy,
    )
}

#[allow(clippy::too_many_arguments)]
fn freeze_with_allocation<F>(
    material: FrozenRequestMaterial<'_>,
    expected_anchor: AuthorityBinding,
    current_global_keys: Option<GlobalKeyStateV1>,
    allocation: GrantAllocation,
    next_revision: KeyDirectoryRevision,
    authority: &impl GrantCryptographicAuthority,
    mut entropy: F,
) -> Result<FrozenGrantArtifacts, GrantFreezeError>
where
    F: FnMut(&mut [u8]) -> Result<(), GrantFreezeError>,
{
    let active_anchor = authority.active_binding()?;
    if active_anchor != expected_anchor {
        return Err(GrantFreezeError::AuthorityMismatch);
    }
    let recipient = validate_frozen_material(
        &material,
        &expected_anchor,
        current_global_keys.as_ref(),
        &allocation,
        next_revision,
    )?;

    let device_route = match allocation.device_route() {
        Some(device_route) => device_route,
        None => DeviceRouteId::from_bytes(random_nonzero(&mut entropy)?),
    };
    let grant_serial = allocation.grant_serial();
    let catalog_key = random_secret_key(&mut entropy)?;
    let command_key = random_secret_key_distinct(&mut entropy, &[&*catalog_key])?;
    let reply_key = random_secret_key_distinct(&mut entropy, &[&*catalog_key, &*command_key])?;

    let global_key_state = transition_global_key_state(
        current_global_keys,
        next_revision,
        device_route,
        catalog_key,
        command_key,
        reply_key,
        allocation.is_renewal(),
    )?;

    let relay_grant = authority.sign_relay_grant(RelayGrant {
        machine_route: expected_anchor.machine_route,
        device_route,
        device_sign_pubkey: material.request.device_sign_pubkey,
        grant_serial,
        root_key_id: expected_anchor.root_key_id,
        trust_epoch: expected_anchor.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    })?;

    let authorization_request = &material.request.authorization_request;
    let device_authorization = authority.sign_device_authorization(
        &relay_grant,
        DeviceAuthorizationV1 {
            format_version: E2EE_FORMAT_VERSION,
            grant_hash: relay_grant.canonical_sha256(),
            machine_route: relay_grant.machine_route,
            device_route: relay_grant.device_route,
            device_sign_fingerprint: sha256(&relay_grant.device_sign_pubkey.0),
            grant_serial: relay_grant.grant_serial,
            device_hpke_pubkey: material.request.device_hpke_pubkey,
            capabilities: authorization_request.capabilities.clone(),
            permissions: authorization_request.permissions.clone(),
            root_key_id: relay_grant.root_key_id,
            trust_epoch: relay_grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        },
    )?;

    let directory_context = KeyDirectorySignatureContextV1 {
        relay_server_id: expected_anchor.relay_server_id,
        machine_route: expected_anchor.machine_route,
        device_route,
        grant_serial,
        root_trust_epoch: expected_anchor.trust_epoch,
    };
    let mut entries = Vec::with_capacity(3);
    for view in global_key_state
        .bootstrap_view(device_route)
        .map_err(|_| GrantFreezeError::KeyStateConflict)?
    {
        let info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: expected_anchor.relay_server_id,
            machine_route: expected_anchor.machine_route,
            device_route,
            stream_route: None,
            grant_serial,
            root_trust_epoch: expected_anchor.trust_epoch,
            key_directory_revision: next_revision,
            key_purpose: view.purpose,
            key_epoch: view.epoch,
        };
        let context = key_update_context(&info);
        entries.push(authority.seal_key_directory_entry(&recipient, &info, &context, &view.key)?);
    }
    entries.sort_by_key(|entry| key_purpose_rank(entry.key_id.purpose));
    validate_bootstrap_entries(&entries, device_route)?;
    let key_directory = authority.sign_key_directory(
        &directory_context,
        KeyDirectoryV1 {
            revision: next_revision,
            entries,
            signature: Ed25519Signature([0; 64]),
        },
    )?;

    let invite_hash = material
        .invite
        .canonical_sha256()
        .map_err(|_| GrantFreezeError::InvalidFrozenRequest)?;
    let response_info = PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: expected_anchor.relay_server_id,
        pair_route: material.invite.pair_route,
        invite_hash,
        expiry_ms: material.invite.expires_at_ms,
        request_hash: material.request_hash,
        machine_route: expected_anchor.machine_route,
        device_route,
        grant_serial,
        root_trust_epoch: expected_anchor.trust_epoch,
    };
    let response_context = pairing_response_context(material.invite.pair_route);
    let pair_response = authority.seal_pair_response(
        &recipient,
        &response_info,
        &response_context,
        &PairResponsePlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            request_hash: material.request_hash,
            relay_grant: relay_grant.clone(),
            device_authorization: device_authorization.clone(),
            key_directory: key_directory.clone(),
        },
    )?;

    verify_frozen_outputs(
        &material,
        &expected_anchor,
        &relay_grant,
        &device_authorization,
        &directory_context,
        &key_directory,
        next_revision,
        &response_info,
        &response_context,
        &pair_response,
    )?;

    #[cfg(test)]
    let authorization_hash = device_authorization
        .canonical_sha256()
        .map_err(|_| GrantFreezeError::CryptoFailure)?;
    #[cfg(test)]
    let key_directory_hash = key_directory
        .canonical_sha256()
        .map_err(|_| GrantFreezeError::CryptoFailure)?;
    #[cfg(test)]
    let response_hash = pair_response
        .canonical_sha256()
        .map_err(|_| GrantFreezeError::CryptoFailure)?;
    #[cfg(test)]
    let grant_hash = relay_grant.canonical_sha256();

    Ok(FrozenGrantArtifacts {
        pairing_id: material.pairing_id,
        request_hash: material.request_hash,
        relay_grant,
        device_authorization,
        key_directory,
        pair_response,
        global_key_state,
        #[cfg(test)]
        response_info,
        #[cfg(test)]
        response_context,
        #[cfg(test)]
        grant_hash,
        #[cfg(test)]
        authorization_hash,
        #[cfg(test)]
        key_directory_hash,
        #[cfg(test)]
        response_hash,
    })
}

fn validate_frozen_material(
    material: &FrozenRequestMaterial<'_>,
    anchor: &AuthorityBinding,
    current_global_keys: Option<&GlobalKeyStateV1>,
    allocation: &GrantAllocation,
    next_revision: KeyDirectoryRevision,
) -> Result<HpkePublicKey, GrantFreezeError> {
    material
        .invite
        .validate_static()
        .map_err(|_| GrantFreezeError::InvalidFrozenRequest)?;
    material
        .request
        .validate()
        .map_err(|_| GrantFreezeError::InvalidFrozenRequest)?;
    if material.request_hash == [0; 32]
        || material.request.invite_secret != material.invite.invite_secret
    {
        return Err(GrantFreezeError::InvalidFrozenRequest);
    }
    if material.invite.relay_server_id != anchor.relay_server_id
        || material.invite.machine_root_pubkey != anchor.root_public_key
        || material.invite.machine_root_fingerprint != anchor.root_fingerprint
        || material.invite.data_sign_cert != anchor.data_certificate
        || material.invite.data_sign_cert.root_key_id != anchor.root_key_id
        || material.invite.data_sign_cert.trust_epoch != anchor.trust_epoch
        || material.invite.data_sign_cert.generation != anchor.data_generation
    {
        return Err(GrantFreezeError::AuthorityMismatch);
    }
    let root_verifier = VerifyingKey::from_bytes(&anchor.root_public_key.0)
        .map_err(|_| GrantFreezeError::AuthorityMismatch)?;
    verify_tbs(
        &root_verifier,
        &anchor.data_certificate.to_be_signed_v1(
            anchor.relay_server_id,
            anchor.machine_route,
            anchor.root_fingerprint,
        ),
        &SignatureBytes::from(anchor.data_certificate.signature),
    )
    .map_err(|_| GrantFreezeError::AuthorityMismatch)?;
    validate_pairing_device_sign_key(anchor.relay_server_id, material.request.device_sign_pubkey)
        .map_err(|_| GrantFreezeError::InvalidFrozenRequest)?;
    if material.request.device_hpke_pubkey.0 == [0; 32] {
        return Err(GrantFreezeError::InvalidFrozenRequest);
    }
    let recipient = HpkePublicKey::from_bytes(&material.request.device_hpke_pubkey.0)
        .map_err(|_| GrantFreezeError::InvalidFrozenRequest)?;

    allocation.validate(sha256(&material.request.device_sign_pubkey.0))?;
    let current_revision =
        current_global_keys.map_or(KeyDirectoryRevision::ZERO, GlobalKeyStateV1::revision);
    let expected_revision = current_revision
        .next()
        .map_err(|_| GrantFreezeError::InvalidKeyDirectoryRevision)?;
    if next_revision != expected_revision {
        return Err(GrantFreezeError::InvalidKeyDirectoryRevision);
    }
    Ok(recipient)
}

#[allow(clippy::too_many_arguments)]
fn verify_frozen_outputs(
    material: &FrozenRequestMaterial<'_>,
    anchor: &AuthorityBinding,
    grant: &RelayGrant,
    authorization: &DeviceAuthorizationV1,
    directory_context: &KeyDirectorySignatureContextV1,
    directory: &KeyDirectoryV1,
    expected_revision: KeyDirectoryRevision,
    response_info: &PairResponseInfoV1,
    response_context: &OuterContextV1,
    response: &PairResponseV1,
) -> Result<(), GrantFreezeError> {
    if grant.machine_route != anchor.machine_route
        || grant.device_route != response_info.device_route
        || grant.device_sign_pubkey != material.request.device_sign_pubkey
        || grant.grant_serial != response_info.grant_serial
        || grant.root_key_id != anchor.root_key_id
        || grant.trust_epoch != anchor.trust_epoch
        || authorization.device_hpke_pubkey != material.request.device_hpke_pubkey
        || authorization.capabilities != material.request.authorization_request.capabilities
        || authorization.permissions != material.request.authorization_request.permissions
        || directory.revision != expected_revision
    {
        return Err(GrantFreezeError::CryptoFailure);
    }
    authorization
        .validate_for_grant(grant)
        .map_err(|_| GrantFreezeError::CryptoFailure)?;
    directory
        .validate_bootstrap_for_device(grant.device_route)
        .map_err(|_| GrantFreezeError::CryptoFailure)?;

    let root_verifier = VerifyingKey::from_bytes(&anchor.root_public_key.0)
        .map_err(|_| GrantFreezeError::AuthorityMismatch)?;
    verify_tbs(
        &root_verifier,
        &grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(|_| GrantFreezeError::CryptoFailure)?;
    verify_device_authorization(&root_verifier, anchor.relay_server_id, grant, authorization)
        .map_err(|_| GrantFreezeError::CryptoFailure)?;

    let data_verifier = VerifyingKey::from_bytes(&anchor.data_certificate.subject_pubkey.0)
        .map_err(|_| GrantFreezeError::AuthorityMismatch)?;
    let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
        .map_err(|_| GrantFreezeError::AuthorityMismatch)?;
    verify_key_directory(&data_verifier, &signer, directory_context, directory)
        .map_err(|_| GrantFreezeError::CryptoFailure)?;
    verify_pair_response_envelope(
        &data_verifier,
        response_info,
        response_context,
        response,
        &signer,
    )
    .map_err(|_| GrantFreezeError::CryptoFailure)
}

fn transition_global_key_state(
    current: Option<GlobalKeyStateV1>,
    next_revision: KeyDirectoryRevision,
    device_route: DeviceRouteId,
    catalog_key: Zeroizing<[u8; 32]>,
    command_key: Zeroizing<[u8; 32]>,
    reply_key: Zeroizing<[u8; 32]>,
    renewal: bool,
) -> Result<GlobalKeyStateV1, GrantFreezeError> {
    let catalog_key = SecretBytes::new(catalog_key.as_ref().to_vec());
    let command_key = SecretBytes::new(command_key.as_ref().to_vec());
    let reply_key = SecretBytes::new(reply_key.as_ref().to_vec());
    let next = match (current, renewal) {
        (Some(current), true) => {
            current.renew_for_device(device_route, catalog_key, command_key, reply_key)
        }
        (Some(current), false) => {
            current.next_for_device(device_route, catalog_key, command_key, reply_key)
        }
        (None, true) => Err(crate::runtime::store::RuntimeStoreError::PairingConflict),
        (None, false) => GlobalKeyStateV1::bootstrap(
            next_revision.value(),
            FIRST_KEY_EPOCH,
            catalog_key,
            device_route,
            FIRST_KEY_EPOCH,
            command_key,
            FIRST_KEY_EPOCH,
            reply_key,
        ),
    }
    .map_err(|_| GrantFreezeError::KeyStateConflict)?;
    if next.revision() != next_revision {
        return Err(GrantFreezeError::InvalidKeyDirectoryRevision);
    }
    Ok(next)
}

fn random_nonzero<const N: usize>(
    entropy: &mut impl FnMut(&mut [u8]) -> Result<(), GrantFreezeError>,
) -> Result<[u8; N], GrantFreezeError> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let mut bytes = [0_u8; N];
        entropy(&mut bytes)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(GrantFreezeError::EntropyUnavailable)
}

fn random_secret_key(
    entropy: &mut impl FnMut(&mut [u8]) -> Result<(), GrantFreezeError>,
) -> Result<Zeroizing<[u8; 32]>, GrantFreezeError> {
    Ok(Zeroizing::new(random_nonzero(entropy)?))
}

fn random_secret_key_distinct(
    entropy: &mut impl FnMut(&mut [u8]) -> Result<(), GrantFreezeError>,
    prior: &[&[u8; 32]],
) -> Result<Zeroizing<[u8; 32]>, GrantFreezeError> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let candidate = random_secret_key(entropy)?;
        if prior.iter().all(|previous| candidate.as_ref() != *previous) {
            return Ok(candidate);
        }
    }
    Err(GrantFreezeError::EntropyUnavailable)
}

fn key_purpose_rank(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn validate_bootstrap_entries(
    entries: &[KeyDirectoryEntry],
    device_route: DeviceRouteId,
) -> Result<(), GrantFreezeError> {
    let expected = [
        KeyPurpose::Catalog,
        KeyPurpose::DeviceCommandTx,
        KeyPurpose::DeviceReplyTx,
    ];
    if entries.len() != expected.len()
        || entries.iter().zip(expected).any(|(entry, purpose)| {
            entry.key_id.purpose != purpose
                || entry.device_route != device_route
                || entry.stream_route.is_some()
        })
    {
        return Err(GrantFreezeError::CryptoFailure);
    }
    Ok(())
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

fn pairing_response_context(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

#[cfg(test)]
#[path = "grants_tests.rs"]
mod tests;
