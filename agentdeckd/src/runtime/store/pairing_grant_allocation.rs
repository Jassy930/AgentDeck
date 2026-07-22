//! 设备 grant serial 的 authenticated 只读分配与 confirm 二次校验。

use std::collections::HashSet;

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial, RelayGrant, StreamRouteId};
use rusqlite::Connection;

use crate::runtime::model::RuntimeStoreError;

use super::cipher::RuntimeKeyBundle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::{AuthenticatedPairingRow, PairingDirectory, PairingInviteLifecycle};
use super::pairing_authorization::{AuthenticatedAuthorization, AuthorizationLifecycle};
use super::pairing_grant::{AuthenticatedGrantDirectory, GlobalKeyStateV1};

/// Coordinator 只能消费、不能自行构造的 authenticated serial allocation 投影。
#[derive(Debug)]
pub(crate) enum GrantAllocationProjection {
    New {
        device_sign_fingerprint: [u8; 32],
        current_global_keys: Option<GlobalKeyStateV1>,
        /// 完整 authenticated publication directory 中的 active conversation routes。
        active_conversation_routes: Vec<StreamRouteId>,
    },
    Renew {
        device_sign_fingerprint: [u8; 32],
        device_route: DeviceRouteId,
        current_serial: GrantSerial,
        next_serial: GrantSerial,
        current_global_keys: GlobalKeyStateV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ValidatedGrantAllocation {
    New,
    Renew {
        device_route: DeviceRouteId,
        previous_serial: GrantSerial,
        next_serial: GrantSerial,
    },
}

pub(super) fn checked_next_serial(current: GrantSerial) -> Result<GrantSerial, RuntimeStoreError> {
    current
        .value()
        .checked_add(1)
        .map(GrantSerial::new)
        .ok_or(RuntimeStoreError::GrantSerialTrustResetRequired)
}

impl ValidatedGrantAllocation {
    #[must_use]
    pub(super) const fn is_renewal(self) -> bool {
        matches!(self, Self::Renew { .. })
    }
}

fn pairing_fingerprint(
    pairing: &AuthenticatedPairingRow,
    pairing_id: RuntimeId,
    expected_fingerprint: [u8; 32],
) -> Result<[u8; 32], RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    let fingerprint = pairing
        .record
        .device_sign_fingerprint
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if pairing.record.pairing_id != pairing_id
        || pairing.record.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation
        || pairing.record.request_hash.is_none()
        || fingerprint == [0; 32]
        || fingerprint != expected_fingerprint
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(fingerprint)
}

fn matching_history(
    grants: &AuthenticatedGrantDirectory,
    fingerprint: [u8; 32],
) -> Vec<&AuthenticatedAuthorization> {
    grants
        .authorizations
        .iter()
        .filter(|authorization| authorization.device_sign_fingerprint == fingerprint)
        .collect()
}

fn classify_authenticated(
    grants: &AuthenticatedGrantDirectory,
    pairings: &[AuthenticatedPairingRow],
    fingerprint: [u8; 32],
) -> Result<ValidatedGrantAllocation, RuntimeStoreError> {
    if fingerprint == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let history = matching_history(grants, fingerprint);
    if history.is_empty() {
        return Ok(ValidatedGrantAllocation::New);
    }
    let routes = history
        .iter()
        .map(|authorization| *authorization.device_route.as_bytes())
        .collect::<HashSet<_>>();
    if routes.len() != 1 {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if history.iter().any(|authorization| {
        matches!(
            authorization.lifecycle,
            AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked
        )
    }) {
        return Err(RuntimeStoreError::GrantRouteRevoked);
    }
    let mut active = history
        .iter()
        .copied()
        .filter(|authorization| authorization.lifecycle == AuthorizationLifecycle::Active);
    let current = active.next().ok_or(RuntimeStoreError::PairingConflict)?;
    if active.next().is_some()
        || history.iter().any(|authorization| {
            !matches!(
                authorization.lifecycle,
                AuthorizationLifecycle::Active | AuthorizationLifecycle::Superseded
            )
        })
        || history
            .iter()
            .any(|authorization| authorization.grant_serial > current.grant_serial)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if pairings.iter().any(|pairing| {
        pairing.record.grant_hash == Some(current.grant_hash)
            && pairing.record.lifecycle != PairingInviteLifecycle::Delivered
    }) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let next_serial = checked_next_serial(current.grant_serial)?;
    Ok(ValidatedGrantAllocation::Renew {
        device_route: current.device_route,
        previous_serial: current.grant_serial,
        next_serial,
    })
}

fn pairing(
    directory: &PairingDirectory,
    pairing_id: RuntimeId,
) -> Result<&AuthenticatedPairingRow, RuntimeStoreError> {
    directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)
}

pub(crate) fn load_grant_allocation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing_id: RuntimeId,
    device_sign_fingerprint: [u8; 32],
) -> Result<GrantAllocationProjection, RuntimeStoreError> {
    let mut directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let publication_ledger =
        super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let mut active_conversation_routes = super::publication::authenticate_directory_records(
        connection,
        key_bundle,
        &publication_ledger,
    )?
    .into_iter()
    .filter_map(|stream| {
        (stream.state == super::publication::PublicationStreamState::Active).then_some(stream)
    })
    .filter_map(|stream| match stream.scope {
        super::publication::PublicationScope::Catalog => None,
        super::publication::PublicationScope::Conversation(_) => {
            Some(StreamRouteId::from_bytes(stream.stream_route))
        }
    })
    .collect::<Vec<_>>();
    active_conversation_routes.sort_by_key(|route| *route.as_bytes());
    if active_conversation_routes
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let authenticated_fingerprint = pairing_fingerprint(
        pairing(&directory, pairing_id)?,
        pairing_id,
        device_sign_fingerprint,
    )?;
    let allocation = classify_authenticated(
        &directory.grants,
        &directory.pairings,
        authenticated_fingerprint,
    )?;
    let current_global_keys = directory.grants.global.take().map(|global| global.state);
    if current_global_keys
        .as_ref()
        .is_some_and(|global| global.active_conversation_routes() != active_conversation_routes)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    match allocation {
        ValidatedGrantAllocation::New => Ok(GrantAllocationProjection::New {
            device_sign_fingerprint: authenticated_fingerprint,
            current_global_keys,
            active_conversation_routes,
        }),
        ValidatedGrantAllocation::Renew {
            device_route,
            previous_serial,
            next_serial,
        } => Ok(GrantAllocationProjection::Renew {
            device_sign_fingerprint: authenticated_fingerprint,
            device_route,
            current_serial: previous_serial,
            next_serial,
            current_global_keys: current_global_keys
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        }),
    }
}

pub(super) fn validate_confirm_allocation(
    pairing: &AuthenticatedPairingRow,
    pairings: &[AuthenticatedPairingRow],
    grants: &AuthenticatedGrantDirectory,
    grant: &RelayGrant,
) -> Result<ValidatedGrantAllocation, RuntimeStoreError> {
    let fingerprint = pairing
        .record
        .device_sign_fingerprint
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if fingerprint == [0; 32] || sha256(&grant.device_sign_pubkey.0) != fingerprint {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let allocation = classify_authenticated(grants, pairings, fingerprint)?;
    match allocation {
        ValidatedGrantAllocation::New => {
            if grant.device_route.as_bytes() == &[0; 16]
                || grant.grant_serial.value() != 1
                || grants
                    .authorizations
                    .iter()
                    .any(|authorization| authorization.device_route == grant.device_route)
                || grants
                    .global
                    .as_ref()
                    .is_some_and(|global| global.state.contains_device_route(grant.device_route))
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
        ValidatedGrantAllocation::Renew {
            device_route,
            previous_serial: _,
            next_serial,
        } => {
            if grant.device_route != device_route || grant.grant_serial != next_serial {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
    }
    Ok(allocation)
}
