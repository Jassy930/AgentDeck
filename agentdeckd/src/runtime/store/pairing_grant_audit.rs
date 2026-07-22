//! grant/auth/key-directory/outbox 的全库 authenticated consistency audit。

use super::*;

pub(in crate::runtime::store) fn validate_authorization_histories(
    authorizations: &[AuthenticatedAuthorization],
) -> Result<(), RuntimeStoreError> {
    let mut fingerprint_routes = HashMap::<[u8; 32], [u8; 16]>::new();
    let mut start = 0_usize;
    while start < authorizations.len() {
        let route = authorizations[start].device_route;
        let mut end = start + 1;
        while end < authorizations.len() && authorizations[end].device_route == route {
            end += 1;
        }
        let history = &authorizations[start..end];
        let fingerprint = history[0].device_sign_fingerprint;
        if history.iter().any(|authorization| {
            authorization.device_sign_fingerprint != fingerprint
                || authorization.device_route != route
        }) || fingerprint_routes
            .insert(fingerprint, *route.as_bytes())
            .is_some_and(|existing| existing != *route.as_bytes())
            || history
                .windows(2)
                .any(|pair| pair[0].grant_serial.value() >= pair[1].grant_serial.value())
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let (latest, superseded) = history
            .split_last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if superseded
            .iter()
            .any(|authorization| authorization.lifecycle != AuthorizationLifecycle::Superseded)
            || !matches!(
                latest.lifecycle,
                AuthorizationLifecycle::GrantPreparing
                    | AuthorizationLifecycle::Active
                    | AuthorizationLifecycle::Revoking
                    | AuthorizationLifecycle::Revoked
            )
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        start = end;
    }
    Ok(())
}

pub(in crate::runtime::store) fn authenticate_grant_directory(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    pairings: &[AuthenticatedPairingRow],
    terminal: &super::super::pairing_terminal::AuthenticatedTerminalDirectory,
    ledger: &RuntimeLedger,
) -> Result<AuthenticatedGrantDirectory, RuntimeStoreError> {
    let authorizations = load_authorizations(connection, key_bundle, database_id)?;
    let global = load_global_key_state(connection, key_bundle, database_id)?;
    let installs = load_install_outboxes(connection, key_bundle, database_id)?;
    let revocations = load_revocation_outboxes(connection, key_bundle, database_id)?;
    let directory = AuthenticatedGrantDirectory {
        authorizations,
        global,
        installs,
        revocations,
    };
    if directory.authorization_count() != ledger.remote_authorization_count
        || directory.authorization_preparing_count() != ledger.remote_authorization_preparing_count
        || directory.authorization_active_count() != ledger.remote_authorization_active_count
        || directory.authorization_revoking_count() != ledger.remote_authorization_revoking_count
        || directory.authorization_revoked_count() != ledger.remote_authorization_revoked_count
        || directory.authorization_bytes() != ledger.remote_authorization_sealed_bytes
        || directory.key_state_count() != ledger.remote_key_directory_count
        || directory.key_state_bytes() != ledger.remote_key_directory_sealed_bytes
        || directory.authorization_count() > MAX_AUTHORIZATIONS
        || directory.authorization_bytes() > MAX_AUTHORIZATION_SEALED_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if directory.authorizations.is_empty() {
        if directory.global.is_some()
            || !directory.installs.is_empty()
            || !directory.revocations.is_empty()
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(directory);
    }
    let global = directory
        .global
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authorization_routes = directory
        .authorizations
        .iter()
        .map(|authorization| *authorization.device_route.as_bytes())
        .collect::<HashSet<_>>();
    if global.state.devices.len() != authorization_routes.len()
        || global.state.revision != global.revision
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let active = super::super::machine_remote::machine_authority_for_integrity(
        connection,
        key_bundle,
        database_id,
    )?;
    validate_authorization_histories(&directory.authorizations)?;
    for authorization in &directory.authorizations {
        validate_durable_authorization(authorization, global, &active)?;
        match authorization.lifecycle {
            AuthorizationLifecycle::GrantPreparing
            | AuthorizationLifecycle::Active
            | AuthorizationLifecycle::Superseded
                if authorization.revocation.is_none()
                    && authorization.revocation_hash.is_none()
                    && authorization.canonical_revocation_frame.is_none()
                    && authorization.sealed_revocation_bytes.is_none() => {}
            AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked => {
                let revocation = authorization
                    .revocation
                    .as_ref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                validate_revocation_signature(authorization, revocation, &active)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
                if revocation.canonical_sha256()
                    != authorization
                        .revocation_hash
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                    || authorization.canonical_revocation_frame.is_none()
                    || authorization.sealed_revocation_bytes.is_none()
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
    let mut matched_authorizations = HashSet::new();
    let mut matched_installs = HashSet::new();
    for pairing in pairings.iter().filter(|pairing| {
        matches!(
            pairing.record.lifecycle,
            PairingInviteLifecycle::GrantPreparing
                | PairingInviteLifecycle::GrantCommitted
                | PairingInviteLifecycle::Delivered
                | PairingInviteLifecycle::OrphanRevoking
        ) || (pairing.record.lifecycle == PairingInviteLifecycle::Expired
            && pairing.record.grant_hash.is_some())
            || (pairing.record.lifecycle == PairingInviteLifecycle::Canceled
                && pairing.record.grant_hash.is_some())
    }) {
        if !matches!(
            terminal.receipt_value(pairing.record.pairing_id),
            Some(PairingReceipt::Confirmed { pairing_id })
                if pairing_id.as_str() == pairing.record.pairing_id.to_canonical_string()
        ) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let grant_hash = pairing
            .record
            .grant_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let response_hash = pairing
            .record
            .response_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let (grant, observed_grant_hash) = exact_install_frame(
            pairing
                .record
                .canonical_install_frame
                .as_deref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        if observed_grant_hash != grant_hash
            || pairing.record.canonical_relay_grant.as_deref()
                != Some(grant.canonical_bytes().as_slice())
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let authorization = directory
            .authorizations
            .iter()
            .find(|authorization| {
                authorization.device_route == grant.device_route
                    && authorization.grant_serial == grant.grant_serial
            })
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let expected_authorization_lifecycle = match pairing.record.lifecycle {
            PairingInviteLifecycle::GrantPreparing => AuthorizationLifecycle::GrantPreparing,
            PairingInviteLifecycle::GrantCommitted => AuthorizationLifecycle::Active,
            PairingInviteLifecycle::Delivered
                if matches!(
                    authorization.lifecycle,
                    AuthorizationLifecycle::Active
                        | AuthorizationLifecycle::Superseded
                        | AuthorizationLifecycle::Revoking
                        | AuthorizationLifecycle::Revoked
                ) =>
            {
                authorization.lifecycle
            }
            PairingInviteLifecycle::OrphanRevoking => AuthorizationLifecycle::Revoking,
            PairingInviteLifecycle::Expired | PairingInviteLifecycle::Canceled => {
                AuthorizationLifecycle::Revoked
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let timestamps_match = match pairing.record.lifecycle {
            PairingInviteLifecycle::GrantPreparing | PairingInviteLifecycle::GrantCommitted => {
                pairing.record.state_changed_at_ms == authorization.state_changed_at_ms
            }
            PairingInviteLifecycle::Delivered
                if authorization.lifecycle == AuthorizationLifecycle::Active =>
            {
                pairing.record.state_changed_at_ms >= authorization.state_changed_at_ms
            }
            PairingInviteLifecycle::Delivered => {
                authorization.state_changed_at_ms >= pairing.record.state_changed_at_ms
            }
            PairingInviteLifecycle::OrphanRevoking
            | PairingInviteLifecycle::Expired
            | PairingInviteLifecycle::Canceled => {
                pairing.record.state_changed_at_ms == authorization.state_changed_at_ms
            }
            _ => false,
        };
        if !matched_authorizations.insert((
            *authorization.device_route.as_bytes(),
            authorization.grant_serial.value(),
        )) || authorization.lifecycle != expected_authorization_lifecycle
            || !timestamps_match
            || authorization.grant_hash != grant_hash
            || authorization.canonical_relay_grant.as_slice()
                != pairing
                    .record
                    .canonical_relay_grant
                    .as_deref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            || authorization.canonical_install_frame.as_slice()
                != pairing
                    .record
                    .canonical_install_frame
                    .as_deref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            || authorization.authorization_hash
                != authorization
                    .authorization
                    .canonical_sha256()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            || authorization.device_sign_fingerprint
                != pairing
                    .record
                    .device_sign_fingerprint
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            || pairing
                .record
                .canonical_device_authorization
                .as_ref()
                .map(SecretBytes::expose_secret)
                != Some(authorization.canonical_authorization.expose_secret())
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let install = directory.installs.iter().find(|install| {
            install.device_route == grant.device_route && install.grant_serial == grant.grant_serial
        });
        match pairing.record.lifecycle {
            PairingInviteLifecycle::GrantPreparing => {
                let install = install.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                if !matched_installs.insert(*install.outbox_id.as_bytes())
                    || pairing.record.state_changed_at_ms != install.created_at_ms
                    || pairing.record.state_changed_at_ms != authorization.created_at_ms
                    || pairing.record.canonical_install_frame.as_deref()
                        != Some(install.canonical_frame.as_slice())
                    || install.grant.canonical_sha256() != grant_hash
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            PairingInviteLifecycle::GrantCommitted | PairingInviteLifecycle::Delivered => {
                if install.is_some()
                    || authorization.created_at_ms > authorization.state_changed_at_ms
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            PairingInviteLifecycle::OrphanRevoking => {
                if let Some(install) = install
                    && (!matched_installs.insert(*install.outbox_id.as_bytes())
                        || pairing.record.canonical_install_frame.as_deref()
                            != Some(install.canonical_frame.as_slice())
                        || install.grant.canonical_sha256() != grant_hash)
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            PairingInviteLifecycle::Expired | PairingInviteLifecycle::Canceled => {
                if install.is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
        let key_directory = KeyDirectoryV1::from_canonical_bytes(
            pairing
                .record
                .canonical_key_directory_view
                .as_ref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .expose_secret(),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let response = PairResponseV1::from_canonical_bytes(
            pairing
                .record
                .canonical_pair_response
                .as_ref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .expose_secret(),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        // PairResponse 中的 bootstrap directory 是不可变历史证据；成员轮换只推进
        // authenticated authorization ledger 的 current revision，不能重签旧 response。
        if key_directory.revision.value() > authorization.key_directory_revision
            || response.canonical_sha256().ok() != Some(response_hash)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        verify_materials(
            pairing,
            &grant,
            &authorization.authorization,
            &key_directory,
            &response,
            &global.state,
            &active,
            authorization.lifecycle != AuthorizationLifecycle::Superseded,
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    let mut matched_revocations = HashSet::new();
    for authorization in &directory.authorizations {
        let revoke = directory.revocations.iter().find(|revoke| {
            revoke.device_route == authorization.device_route
                && revoke.grant_serial == authorization.grant_serial
        });
        match authorization.lifecycle {
            AuthorizationLifecycle::Revoking => {
                let revoke = revoke.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
                if !matched_revocations.insert(*revoke.outbox_id.as_bytes())
                    || Some(revoke.revocation_hash) != authorization.revocation_hash
                    || Some(revoke.canonical_frame.as_slice())
                        != authorization.canonical_revocation_frame.as_deref()
                    || authorization.revocation.as_ref() != Some(&revoke.revocation)
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            AuthorizationLifecycle::GrantPreparing
            | AuthorizationLifecycle::Active
            | AuthorizationLifecycle::Superseded
            | AuthorizationLifecycle::Revoked => {
                if revoke.is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
        }
    }
    let grant_pairing_count = pairings
        .iter()
        .filter(|pairing| {
            matches!(
                pairing.record.lifecycle,
                PairingInviteLifecycle::GrantPreparing
                    | PairingInviteLifecycle::GrantCommitted
                    | PairingInviteLifecycle::Delivered
                    | PairingInviteLifecycle::OrphanRevoking
            ) || (pairing.record.lifecycle == PairingInviteLifecycle::Expired
                && pairing.record.grant_hash.is_some())
                || (pairing.record.lifecycle == PairingInviteLifecycle::Canceled
                    && pairing.record.grant_hash.is_some())
        })
        .count();
    if grant_pairing_count != matched_authorizations.len()
        || matched_installs.len() != directory.installs.len()
        || matched_revocations.len() != directory.revocations.len()
        || directory.authorizations.iter().any(|authorization| {
            !matched_authorizations.contains(&(
                *authorization.device_route.as_bytes(),
                authorization.grant_serial.value(),
            )) && authorization.lifecycle == AuthorizationLifecycle::GrantPreparing
        })
        || global.state.devices.iter().any(|device| {
            !directory
                .authorizations
                .iter()
                .any(|authorization| authorization.device_route == device.device_route)
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(directory)
}
