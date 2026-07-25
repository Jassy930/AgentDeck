//! Active key transition 的 Store-owned authenticated material projection。
//!
//! 本模块只依赖 Store/protocol 类型，不依赖 `crate::remote::*`。它在同一 blocking
//! worker 上认证 transition、ADGK2、machine identity/enrollment 与 authorization
//! ledger 后生成可持有 DTO；Remote coordinator 不得自行拼接这些轴。

use std::sync::Arc;

use agentdeck_protocol::e2ee::DeviceAuthorizationV1;
use agentdeck_protocol::relay_v2::{
    KeyDirectoryRevision, MachineRouteId, RelayGrant, RelayServerId, RootKeyId, TrustEpoch,
};
use rusqlite::{Connection, Transaction};

use crate::runtime::model::{
    MachineEnrollmentState, MachineIdentityLifecycle, RuntimeStoreConfig, RuntimeStoreError,
};

use super::cipher::RuntimeKeyBundle;
use super::key_transition::{
    KeyTransitionOperation, KeyTransitionPhase, KeyTransitionRecipient, KeyTransitionRecord,
    KeyTransitionRecovery, KeyTransitionStreamScope, KeyTransitionTarget,
};
use super::pairing_authorization::{AuthorizationLifecycle, load_authorizations};
use super::pairing_grant::{GlobalKeyStateV1, load_global_key_state};
use super::sqlite::RuntimeSqlite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionAnchorProjection {
    pub(crate) relay_server_id: RelayServerId,
    pub(crate) machine_route: MachineRouteId,
    pub(crate) root_key_id: RootKeyId,
    pub(crate) trust_epoch: TrustEpoch,
    pub(crate) machine_trust_domain: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransitionRecipientProjection {
    pub(crate) recipient: KeyTransitionRecipient,
    pub(crate) relay_grant: RelayGrant,
    pub(crate) authorization: DeviceAuthorizationV1,
    pub(crate) authorization_revision: KeyDirectoryRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionCatalogStreamProjection {
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
}

#[derive(Clone)]
pub(crate) struct TransitionMaterialProjection {
    pub(crate) recovery: KeyTransitionRecovery,
    pub(crate) global_keys: Arc<GlobalKeyStateV1>,
    pub(crate) anchor: TransitionAnchorProjection,
    pub(crate) recipients: Vec<TransitionRecipientProjection>,
    pub(crate) activation_catalog_stream: Option<TransitionCatalogStreamProjection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransitionCommittedCutProjection {
    pub(crate) scope: KeyTransitionStreamScope,
    pub(crate) publication_stream_id: [u8; 16],
    pub(crate) stream_route: [u8; 16],
    pub(crate) generation: [u8; 16],
    pub(crate) reserved_outer_cursor: Option<u64>,
    pub(crate) committed_outer_cursor: Option<u64>,
    pub(crate) committed_inner_cursor: Option<u64>,
}

struct ValidatedTransitionAuthorizations {
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
    recipients: Vec<TransitionRecipientProjection>,
}

/// `mark_key_barriers_committed` 的最后一道 durable authorization fence。
///
/// 参数刻意要求调用方持有现成 transaction，避免 coordinator 先前生成的 material
/// projection 与最终 phase mutation 分属两笔事务。所有 authorization rows、MachineRoot
/// 与 trust binding 都必须在写 transition/ledger 前重新认证。
pub(super) fn validate_transition_authorizations_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
) -> Result<(), RuntimeStoreError> {
    let _ = validate_transition_authorizations(transaction, key_bundle, database_id, transition)?;
    Ok(())
}

fn validate_transition_authorizations(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    transition: &KeyTransitionRecord,
) -> Result<ValidatedTransitionAuthorizations, RuntimeStoreError> {
    let identity =
        super::machine_identity::load_machine_identity_state(connection, key_bundle, database_id)?
            .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
    let remote =
        super::machine_remote::load_machine_enrollment_state(connection, key_bundle, database_id)?
            .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    let MachineEnrollmentState::Active(remote) = remote else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    let authorizations = load_authorizations(connection, key_bundle, database_id)?;

    let expected_binding_revision = match transition.phase {
        KeyTransitionPhase::DrainingOld => transition.from_revision,
        KeyTransitionPhase::RotatedPreparingUpdates
        | KeyTransitionPhase::UpdatesFrozen
        | KeyTransitionPhase::BarriersFrozen
        | KeyTransitionPhase::BarriersCommitted => transition.to_revision,
        KeyTransitionPhase::Complete => return Err(RuntimeStoreError::PublicationMismatch),
    };
    let binding = &identity.binding;
    if identity.lifecycle != MachineIdentityLifecycle::Active
        || binding.key_directory_revision != expected_binding_revision
        || remote.binding != *binding
        || remote.record.relay_server_id != *remote.connection.relay_server_id.as_bytes()
        || remote.record.machine_route == [0; 16]
        || remote.record.root_key_id != binding.root_key_id
        || remote.record.root_fingerprint != binding.root_fingerprint
        || remote.record.trust_epoch != binding.trust_epoch
        || binding.root_key_id == [0; 16]
        || binding.root_fingerprint == [0; 32]
        || binding.trust_epoch == 0
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let current = authorizations
        .iter()
        .filter(|authorization| {
            matches!(
                authorization.lifecycle,
                AuthorizationLifecycle::GrantPreparing | AuthorizationLifecycle::Active
            )
        })
        .collect::<Vec<_>>();
    let current_roster = current
        .iter()
        .map(|authorization| KeyTransitionRecipient {
            device_route: *authorization.device_route.as_bytes(),
            grant_serial: authorization.grant_serial.value(),
        })
        .collect::<Vec<_>>();
    if current_roster != transition.recipients {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let revision = KeyDirectoryRevision::new(transition.to_revision);
    let mut recipients = Vec::with_capacity(current.len());
    for (expected, authorization) in transition.recipients.iter().zip(current) {
        if authorization.key_directory_revision != revision.value()
            || authorization.device_route.as_bytes() != &expected.device_route
            || authorization.grant_serial.value() != expected.grant_serial
            || authorization.grant.machine_route
                != MachineRouteId::from_bytes(remote.record.machine_route)
            || authorization.grant.device_route != authorization.device_route
            || authorization.grant.grant_serial != authorization.grant_serial
            || authorization.grant.root_key_id != RootKeyId::from_bytes(binding.root_key_id)
            || authorization.grant.trust_epoch != TrustEpoch::new(binding.trust_epoch)
            || authorization
                .authorization
                .validate_for_grant(&authorization.grant)
                .is_err()
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        recipients.push(TransitionRecipientProjection {
            recipient: *expected,
            relay_grant: authorization.grant.clone(),
            authorization: authorization.authorization.clone(),
            authorization_revision: revision,
        });
    }

    Ok(ValidatedTransitionAuthorizations {
        relay_server_id: remote.connection.relay_server_id,
        machine_route: MachineRouteId::from_bytes(remote.record.machine_route),
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        recipients,
    })
}

pub(crate) fn load_transition_material_projection(
    state: &RuntimeSqlite,
    machine_trust_domain: [u8; 32],
) -> Result<Option<TransitionMaterialProjection>, RuntimeStoreError> {
    if machine_trust_domain == [0; 32] {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let Some(recovery) = super::key_transition::load_active_key_transition(state)? else {
        return Ok(None);
    };
    let global = load_global_key_state(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if recovery.transition.phase == KeyTransitionPhase::Complete
        || recovery.transition.terminal.is_some()
        || recovery.transition.to_revision == 0
        || recovery.transition.from_revision.checked_add(1) != Some(recovery.transition.to_revision)
        || global.revision != recovery.transition.to_revision
        || global.state.revision().value() != global.revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let validated = validate_transition_authorizations(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &recovery.transition,
    )?;

    let activation_catalog_stream =
        if recovery.transition.operation == KeyTransitionOperation::ActivateConversation {
            let ledger = super::sqlite::load_runtime_ledger(
                &state.connection,
                &state.key_bundle,
                state.database_id,
            )?;
            let streams = super::publication::authenticate_directory_records(
                &state.connection,
                &state.key_bundle,
                &ledger,
            )?;
            let mut catalog = streams.into_iter().filter(|stream| {
                stream.scope == super::publication::PublicationScope::Catalog
                    && matches!(
                        stream.state,
                        super::publication::PublicationStreamState::Active
                            | super::publication::PublicationStreamState::NeedsSnapshot
                    )
            });
            let stream = catalog
                .next()
                .ok_or(RuntimeStoreError::PublicationMismatch)?;
            if catalog.next().is_some() {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
            Some(TransitionCatalogStreamProjection {
                publication_stream_id: stream.publication_stream_id,
                stream_route: stream.stream_route,
                generation: stream.generation,
            })
        } else {
            None
        };

    Ok(Some(TransitionMaterialProjection {
        recovery,
        global_keys: Arc::new(global.state),
        anchor: TransitionAnchorProjection {
            relay_server_id: validated.relay_server_id,
            machine_route: validated.machine_route,
            root_key_id: validated.root_key_id,
            trust_epoch: validated.trust_epoch,
            machine_trust_domain,
        },
        recipients: validated.recipients,
        activation_catalog_stream,
    }))
}

pub(crate) fn load_transition_committed_cuts_projection(
    state: &RuntimeSqlite,
    operation_id: [u8; 16],
) -> Result<Vec<TransitionCommittedCutProjection>, RuntimeStoreError> {
    committed_cuts_from_required(load_required_transition_streams(state, operation_id)?)
}

/// Key transition 冻结 cut 前的唯一 generation-rollover seam。旧 outbox 必须先由
/// caller 驱动到 COMMIT+ACK；只有 ready snapshot 已认证覆盖 inner H 的
/// NeedsSnapshot stream 才能在这里原地 rotation。rotation 后重新认证 directory，
/// 返回的新 cut 必须绑定新 route/generation 与 `(BeforeFirst, H)`。
pub(crate) fn prepare_transition_committed_cuts_projection(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    operation_id: [u8; 16],
    now_ms: u64,
) -> Result<Vec<TransitionCommittedCutProjection>, RuntimeStoreError> {
    let required = load_required_transition_streams(state, operation_id)?;
    let rotations = required
        .iter()
        .filter(|(stream, _)| {
            stream.state == super::publication::PublicationStreamState::NeedsSnapshot
        })
        .map(
            |(stream, _)| super::publication::RotatePublicationStreamRequest {
                publication_stream_id: stream.publication_stream_id,
                expected_generation: stream.generation,
            },
        )
        .collect::<Vec<_>>();
    if rotations.is_empty() {
        return committed_cuts_from_required(required);
    }
    for request in rotations {
        super::publication::rotate_publication_stream(state, config, request, now_ms)?;
    }
    load_transition_committed_cuts_projection(state, operation_id)
}

fn load_required_transition_streams(
    state: &RuntimeSqlite,
    operation_id: [u8; 16],
) -> Result<
    Vec<(
        super::publication::PublicationStreamRecord,
        KeyTransitionStreamScope,
    )>,
    RuntimeStoreError,
> {
    let recovery = super::key_transition::load_active_key_transition(state)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if operation_id == [0; 16]
        || recovery.transition.operation_id != operation_id
        || recovery.transition.phase != KeyTransitionPhase::UpdatesFrozen
        || recovery.transition.terminal.is_some()
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let global = load_global_key_state(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if global.revision != recovery.transition.to_revision
        || global.state.revision().value() != global.revision
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }

    let counter_recovery_stream_route =
        match (recovery.transition.operation, recovery.transition.target) {
            (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(_)) => {
                return Ok(Vec::new());
            }
            (
                KeyTransitionOperation::CounterRecovery,
                KeyTransitionTarget::Conversation { stream_route, .. },
            ) => Some(stream_route),
            _ => None,
        };
    let required_routes = match recovery.transition.operation {
        KeyTransitionOperation::Renew => Vec::new(),
        KeyTransitionOperation::Add | KeyTransitionOperation::Revoke => {
            global.state.active_conversation_routes()
        }
        KeyTransitionOperation::ActivateConversation => return Ok(Vec::new()),
        KeyTransitionOperation::CounterRecovery => Vec::new(),
    };
    let ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    let streams = super::publication::authenticate_directory_records(
        &state.connection,
        &state.key_bundle,
        &ledger,
    )?;

    // 首个 remote device 加入前本机可以完全没有 publication stream；只有这种
    // authenticated empty directory 才是合法 zero-cut。只要存在 active/
    // NeedsSnapshot stream，就必须走下面的完整 Catalog + conversation cut 对账，
    // 不能再仅凭 recipients==target 跳过已有本机 history。
    let first_device_add = recovery.transition.operation == KeyTransitionOperation::Add
        && matches!(
            recovery.transition.target,
            KeyTransitionTarget::Device(target)
                if recovery.transition.recipients.as_slice() == [target]
        );
    if first_device_add && streams.is_empty() {
        return Ok(Vec::new());
    }

    if let Some(target_stream_route) = counter_recovery_stream_route {
        let stream = unique_current_stream(&streams, |stream| {
            stream.stream_route == target_stream_route
        })?;
        let scope = match stream.scope {
            super::publication::PublicationScope::Catalog => KeyTransitionStreamScope::Catalog,
            super::publication::PublicationScope::Conversation(conversation_id) => {
                KeyTransitionStreamScope::Conversation(*conversation_id.as_bytes())
            }
        };
        return Ok(vec![(stream.clone(), scope)]);
    }

    let mut required = Vec::with_capacity(required_routes.len() + 1);
    let catalog = unique_current_stream(&streams, |stream| {
        stream.scope == super::publication::PublicationScope::Catalog
    })?;
    required.push((catalog.clone(), KeyTransitionStreamScope::Catalog));
    for route in required_routes {
        let stream = unique_current_stream(&streams, |stream| {
            stream.stream_route == *route.as_bytes()
                && matches!(
                    stream.scope,
                    super::publication::PublicationScope::Conversation(_)
                )
        })?;
        let super::publication::PublicationScope::Conversation(conversation_id) = stream.scope
        else {
            unreachable!("conversation stream filtered above")
        };
        required.push((
            stream.clone(),
            KeyTransitionStreamScope::Conversation(*conversation_id.as_bytes()),
        ));
    }
    required.sort_by_key(|(stream, scope)| (*scope, stream.publication_stream_id));
    Ok(required)
}

fn unique_current_stream(
    streams: &[super::publication::PublicationStreamRecord],
    mut matches_target: impl FnMut(&super::publication::PublicationStreamRecord) -> bool,
) -> Result<&super::publication::PublicationStreamRecord, RuntimeStoreError> {
    let mut matches = streams.iter().filter(|stream| {
        stream.state != super::publication::PublicationStreamState::Retired
            && matches_target(stream)
    });
    let stream = matches
        .next()
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if matches.next().is_some() {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(stream)
}

fn committed_cuts_from_required(
    required: Vec<(
        super::publication::PublicationStreamRecord,
        KeyTransitionStreamScope,
    )>,
) -> Result<Vec<TransitionCommittedCutProjection>, RuntimeStoreError> {
    required
        .into_iter()
        .map(|(stream, scope)| {
            if stream.state != super::publication::PublicationStreamState::Active {
                return Err(RuntimeStoreError::PublicationNeedsSnapshot);
            }
            committed_cut(&stream, scope)
        })
        .collect()
}

fn committed_cut(
    stream: &super::publication::PublicationStreamRecord,
    scope: KeyTransitionStreamScope,
) -> Result<TransitionCommittedCutProjection, RuntimeStoreError> {
    let authenticated_rotation_baseline = stream.committed_high_water.is_none()
        && stream.committed_inner_cursor.is_some()
        && stream.acknowledged_high_water.is_none()
        && stream.acknowledged_inner_cursor == stream.committed_inner_cursor
        && stream.rotation_serial > 0
        && stream.last_rotation_request_digest.is_some();
    if stream.publication_stream_id == [0; 16]
        || stream.stream_route == [0; 16]
        || stream.generation == [0; 16]
        || stream.reserved_high_water != stream.committed_high_water
        // Relay outer 与 Runtime inner 是两个独立 cursor：control-only COMMIT
        // 合法产生 `(At(C), BeforeFirst)`。反向的 `(BeforeFirst, At(H))`
        // 只能来自上面完整认证过的 generation rotation baseline。
        || stream.committed_high_water.is_none()
            && stream.committed_inner_cursor.is_some()
            && !authenticated_rotation_baseline
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(TransitionCommittedCutProjection {
        scope,
        publication_stream_id: stream.publication_stream_id,
        stream_route: stream.stream_route,
        generation: stream.generation,
        reserved_outer_cursor: stream.reserved_high_water,
        committed_outer_cursor: stream.committed_high_water,
        committed_inner_cursor: stream.committed_inner_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication_stream_with_cuts(
        outer: Option<u64>,
        inner: Option<u64>,
    ) -> super::super::publication::PublicationStreamRecord {
        super::super::publication::PublicationStreamRecord {
            publication_stream_id: [0x11; 16],
            scope: super::super::publication::PublicationScope::Catalog,
            stream_route: [0x12; 16],
            generation: [0x13; 16],
            counter_scope_token: None,
            sender_counter_high_water: None,
            reserved_high_water: outer,
            committed_high_water: outer,
            committed_inner_cursor: inner,
            last_committed_blob_hash: outer.map(|_| [0x14; 32]),
            acknowledged_high_water: outer,
            acknowledged_inner_cursor: inner,
            last_acknowledged_blob_hash: outer.map(|_| [0x14; 32]),
            last_acknowledged_publication_id: outer.map(|_| [0x15; 16]),
            last_acknowledged_request_digest: outer.map(|_| [0x16; 32]),
            last_rotation_request_digest: None,
            rotation_serial: 0,
            state: super::super::publication::PublicationStreamState::Active,
            created_at_ms: 1,
            updated_at_ms: 2,
        }
    }

    #[test]
    fn committed_cut_keeps_outer_and_inner_independent_but_authenticates_inner_only_baseline() {
        for (outer, inner) in [(None, None), (Some(7), None), (Some(7), Some(11))] {
            let projection = committed_cut(
                &publication_stream_with_cuts(outer, inner),
                KeyTransitionStreamScope::Catalog,
            )
            .expect("authenticated committed cursor pair");
            assert_eq!(projection.committed_outer_cursor, outer);
            assert_eq!(projection.committed_inner_cursor, inner);
        }

        let mut unauthenticated_inner_only = publication_stream_with_cuts(None, Some(11));
        assert!(matches!(
            committed_cut(
                &unauthenticated_inner_only,
                KeyTransitionStreamScope::Catalog
            ),
            Err(RuntimeStoreError::PublicationMismatch)
        ));

        unauthenticated_inner_only.last_rotation_request_digest = Some([0x17; 32]);
        unauthenticated_inner_only.rotation_serial = 1;
        let rotation = committed_cut(
            &unauthenticated_inner_only,
            KeyTransitionStreamScope::Catalog,
        )
        .expect("authenticated generation rotation baseline");
        assert_eq!(rotation.committed_outer_cursor, None);
        assert_eq!(rotation.committed_inner_cursor, Some(11));

        let mut reserved_gap = publication_stream_with_cuts(Some(7), None);
        reserved_gap.reserved_high_water = Some(8);
        assert!(matches!(
            committed_cut(&reserved_gap, KeyTransitionStreamScope::Catalog),
            Err(RuntimeStoreError::PublicationMismatch)
        ));
    }

    #[tokio::test]
    async fn production_projection_authenticates_real_draining_old_state() {
        let root = tempfile::tempdir().expect("create transition projection tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure transition projection tempdir");
        }
        let database = root.path().join("runtime.db");
        let keys = crate::security::MemoryKeyStore::new();
        let storage_kek = crate::security::load_or_create_storage_kek(&keys, &database)
            .expect("create transition projection StorageKEK");
        let store =
            crate::runtime::store::active_authorization_store_with_pending_transition_for_test(
                &database,
                storage_kek,
                vec![agentdeck_protocol::e2ee::AuthorizationCapabilityV1::Catalog],
                vec![agentdeck_protocol::e2ee::AuthorizationPermissionV1::CatalogRead],
            )
            .await;

        let projection = store
            .load_transition_material_projection()
            .await
            .expect("load authenticated transition projection")
            .expect("initial active grant stages DrainingOld transition");
        let transition = &projection.recovery.transition;
        assert_eq!(transition.phase, KeyTransitionPhase::DrainingOld);
        assert_eq!(transition.operation, KeyTransitionOperation::Add);
        assert_eq!(transition.from_revision + 1, transition.to_revision);
        assert_eq!(
            projection.global_keys.revision().value(),
            transition.to_revision
        );
        assert_ne!(projection.anchor.machine_route.as_bytes(), &[0; 16]);
        assert_ne!(projection.anchor.root_key_id.as_bytes(), &[0; 16]);
        assert_ne!(projection.anchor.machine_trust_domain, [0; 32]);
        assert_eq!(projection.recipients.len(), transition.recipients.len());
        for (projected, expected) in projection.recipients.iter().zip(&transition.recipients) {
            assert_eq!(projected.recipient, *expected);
            assert_eq!(
                projected.authorization_revision.value(),
                transition.to_revision
            );
            assert_eq!(
                projected.relay_grant.machine_route,
                projection.anchor.machine_route
            );
        }

        store.shutdown().await.expect("shutdown projection Store");
    }
}
