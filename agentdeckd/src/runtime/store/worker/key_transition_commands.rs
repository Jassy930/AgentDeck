//! P4.5 key-transition 的单 worker async facade。

#![allow(
    dead_code,
    reason = "P4.5 key-directory coordinator consumes these typed commands in the next slice"
)]

use super::*;

fn retained_vec_bytes<T>(capacity: usize) -> Result<usize, RuntimeStoreError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(RuntimeStoreError::PayloadTooLarge)
}

fn retained_key_updates_bytes(
    updates: &[key_transition::FrozenKeyUpdate],
    capacity: usize,
) -> Result<usize, RuntimeStoreError> {
    updates.iter().try_fold(
        retained_vec_bytes::<key_transition::FrozenKeyUpdate>(capacity)?,
        |retained, update| {
            retained
                .checked_add(update.canonical_update_set.capacity())
                .ok_or(RuntimeStoreError::PayloadTooLarge)
        },
    )
}

impl RuntimeStoreHandle {
    pub(crate) async fn begin_key_transition(
        &self,
        input: key_transition::BeginKeyTransition,
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        let retained = retained_vec_bytes::<key_transition::KeyTransitionRecipient>(
            input.recipients.capacity(),
        )?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[retained])?,
            |reply| NormalCommand::BeginKeyTransition { input, reply },
        )
        .await?
    }

    #[cfg(test)]
    pub(crate) async fn mark_key_transition_rotated(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::MarkKeyTransitionRotated {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn finalize_key_directory_rotation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::FinalizeKeyDirectoryRotation {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn freeze_key_updates(
        &self,
        operation_id: [u8; 16],
        updates: Vec<key_transition::FrozenKeyUpdate>,
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        let retained = retained_key_updates_bytes(&updates, updates.capacity())?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[retained])?,
            |reply| NormalCommand::FreezeKeyUpdates {
                operation_id,
                updates,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn freeze_key_barriers(
        &self,
        operation_id: [u8; 16],
        cuts: Vec<key_transition::KeyTransitionStreamCut>,
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        let retained =
            retained_vec_bytes::<key_transition::KeyTransitionStreamCut>(cuts.capacity())?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[retained])?,
            |reply| NormalCommand::FreezeKeyBarriers {
                operation_id,
                cuts,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn mark_key_barriers_committed(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::MarkKeyBarriersCommitted {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn acknowledge_key_update(
        &self,
        input: key_transition::AcknowledgeKeyUpdate,
    ) -> Result<key_transition::KeyUpdateRecord, RuntimeStoreError> {
        let retained = input.canonical_ack.capacity();
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[retained])?,
            |reply| NormalCommand::AcknowledgeKeyUpdate { input, reply },
        )
        .await?
    }

    pub(crate) async fn acknowledge_stream_applied(
        &self,
        input: key_transition::AcknowledgeStreamApplied,
    ) -> Result<key_transition::KeyUpdateRecord, RuntimeStoreError> {
        let retained = input.canonical_ack.capacity();
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[retained])?,
            |reply| NormalCommand::AcknowledgeStreamApplied { input, reply },
        )
        .await?
    }

    pub(crate) async fn resolve_transition_snapshot_permit(
        &self,
        request: key_transition::TransitionSnapshotRequest,
    ) -> Result<key_transition::TransitionSnapshotPermit, RuntimeStoreError> {
        let machine_trust_domain = self.machine_trust_domain()?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::ResolveTransitionSnapshotPermit {
                machine_trust_domain,
                request,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn mark_transition_snapshot_flushed(
        &self,
        flush: key_transition::TransitionSnapshotFlush,
    ) -> Result<key_transition::TransitionSnapshotFlushRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::MarkTransitionSnapshotFlushed { flush, reply },
        )
        .await?
    }

    pub(crate) async fn complete_key_transition(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::CompleteKeyTransition {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn try_complete_key_transition(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionCompletion, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::TryCompleteKeyTransition {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn cancel_key_transition(
        &self,
        operation_id: [u8; 16],
    ) -> Result<key_transition::KeyTransitionRecord, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::CancelKeyTransition {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn gc_expired_key_transitions(
        &self,
        limits: key_transition::KeyTransitionGcLimits,
    ) -> Result<key_transition::KeyTransitionGcOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::GcExpiredKeyTransitions { limits, reply },
        )
        .await?
    }

    pub(crate) async fn apply_pending_replay_retirement(
        &self,
    ) -> Result<key_transition::ReplayRetirementApplyOutcome, RuntimeStoreError> {
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[])?,
            |reply| SafetyCommand::ApplyPendingReplayRetirement { reply },
        )
        .await?
    }

    /// 只读返回下一笔 authenticated guard-first GC plan；maintenance 必须先按
    /// `scope_tokens` existing-only 删除 Keychain guard 并逐项读回 absent。
    pub(crate) async fn load_pending_counter_retirement_plan(
        &self,
    ) -> Result<Option<key_transition::CounterRetirementPlan>, RuntimeStoreError> {
        let machine_trust_domain = self.machine_trust_domain()?;
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadPendingCounterRetirementPlan {
                machine_trust_domain,
                reply,
            },
        )
        .await?
    }

    /// caller 已完成 plan 全部 Keychain absent readback 后的 DB finalize seam。
    pub(crate) async fn apply_counter_retirement_after_guard_readback(
        &self,
        plan: key_transition::CounterRetirementPlan,
    ) -> Result<key_transition::CounterRetirementApplyOutcome, RuntimeStoreError> {
        let retained = retained_vec_bytes::<[u8; 32]>(plan.scope_tokens.capacity())?;
        let machine_trust_domain = self.machine_trust_domain()?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            memory_charge(size_of::<SafetyCommand>(), &[retained])?,
            |reply| SafetyCommand::ApplyCounterRetirementAfterGuardReadback {
                machine_trust_domain,
                plan,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn check_remote_transition_ingress(
        &self,
        class: key_transition::RemoteTransitionIngressClass,
    ) -> Result<(), RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::CheckRemoteTransitionIngress { class, reply },
        )
        .await?
    }

    pub(crate) async fn load_active_key_transition(
        &self,
    ) -> Result<Option<key_transition::KeyTransitionRecovery>, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::LoadActiveKeyTransition { reply },
        )
        .await?
    }

    pub(crate) async fn load_transition_material_projection(
        &self,
    ) -> Result<Option<transition_material::TransitionMaterialProjection>, RuntimeStoreError> {
        let machine_trust_domain = self.machine_trust_domain()?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::LoadTransitionMaterialProjection {
                machine_trust_domain,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn load_transition_committed_cuts(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<transition_material::TransitionCommittedCutProjection>, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::LoadTransitionCommittedCuts {
                operation_id,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn load_key_update_for_sync(
        &self,
        query: key_transition::KeySyncRead,
    ) -> Result<key_transition::FrozenKeyUpdate, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::LoadKeyUpdateForSync { query, reply },
        )
        .await?
    }

    pub(crate) async fn resolve_key_update_ack(
        &self,
        query: key_transition::KeyUpdateAckResolve,
    ) -> Result<key_transition::KeyUpdateAckBinding, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::ResolveKeyUpdateAck { query, reply },
        )
        .await?
    }

    pub(crate) async fn resolve_stream_applied_ack(
        &self,
        query: key_transition::StreamAppliedAckResolve,
    ) -> Result<key_transition::StreamAppliedAckBinding, RuntimeStoreError> {
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            memory_charge(size_of::<NormalCommand>(), &[])?,
            |reply| NormalCommand::ResolveStreamAppliedAck { query, reply },
        )
        .await?
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
    use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial, MachineRouteId, TrustEpoch};

    use crate::remote::counter::{COUNTER_BLOCK_SIZE, CounterScope};
    use crate::runtime::model::{RuntimeClock, RuntimeClockError};
    use crate::runtime::store::publication::{
        FreezePublicationRequest, PublicationPayloadKind, PublicationScope,
    };
    use crate::runtime::store::remote_counter::RemoteCounterGapRequest;
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::*;

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicU64>);

    impl RuntimeClock for ManualClock {
        fn now_ms(&self) -> Result<u64, RuntimeClockError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    fn recipient(route: u8, grant_serial: u64) -> key_transition::KeyTransitionRecipient {
        key_transition::KeyTransitionRecipient {
            device_route: [route; 16],
            grant_serial,
        }
    }

    async fn open_store(now_ms: u64) -> (tempfile::TempDir, Arc<AtomicU64>, RuntimeStoreHandle) {
        let root = tempfile::tempdir().expect("create key-transition handle test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("secure key-transition handle test root");
        }
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &root.path().join("key-state.db"))
            .expect("create key-transition handle StorageKEK");
        let clock = Arc::new(AtomicU64::new(now_ms));
        let config = RuntimeStoreConfig::new(root.path().join("runtime.db"))
            .with_clock(ManualClock(clock.clone()))
            .with_capacity_probe(crate::runtime::store::pairing_tests::GenerousCapacity);
        let store = RuntimeStoreHandle::open(config, storage_kek)
            .await
            .expect("open key-transition handle store");
        (root, clock, store)
    }

    #[tokio::test]
    async fn handle_serializes_transition_recovery_keysync_and_business_fence() {
        let (_root, clock, store) = open_store(100).await;
        let operation_id = [0x31; 16];
        let member = recipient(0x41, 7);
        let begin = key_transition::BeginKeyTransition {
            operation_id,
            operation: key_transition::KeyTransitionOperation::ActivateConversation,
            target: key_transition::KeyTransitionTarget::Conversation {
                conversation_id: [0x51; 16],
                stream_route: [0x52; 16],
            },
            from_revision: 8,
            to_revision: 9,
            recipients: vec![member],
            replay_retirement: None,
            // Caller time is deliberately untrusted; the blocking worker owns it.
            created_at_ms: 1,
        };

        let (started, active) = tokio::join!(
            biased;
            store.begin_key_transition(begin),
            store.load_active_key_transition(),
        );
        let started = started.expect("begin transition through handle");
        let active = active
            .expect("load serialized recovery")
            .expect("transition is active");
        assert_eq!(started.created_at_ms, 100);
        assert_eq!(active.transition, started);
        assert!(active.updates.is_empty());
        assert!(matches!(
            store
                .check_remote_transition_ingress(
                    key_transition::RemoteTransitionIngressClass::Business,
                )
                .await,
            Err(RuntimeStoreError::InvalidStateTransition)
        ));
        for class in [
            key_transition::RemoteTransitionIngressClass::KeySync,
            key_transition::RemoteTransitionIngressClass::KeyUpdateAck,
            key_transition::RemoteTransitionIngressClass::StreamAppliedAck,
        ] {
            store
                .check_remote_transition_ingress(class)
                .await
                .expect("key control ingress remains available");
        }

        clock.store(101, Ordering::SeqCst);
        store
            .mark_key_transition_rotated(operation_id)
            .await
            .expect("record completed guard rotation");
        let update = key_transition::FrozenKeyUpdate {
            recipient: member,
            key_revision: 9,
            canonical_update_set: b"exact-handle-key-update".to_vec(),
        };
        clock.store(102, Ordering::SeqCst);
        store
            .freeze_key_updates(operation_id, vec![update.clone()])
            .await
            .expect("freeze exact update through handle");
        let query = key_transition::KeySyncRead {
            recipient: member,
            known_revision: 8,
            requested_revision: 9,
        };
        assert_eq!(
            store
                .load_key_update_for_sync(query)
                .await
                .expect("load exact KeySync response"),
            update
        );
        assert_eq!(
            store
                .load_key_update_for_sync(query)
                .await
                .expect("replay exact KeySync response"),
            update
        );
        assert!(matches!(
            store
                .load_key_update_for_sync(key_transition::KeySyncRead {
                    known_revision: 7,
                    ..query
                })
                .await,
            Err(RuntimeStoreError::PublicationMismatch)
        ));
        let active = store
            .load_active_key_transition()
            .await
            .expect("load active transition with update")
            .expect("transition remains active");
        assert_eq!(active.transition.state_changed_at_ms, 102);
        assert_eq!(active.updates.len(), 1);

        clock.store(103, Ordering::SeqCst);
        store
            .freeze_key_barriers(operation_id, Vec::new())
            .await
            .expect("activation has an empty barrier set");
        clock.store(104, Ordering::SeqCst);
        store
            .mark_key_barriers_committed(operation_id)
            .await
            .expect("commit empty activation barrier set");
        store
            .check_remote_transition_ingress(
                key_transition::RemoteTransitionIngressClass::ControlPlaneReady,
            )
            .await
            .expect("control-plane ingress resumes after barrier commit");
        assert!(matches!(
            store
                .check_remote_transition_ingress(
                    key_transition::RemoteTransitionIngressClass::Business,
                )
                .await,
            Err(RuntimeStoreError::InvalidStateTransition)
        ));
        clock.store(105, Ordering::SeqCst);
        assert!(matches!(
            store.complete_key_transition(operation_id).await,
            Err(RuntimeStoreError::InvalidStateTransition)
        ));

        let update_hash = key_transition::canonical_update_hash(&update.canonical_update_set)
            .expect("hash exact update");
        let ack = key_transition::AcknowledgeKeyUpdate {
            operation_id,
            recipient: member,
            key_revision: 9,
            update_hash,
            canonical_ack: b"exact-handle-key-ack".to_vec(),
            acknowledged_at_ms: 1,
        };
        let first_ack = store
            .acknowledge_key_update(ack.clone())
            .await
            .expect("record exact key update ACK");
        assert_eq!(first_ack.state_changed_at_ms, 105);
        clock.store(106, Ordering::SeqCst);
        let replayed_ack = store
            .acknowledge_key_update(ack)
            .await
            .expect("new worker time does not conflict with exact ACK replay");
        assert_eq!(replayed_ack.state_changed_at_ms, 105);
        let completed = store
            .complete_key_transition(operation_id)
            .await
            .expect("complete after exact key ACK");
        store
            .check_remote_transition_ingress(key_transition::RemoteTransitionIngressClass::Business)
            .await
            .expect("business ingress resumes only after transition completion");
        assert_eq!(
            completed.terminal,
            Some(key_transition::KeyTransitionTerminal::Completed)
        );
        assert!(
            store
                .load_active_key_transition()
                .await
                .expect("load terminal recovery projection")
                .is_none()
        );
        store.shutdown().await.expect("shutdown transition store");
    }

    #[tokio::test]
    async fn handle_relay_commit_is_not_stream_applied_ack() {
        let (_root, clock, store) = open_store(400).await;
        let publication_stream_id = [0x21; 16];
        let stream_route = [0x22; 16];
        let generation = [0x23; 16];
        store
            .create_publication_stream(
                publication_stream_id,
                PublicationScope::Catalog,
                stream_route,
                generation,
            )
            .await
            .expect("create catalog publication stream");

        let operation_id = [0x24; 16];
        let member = recipient(0x25, 7);
        let replay_scope =
            remote_replay::canonical_device_command_scope([0x29; 16], 3, member.device_route, 6, 6)
                .expect("freeze full old DeviceCommandTx axes");
        clock.store(401, Ordering::SeqCst);
        store
            .begin_key_transition(key_transition::BeginKeyTransition {
                operation_id,
                operation: key_transition::KeyTransitionOperation::Renew,
                target: key_transition::KeyTransitionTarget::Device(member),
                from_revision: 4,
                to_revision: 5,
                recipients: vec![member],
                replay_retirement: Some(
                    key_transition::ReplayRetirement::pending_device_command(replay_scope, 7)
                        .expect("freeze old DeviceReplyTx epoch"),
                ),
                created_at_ms: 0,
            })
            .await
            .expect("begin add transition");
        clock.store(402, Ordering::SeqCst);
        store
            .mark_key_transition_rotated(operation_id)
            .await
            .expect("record completed key guard rotation");
        let canonical_update_set = b"new-member-handle-update".to_vec();
        clock.store(403, Ordering::SeqCst);
        store
            .freeze_key_updates(
                operation_id,
                vec![key_transition::FrozenKeyUpdate {
                    recipient: member,
                    key_revision: 5,
                    canonical_update_set: canonical_update_set.clone(),
                }],
            )
            .await
            .expect("freeze member key update");

        let epoch_barrier_sha256 = [0x26; 32];
        let cut = key_transition::KeyTransitionStreamCut {
            scope: key_transition::KeyTransitionStreamScope::Catalog,
            publication_stream_id,
            stream_route,
            generation,
            relay_committed_outer: None,
            relay_committed_inner: None,
            barrier_sequence: 0,
            old_epoch: 7,
            new_epoch: 8,
            epoch_barrier_sha256,
        };
        clock.store(404, Ordering::SeqCst);
        store
            .freeze_key_barriers(operation_id, vec![cut])
            .await
            .expect("freeze exact committed cut");
        clock.store(405, Ordering::SeqCst);
        let frozen = store
            .freeze_publication(FreezePublicationRequest {
                publication_id: [0x27; 16],
                publication_stream_id,
                generation,
                counter_scope_token: [0x28; 32],
                sender_counter: 0,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"sealed-handle-epoch-barrier".to_vec(),
            })
            .await
            .expect("freeze barrier publication");
        clock.store(406, Ordering::SeqCst);
        store
            .acknowledge_publication_commit(
                publication_stream_id,
                generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await
            .expect("record Relay COMMIT");
        clock.store(407, Ordering::SeqCst);
        store
            .mark_key_barriers_committed(operation_id)
            .await
            .expect("record exact barrier set committed");
        clock.store(408, Ordering::SeqCst);
        store
            .acknowledge_key_update(key_transition::AcknowledgeKeyUpdate {
                operation_id,
                recipient: member,
                key_revision: 5,
                update_hash: key_transition::canonical_update_hash(&canonical_update_set)
                    .expect("hash exact member update"),
                canonical_ack: b"member-key-update-ack".to_vec(),
                acknowledged_at_ms: 0,
            })
            .await
            .expect("record key update ACK");

        clock.store(409, Ordering::SeqCst);
        assert!(matches!(
            store.complete_key_transition(operation_id).await,
            Err(RuntimeStoreError::InvalidStateTransition)
        ));
        let stream_ack = key_transition::AcknowledgeStreamApplied {
            operation_id,
            recipient: member,
            key_revision: 5,
            scope: key_transition::KeyTransitionStreamScope::Catalog,
            stream_route,
            stream_generation: generation,
            applied_stream_seq: 0,
            inner_cursor: None,
            key_epoch: 8,
            epoch_barrier_sha256,
            authorization_hash: [0xa3; 32],
            canonical_ack: b"member-stream-applied-ack".to_vec(),
            acknowledged_at_ms: 0,
        };
        let first = store
            .acknowledge_stream_applied(stream_ack.clone())
            .await
            .expect("record StreamAppliedAck");
        assert_eq!(first.state_changed_at_ms, 409);
        clock.store(410, Ordering::SeqCst);
        let replayed = store
            .acknowledge_stream_applied(stream_ack)
            .await
            .expect("exact StreamAppliedAck ignores later worker time");
        assert_eq!(replayed.state_changed_at_ms, 409);
        store
            .complete_key_transition(operation_id)
            .await
            .expect("complete only after both ACK families");
        let replay = store
            .apply_pending_replay_retirement()
            .await
            .expect("retire old command replay scope before counter GC");
        assert!(matches!(
            replay,
            key_transition::ReplayRetirementApplyOutcome::Applied {
                replay_scope_observed: false,
                ..
            }
        ));

        let trust_domain = store.machine_trust_domain().expect("machine trust domain");
        let catalog_key_id = KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 7,
        };
        let catalog_scope =
            CounterScope::publication(trust_domain, catalog_key_id, publication_stream_id)
                .expect("derive old catalog CounterGuard scope");
        let reply_scope = CounterScope::directed_reply_for_trust_epoch(
            trust_domain,
            MachineRouteId::from_bytes([0x29; 16]),
            TrustEpoch::new(3),
            DeviceRouteId::from_bytes(member.device_route),
            GrantSerial::new(6),
            7,
        )
        .expect("derive old renewal reply CounterGuard scope");
        for scope in [catalog_scope, reply_scope] {
            store
                .register_remote_counter_guard_scope(scope.token())
                .await
                .expect("register exact counter manifest scope");
        }
        // Catalog scope has a materialized DB row; reply scope intentionally remains
        // Reserved+absent to cover the crash gap before Keychain materialization.
        store
            .mark_remote_counter_guard_scope_materialized(catalog_scope.token())
            .await
            .expect("mark catalog guard materialized");
        let genesis = store
            .load_remote_counter_record(catalog_scope.token(), catalog_key_id)
            .await
            .expect("load catalog counter genesis");
        store
            .record_remote_counter_gap(RemoteCounterGapRequest {
                scope_token: catalog_scope.token(),
                key_id: catalog_key_id,
                expected_reserved_end: genesis.reserved_end,
                expected_db_anchor: genesis.db_anchor,
                abandoned_through: COUNTER_BLOCK_SIZE,
                reservation_id: [0x2a; 16],
                publication_id: [0x2b; 16],
            })
            .await
            .expect("materialize old catalog counter row");

        clock.store(
            410 + key_transition::COUNTER_RETIREMENT_RETENTION_MS - 1,
            Ordering::SeqCst,
        );
        assert!(
            store
                .load_pending_counter_retirement_plan()
                .await
                .expect("pre-retention counter plan")
                .is_none()
        );
        clock.store(
            410 + key_transition::COUNTER_RETIREMENT_RETENTION_MS,
            Ordering::SeqCst,
        );
        let plan = store
            .load_pending_counter_retirement_plan()
            .await
            .expect("load retained exact counter plan")
            .expect("renewal counter plan is ready");
        let mut expected_tokens = vec![catalog_scope.token(), reply_scope.token()];
        expected_tokens.sort_unstable();
        assert_eq!(plan.operation_id, operation_id);
        assert_eq!(plan.scope_tokens, expected_tokens);
        assert_eq!(
            store
                .apply_counter_retirement_after_guard_readback(plan.clone())
                .await
                .expect("finalize simulated Keychain absent readback"),
            key_transition::CounterRetirementApplyOutcome::Applied {
                operation_id,
                counter_rows_deleted: 1,
                manifest_rows_deleted: 2,
            }
        );
        assert_eq!(
            store
                .apply_counter_retirement_after_guard_readback(plan)
                .await
                .expect("after-COMMIT retry converges"),
            key_transition::CounterRetirementApplyOutcome::AlreadyCollected { operation_id }
        );
        store.shutdown().await.expect("shutdown transition store");
    }

    #[tokio::test]
    async fn handle_runs_bounded_key_transition_gc_on_worker_clock() {
        let (_root, clock, store) = open_store(700).await;
        let operation_id = [0xe1; 16];
        store
            .begin_key_transition(key_transition::BeginKeyTransition {
                operation_id,
                operation: key_transition::KeyTransitionOperation::ActivateConversation,
                target: key_transition::KeyTransitionTarget::Conversation {
                    conversation_id: [0xe2; 16],
                    stream_route: [0xe3; 16],
                },
                from_revision: 1,
                to_revision: 2,
                recipients: vec![recipient(0xe4, 1)],
                replay_retirement: None,
                created_at_ms: 0,
            })
            .await
            .expect("begin worker GC fixture");
        clock.store(701, Ordering::SeqCst);
        store
            .cancel_key_transition(operation_id)
            .await
            .expect("terminalize worker GC fixture");
        clock.store(
            701 + key_transition::COUNTER_RETIREMENT_RETENTION_MS,
            Ordering::SeqCst,
        );
        let retirement = store
            .load_pending_counter_retirement_plan()
            .await
            .expect("load empty counter-retirement plan")
            .expect("cancelled transition still requires explicit guard-first finalization");
        assert!(retirement.scope_tokens.is_empty());
        assert_eq!(
            store
                .apply_counter_retirement_after_guard_readback(retirement)
                .await
                .expect("apply empty counter-retirement plan"),
            key_transition::CounterRetirementApplyOutcome::Applied {
                operation_id,
                counter_rows_deleted: 0,
                manifest_rows_deleted: 0,
            }
        );
        clock.store(
            701 + key_transition::KEY_TRANSITION_TOMBSTONE_RETENTION_MS - 1,
            Ordering::SeqCst,
        );
        assert_eq!(
            store
                .gc_expired_key_transitions(key_transition::KeyTransitionGcLimits::default())
                .await
                .expect("pre-deadline worker GC"),
            key_transition::KeyTransitionGcOutcome::default()
        );
        clock.store(
            701 + key_transition::KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
            Ordering::SeqCst,
        );
        let collected = store
            .gc_expired_key_transitions(key_transition::KeyTransitionGcLimits::default())
            .await
            .expect("deadline worker GC");
        assert_eq!(collected.transitions_deleted, 1);
        assert_eq!(collected.updates_deleted, 0);
        assert_eq!(
            store
                .gc_expired_key_transitions(key_transition::KeyTransitionGcLimits::default())
                .await
                .expect("post-GC exact retry"),
            key_transition::KeyTransitionGcOutcome::default()
        );
        store.shutdown().await.expect("shutdown worker GC store");
    }
}
