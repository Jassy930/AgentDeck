//! Runtime store stream/backfill/snapshot/publication async facade 与 barrier capture。

use super::*;
use crate::runtime::events::WatchGeneration;

/// Worker 在 oneshot send 前就绑定 TEMP backfill pin 的 Drop cleanup。
///
/// 威胁场景：unsubscribe/disconnect 与 live pin acquire 同时完成时，biased cancellation
/// 会丢弃尚未被 caller poll 的成功 reply；若 channel 中只是裸 pin，该 pin 会占住全局
/// 配额直到 TTL。managed plan 即使停在 oneshot slot 内也会在 receiver drop 时精确回收。
pub(super) struct ManagedBackfillPlan {
    plan: Option<RuntimeBackfillPlan>,
    cleanup_tx: mpsc::UnboundedSender<StoreCleanup>,
}

impl ManagedBackfillPlan {
    fn new(plan: RuntimeBackfillPlan, cleanup_tx: mpsc::UnboundedSender<StoreCleanup>) -> Self {
        Self {
            plan: Some(plan),
            cleanup_tx,
        }
    }

    fn into_unmanaged(mut self) -> RuntimeBackfillPlan {
        self.plan
            .take()
            .expect("managed backfill plan is consumed exactly once")
    }
}

impl Drop for ManagedBackfillPlan {
    fn drop(&mut self) {
        if let Some(RuntimeBackfillPlan::Pinned(pin)) = self.plan.take() {
            let _ = self.cleanup_tx.send(StoreCleanup::BackfillPin(pin.pin_id));
        }
    }
}

impl RuntimeStoreHandle {
    /// watcher 注册、H capture、retained/snapshot/publication cut 均在唯一 store
    /// worker 的同一个短 ReadCommand 内完成；返回前不保留 SQLite transaction。
    pub async fn register_stream_barrier(
        &self,
        request: RegisterStreamBarrier,
    ) -> Result<StreamBarrierRegistration, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::RegisterStreamBarrier { request, reply },
        )
        .await?
    }

    /// Active Add transition 的专用 snapshot capture。permit 的 frozen H/C、stream
    /// identity 与 revision 由 Store 重新认证；本地 head 即使已推进到 L，也不能把
    /// L 混入定向 snapshot，H→L 只作为 continuation pin 随 registration 返回。
    pub(crate) async fn register_transition_snapshot_barrier(
        &self,
        permit: key_transition::TransitionSnapshotPermit,
        generation: WatchGeneration,
    ) -> Result<StreamBarrierRegistration, RuntimeStoreError> {
        let machine_trust_domain = self.machine_trust_domain()?;
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::RegisterTransitionSnapshotBarrier {
                permit,
                generation,
                machine_trust_domain,
                reply,
            },
        )
        .await?
    }

    pub async fn release_stream_watch(
        &self,
        token: StoreWatchToken,
    ) -> Result<bool, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ReleaseStreamWatch { token, reply },
        )
        .await
    }

    /// 短 store operation 内冻结 retained range 并建立 TEMP pin；返回后不持有
    /// SQLite transaction，调用方可跨多页/网络 flush 使用 pin。
    pub async fn acquire_backfill_pin(
        &self,
        target: RuntimeBackfillTarget,
        after: Option<u64>,
    ) -> Result<RuntimeBackfillPlan, RuntimeStoreError> {
        let managed = dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::AcquireBackfillPin {
                target,
                after,
                reply,
            },
        )
        .await??;
        // managed reply 已经离开 cancellation handoff；这里到 raw return 之间没有 await，
        // caller 不能在 cleanup ownership 转交前丢失 pin。
        Ok(managed.into_unmanaged())
    }

    /// 每个 SQLite page 最多复制 64 events / 8 MiB；wire backfill 可在 P3.6-C
    /// 聚合多个已释放 transaction 的 page，但不能把 512/64 MiB wire cap 下推成 DB 长读。
    pub async fn load_event_backfill_page(
        &self,
        pin: RuntimeBackfillPin,
        after: Option<u64>,
    ) -> Result<RuntimeEventBackfillPage, RuntimeStoreError> {
        let plan = dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::PrepareBackfillPage { pin, after, reply },
        )
        .await??;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let read_plan = plan.clone();
        let retained = match self
            .read_pool
            .run_sqlite_backfill_page(move |connection| {
                stream::read_event_backfill_page(connection, &read_crypto, database_id, &read_plan)
                    .map_err(ReadPoolError::Operation)
            })
            .await
        {
            Ok(retained) => retained,
            Err(ReadPoolError::Operation(RuntimeStoreError::BackfillNeedSnapshot)) => {
                let read_crypto = self.read_crypto.clone();
                let read_plan = plan.clone();
                self.read_pool
                    .run_sqlite_snapshot(move |connection| {
                        stream::read_oversized_event_backfill_page(
                            connection,
                            &read_crypto,
                            database_id,
                            &read_plan,
                        )
                        .map_err(ReadPoolError::Operation)
                    })
                    .await
                    .map_err(map_read_pool_error)?
            }
            Err(error) => return Err(map_read_pool_error(error)),
        };
        let (mut page, lease) = retained.into_parts();
        let completion = page.completion().clone();
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ValidateBackfillPage { completion, reply },
        )
        .await??;
        page.memory_lease = Some(lease);
        Ok(page)
    }

    /// Catalog 使用与 conversation 相同的 pin/cursor/TTL 算法。
    pub async fn load_catalog_backfill_page(
        &self,
        pin: RuntimeBackfillPin,
        after: Option<u64>,
    ) -> Result<RuntimeCatalogBackfillPage, RuntimeStoreError> {
        let plan = dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::PrepareBackfillPage { pin, after, reply },
        )
        .await??;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let read_plan = plan.clone();
        let retained = self
            .read_pool
            .run_sqlite_backfill_page(move |connection| {
                stream::read_catalog_backfill_page(
                    connection,
                    &read_crypto,
                    database_id,
                    &read_plan,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut page, lease) = retained.into_parts();
        let completion = page.completion().clone();
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ValidateBackfillPage { completion, reply },
        )
        .await??;
        page.memory_lease = Some(lease);
        Ok(page)
    }

    /// 只有对应 page 已收到 transport write/flush ACK 后才可调用。重复、过期或
    /// cursor 已推进的 completion 全部 fail closed。
    pub async fn complete_backfill_page(
        &self,
        completion: RuntimeBackfillPageCompletion,
    ) -> Result<(), RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::CompleteBackfillPage { completion, reply },
        )
        .await?
    }

    /// disconnect/unsubscribe 清理幂等；已完成或已过期 pin 也返回成功。
    pub async fn release_backfill_pin(&self, pin_id: [u8; 16]) -> Result<(), RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ReleaseBackfillPin { pin_id, reply },
        )
        .await?
    }

    /// 在单 worker 的短 operation 内认证 origin、冻结当前 conversation H，并建立
    /// tagged TEMP snapshot pin。Managed 返回可物化的 Build，NativeProjected 只返回
    /// 无 durable bind 能力的 Dynamic。snapshot build 期间 writer/retention 可继续推进；
    /// pin 只证明 reducer 已在该 cut 开始 capture，绝不把慢 build 变成长事务。
    pub async fn acquire_snapshot_build_source(
        &self,
        conversation_id: super::super::RuntimeId,
    ) -> Result<SnapshotMaterializationSource, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::AcquireSnapshotBuildPin {
                conversation_id,
                reply,
            },
        )
        .await?
    }

    pub async fn release_snapshot_build_pin(
        &self,
        pin: RuntimeSnapshotBuildPin,
    ) -> Result<(), RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ReleaseSnapshotBuildPin { pin, reply },
        )
        .await?
    }

    #[cfg(test)]
    pub(crate) async fn active_snapshot_build_pin_count_for_test(
        &self,
    ) -> Result<u64, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::ActiveSnapshotBuildPinCountForTest { reply },
        )
        .await?
    }

    /// 在唯一 store worker 上读取并认证 conversation descriptor/context。Ready
    /// materializer 必须先完成这个小 read，再申请 exact snapshot 的整池 lease。
    pub(crate) async fn load_authenticated_conversation_snapshot_context(
        &self,
        conversation_id: super::super::RuntimeId,
    ) -> Result<AuthenticatedConversationSnapshotContext, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadAuthenticatedConversationSnapshotContext {
                conversation_id,
                reply,
            },
        )
        .await?
    }

    /// 认证并选择 frozen event cursor 处的 configuration state。BeforeFirst 由
    /// `None` 精确表达，不能与 event sequence 0 合并。
    pub(crate) async fn load_configuration_state_at_event_cursor(
        &self,
        conversation_id: super::super::RuntimeId,
        base_event_seq: Option<u64>,
    ) -> Result<ConversationConfigurationState, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadConfigurationStateAtEventCursor {
                conversation_id,
                base_event_seq,
                reply,
            },
        )
        .await?
    }

    /// 在持有 TEMP pin 的同一 worker connection 上验 pin、打开完整 descriptor 并
    /// 读取当前 authenticated H。方法只借用语义上的原 pin；BuildInput 继续拥有它。
    pub(crate) async fn prepare_authenticated_snapshot_build_context(
        &self,
        pin: RuntimeSnapshotBuildPin,
    ) -> Result<AuthenticatedConversationSnapshotContext, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::PrepareAuthenticatedSnapshotBuildContext { pin, reply },
        )
        .await?
    }

    /// exact snapshot build pin 下只读取一页 canonical RuntimeEvent。返回前已经
    /// 离开只读 transaction；memory lease 必须由 reducer 持有到本页消费完毕，
    /// 不能先累计完整 RuntimeEvent Vec 再做第二次全量转换。
    pub(crate) async fn load_snapshot_event_page(
        &self,
        pin: RuntimeSnapshotBuildPin,
        after: Option<u64>,
    ) -> Result<(Vec<RuntimeEvent>, u64, bool, ReadMemoryLease), RuntimeStoreError> {
        let context = self
            .prepare_authenticated_snapshot_build_context(pin.clone())
            .await?;
        let through = pin
            .base_event_seq()
            .ok_or(RuntimeStoreError::InvalidStateTransition)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let conversation_id = pin.conversation_id();
        let page = match self
            .read_pool
            .run_sqlite_page(MAX_RUNTIME_READ_PAGE_BYTES, move |connection| {
                stream::read_snapshot_event_page(
                    connection,
                    &read_crypto,
                    database_id,
                    conversation_id,
                    through,
                    after,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
        {
            Ok(page) => page,
            Err(ReadPoolError::Operation(RuntimeStoreError::BackfillNeedSnapshot)) => {
                let read_crypto = self.read_crypto.clone();
                self.read_pool
                    .run_sqlite_snapshot(move |connection| {
                        stream::read_oversized_snapshot_event_page(
                            connection,
                            &read_crypto,
                            database_id,
                            conversation_id,
                            through,
                            after,
                        )
                        .map_err(ReadPoolError::Operation)
                    })
                    .await
                    .map_err(map_read_pool_error)?
            }
            Err(error) => return Err(map_read_pool_error(error)),
        };
        let (page, lease) = page.into_parts();
        let next_after = page.next_after;
        let complete = page.complete;
        let events = page.events;
        self.prepare_authenticated_snapshot_build_context(pin.clone())
            .await?;
        if context.conversation_id != pin.conversation_id() {
            return Err(RuntimeStoreError::InvalidStateTransition);
        }
        Ok((events, next_after, complete, lease))
    }

    /// 原子替换某 conversation 的唯一 ready snapshot；frozen base 不得高于
    /// transaction 内再次读取的当前 event high-water，也不得倒退于已存 snapshot。
    pub async fn store_conversation_snapshot(
        &self,
        write: PreparedConversationSnapshotWrite,
    ) -> Result<StoredConversationSnapshot, StoreConversationSnapshotError> {
        self.store_conversation_snapshot_inner(write, None).await
    }

    pub(crate) async fn store_conversation_snapshot_guarded(
        &self,
        write: PreparedConversationSnapshotWrite,
        build_permit: SharedSnapshotBuildPermit,
    ) -> Result<StoredConversationSnapshot, StoreConversationSnapshotError> {
        self.store_conversation_snapshot_inner(write, Some(build_permit))
            .await
    }

    async fn store_conversation_snapshot_inner(
        &self,
        write: PreparedConversationSnapshotWrite,
        build_permit: Option<SharedSnapshotBuildPermit>,
    ) -> Result<StoredConversationSnapshot, StoreConversationSnapshotError> {
        if let Err(error) = validate_maximum(
            write.parts().2.len(),
            super::super::snapshot::MAX_SNAPSHOT_BYTES,
        ) {
            return Err(StoreConversationSnapshotError::with_retry_write(
                error, write,
            ));
        }
        let charge = match memory_charge(size_of::<NormalCommand>(), &[write.payload_capacity()]) {
            Ok(charge) => charge,
            Err(error) => {
                return Err(StoreConversationSnapshotError::with_retry_write(
                    error, write,
                ));
            }
        };
        if let Err(error) = ensure_running(&self.lifecycle) {
            return Err(StoreConversationSnapshotError::with_retry_write(
                error, write,
            ));
        }
        let permit = match self.normal_budget.clone().try_acquire_many_owned(charge) {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Err(StoreConversationSnapshotError::with_retry_write(
                    RuntimeStoreError::WorkerBusy {
                        lane: RuntimeStoreLane::Normal,
                    },
                    write,
                ));
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(StoreConversationSnapshotError::with_retry_write(
                    RuntimeStoreError::WorkerStopped,
                    write,
                ));
            }
        };
        let (reply, result) = oneshot::channel();
        let queued = Queued {
            command: NormalCommand::StoreConversationSnapshot {
                write,
                build_permit,
                reply,
            },
            memory_permit: permit,
        };
        if let Err(error) = self.normal_tx.try_send(queued) {
            let (error, queued) = match error {
                mpsc::error::TrySendError::Full(queued) => (
                    RuntimeStoreError::WorkerBusy {
                        lane: RuntimeStoreLane::Normal,
                    },
                    queued,
                ),
                mpsc::error::TrySendError::Closed(queued) => {
                    (RuntimeStoreError::WorkerStopped, queued)
                }
            };
            let NormalCommand::StoreConversationSnapshot { write, .. } = queued.command else {
                unreachable!("snapshot dispatch must preserve its opaque write")
            };
            return Err(StoreConversationSnapshotError::with_retry_write(
                error, write,
            ));
        }
        result.await.unwrap_or_else(|_| {
            Err(StoreConversationSnapshotError::without_retry_write(
                RuntimeStoreError::WorkerStopped,
            ))
        })
    }

    /// 仅供 crate unit fault fixture 注入 authenticated-but-malformed ready row。
    /// integration 与 production surface 均无法绕过 SnapshotBuildInput binding。
    #[cfg(test)]
    pub(crate) async fn store_conversation_snapshot_fixture_for_test(
        &self,
        source: SnapshotMaterializationSource,
        item_count: u64,
        mut payload: Vec<u8>,
    ) -> Result<StoredConversationSnapshot, StoreConversationSnapshotError> {
        let (source, cleanup) = source.into_parts();
        let (SnapshotBarrierSource::Build(pin), Some(cleanup)) = (source, cleanup) else {
            return Err(StoreConversationSnapshotError::without_retry_write(
                RuntimeStoreError::InvalidStateTransition,
            ));
        };
        let Some(required_capacity) = payload
            .len()
            .checked_add(super::super::cipher::ROW_BLOB_V1_OVERHEAD_LEN)
        else {
            return Err(StoreConversationSnapshotError::with_retry_write(
                RuntimeStoreError::PayloadTooLarge,
                PreparedConversationSnapshotWrite::new(pin, item_count, payload, cleanup),
            ));
        };
        if payload.capacity() < required_capacity
            && payload
                .try_reserve_exact(required_capacity - payload.capacity())
                .is_err()
        {
            return Err(StoreConversationSnapshotError::with_retry_write(
                RuntimeStoreError::PayloadTooLarge,
                PreparedConversationSnapshotWrite::new(pin, item_count, payload, cleanup),
            ));
        }
        self.store_conversation_snapshot(PreparedConversationSnapshotWrite::new(
            pin, item_count, payload, cleanup,
        ))
        .await
    }

    pub async fn load_conversation_snapshot(
        &self,
        conversation_id: super::super::RuntimeId,
    ) -> Result<Option<StoredConversationSnapshot>, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let retained = self
            .read_pool
            .run_sqlite_snapshot(move |connection| {
                super::super::snapshot::load_conversation_snapshot_read(
                    connection,
                    &read_crypto,
                    database_id,
                    conversation_id,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut snapshot, lease) = retained.into_parts();
        if let Some(snapshot) = &mut snapshot {
            snapshot.memory_lease = Some(lease);
        }
        Ok(snapshot)
    }

    /// 只加载 barrier 已认证并冻结的 exact ready row。row 已被替换、删除或任一
    /// target/base/count/bytes/hash 发生变化都 fail-close，绝不重新选择最新 snapshot。
    pub async fn load_conversation_snapshot_by_reference(
        &self,
        reference: super::super::snapshot::ReadySnapshotReference,
    ) -> Result<StoredConversationSnapshot, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let retained = self
            .read_pool
            .run_sqlite_snapshot(move |connection| {
                super::super::snapshot::load_conversation_snapshot_reference_read(
                    connection,
                    &read_crypto,
                    database_id,
                    &reference,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut snapshot, lease) = retained.into_parts();
        snapshot.memory_lease = Some(lease);
        Ok(snapshot)
    }

    pub(crate) async fn refresh_catalog_snapshot(
        &self,
        source: Option<super::super::snapshot::ReadySnapshotReference>,
        frozen_base: agentdeck_protocol::runtime::StreamCursor,
        build_permit: SharedSnapshotBuildPermit,
    ) -> Result<super::super::snapshot::ReadySnapshotReference, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::RefreshCatalogSnapshot {
                source,
                frozen_base,
                build_permit,
                reply,
            },
        )
        .await?
    }

    /// 在解密/物化 catalog baseline 与 frozen delta 之前，由唯一 store worker
    /// 认证 exact source、frozen cut 及 delta metadata，并返回共享 build budget
    /// 所需的 conservative 峰值。该 command 不修改 durable state。
    pub(crate) async fn preflight_catalog_snapshot_refresh(
        &self,
        source: Option<super::super::snapshot::ReadySnapshotReference>,
        frozen_base: agentdeck_protocol::runtime::StreamCursor,
    ) -> Result<super::super::snapshot::CatalogSnapshotRefreshPreflight, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::PreflightCatalogSnapshotRefresh {
                source,
                frozen_base,
                reply,
            },
        )
        .await?
    }

    /// Transition-only Catalog H 的 metadata preflight。允许 observed durable D > H，
    /// 但只返回只读 rebuild 计划，不触发 generic durable refresh。
    pub(crate) async fn preflight_transition_catalog_snapshot(
        &self,
        observed_reference: Option<super::super::snapshot::ReadySnapshotReference>,
        frozen: agentdeck_protocol::runtime::StreamCursor,
    ) -> Result<super::super::snapshot::CatalogTransitionSnapshotPreflight, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::PreflightTransitionCatalogSnapshot {
                observed_reference,
                frozen,
                reply,
            },
        )
        .await?
    }

    /// 在共享 snapshot budget 下只读组装 transition Catalog H。permit 仅证明 caller
    /// 已预留完整峰值；worker 完成/失败后归还 clone，不产生 durable write。
    pub(crate) async fn materialize_transition_catalog_snapshot(
        &self,
        preflight: super::super::snapshot::CatalogTransitionSnapshotPreflight,
        ephemeral_id: [u8; 16],
        build_permit: SharedSnapshotBuildPermit,
    ) -> Result<super::super::snapshot::EphemeralCatalogMaterialization, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::MaterializeTransitionCatalogSnapshot {
                preflight,
                ephemeral_id,
                build_permit,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn load_catalog_snapshot_by_reference(
        &self,
        reference: super::super::snapshot::ReadySnapshotReference,
    ) -> Result<StoredCatalogSnapshot, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let retained = self
            .read_pool
            .run_sqlite_snapshot(move |connection| {
                super::super::snapshot::load_catalog_snapshot_reference_read(
                    connection,
                    &read_crypto,
                    database_id,
                    &reference,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut snapshot, lease) = retained.into_parts();
        snapshot.memory_lease = Some(lease);
        Ok(snapshot)
    }

    pub async fn create_publication_stream(
        &self,
        publication_stream_id: [u8; 16],
        scope: PublicationScope,
        stream_route: [u8; 16],
        generation: [u8; 16],
    ) -> Result<PublicationStreamRecord, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::CreatePublicationStream {
                publication_stream_id,
                scope,
                stream_route,
                generation,
                reply,
            },
        )
        .await?
    }

    pub(crate) async fn preflight_shared_publication(
        &self,
        request: super::super::publication::SharedPublicationPreflightRequest,
        proposal: super::super::publication::SharedPublicationStreamProposal,
    ) -> Result<super::super::publication::SharedPublicationPreflight, RuntimeStoreError> {
        let retained = request.canonical_item_bytes.capacity();
        let charge = memory_charge(size_of::<NormalCommand>(), &[retained])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::PreflightSharedPublication {
                request,
                proposal,
                reply,
            },
        )
        .await?
    }

    pub async fn rotate_publication_stream(
        &self,
        request: RotatePublicationStreamRequest,
    ) -> Result<PublicationStreamRecord, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::RotatePublicationStream { request, reply },
        )
        .await?
    }

    pub async fn freeze_publication(
        &self,
        request: FreezePublicationRequest,
    ) -> Result<FrozenPublication, RuntimeStoreError> {
        validate_maximum(
            request.blob.len(),
            super::super::publication::MAX_PUBLICATION_BLOB_BYTES,
        )?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[request.blob.capacity()])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::FreezePublication { request, reply },
        )
        .await?
    }

    /// P4 signed path：worker queue 保留一次性 sealer，真正的 streamSeq/counter
    /// 只在同一个 `BEGIN IMMEDIATE` transaction 内分配并交给它一次。
    pub(crate) async fn freeze_signed_publication(
        &self,
        request: FreezeSignedPublicationRequest,
    ) -> Result<FrozenPublication, RuntimeStoreError> {
        let charge = memory_charge(size_of::<NormalCommand>(), &[request.sealer_retained_bytes])?;
        dispatch_with_budget(
            &self.normal_tx,
            &self.normal_budget,
            &self.lifecycle,
            RuntimeStoreLane::Normal,
            charge,
            |reply| NormalCommand::FreezeSignedPublication { request, reply },
        )
        .await?
    }

    /// Relay durable commit receipt；走 safety lane，容量水位下仍可删除 outbox 并推进 cut。
    pub async fn acknowledge_publication_commit(
        &self,
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
    ) -> Result<PublicationBarrierCut, RuntimeStoreError> {
        let charge = memory_charge(size_of::<SafetyCommand>(), &[])?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::AcknowledgePublicationCommit {
                publication_stream_id,
                generation,
                stream_seq,
                blob_sha256,
                reply,
            },
        )
        .await?
    }

    /// daemon local ACK；与 Relay COMMIT 分离。只有 exact ACK 成功才删除 frozen
    /// outbox row 并推进 acknowledged cursor。它不代表任一远端 device 已应用业务流；
    /// key transition 的 `StreamAppliedAck` 仍是独立的端到端门禁。
    pub async fn acknowledge_publication_delivery(
        &self,
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
    ) -> Result<PublicationAcknowledgement, RuntimeStoreError> {
        let charge = memory_charge(size_of::<SafetyCommand>(), &[])?;
        dispatch_with_budget(
            &self.safety_tx,
            &self.safety_budget,
            &self.lifecycle,
            RuntimeStoreLane::Safety,
            charge,
            |reply| SafetyCommand::AcknowledgePublicationDelivery {
                publication_stream_id,
                generation,
                stream_seq,
                blob_sha256,
                reply,
            },
        )
        .await?
    }

    pub async fn load_pending_publications(
        &self,
        publication_stream_id: [u8; 16],
    ) -> Result<Vec<FrozenPublication>, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let retained = self
            .read_pool
            .run_sqlite_page(MAX_RUNTIME_READ_PAGE_BYTES, move |connection| {
                super::super::publication::load_pending_publications_read(
                    connection,
                    &read_crypto,
                    database_id,
                    publication_stream_id,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut publications, lease) = retained.into_parts();
        for publication in &mut publications {
            publication.memory_lease = Some(lease.clone());
        }
        Ok(publications)
    }

    /// transaction-bound signed publisher 的 exact retry 入口。该查询按
    /// `publication_id` 直达 authenticated row，不受 pending page 的 64-row/8 MiB 截断影响。
    pub(crate) async fn load_frozen_publication(
        &self,
        publication_id: [u8; 16],
    ) -> Result<Option<FrozenPublication>, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let database_id = self.database_id;
        let retained = self
            .read_pool
            .run_sqlite_page(MAX_RUNTIME_READ_PAGE_BYTES, move |connection| {
                super::super::publication::load_optional_outbox_read(
                    connection,
                    &read_crypto,
                    database_id,
                    publication_id,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (mut publication, lease) = retained.into_parts();
        if let Some(publication) = &mut publication {
            publication.memory_lease = Some(lease);
        }
        Ok(publication)
    }

    /// 重启恢复先在唯一 worker 上认证完整 publication directory/ledger，再返回
    /// `reserved > acknowledged` 的稳定排序 stream IDs。调用方不能从裸 SQL 枚举恢复；
    /// 对 `committed > acknowledged` 的 row 只能做 local ACK repair，不能重新 publish。
    pub async fn load_pending_publication_streams(
        &self,
    ) -> Result<Vec<[u8; 16]>, RuntimeStoreError> {
        dispatch(
            &self.read_tx,
            &self.lifecycle,
            RuntimeStoreLane::Read,
            |reply| ReadCommand::LoadPendingPublicationStreams { reply },
        )
        .await?
    }

    pub async fn load_publication_barrier(
        &self,
        publication_stream_id: [u8; 16],
    ) -> Result<PublicationBarrierCut, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let retained = self
            .read_pool
            .run_sqlite_page(64 * 1024, move |connection| {
                super::super::publication::load_publication_barrier_read(
                    connection,
                    &read_crypto,
                    publication_stream_id,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (barrier, _lease) = retained.into_parts();
        Ok(barrier)
    }

    /// exact publisher readback 的 authenticated ACK tombstone seam。只复用现有
    /// read pool 与 publication row MAC，不创建第二 writer 或裸 SQL 旁路。
    pub(crate) async fn load_publication_stream_record(
        &self,
        publication_stream_id: [u8; 16],
    ) -> Result<PublicationStreamRecord, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        let read_crypto = self.read_crypto.clone();
        let retained = self
            .read_pool
            .run_sqlite_page(64 * 1024, move |connection| {
                super::super::publication::load_stream_read(
                    connection,
                    &read_crypto,
                    publication_stream_id,
                )
                .map_err(ReadPoolError::Operation)
            })
            .await
            .map_err(map_read_pool_error)?;
        let (stream, _lease) = retained.into_parts();
        Ok(stream)
    }
}

pub(super) fn send_stream_barrier_reply(
    reply: oneshot::Sender<Result<StreamBarrierRegistration, RuntimeStoreError>>,
    result: Result<StreamBarrierRegistration, RuntimeStoreError>,
    state: &sqlite::RuntimeSqlite,
    commit_hub: &mut StoreCommitHub,
) {
    if let Err(Ok(mut registration)) = reply.send(result) {
        commit_hub.release(&registration.watch.token());
        if let Some(source) = registration.take_backfill_source() {
            let pin = source.disarm();
            apply_store_cleanup(state, commit_hub, StoreCleanup::BackfillPin(pin.pin_id));
        }
        if let Some(pin) = registration
            .take_snapshot_source()
            .and_then(|source| source.into_build_pin_for_immediate_cleanup())
        {
            apply_store_cleanup(state, commit_hub, StoreCleanup::SnapshotBuildPin(pin));
        }
    }
}

pub(super) fn send_backfill_pin_reply(
    reply: oneshot::Sender<Result<ManagedBackfillPlan, RuntimeStoreError>>,
    result: Result<RuntimeBackfillPlan, RuntimeStoreError>,
    cleanup_tx: &mpsc::UnboundedSender<StoreCleanup>,
) {
    let managed = result.map(|plan| ManagedBackfillPlan::new(plan, cleanup_tx.clone()));
    let _ = reply.send(managed);
}

pub(super) fn send_snapshot_build_pin_reply(
    reply: oneshot::Sender<Result<SnapshotMaterializationSource, RuntimeStoreError>>,
    result: Result<SnapshotBarrierSource, RuntimeStoreError>,
    state: &sqlite::RuntimeSqlite,
    commit_hub: &mut StoreCommitHub,
    cleanup_tx: &mpsc::UnboundedSender<StoreCleanup>,
) {
    let managed = result.map(|source| {
        let pin = match &source {
            SnapshotBarrierSource::Build(pin)
            | SnapshotBarrierSource::TransitionBuild(pin)
            | SnapshotBarrierSource::Dynamic(pin) => pin.clone(),
            SnapshotBarrierSource::Ready(_) => unreachable!("direct acquire cannot return Ready"),
        };
        let cleanup = SnapshotBuildPinCleanup::new(pin.clone(), cleanup_tx.clone());
        SnapshotMaterializationSource::new(source, Some(cleanup))
    });
    if let Err(Ok(source)) = reply.send(managed)
        && let Some(pin) = source.into_build_pin_for_immediate_cleanup()
    {
        apply_store_cleanup(state, commit_hub, StoreCleanup::SnapshotBuildPin(pin));
    }
}

pub(super) fn decision_requires_snapshot_source(
    decision: &crate::runtime::backfill::BarrierDecision,
) -> bool {
    matches!(
        decision,
        crate::runtime::backfill::BarrierDecision::Snapshot { .. }
    )
}

pub(super) fn validate_ready_snapshot_origin(
    dynamic_native: bool,
    ready: Option<&ReadySnapshotReference>,
) -> Result<(), RuntimeStoreError> {
    if dynamic_native && ready.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

struct CapturedStreamBarrier {
    target: RuntimeStreamTarget,
    high_water: agentdeck_protocol::runtime::StreamCursor,
    retained_floor: Option<u64>,
    ready_snapshot_base: Option<agentdeck_protocol::runtime::StreamCursor>,
    snapshot_source: Option<SnapshotBarrierSource>,
    catalog_snapshot_source: Option<CatalogSnapshotSource>,
    backfill_pin: Option<RuntimeBackfillPin>,
    relay_committed: RelayCommittedCut,
    decision: crate::runtime::backfill::BarrierDecision,
}

pub(super) fn register_stream_barrier_on_worker(
    state: &sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
    request: RegisterStreamBarrier,
) -> Result<StreamBarrierRegistration, RuntimeStoreError> {
    let target = request.target;
    let generation = request.generation;
    let result = commit_hub.register_then_capture(target, generation, |_| {
        // 此处必须从共享 connection 引用显式创建 Deferred transaction；closure
        // 返回前结束，不跨 await/I/O。
        let transaction = rusqlite::Transaction::new_unchecked(
            &state.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let ledger =
            sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
        let ready_snapshot_reference = super::super::snapshot::authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            target,
        )?;
        let target_cut = stream::load_authenticated_target_cut_in(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &ledger,
            target,
        )?;
        let publication_scope = match target {
            RuntimeStreamTarget::Catalog => PublicationScope::Catalog,
            RuntimeStreamTarget::Conversation(conversation_id) => {
                PublicationScope::Conversation(conversation_id)
            }
        };
        let relay_committed = match super::super::publication::authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            publication_scope,
        )? {
            None => RelayCommittedCut::default(),
            Some(publication) => {
                let inner = agentdeck_protocol::runtime::StreamCursor::from_high_water(
                    publication.committed_inner_cursor,
                );
                if inner
                    .high_water()
                    .zip(target_cut.high_water.high_water())
                    .is_some_and(|(inner, high_water)| inner > high_water)
                    || inner.high_water().is_some() && target_cut.high_water.high_water().is_none()
                {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                RelayCommittedCut {
                    publication_stream_id: Some(publication.publication_stream_id),
                    generation: Some(publication.generation),
                    outer: agentdeck_protocol::runtime::StreamCursor::from_high_water(
                        publication.committed_high_water,
                    ),
                    inner,
                }
            }
        };
        let conversation_origin = match target {
            RuntimeStreamTarget::Catalog => None,
            RuntimeStreamTarget::Conversation(conversation_id) => Some(
                journal::load_authenticated_conversation_snapshot_context(
                    &transaction,
                    &state.key_bundle,
                    state.database_id,
                    conversation_id,
                )?
                .origin,
            ),
        };
        let dynamic_native = conversation_origin == Some(SnapshotOrigin::NativeProjected);
        // directory row 已先完成全量认证；若 exact requested parent 又认证为 native，
        // 该 Ready 仍是语义非法的 legacy/resealed durable row，必须在创建 TEMP pin
        // 或规划 source 前 fail-close，不能只忽略 payload 后继续。
        validate_ready_snapshot_origin(dynamic_native, ready_snapshot_reference.as_ref())?;
        let ready_snapshot_base = (!dynamic_native)
            .then(|| {
                ready_snapshot_reference
                    .as_ref()
                    .map(|reference| reference.base)
            })
            .flatten();
        // CatalogSnapshotProvider 会从 exact durable baseline refresh 到本次冻结 H，
        // 因此它实际发送的 snapshot base 必须就是 H；若仍用旧 ready base 规划，
        // pump 会在 H snapshot 后再次 backfill 同一 delta。Conversation ready row
        // 则保持 exact old base，并由后续 pinned backfill 补到 H。
        let snapshot_base = match target {
            RuntimeStreamTarget::Catalog => target_cut.high_water,
            RuntimeStreamTarget::Conversation(_) if !dynamic_native => {
                ready_snapshot_base.unwrap_or(target_cut.high_water)
            }
            RuntimeStreamTarget::Conversation(_) => target_cut.high_water,
        };
        let decision = plan_barrier(BarrierInput {
            target,
            request: request.request,
            high_water: target_cut.high_water,
            retained_floor: target_cut.retained_floor,
            snapshot_base,
            committed_outer: relay_committed.outer,
        })
        .map_err(|_| RuntimeStoreError::InvalidConfig("stream generation rotation required"))?;
        drop(transaction);
        let now_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
        let catalog_snapshot_source = if target == RuntimeStreamTarget::Catalog
            && decision_requires_snapshot_source(&decision)
        {
            Some(CatalogSnapshotSource::new(
                ready_snapshot_reference.clone(),
                target_cut.high_water,
            ))
        } else {
            None
        };
        let snapshot_source = if decision_requires_snapshot_source(&decision) {
            match (dynamic_native, ready_snapshot_reference) {
                (true, _) => match target {
                    RuntimeStreamTarget::Catalog => None,
                    RuntimeStreamTarget::Conversation(conversation_id) => {
                        let pin = stream::acquire_snapshot_build_pin_at(
                            &state.connection,
                            conversation_id,
                            target_cut.high_water.high_water(),
                            now_ms,
                        )?;
                        Some(SnapshotBarrierSource::Dynamic(pin))
                    }
                },
                (false, Some(reference)) if target != RuntimeStreamTarget::Catalog => {
                    Some(SnapshotBarrierSource::Ready(reference))
                }
                (false, Some(_)) => None,
                (false, None) => match target {
                    RuntimeStreamTarget::Catalog => None,
                    RuntimeStreamTarget::Conversation(conversation_id) => {
                        let pin = stream::acquire_snapshot_build_pin_at(
                            &state.connection,
                            conversation_id,
                            target_cut.high_water.high_water(),
                            now_ms,
                        )?;
                        Some(SnapshotBarrierSource::Build(pin))
                    }
                },
            }
        } else {
            None
        };
        let exact_backfill = match decision {
            crate::runtime::backfill::BarrierDecision::Backfill { after, through, .. }
            | crate::runtime::backfill::BarrierDecision::Snapshot {
                base: after,
                through,
                ..
            } if after != through => through
                .high_water()
                .map(|through| (after.high_water(), through)),
            _ => None,
        };
        let backfill_pin = if let Some((after, through)) = exact_backfill {
            let target = match target {
                RuntimeStreamTarget::Catalog => RuntimeBackfillTarget::Catalog,
                RuntimeStreamTarget::Conversation(conversation_id) => {
                    RuntimeBackfillTarget::Conversation(conversation_id)
                }
            };
            match stream::acquire_backfill_pin_at(state, target, after, through, now_ms) {
                Ok(RuntimeBackfillPlan::Pinned(pin)) => Some(pin),
                Ok(RuntimeBackfillPlan::Current { .. }) => {
                    if let Some(
                        SnapshotBarrierSource::Build(pin)
                        | SnapshotBarrierSource::TransitionBuild(pin)
                        | SnapshotBarrierSource::Dynamic(pin),
                    ) = &snapshot_source
                    {
                        let _ = stream::release_snapshot_build_pin(state, pin);
                    }
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                Err(error) => {
                    if let Some(
                        SnapshotBarrierSource::Build(pin)
                        | SnapshotBarrierSource::TransitionBuild(pin)
                        | SnapshotBarrierSource::Dynamic(pin),
                    ) = &snapshot_source
                    {
                        let _ = stream::release_snapshot_build_pin(state, pin);
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok::<_, RuntimeStoreError>((
            target_cut.high_water,
            CapturedStreamBarrier {
                target,
                high_water: target_cut.high_water,
                retained_floor: target_cut.retained_floor,
                ready_snapshot_base,
                snapshot_source,
                catalog_snapshot_source,
                backfill_pin,
                relay_committed,
                decision,
            },
        ))
    });
    match result {
        Ok((watch, captured)) => {
            let snapshot_cleanup = match &captured.snapshot_source {
                Some(
                    SnapshotBarrierSource::Build(pin)
                    | SnapshotBarrierSource::TransitionBuild(pin)
                    | SnapshotBarrierSource::Dynamic(pin),
                ) => Some(watch.snapshot_build_pin_cleanup(pin.clone())),
                Some(SnapshotBarrierSource::Ready(_)) | None => None,
            };
            let backfill_cleanup = captured
                .backfill_pin
                .as_ref()
                .map(|pin| watch.backfill_pin_cleanup(pin.pin_id));
            Ok(StreamBarrierRegistration {
                target: captured.target,
                high_water: captured.high_water,
                retained_floor: captured.retained_floor,
                ready_snapshot_base: captured.ready_snapshot_base,
                snapshot_source: captured.snapshot_source,
                snapshot_cleanup,
                catalog_snapshot_source: captured.catalog_snapshot_source,
                backfill_pin: captured.backfill_pin,
                backfill_cleanup,
                relay_committed: captured.relay_committed,
                decision: captured.decision,
                watch,
            })
        }
        Err(RegisterCaptureError::Capture(error)) => Err(error),
        Err(RegisterCaptureError::Hub(StoreCommitHubError::WatchIdentityExhausted)) => Err(
            RuntimeStoreError::InvalidConfig("store commit watch identity exhausted"),
        ),
    }
}

/// Transition snapshot 的 frozen cut 不能复用 generic capture：generic 路径会把
/// subscription 当下的 local head L 写入 snapshot/SyncComplete。这里以 Store-issued
/// permit 的 H 作为初始 barrier，同时把 capture 时已经存在的 H→L 区间独立 pin 住，
/// 供 StreamAppliedAck 释放 transition 后再进入 shared publication。
pub(super) fn register_transition_snapshot_barrier_on_worker(
    state: &sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    commit_hub: &mut StoreCommitHub,
    permit: key_transition::TransitionSnapshotPermit,
    generation: WatchGeneration,
    machine_trust_domain: [u8; 32],
) -> Result<StreamBarrierRegistration, RuntimeStoreError> {
    let target = transition_snapshot_target(&permit)?;
    let frozen =
        agentdeck_protocol::runtime::StreamCursor::from_high_water(permit.relay_committed_inner());
    let committed_outer =
        agentdeck_protocol::runtime::StreamCursor::from_high_water(permit.relay_committed_outer());
    let result = commit_hub.register_then_capture(target, generation, |_| {
        let transaction = rusqlite::Transaction::new_unchecked(
            &state.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        key_transition::validate_transition_snapshot_permit_axes_in_transaction(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &permit,
        )?;
        let active_machine =
            pairing::active_machine(&transaction, &state.key_bundle, state.database_id)?;
        let current_authorization = pairing_authorization::load_active_remote_ingress(
            &transaction,
            &state.key_bundle,
            state.database_id,
            machine_trust_domain,
            agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(
                active_machine.record.machine_route,
            ),
            agentdeck_protocol::relay_v2::DeviceRouteId::from_bytes(
                permit.recipient().device_route,
            ),
        )?;
        if current_authorization.grant_serial().value() != permit.recipient().grant_serial
            || current_authorization.key_directory_revision().value()
                != permit.key_directory_revision()
            || current_authorization.authorization_hash() != permit.authorization_hash()
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let ledger =
            sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
        let ready_snapshot_reference = super::super::snapshot::authenticate_directory(
            &transaction,
            &state.key_bundle,
            &ledger,
            target,
        )?;
        let target_cut = stream::load_authenticated_target_cut_in(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &ledger,
            target,
        )?;
        if !cursor_is_at_or_after(target_cut.high_water, frozen) {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        let conversation_origin = match target {
            RuntimeStreamTarget::Catalog => None,
            RuntimeStreamTarget::Conversation(conversation_id) => Some(
                journal::load_authenticated_conversation_snapshot_context(
                    &transaction,
                    &state.key_bundle,
                    state.database_id,
                    conversation_id,
                )?
                .origin,
            ),
        };
        let dynamic_native = conversation_origin == Some(SnapshotOrigin::NativeProjected);
        validate_ready_snapshot_origin(dynamic_native, ready_snapshot_reference.as_ref())?;
        drop(transaction);

        let now_ms = config.clock.now_ms().map_err(RuntimeStoreError::from)?;
        let catalog_snapshot_source = (target == RuntimeStreamTarget::Catalog)
            .then(|| CatalogSnapshotSource::transition(ready_snapshot_reference.clone(), frozen));
        let snapshot_source = match target {
            RuntimeStreamTarget::Catalog => None,
            RuntimeStreamTarget::Conversation(_) if !dynamic_native => {
                match ready_snapshot_reference.clone() {
                    Some(reference) if reference.base == frozen => {
                        Some(SnapshotBarrierSource::Ready(reference))
                    }
                    Some(reference) if cursor_is_strictly_newer(reference.base, frozen) => {
                        let RuntimeStreamTarget::Conversation(conversation_id) = target else {
                            unreachable!("transition conversation target was matched above")
                        };
                        Some(SnapshotBarrierSource::TransitionBuild(
                            stream::acquire_snapshot_build_pin_at(
                                &state.connection,
                                conversation_id,
                                frozen.high_water(),
                                now_ms,
                            )?,
                        ))
                    }
                    _ => {
                        let RuntimeStreamTarget::Conversation(conversation_id) = target else {
                            unreachable!("transition conversation target was matched above")
                        };
                        Some(SnapshotBarrierSource::Build(
                            stream::acquire_snapshot_build_pin_at(
                                &state.connection,
                                conversation_id,
                                frozen.high_water(),
                                now_ms,
                            )?,
                        ))
                    }
                }
            }
            RuntimeStreamTarget::Conversation(conversation_id) => Some(
                SnapshotBarrierSource::Dynamic(stream::acquire_snapshot_build_pin_at(
                    &state.connection,
                    conversation_id,
                    frozen.high_water(),
                    now_ms,
                )?),
            ),
        };
        let continuation_pin = if cursor_is_strictly_newer(target_cut.high_water, frozen) {
            let through = target_cut
                .high_water
                .high_water()
                .ok_or(RuntimeStoreError::PublicationMismatch)?;
            let backfill_target = match target {
                RuntimeStreamTarget::Catalog => RuntimeBackfillTarget::Catalog,
                RuntimeStreamTarget::Conversation(conversation_id) => {
                    RuntimeBackfillTarget::Conversation(conversation_id)
                }
            };
            match stream::acquire_backfill_pin_at(
                state,
                backfill_target,
                frozen.high_water(),
                through,
                now_ms,
            ) {
                Ok(RuntimeBackfillPlan::Pinned(pin)) => Some(pin),
                Ok(RuntimeBackfillPlan::Current { .. }) => {
                    if let Some(
                        SnapshotBarrierSource::Build(pin)
                        | SnapshotBarrierSource::TransitionBuild(pin)
                        | SnapshotBarrierSource::Dynamic(pin),
                    ) = &snapshot_source
                    {
                        let _ = stream::release_snapshot_build_pin(state, pin);
                    }
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
                Err(error) => {
                    if let Some(
                        SnapshotBarrierSource::Build(pin)
                        | SnapshotBarrierSource::TransitionBuild(pin)
                        | SnapshotBarrierSource::Dynamic(pin),
                    ) = &snapshot_source
                    {
                        let _ = stream::release_snapshot_build_pin(state, pin);
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok::<_, RuntimeStoreError>((
            frozen,
            CapturedStreamBarrier {
                target,
                high_water: frozen,
                retained_floor: target_cut.retained_floor,
                ready_snapshot_base: ready_snapshot_reference
                    .as_ref()
                    .map(|reference| reference.base),
                snapshot_source,
                catalog_snapshot_source,
                backfill_pin: continuation_pin,
                relay_committed: RelayCommittedCut {
                    publication_stream_id: Some(permit.publication_stream_id()),
                    generation: Some(permit.generation()),
                    outer: committed_outer,
                    inner: frozen,
                },
                decision: crate::runtime::backfill::BarrierDecision::Snapshot {
                    base: frozen,
                    through: frozen,
                    committed_outer,
                },
            },
        ))
    });
    match result {
        Ok((watch, captured)) => {
            let snapshot_cleanup = match &captured.snapshot_source {
                Some(
                    SnapshotBarrierSource::Build(pin)
                    | SnapshotBarrierSource::TransitionBuild(pin)
                    | SnapshotBarrierSource::Dynamic(pin),
                ) => Some(watch.snapshot_build_pin_cleanup(pin.clone())),
                Some(SnapshotBarrierSource::Ready(_)) | None => None,
            };
            let backfill_cleanup = captured
                .backfill_pin
                .as_ref()
                .map(|pin| watch.backfill_pin_cleanup(pin.pin_id));
            Ok(StreamBarrierRegistration {
                target: captured.target,
                high_water: captured.high_water,
                retained_floor: captured.retained_floor,
                ready_snapshot_base: captured.ready_snapshot_base,
                snapshot_source: captured.snapshot_source,
                snapshot_cleanup,
                catalog_snapshot_source: captured.catalog_snapshot_source,
                backfill_pin: captured.backfill_pin,
                backfill_cleanup,
                relay_committed: captured.relay_committed,
                decision: captured.decision,
                watch,
            })
        }
        Err(RegisterCaptureError::Capture(error)) => Err(error),
        Err(RegisterCaptureError::Hub(StoreCommitHubError::WatchIdentityExhausted)) => Err(
            RuntimeStoreError::InvalidConfig("store commit watch identity exhausted"),
        ),
    }
}

fn transition_snapshot_target(
    permit: &key_transition::TransitionSnapshotPermit,
) -> Result<RuntimeStreamTarget, RuntimeStoreError> {
    match permit.scope() {
        key_transition::KeyTransitionStreamScope::Catalog => Ok(RuntimeStreamTarget::Catalog),
        key_transition::KeyTransitionStreamScope::Conversation(bytes) => {
            Ok(RuntimeStreamTarget::Conversation(RuntimeId::from_bytes(
                RuntimeIdKind::Conversation,
                bytes,
            )?))
        }
    }
}

fn cursor_is_at_or_after(
    candidate: agentdeck_protocol::runtime::StreamCursor,
    baseline: agentdeck_protocol::runtime::StreamCursor,
) -> bool {
    match (candidate.high_water(), baseline.high_water()) {
        (_, None) => true,
        (Some(candidate), Some(baseline)) => candidate >= baseline,
        (None, Some(_)) => false,
    }
}

fn cursor_is_strictly_newer(
    candidate: agentdeck_protocol::runtime::StreamCursor,
    baseline: agentdeck_protocol::runtime::StreamCursor,
) -> bool {
    match (candidate.high_water(), baseline.high_water()) {
        (Some(_), None) => true,
        (Some(candidate), Some(baseline)) => candidate > baseline,
        _ => false,
    }
}
