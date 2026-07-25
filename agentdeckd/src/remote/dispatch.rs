//! Machine RemoteLink 的 endpoint ingress 验证链。
//!
//! 本模块只把 Relay `Send` 按 DeviceSign/AAD → exact current recheck → durable replay →
//! AEAD/decode 的固定顺序规范化，并在通过
//! 本机 authorization ledger 二次复核的 Runtime request。它不持有 conversation、
//! command、receipt 等 canonical 业务状态；这些状态仍只属于 [`RuntimeCore`]。

use agentdeck_crypto::{open_sealed_payload, sha256, verify_sealed};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyControlRequestV1, KeyPurpose, OuterContextV1, OuterFrameKind,
    SealedPayloadKind, SignedSealedBlobV1, VerifiedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::Send as RouteSend;
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
};
use agentdeck_protocol::runtime::{RuntimeEnvelope, RuntimeMessage};

use crate::runtime::store::{
    CurrentRemoteAuthorizationProof, RemoteReplyAuthorization, RuntimeStoreHandle,
};
use crate::runtime::{RemoteIngressReplayClass, RemotePrincipalActivation, RuntimeCore};

use super::key_control::{
    AuthenticatedKeyControlIngress, KeyControlReplyRoute, validate_control_authority,
};
use super::replay::{
    RemoteReplayConfig, RemoteReplayGuard, ReplayDecision, ReplayError, ReplayKeyScope,
    ReplayObservation, ReplayReadiness, ReplaySignatureStatus,
};

/// Remote ingress 在进入 RuntimeCore 前的 typed fail-close 结果。
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RemoteDispatchError {
    #[error("remote outer route is invalid")]
    InvalidOuter,
    #[error("remote authorization is not active")]
    AuthorizationDenied,
    #[error("remote sealed blob is not canonical")]
    InvalidSealedBlob,
    #[error("remote command key binding is invalid")]
    InvalidKeyBinding,
    #[error("remote sender signature is invalid")]
    InvalidSignature,
    #[error("remote replay tuple is invalid")]
    ReplayRejected,
    #[error("remote AEAD payload is invalid")]
    InvalidCiphertext,
    #[error("remote payload is not a Runtime request")]
    InvalidRuntimeRequest,
    #[error("remote payload is not a canonical key-control request")]
    InvalidKeyControl,
    #[error("remote sealed payload kind is not accepted on ingress")]
    InvalidPayloadKind,
}

impl RemoteDispatchError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidOuter => "daemon.remote.ingress.invalid_outer",
            Self::AuthorizationDenied => "daemon.remote.ingress.authorization_denied",
            Self::InvalidSealedBlob => "daemon.remote.ingress.invalid_sealed_blob",
            Self::InvalidKeyBinding => "daemon.remote.ingress.invalid_key_binding",
            Self::InvalidSignature => "daemon.remote.ingress.invalid_signature",
            Self::ReplayRejected => "daemon.remote.ingress.replay_rejected",
            Self::InvalidCiphertext => "daemon.remote.ingress.invalid_ciphertext",
            Self::InvalidRuntimeRequest => "daemon.remote.ingress.invalid_runtime_request",
            Self::InvalidKeyControl => "daemon.remote.ingress.invalid_key_control",
            Self::InvalidPayloadKind => "daemon.remote.ingress.invalid_payload_kind",
        }
    }

    /// Relay 已把 frame 绑定到 claimed device route；sender signature/AAD 或 AEAD tag
    /// 失败时必须隔离该逻辑连接。无法认证到具体 sender 的 outer/canonical 错误仍只丢帧，
    /// 避免把任意畸形 route 变成针对其他设备的断连原语。
    pub(crate) const fn requires_connection_isolation(self) -> bool {
        matches!(self, Self::InvalidSignature | Self::InvalidCiphertext)
    }
}

/// Store/Core 之外只保留机器 route 与 Store handle；不缓存 canonical authorization。
#[derive(Clone)]
pub(crate) struct RemoteIngressDispatcher {
    machine_route: MachineRouteId,
    store: RuntimeStoreHandle,
    replay: RemoteReplayGuard,
}

impl RemoteIngressDispatcher {
    pub(crate) fn new(machine_route: MachineRouteId, store: RuntimeStoreHandle) -> Self {
        Self {
            machine_route,
            replay: RemoteReplayGuard::new(store.clone(), RemoteReplayConfig::default()),
            store,
        }
    }

    /// 第一段：outer 基本约束后从 Store 取得 Active proof，完成 canonical、DeviceSign 与
    /// replay tuple 提取。AEAD/decode 必须等 durable replay admission 之后执行，避免同一
    /// nonce 的不同已签名 ciphertext 用 bad tag 绕过 nonce-reuse quarantine。
    /// 此阶段没有任何 Core API 或 durable mutation。
    pub(crate) async fn verify_send(
        &self,
        send: RouteSend,
    ) -> Result<VerifiedRemoteIngress, RemoteDispatchError> {
        if send.device_route.as_bytes() == &[0; 16] || send.request_route.as_bytes() == &[0; 16] {
            return Err(RemoteDispatchError::InvalidOuter);
        }

        let active = self
            .store
            .load_active_remote_ingress(self.machine_route, send.device_route)
            .await
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;

        let signed = SignedSealedBlobV1::from_wire_bytes(&send.sealed_blob.0)
            .map_err(|_| RemoteDispatchError::InvalidSealedBlob)?;
        if signed.inner.key_id.purpose != KeyPurpose::DeviceCommandTx
            || signed.inner.key_id.epoch != active.command_key_epoch()
            || signed.inner.key_epoch != active.command_key_epoch()
            || signed.inner.key_directory_revision == 0
        {
            return Err(RemoteDispatchError::InvalidKeyBinding);
        }
        let context = uplink_context(
            self.machine_route,
            send.device_route,
            send.request_route,
            signed.inner.key_epoch,
        );
        context
            .validate()
            .map_err(|_| RemoteDispatchError::InvalidOuter)?;
        let verified = verify_sealed(signed, active.device_verifying_key(), &context)
            .map_err(|_| RemoteDispatchError::InvalidSignature)?;

        let counter = u64::from_be_bytes(
            verified.sealed().inner.nonce[4..]
                .try_into()
                .map_err(|_| RemoteDispatchError::ReplayRejected)?,
        );
        let ciphertext_hash = sha256(&verified.sealed().inner.ciphertext);
        let observed_revision =
            KeyDirectoryRevision::new(verified.sealed().inner.key_directory_revision);

        Ok(VerifiedRemoteIngress {
            active,
            sealed: verified,
            context,
            device_route: send.device_route,
            request_route: send.request_route,
            observed_revision,
            counter,
            ciphertext_hash,
        })
    }

    /// 第二段：DeviceSign 与 tuple 提取后，回到 Store 对同一个 opaque Active proof 做
    /// exact Current 复核。revoke/renew/key-directory 变化均在此处阻断；仍未进行
    /// AEAD/decode，也未调用 Core。
    pub(crate) async fn recheck_current(
        &self,
        verified: VerifiedRemoteIngress,
    ) -> Result<CurrentRemoteIngress, RemoteDispatchError> {
        let current = self
            .store
            .recheck_active_remote_ingress(&verified.active)
            .await
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;
        Ok(CurrentRemoteIngress {
            current,
            sealed: verified.sealed,
            context: verified.context,
            device_route: verified.device_route,
            request_route: verified.request_route,
            observed_revision: verified.observed_revision,
            counter: verified.counter,
            ciphertext_hash: verified.ciphertext_hash,
        })
    }

    /// 第三段：exact Active 复核后，先把完整 nonce scope 线性化提交到 durable replay
    /// ledger。只有 Fresh / ExactDuplicate 会释放可进入 RuntimeCore 的 capability。
    pub(crate) async fn admit_replay(
        &self,
        current: CurrentRemoteIngress,
    ) -> Result<AdmittedRemoteIngress, ReplayError> {
        let active = current.current.active();
        let scope = ReplayKeyScope::device_command(
            active.machine_route(),
            active.trust_epoch(),
            active.device_route(),
            active.grant_serial(),
            active.command_key_epoch(),
        )?;
        let decision = self
            .replay
            .admit(
                active.key_directory_revision(),
                ReplayObservation {
                    scope,
                    key_directory_revision: current.observed_revision,
                    sender_counter: current.counter,
                    ciphertext_sha256: current.ciphertext_hash,
                    signature: ReplaySignatureStatus::Verified,
                    readiness: ReplayReadiness::Ready,
                },
            )
            .await?;
        Ok(AdmittedRemoteIngress { decision, current })
    }
}

pub(crate) struct VerifiedRemoteIngress {
    active: crate::runtime::store::ActiveRemoteIngressProof,
    sealed: VerifiedSealedBlobV1,
    context: OuterContextV1,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    observed_revision: KeyDirectoryRevision,
    counter: u64,
    ciphertext_hash: [u8; 32],
}

/// 通过 Store final recheck、尚未消费 staged Core capability 的单次 ingress。
pub(crate) struct CurrentRemoteIngress {
    current: CurrentRemoteAuthorizationProof,
    sealed: VerifiedSealedBlobV1,
    context: OuterContextV1,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    observed_revision: KeyDirectoryRevision,
    counter: u64,
    ciphertext_hash: [u8; 32],
}

enum VerifiedRemotePayload {
    Business(RuntimeEnvelope),
    KeyControl(KeyControlRequestV1),
}

/// durable replay COMMIT 的 typed 结果。非 dispatchable 决策无法取得 Core capability。
pub(crate) struct AdmittedRemoteIngress {
    decision: ReplayDecision,
    current: CurrentRemoteIngress,
}

impl std::fmt::Debug for AdmittedRemoteIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRemoteIngress")
            .field("decision", &self.decision)
            .field("current", &"[REDACTED]")
            .finish()
    }
}

impl AdmittedRemoteIngress {
    #[cfg(test)]
    pub(crate) const fn decision(&self) -> ReplayDecision {
        self.decision
    }

    #[allow(
        dead_code,
        reason = "P4.4 staged-dispatch compatibility entry remains covered by focused tests"
    )]
    pub(crate) fn into_dispatchable(
        self,
    ) -> Result<Option<DispatchableRemoteIngress>, RemoteDispatchError> {
        Ok(match self.into_route()? {
            Some(RemoteIngressRoute::Business(dispatchable)) => Some(dispatchable),
            Some(RemoteIngressRoute::KeyControl(_)) | None => None,
        })
    }

    /// durable replay admission 后才执行 AEAD open/inner decode，并在任何 RuntimeCore API
    /// 前把 business/control 分流。Fresh bad-tag 已经消费 counter；nonce reuse 则在调用本
    /// 方法前被 durable replay ledger 隔离。
    pub(crate) fn into_route(self) -> Result<Option<RemoteIngressRoute>, RemoteDispatchError> {
        let CurrentRemoteIngress {
            current,
            sealed,
            context,
            device_route,
            request_route,
            observed_revision: frame_revision,
            ..
        } = self.current;
        let opened =
            open_sealed_payload(current.active().command_receiving_key(), &context, sealed)
                .map_err(|_| RemoteDispatchError::InvalidCiphertext)?;
        let payload = match opened.payload_kind {
            SealedPayloadKind::CommandRequest => {
                let envelope = RuntimeEnvelope::from_json_bytes_checked(&opened.payload)
                    .map_err(|_| RemoteDispatchError::InvalidRuntimeRequest)?;
                if !matches!(&envelope.body, RuntimeMessage::Request(_)) {
                    return Err(RemoteDispatchError::InvalidRuntimeRequest);
                }
                VerifiedRemotePayload::Business(envelope)
            }
            SealedPayloadKind::KeyUpdate => {
                let control = KeyControlRequestV1::from_canonical_bytes(&opened.payload)
                    .map_err(|_| RemoteDispatchError::InvalidKeyControl)?;
                validate_control_authority(&control, current.active())
                    .map_err(|_| RemoteDispatchError::InvalidKeyControl)?;
                VerifiedRemotePayload::KeyControl(control)
            }
            _ => return Err(RemoteDispatchError::InvalidPayloadKind),
        };
        let route_allowed = match (self.decision, &payload) {
            (ReplayDecision::Fresh | ReplayDecision::ExactDuplicate, _) => true,
            (
                ReplayDecision::KeySyncRequired {
                    local_revision,
                    observed_revision,
                },
                VerifiedRemotePayload::KeyControl(KeyControlRequestV1::KeySync { request }),
            ) => {
                let active_revision = current.active().key_directory_revision();
                active_revision == local_revision
                    && frame_revision == observed_revision
                    && request.known_key_directory_revision == local_revision
                    && request.requested_key_directory_revision == observed_revision
                    && local_revision
                        .value()
                        .checked_add(1)
                        .is_some_and(|next| next == observed_revision.value())
            }
            _ => false,
        };
        if !route_allowed {
            return Ok(None);
        }
        let machine_route = current.active().machine_route();
        Ok(Some(match payload {
            VerifiedRemotePayload::Business(envelope) => {
                let replay = match self.decision {
                    ReplayDecision::Fresh => RemoteIngressReplayClass::Fresh,
                    ReplayDecision::ExactDuplicate => RemoteIngressReplayClass::ExactDuplicate,
                    _ => return Err(RemoteDispatchError::ReplayRejected),
                };
                RemoteIngressRoute::Business(DispatchableRemoteIngress {
                    current,
                    envelope,
                    device_route,
                    request_route,
                    replay,
                })
            }
            VerifiedRemotePayload::KeyControl(control) => {
                RemoteIngressRoute::KeyControl(AuthenticatedKeyControlIngress::new(
                    current,
                    KeyControlReplyRoute {
                        machine_route,
                        device_route,
                        request_route,
                    },
                    control,
                ))
            }
        }))
    }
}

/// RemoteLink 的 pre-Core typed route；control variant 永远不能取得 Core capability。
pub(crate) enum RemoteIngressRoute {
    Business(DispatchableRemoteIngress),
    KeyControl(AuthenticatedKeyControlIngress),
}

/// Fresh / ExactDuplicate durable admission 后才存在的单次 Core capability。
pub(crate) struct DispatchableRemoteIngress {
    current: CurrentRemoteAuthorizationProof,
    envelope: RuntimeEnvelope,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    replay: RemoteIngressReplayClass,
}

impl DispatchableRemoteIngress {
    pub(crate) const fn authorization(&self) -> &CurrentRemoteAuthorizationProof {
        &self.current
    }

    pub(crate) const fn envelope(&self) -> &RuntimeEnvelope {
        &self.envelope
    }

    /// activation 与 shared revoke lease 线性化；replay tuple 已在此调用之前 durable COMMIT。
    pub(crate) fn activate(
        self,
        core: &RuntimeCore,
    ) -> Result<ActivatedRemoteIngress, RemoteDispatchError> {
        let registered = core
            .register_remote_principal(self.current.active())
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;
        let principal = core
            .activate_registered_remote_principal_for_envelope(
                registered,
                &self.current,
                &self.envelope,
                self.replay,
            )
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;
        Ok(ActivatedRemoteIngress {
            principal,
            reply_authorization: self.current.remote_reply_authorization(),
            envelope: self.envelope,
            device_route: self.device_route,
            request_route: self.request_route,
            replay: self.replay,
        })
    }
}

/// RemoteLink 唯一允许交给 RuntimeCore 的规范化结果。
pub(crate) struct ActivatedRemoteIngress {
    principal: RemotePrincipalActivation,
    reply_authorization: RemoteReplyAuthorization,
    envelope: RuntimeEnvelope,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    replay: RemoteIngressReplayClass,
}

impl ActivatedRemoteIngress {
    pub(crate) fn envelope(&self) -> &RuntimeEnvelope {
        &self.envelope
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RemotePrincipalActivation,
        RemoteReplyAuthorization,
        RuntimeEnvelope,
        DeviceRouteId,
        RequestRouteId,
        RemoteIngressReplayClass,
    ) {
        (
            self.principal,
            self.reply_authorization,
            self.envelope,
            self.device_route,
            self.request_route,
            self.replay,
        )
    }
}

fn uplink_context(
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
    key_epoch: u64,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::UplinkSend,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(machine_route),
        device_route: Some(device_route),
        stream_route: None,
        request_route: Some(request_route),
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: key_epoch,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;
    use std::sync::Arc;

    use agentdeck_crypto::{
        AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, seal_symmetric, sign_sealed,
    };
    use agentdeck_protocol::e2ee::{
        AuthorizationCapabilityV1, AuthorizationPermissionV1, KeyControlRequestV1, KeyId,
        KeyPurpose, SealedPayloadKind,
    };
    use agentdeck_protocol::relay_v2::frame::{SealedBlob, Send as RouteSend};
    use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId, RequestRouteId};
    use agentdeck_protocol::runtime::identity::{ConversationId, MessageId};
    use agentdeck_protocol::runtime::{
        RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeRequest,
    };
    use tempfile::TempDir;

    use crate::runtime::store::{
        ConversationDescriptor, MarkConversationRecoveryBlocked, NewConversation,
        RemoteReplyAuthorization, RuntimeId, RuntimeIdKind, RuntimeStoreHandle,
        active_authorization_store_with_pending_transition_for_test,
        active_authorization_store_with_permissions_for_test, complete_active_zero_cut_transition,
        two_active_authorization_store_with_permissions_for_test,
    };
    use crate::runtime::{AgentRouter, RevocationAdministration, RuntimeCore};
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::{RemoteIngressDispatcher, uplink_context};

    const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];
    const DEVICE_COMMAND_KEY: [u8; 32] = [0xc2; 32];
    const SECOND_DEVICE_SIGN_SEED: [u8; 32] = [0xb4; 32];
    const SECOND_DEVICE_COMMAND_KEY: [u8; 32] = [0xe2; 32];

    pub(crate) struct ActiveRemoteDispatchFixture {
        _root: TempDir,
        store: RuntimeStoreHandle,
        core: Arc<RuntimeCore>,
        dispatcher: RemoteIngressDispatcher,
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        command_key: AeadSendingKey,
        device_sign: SigningKey,
    }

    pub(crate) struct SignedRuntimeSendFixture {
        send: RouteSend,
        counter: u64,
    }

    pub(crate) struct TwoActiveRemoteDispatchFixture {
        _root: TempDir,
        store: RuntimeStoreHandle,
        core: Arc<RuntimeCore>,
        machine_route: MachineRouteId,
        first_device: DeviceRouteId,
        second_device: DeviceRouteId,
        first_command_key: AeadSendingKey,
        second_command_key: AeadSendingKey,
        first_device_sign: SigningKey,
        second_device_sign: SigningKey,
    }

    impl SignedRuntimeSendFixture {
        pub(crate) fn send(&self) -> &RouteSend {
            &self.send
        }

        pub(crate) const fn counter(&self) -> u64 {
            self.counter
        }
    }

    pub(crate) async fn active_remote_dispatch_for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    ) -> ActiveRemoteDispatchFixture {
        active_remote_dispatch_for_test_inner(machine_route, device_route, false, None).await
    }

    pub(crate) async fn active_remote_dispatch_with_revocation_for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        revocation: Arc<dyn RevocationAdministration>,
    ) -> ActiveRemoteDispatchFixture {
        active_remote_dispatch_for_test_inner(machine_route, device_route, false, Some(revocation))
            .await
    }

    pub(crate) async fn active_remote_dispatch_with_pending_transition_for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    ) -> ActiveRemoteDispatchFixture {
        active_remote_dispatch_for_test_inner(machine_route, device_route, true, None).await
    }

    async fn active_remote_dispatch_for_test_inner(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        preserve_bootstrap_transition: bool,
        revocation: Option<Arc<dyn RevocationAdministration>>,
    ) -> ActiveRemoteDispatchFixture {
        let root = tempfile::tempdir().expect("create P4.4 dispatch tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure P4.4 dispatch tempdir");
        }
        let database = root.path().join("runtime.db");
        let keys = MemoryKeyStore::new();
        let storage_kek =
            load_or_create_storage_kek(&keys, &database).expect("create dispatch StorageKEK");
        let store = if preserve_bootstrap_transition {
            active_authorization_store_with_pending_transition_for_test(
                &database,
                storage_kek,
                all_capabilities(),
                all_permissions(),
            )
            .await
        } else {
            active_authorization_store_with_permissions_for_test(
                &database,
                storage_kek,
                all_capabilities(),
                all_permissions(),
            )
            .await
        };
        let trust_domain = store
            .machine_trust_domain_for_test()
            .expect("derive dispatch domain");
        let core = RuntimeCore::new(
            store.clone(),
            Arc::new(AgentRouter::with_runtime_store(store.clone())),
            trust_domain,
        )
        .expect("construct dispatch Core");
        let core = match revocation {
            Some(revocation) => core.with_revocation_administration(revocation),
            None => core,
        };
        let core = Arc::new(core);
        core.recover()
            .await
            .expect("recover dispatch Core before remote start");
        ActiveRemoteDispatchFixture {
            _root: root,
            store: store.clone(),
            core,
            dispatcher: RemoteIngressDispatcher::new(machine_route, store),
            machine_route,
            device_route,
            command_key: AeadSendingKey::with_derived_nonce_prefix(
                KeyId {
                    purpose: KeyPurpose::DeviceCommandTx,
                    epoch: 1,
                },
                1,
                1,
                SecretAeadKey::from_bytes(DEVICE_COMMAND_KEY),
            ),
            device_sign: SigningKey::from_seed(&DEVICE_SIGN_SEED),
        }
    }

    pub(crate) async fn active_remote_dispatch_with_recovery_blocked_for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    ) -> (ActiveRemoteDispatchFixture, ConversationId, ConversationId) {
        let root = tempfile::tempdir().expect("create P4.4 recovery-policy tempdir");
        secure_tempdir_for_test(&root);
        let database = root.path().join("runtime.db");
        let keys = MemoryKeyStore::new();
        let store = active_authorization_store_with_permissions_for_test(
            &database,
            load_or_create_storage_kek(&keys, &database)
                .expect("create recovery-policy StorageKEK"),
            all_capabilities(),
            all_permissions(),
        )
        .await;
        store
            .ensure_remote_catalog_publication_after_transition()
            .await
            .expect("ensure recovery-policy production Catalog carrier");
        let blocked = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xb1; 16])
            .expect("valid blocked conversation id");
        let healthy = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xb2; 16])
            .expect("valid healthy conversation id");
        for (conversation_id, adapter_seed, title) in
            [(blocked, 0xc1, "blocked"), (healthy, 0xc2, "healthy")]
        {
            store
                .create_conversation(NewConversation {
                    conversation_id,
                    adapter_state_key: RuntimeId::from_bytes(
                        RuntimeIdKind::AdapterState,
                        [adapter_seed; 16],
                    )
                    .expect("valid recovery-policy adapter state id"),
                    descriptor: ConversationDescriptor {
                        agent_kind: agentdeck_protocol::AgentKind::Codex,
                        title: Some(title.to_owned()),
                        cwd: PathBuf::from("/tmp/agentdeck-p44-recovery-policy"),
                    },
                })
                .await
                .expect("create recovery-policy conversation");
            complete_active_zero_cut_transition(&store).await;
        }
        store
            .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
                conversation_id: blocked,
                expected_command: None,
            })
            .await
            .expect("mark one RemoteLink conversation RecoveryBlocked");
        let command_revision = store
            .load_active_remote_ingress(machine_route, device_route)
            .await
            .expect("load recovery-policy authorization after conversation activations")
            .key_directory_revision()
            .value();
        let trust_domain = store
            .machine_trust_domain_for_test()
            .expect("derive recovery-policy trust domain");
        let core = Arc::new(
            RuntimeCore::new(
                store.clone(),
                Arc::new(AgentRouter::with_runtime_store(store.clone())),
                trust_domain,
            )
            .expect("construct recovery-policy Core"),
        );
        core.recover()
            .await
            .expect("recover mixed RecoveryBlocked/healthy Core");
        let fixture = ActiveRemoteDispatchFixture {
            _root: root,
            store: store.clone(),
            core,
            dispatcher: RemoteIngressDispatcher::new(machine_route, store),
            machine_route,
            device_route,
            command_key: command_key(DEVICE_COMMAND_KEY, command_revision),
            device_sign: SigningKey::from_seed(&DEVICE_SIGN_SEED),
        };
        (
            fixture,
            ConversationId::new(blocked.to_canonical_string()),
            ConversationId::new(healthy.to_canonical_string()),
        )
    }

    pub(crate) async fn two_active_remote_dispatch_for_test(
        machine_route: MachineRouteId,
        first_device: DeviceRouteId,
        second_device: DeviceRouteId,
    ) -> TwoActiveRemoteDispatchFixture {
        let root = tempfile::tempdir().expect("create P4.4 two-device tempdir");
        secure_tempdir_for_test(&root);
        let database = root.path().join("runtime.db");
        let keys = MemoryKeyStore::new();
        let store = two_active_authorization_store_with_permissions_for_test(
            &database,
            load_or_create_storage_kek(&keys, &database)
                .expect("create two-device dispatch StorageKEK"),
            all_capabilities(),
            all_permissions(),
        )
        .await;
        let trust_domain = store
            .machine_trust_domain_for_test()
            .expect("derive two-device dispatch domain");
        // Fixture now drives the real P4.5 membership transition to BusinessReady, including
        // the old member's authenticated KeyUpdate ACK. No test-only revision alignment remains.
        let first_revision = store
            .load_active_remote_ingress(machine_route, first_device)
            .await
            .expect("load first two-device authorization")
            .key_directory_revision()
            .value();
        let second_revision = store
            .load_active_remote_ingress(machine_route, second_device)
            .await
            .expect("load second two-device authorization")
            .key_directory_revision()
            .value();
        assert_eq!(
            first_revision, second_revision,
            "both active devices must authenticate the committed directory revision"
        );
        let core = Arc::new(
            RuntimeCore::new(
                store.clone(),
                Arc::new(AgentRouter::with_runtime_store(store.clone())),
                trust_domain,
            )
            .expect("construct two-device dispatch Core"),
        );
        core.recover()
            .await
            .expect("recover two-device Core before remote start");
        TwoActiveRemoteDispatchFixture {
            _root: root,
            store: store.clone(),
            core,
            machine_route,
            first_device,
            second_device,
            first_command_key: command_key(DEVICE_COMMAND_KEY, first_revision),
            second_command_key: command_key(SECOND_DEVICE_COMMAND_KEY, second_revision),
            first_device_sign: SigningKey::from_seed(&DEVICE_SIGN_SEED),
            second_device_sign: SigningKey::from_seed(&SECOND_DEVICE_SIGN_SEED),
        }
    }

    impl ActiveRemoteDispatchFixture {
        pub(crate) fn dispatcher(&self) -> &RemoteIngressDispatcher {
            &self.dispatcher
        }

        pub(crate) fn core(&self) -> &RuntimeCore {
            &self.core
        }

        pub(crate) fn core_arc(&self) -> Arc<RuntimeCore> {
            Arc::clone(&self.core)
        }

        pub(crate) fn store(&self) -> RuntimeStoreHandle {
            self.store.clone()
        }

        pub(crate) fn signed_runtime_send(
            &self,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
        ) -> SignedRuntimeSendFixture {
            let envelope = RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id,
                body: RuntimeMessage::Request(request),
            };
            let bytes = envelope
                .to_json_bytes_checked()
                .expect("encode dispatch Runtime request");
            signed_payload_send(
                self.machine_route,
                self.device_route,
                request_route,
                SealedPayloadKind::CommandRequest,
                &bytes,
                &self.command_key,
                &self.device_sign,
                counter,
                false,
            )
        }

        pub(crate) fn signed_runtime_send_with_tampered_ciphertext_for_test(
            &self,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
        ) -> SignedRuntimeSendFixture {
            let envelope = RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id,
                body: RuntimeMessage::Request(request),
            };
            let bytes = envelope
                .to_json_bytes_checked()
                .expect("encode tampered dispatch Runtime request");
            signed_payload_send(
                self.machine_route,
                self.device_route,
                request_route,
                SealedPayloadKind::CommandRequest,
                &bytes,
                &self.command_key,
                &self.device_sign,
                counter,
                true,
            )
        }

        pub(crate) fn signed_runtime_send_with_revision_for_test(
            &self,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
            key_directory_revision: u64,
        ) -> SignedRuntimeSendFixture {
            let envelope = RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id,
                body: RuntimeMessage::Request(request),
            };
            let bytes = envelope
                .to_json_bytes_checked()
                .expect("encode revision-scoped dispatch Runtime request");
            let command_key = command_key(DEVICE_COMMAND_KEY, key_directory_revision);
            signed_payload_send(
                self.machine_route,
                self.device_route,
                request_route,
                SealedPayloadKind::CommandRequest,
                &bytes,
                &command_key,
                &self.device_sign,
                counter,
                false,
            )
        }

        pub(crate) fn signed_key_control_send_for_test(
            &self,
            request_route: RequestRouteId,
            control: KeyControlRequestV1,
            counter: u64,
            tamper_ciphertext: bool,
        ) -> SignedRuntimeSendFixture {
            let bytes = control
                .canonical_bytes()
                .expect("encode canonical key-control request");
            self.signed_payload_send_for_test(
                request_route,
                SealedPayloadKind::KeyUpdate,
                bytes,
                counter,
                tamper_ciphertext,
            )
        }

        pub(crate) fn signed_key_control_probe_with_revision_for_test(
            &self,
            request_route: RequestRouteId,
            control: KeyControlRequestV1,
            counter: u64,
            key_directory_revision: u64,
        ) -> SignedRuntimeSendFixture {
            let bytes = control
                .canonical_bytes()
                .expect("encode canonical key-control recovery probe");
            let command_key = command_key(DEVICE_COMMAND_KEY, key_directory_revision);
            signed_payload_send(
                self.machine_route,
                self.device_route,
                request_route,
                SealedPayloadKind::KeyUpdate,
                &bytes,
                &command_key,
                &self.device_sign,
                counter,
                false,
            )
        }

        pub(crate) fn signed_payload_send_for_test(
            &self,
            request_route: RequestRouteId,
            payload_kind: SealedPayloadKind,
            payload: Vec<u8>,
            counter: u64,
            tamper_ciphertext: bool,
        ) -> SignedRuntimeSendFixture {
            signed_payload_send(
                self.machine_route,
                self.device_route,
                request_route,
                payload_kind,
                &payload,
                &self.command_key,
                &self.device_sign,
                counter,
                tamper_ciphertext,
            )
        }

        pub(crate) async fn reply_authorization(&self) -> RemoteReplyAuthorization {
            let active = self
                .store
                .load_active_remote_ingress(self.machine_route, self.device_route)
                .await
                .expect("load reply authorization Active proof");
            self.core
                .register_remote_principal(&active)
                .expect("register reply authorization principal");
            self.store
                .recheck_active_remote_ingress(&active)
                .await
                .expect("recheck reply authorization")
                .remote_reply_authorization()
        }

        pub(crate) async fn shutdown(self) {
            self.core.shutdown().await.expect("shutdown dispatch Core");
        }
    }

    impl TwoActiveRemoteDispatchFixture {
        pub(crate) fn core_arc(&self) -> Arc<RuntimeCore> {
            Arc::clone(&self.core)
        }

        pub(crate) fn store(&self) -> RuntimeStoreHandle {
            self.store.clone()
        }

        pub(crate) fn key_directory_revision(&self, device_route: DeviceRouteId) -> u64 {
            if device_route == self.first_device {
                self.first_command_key.key_directory_revision
            } else if device_route == self.second_device {
                self.second_command_key.key_directory_revision
            } else {
                panic!("unknown two-device dispatch route")
            }
        }

        pub(crate) fn signed_runtime_send(
            &self,
            device_route: DeviceRouteId,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
        ) -> SignedRuntimeSendFixture {
            let (command_key, device_sign) = if device_route == self.first_device {
                (&self.first_command_key, &self.first_device_sign)
            } else if device_route == self.second_device {
                (&self.second_command_key, &self.second_device_sign)
            } else {
                panic!("unknown two-device dispatch route")
            };
            signed_runtime_send(
                self.machine_route,
                device_route,
                request_route,
                message_id,
                request,
                counter,
                command_key,
                device_sign,
                false,
            )
        }

        pub(crate) fn signed_runtime_send_with_tampered_ciphertext(
            &self,
            device_route: DeviceRouteId,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
        ) -> SignedRuntimeSendFixture {
            let (command_key, device_sign) = if device_route == self.first_device {
                (&self.first_command_key, &self.first_device_sign)
            } else if device_route == self.second_device {
                (&self.second_command_key, &self.second_device_sign)
            } else {
                panic!("unknown two-device dispatch route")
            };
            signed_runtime_send(
                self.machine_route,
                device_route,
                request_route,
                message_id,
                request,
                counter,
                command_key,
                device_sign,
                true,
            )
        }

        pub(crate) fn signed_runtime_send_with_revision(
            &self,
            device_route: DeviceRouteId,
            request_route: RequestRouteId,
            message_id: MessageId,
            request: RuntimeRequest,
            counter: u64,
            key_directory_revision: u64,
        ) -> SignedRuntimeSendFixture {
            let (key, device_sign) = if device_route == self.first_device {
                (DEVICE_COMMAND_KEY, &self.first_device_sign)
            } else if device_route == self.second_device {
                (SECOND_DEVICE_COMMAND_KEY, &self.second_device_sign)
            } else {
                panic!("unknown two-device dispatch route")
            };
            let command_key = command_key(key, key_directory_revision);
            signed_runtime_send(
                self.machine_route,
                device_route,
                request_route,
                message_id,
                request,
                counter,
                &command_key,
                device_sign,
                false,
            )
        }

        pub(crate) async fn shutdown(self) {
            self.core
                .shutdown()
                .await
                .expect("shutdown two-device dispatch Core");
        }
    }

    fn command_key(key: [u8; 32], revision: u64) -> AeadSendingKey {
        AeadSendingKey::with_derived_nonce_prefix(
            KeyId {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: 1,
            },
            1,
            revision,
            SecretAeadKey::from_bytes(key),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_runtime_send(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        request_route: RequestRouteId,
        message_id: MessageId,
        request: RuntimeRequest,
        counter: u64,
        command_key: &AeadSendingKey,
        device_sign: &SigningKey,
        tamper_ciphertext: bool,
    ) -> SignedRuntimeSendFixture {
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id,
            body: RuntimeMessage::Request(request),
        };
        let bytes = envelope
            .to_json_bytes_checked()
            .expect("encode dispatch Runtime request");
        signed_payload_send(
            machine_route,
            device_route,
            request_route,
            SealedPayloadKind::CommandRequest,
            &bytes,
            command_key,
            device_sign,
            counter,
            tamper_ciphertext,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_payload_send(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        request_route: RequestRouteId,
        payload_kind: SealedPayloadKind,
        payload: &[u8],
        command_key: &AeadSendingKey,
        device_sign: &SigningKey,
        counter: u64,
        tamper_ciphertext: bool,
    ) -> SignedRuntimeSendFixture {
        let context = uplink_context(
            machine_route,
            device_route,
            request_route,
            command_key.epoch,
        );
        let mut unsigned = seal_symmetric(
            command_key,
            &context,
            payload_kind,
            payload,
            SenderCounter(counter),
        )
        .expect("seal dispatch ingress payload");
        if tamper_ciphertext {
            unsigned.ciphertext[0] ^= 0x80;
        }
        let signed = sign_sealed(unsigned, device_sign, &context);
        SignedRuntimeSendFixture {
            send: RouteSend {
                device_route,
                request_route,
                sealed_blob: SealedBlob(signed.to_wire_bytes()),
            },
            counter,
        }
    }

    fn secure_tempdir_for_test(root: &TempDir) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure P4.4 dispatch tempdir");
        }
    }

    fn all_capabilities() -> Vec<AuthorizationCapabilityV1> {
        vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
            AuthorizationCapabilityV1::Prompt,
            AuthorizationCapabilityV1::Command,
            AuthorizationCapabilityV1::Approval,
            AuthorizationCapabilityV1::Metadata,
            AuthorizationCapabilityV1::SelfRevocation,
        ]
    }

    fn all_permissions() -> Vec<AuthorizationPermissionV1> {
        vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
            AuthorizationPermissionV1::ConversationStart,
            AuthorizationPermissionV1::PromptSend,
            AuthorizationPermissionV1::CommandCancel,
            AuthorizationPermissionV1::ApprovalResolve,
            AuthorizationPermissionV1::ApprovalRetry,
            AuthorizationPermissionV1::MetadataWrite,
            AuthorizationPermissionV1::RevokeSelf,
        ]
    }
}
