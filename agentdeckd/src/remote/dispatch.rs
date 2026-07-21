//! Machine RemoteLink 的 endpoint ingress 验证链。
//!
//! 本模块只把 Relay `Send` 规范化为已经完成 DeviceSign/AAD/replay/AEAD、且通过
//! 本机 authorization ledger 二次复核的 Runtime request。它不持有 conversation、
//! command、receipt 等 canonical 业务状态；这些状态仍只属于 [`RuntimeCore`]。

use agentdeck_crypto::replay::{ReplayDisposition, ReplayWindow};
use agentdeck_crypto::{open_sealed_payload, sha256, verify_sealed};
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, KeyPurpose, OuterContextV1, OuterFrameKind, SealedPayloadKind,
    SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::Send as RouteSend;
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
};
use agentdeck_protocol::runtime::{RuntimeEnvelope, RuntimeMessage};

use crate::runtime::store::{
    CurrentRemoteAuthorizationProof, RemoteReplyAuthorization, RuntimeStoreHandle,
};
use crate::runtime::{AuthenticatedPrincipal, RuntimeCore};

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
        }
    }
}

/// Store/Core 之外只保留机器 route 与 Store handle；不缓存 canonical authorization。
#[derive(Clone)]
pub(crate) struct RemoteIngressDispatcher {
    machine_route: MachineRouteId,
    store: RuntimeStoreHandle,
}

impl RemoteIngressDispatcher {
    pub(crate) fn new(machine_route: MachineRouteId, store: RuntimeStoreHandle) -> Self {
        Self {
            machine_route,
            store,
        }
    }

    /// 第一段：outer 基本约束后从 Store 取得 Active proof，完成 canonical、DeviceSign、
    /// AAD、replay candidate、AEAD 与 Runtime request 全链。此阶段没有任何 Core API。
    pub(crate) async fn verify_send(
        &self,
        send: RouteSend,
        live_replay: &ReplayWindow,
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
            || signed.inner.key_directory_revision != active.key_directory_revision().value()
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

        let mut replay_candidate = live_replay.clone();
        let counter = u64::from_be_bytes(
            verified.sealed().inner.nonce[4..]
                .try_into()
                .map_err(|_| RemoteDispatchError::ReplayRejected)?,
        );
        let ciphertext_hash = sha256(&verified.sealed().inner.ciphertext);
        if replay_candidate
            .observe(counter, ciphertext_hash)
            .map_err(|_| RemoteDispatchError::ReplayRejected)?
            != ReplayDisposition::Fresh
        {
            return Err(RemoteDispatchError::ReplayRejected);
        }

        let payload = open_sealed_payload(active.command_receiving_key(), &context, verified)
            .map_err(|_| RemoteDispatchError::InvalidCiphertext)?;
        if payload.payload_kind != SealedPayloadKind::CommandRequest {
            return Err(RemoteDispatchError::InvalidRuntimeRequest);
        }
        let envelope = RuntimeEnvelope::from_json_bytes_checked(&payload.payload)
            .map_err(|_| RemoteDispatchError::InvalidRuntimeRequest)?;
        if !matches!(&envelope.body, RuntimeMessage::Request(_)) {
            return Err(RemoteDispatchError::InvalidRuntimeRequest);
        }

        Ok(VerifiedRemoteIngress {
            active,
            replay_candidate,
            envelope,
            device_route: send.device_route,
            request_route: send.request_route,
        })
    }

    /// 第二段：crypto 全链完成后，回到 Store 对同一个 opaque Active proof 做 exact
    /// Current 复核。revoke/renew/key-directory 变化均在此处阻断；仍未调用 Core。
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
            replay_candidate: verified.replay_candidate,
            envelope: verified.envelope,
            device_route: verified.device_route,
            request_route: verified.request_route,
        })
    }
}

pub(crate) struct VerifiedRemoteIngress {
    active: crate::runtime::store::ActiveRemoteIngressProof,
    replay_candidate: ReplayWindow,
    envelope: RuntimeEnvelope,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
}

/// 通过 Store final recheck、尚未消费 staged Core capability 的单次 ingress。
pub(crate) struct CurrentRemoteIngress {
    current: CurrentRemoteAuthorizationProof,
    replay_candidate: ReplayWindow,
    envelope: RuntimeEnvelope,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
}

impl CurrentRemoteIngress {
    /// activation 与 shared revoke lease 线性化。只有 activation 成功才把 staged replay
    /// window 发布为 live；失败时旧 counter 仍保持未消费，且不存在可进入 Core 的值。
    pub(crate) fn activate(
        self,
        core: &RuntimeCore,
        live_replay: &mut ReplayWindow,
    ) -> Result<ActivatedRemoteIngress, RemoteDispatchError> {
        let registered = core
            .register_remote_principal(self.current.active())
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;
        let principal = core
            .activate_registered_remote_principal(registered, &self.current)
            .map_err(|_| RemoteDispatchError::AuthorizationDenied)?;
        *live_replay = self.replay_candidate;
        Ok(ActivatedRemoteIngress {
            principal,
            reply_authorization: self.current.remote_reply_authorization(),
            envelope: self.envelope,
            device_route: self.device_route,
            request_route: self.request_route,
        })
    }
}

/// RemoteLink 唯一允许交给 RuntimeCore 的规范化结果。
pub(crate) struct ActivatedRemoteIngress {
    principal: AuthenticatedPrincipal,
    reply_authorization: RemoteReplyAuthorization,
    envelope: RuntimeEnvelope,
    device_route: DeviceRouteId,
    request_route: RequestRouteId,
}

impl ActivatedRemoteIngress {
    pub(crate) fn envelope(&self) -> &RuntimeEnvelope {
        &self.envelope
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthenticatedPrincipal,
        RemoteReplyAuthorization,
        RuntimeEnvelope,
        DeviceRouteId,
        RequestRouteId,
    ) {
        (
            self.principal,
            self.reply_authorization,
            self.envelope,
            self.device_route,
            self.request_route,
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
        AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, seal_symmetric, sha256,
        sign_sealed,
    };
    use agentdeck_protocol::e2ee::{
        AuthorizationCapabilityV1, AuthorizationPermissionV1, KeyId, KeyPurpose, SealedPayloadKind,
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
        RemoteReplyAuthorization, RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle,
        active_authorization_store_with_permissions_for_test,
        two_active_authorization_store_with_permissions_for_test,
    };
    use crate::runtime::{AgentRouter, RuntimeCore};
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
        ciphertext_hash: [u8; 32],
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

        pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
            self.ciphertext_hash
        }
    }

    pub(crate) async fn active_remote_dispatch_for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
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
        let store = active_authorization_store_with_permissions_for_test(
            &database,
            load_or_create_storage_kek(&keys, &database).expect("create dispatch StorageKEK"),
            all_capabilities(),
            all_permissions(),
        )
        .await;
        let trust_domain = store
            .machine_trust_domain_for_test()
            .expect("derive dispatch domain");
        let core = Arc::new(
            RuntimeCore::new(
                store.clone(),
                Arc::new(AgentRouter::with_runtime_store(store.clone())),
                trust_domain,
            )
            .expect("construct dispatch Core"),
        );
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
            command_key: AeadSendingKey::new(
                KeyId {
                    purpose: KeyPurpose::DeviceCommandTx,
                    epoch: 1,
                },
                1,
                1,
                [0x7a; 4],
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
        }
        store
            .mark_conversation_recovery_blocked(MarkConversationRecoveryBlocked {
                conversation_id: blocked,
                expected_command: None,
            })
            .await
            .expect("mark one RemoteLink conversation RecoveryBlocked");
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
            command_key: command_key(DEVICE_COMMAND_KEY, 1, [0x7a; 4]),
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
        assert!(matches!(
            store
                .load_active_remote_ingress(machine_route, first_device)
                .await,
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
        // P4.5 才会实现真实 KeyUpdate。这里仅模拟第一台设备已经确认当前
        // directory revision；production lower-revision loader 仍由上面的断言证明 fail-close。
        store
            .align_active_authorization_revision_for_test(first_device)
            .await
            .expect("align first authorization after simulated KeyUpdate confirmation");
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
            first_command_key: command_key(DEVICE_COMMAND_KEY, first_revision, [0x7a; 4]),
            second_command_key: command_key(SECOND_DEVICE_COMMAND_KEY, second_revision, [0x7b; 4]),
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
            let context = uplink_context(
                self.machine_route,
                self.device_route,
                request_route,
                self.command_key.epoch,
            );
            let unsigned = seal_symmetric(
                &self.command_key,
                &context,
                SealedPayloadKind::CommandRequest,
                &bytes,
                SenderCounter(counter),
            )
            .expect("seal dispatch Runtime request");
            let ciphertext_hash = sha256(&unsigned.ciphertext);
            let signed = sign_sealed(unsigned, &self.device_sign, &context);
            SignedRuntimeSendFixture {
                send: RouteSend {
                    device_route: self.device_route,
                    request_route,
                    sealed_blob: SealedBlob(signed.to_wire_bytes()),
                },
                counter,
                ciphertext_hash,
            }
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

        pub(crate) async fn shutdown(self) {
            self.core
                .shutdown()
                .await
                .expect("shutdown two-device dispatch Core");
        }
    }

    fn command_key(key: [u8; 32], revision: u64, nonce_prefix: [u8; 4]) -> AeadSendingKey {
        AeadSendingKey::new(
            KeyId {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: 1,
            },
            1,
            revision,
            nonce_prefix,
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
        let context = uplink_context(
            machine_route,
            device_route,
            request_route,
            command_key.epoch,
        );
        let mut unsigned = seal_symmetric(
            command_key,
            &context,
            SealedPayloadKind::CommandRequest,
            &bytes,
            SenderCounter(counter),
        )
        .expect("seal dispatch Runtime request");
        if tamper_ciphertext {
            unsigned.ciphertext[0] ^= 0x80;
        }
        let ciphertext_hash = sha256(&unsigned.ciphertext);
        let signed = sign_sealed(unsigned, device_sign, &context);
        SignedRuntimeSendFixture {
            send: RouteSend {
                device_route,
                request_route,
                sealed_blob: SealedBlob(signed.to_wire_bytes()),
            },
            counter,
            ciphertext_hash,
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
