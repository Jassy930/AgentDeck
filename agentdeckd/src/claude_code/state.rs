//! Claude Code 私有、派生的 resume 映射。
//!
//! `claude_code_adapter_state` 只保存 StorageKEK 保护的 legacy resume id，或绑定
//! exact project component + transcript filename 的 versioned private ref。CC 原生
//! JSONL/history 始终是事实源；本模块不创建 `cc-meta/`，也不保存 title、archive、
//! status 或 transcript。

use agentdeck_protocol::ThreadId;

use crate::claude_code::history::{
    NativeTranscriptRefV1, VerifiedNativeHistoryEntry, safe_legacy_session_id,
};
#[cfg(test)]
use crate::runtime::store::RuntimeStoreHandle;
use crate::runtime::store::{ClaudeCodeAdapterStateVault, RuntimeId, RuntimeStoreError};
use crate::security::SecretBytes;

/// 只允许 Claude Code adapter/history reconciliation 持有的 typed repository。
#[derive(Clone, Debug)]
pub(super) struct ClaudeCodeStateRepository {
    vault: ClaudeCodeAdapterStateVault,
}

impl ClaudeCodeStateRepository {
    #[must_use]
    pub(super) fn new(vault: ClaudeCodeAdapterStateVault) -> Self {
        Self { vault }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(store: RuntimeStoreHandle) -> Self {
        Self::new(crate::runtime::store::claude_code_adapter_state_vault_for_test(&store))
    }

    /// 首次绑定后不可改写；相同 key/ref 重试返回成功，不同 ref fail-close。
    pub(super) async fn bind(
        &self,
        adapter_state_key: RuntimeId,
        resume_reference: ThreadId,
    ) -> Result<(), RuntimeStoreError> {
        self.vault
            .bind(
                adapter_state_key,
                SecretBytes::new(resume_reference.0.into_bytes()),
            )
            .await
    }

    /// 仅从 CC 私有 namespace 解密；另一 adapter 已占用该 key 时返回 typed mismatch。
    pub(super) async fn resolve(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<Option<ThreadId>, RuntimeStoreError> {
        self.resolve_private(adapter_state_key)
            .await?
            .map(ResolvedClaudeCodeReference::into_thread_id)
            .transpose()
    }

    /// Canonical native-history read 保留 exact versioned ref；旧 managed binding
    /// 继续以 legacy session id 解释，不在 C-a 做不可逆 eager rewrite。
    pub(super) async fn resolve_private(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<Option<ResolvedClaudeCodeReference>, RuntimeStoreError> {
        self.vault
            .resolve(adapter_state_key)
            .await?
            .map(decode_state_reference)
            .transpose()
    }

    /// 只接受 `history` 模块验证过本机 JSONL 实体的 opaque entry；客户端 wire
    /// `HistoryListItem` 不能直接构造该类型。
    pub(super) async fn bind_verified_native_history(
        &self,
        adapter_state_key: RuntimeId,
        native: VerifiedNativeHistoryEntry,
    ) -> Result<(), RuntimeStoreError> {
        self.vault
            .bind(
                adapter_state_key,
                SecretBytes::new(native.into_private_reference().encode()),
            )
            .await
    }
}

pub(super) enum ResolvedClaudeCodeReference {
    LegacySessionId(ThreadId),
    NativeV1(NativeTranscriptRefV1),
}

impl ResolvedClaudeCodeReference {
    pub(super) fn into_thread_id(self) -> Result<ThreadId, RuntimeStoreError> {
        match self {
            Self::LegacySessionId(thread_id) => Ok(thread_id),
            Self::NativeV1(reference) => reference
                .resume_thread_id()
                .map(ThreadId)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

fn decode_state_reference(
    secret: SecretBytes,
) -> Result<ResolvedClaudeCodeReference, RuntimeStoreError> {
    let bytes = secret.expose_secret();
    if NativeTranscriptRefV1::is_encoded(bytes) {
        return NativeTranscriptRefV1::decode(bytes)
            .map(ResolvedClaudeCodeReference::NativeV1)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let value =
        std::str::from_utf8(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if !safe_legacy_session_id(value) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(ResolvedClaudeCodeReference::LegacySessionId(ThreadId(
        value.to_owned(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_decodes_legacy_session_id_without_rewriting_it() {
        let decoded = decode_state_reference(SecretBytes::new(b"legacy-session-00000001".to_vec()))
            .expect("legacy state reference");
        assert_eq!(
            decoded.into_thread_id().unwrap(),
            ThreadId("legacy-session-00000001".into())
        );
    }

    #[test]
    fn state_decodes_v1_exact_ref_to_resume_id() {
        let reference = NativeTranscriptRefV1::from_components_for_test(
            "-tmp-project".into(),
            "10000000-0000-4000-8000-000000000001.jsonl".into(),
        )
        .unwrap();
        let decoded = decode_state_reference(SecretBytes::new(reference.encode()))
            .expect("versioned native state reference");
        assert_eq!(
            decoded.into_thread_id().unwrap(),
            ThreadId("10000000-0000-4000-8000-000000000001".into())
        );
    }

    #[test]
    fn state_rejects_unknown_native_ref_version_instead_of_legacy_fallback() {
        let reference = NativeTranscriptRefV1::from_components_for_test(
            "-tmp-project".into(),
            "10000000-0000-4000-8000-000000000001.jsonl".into(),
        )
        .unwrap();
        let mut encoded = reference.encode();
        encoded[8] = 2;
        assert!(decode_state_reference(SecretBytes::new(encoded)).is_err());
    }
}
