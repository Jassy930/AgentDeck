//! Claude Code 私有、派生的 resume 映射。
//!
//! `claude_code_adapter_state` 只保存 StorageKEK 保护的
//! `adapterStateKey -> CC session id`。CC 原生 JSONL/history 始终是事实源；本模块
//! 不创建 `cc-meta/`，也不保存 title、archive、status 或 transcript。

use agentdeck_protocol::ThreadId;

use crate::claude_code::history::VerifiedNativeHistoryEntry;
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
        self.vault
            .resolve(adapter_state_key)
            .await?
            .map(decode_thread_id)
            .transpose()
    }

    /// 只接受 `history` 模块验证过本机 JSONL 实体的 opaque entry；客户端 wire
    /// `HistoryListItem` 不能直接构造该类型。
    pub(super) async fn bind_verified_native_history(
        &self,
        adapter_state_key: RuntimeId,
        native: VerifiedNativeHistoryEntry,
    ) -> Result<(), RuntimeStoreError> {
        self.bind(adapter_state_key, native.into_thread_id()).await
    }
}

fn decode_thread_id(secret: SecretBytes) -> Result<ThreadId, RuntimeStoreError> {
    let value = std::str::from_utf8(secret.expose_secret())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if value.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(ThreadId(value.to_owned()))
}
