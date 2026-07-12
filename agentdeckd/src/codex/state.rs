//! Codex 私有 resume 映射。
//!
//! common catalog 只持有随机 `adapterStateKey`；Codex thread id 只在本模块与
//! `codex_adapter_state` namespace 之间流动，不进入 Runtime wire、日志或 Relay。

use agentdeck_protocol::ThreadId;

use crate::runtime::store::{CodexAdapterStateVault, RuntimeId, RuntimeStoreError};
use crate::security::SecretBytes;

/// 只允许 Codex adapter 持有的 typed repository。
#[derive(Clone, Debug)]
pub(super) struct CodexStateRepository {
    vault: CodexAdapterStateVault,
}

impl CodexStateRepository {
    #[must_use]
    pub(super) fn new(vault: CodexAdapterStateVault) -> Self {
        Self { vault }
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

    /// 仅从 Codex 私有 namespace 解密；另一 adapter 已占用该 key 时返回 typed mismatch。
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
}

fn decode_thread_id(secret: SecretBytes) -> Result<ThreadId, RuntimeStoreError> {
    let value = std::str::from_utf8(secret.expose_secret())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if value.is_empty() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(ThreadId(value.to_owned()))
}
