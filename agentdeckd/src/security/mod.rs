//! daemon 私钥与本地数据包装密钥的安全存储边界。
//!
//! 本模块不提供文件系统明文回退。stable 模式必须使用经过签名 provisioning 的
//! macOS Data Protection Keychain access group；测试/ephemeral 模式可显式注入
//! [`MemoryKeyStore`]。

mod key_store;
mod macos_keychain;

pub use key_store::{
    KeyStore, KeyStoreError, MemoryKeyStore, STORAGE_KEK_ACCOUNT, SecretBytes, StorageKek,
    StorageKekError, load_or_create_storage_kek,
};
pub use macos_keychain::MacOsKeychainStore;

use crate::config::DaemonConfig;
use crate::runtime::namespace::DaemonMode;

/// 已验证 daemon config 到 secret backend 的唯一生产选择点。接收不可拆分的
/// [`DaemonConfig`]，避免调用方把 stable paths 与 ephemeral mode 组合后误选
/// memory store。stable 不存在明文或 memory fallback；ephemeral 永远不请求
/// daemon release entitlement。
pub fn key_store_for_config(config: &DaemonConfig) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match config.mode() {
        DaemonMode::Ephemeral { .. } => Ok(Box::new(MemoryKeyStore::new())),
        DaemonMode::Stable => {
            #[cfg(not(target_os = "macos"))]
            return Err(KeyStoreError::UnsupportedPlatform);
            #[cfg(target_os = "macos")]
            {
                let store = MacOsKeychainStore::new(
                    config.paths().keychain_service.clone(),
                    config.paths().keychain_access_group.clone(),
                )?;
                Ok(Box::new(store))
            }
        }
    }
}
