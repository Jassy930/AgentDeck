//! Persistent remote CLI 的 production composition root。
//!
//! 构造顺序是安全边界：先验证当前发行二进制的签名与 CLI-only entitlement，
//! 再解析 passwd-derived state root，最后才构造 Data Protection Keychain adapter。
//! 本模块不创建目录、不访问 Keychain、不拨号，也不接受 CLI/env/config 注入的替代 store。

#![cfg(unix)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::installation::{CliInstallationStore, InstallationError};

use super::keychain::RemoteKeyStore;
#[cfg(target_os = "macos")]
use super::macos_keychain::MacOsRemoteKeyStore;
use super::signature::{
    ProductionRemoteCliSignatureVerifier, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    verify_current_remote_cli_identity,
};

/// 发行签名 persistent CLI 的封闭依赖集合。
pub struct PersistentRemoteComposition {
    key_store: Arc<dyn RemoteKeyStore>,
    state_root: PathBuf,
}

impl fmt::Debug for PersistentRemoteComposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentRemoteComposition")
            .field("key_store", &"[VERIFIED DATA PROTECTION KEYCHAIN]")
            .field("state_root", &"[PASSWD-DERIVED]")
            .finish()
    }
}

impl PersistentRemoteComposition {
    /// production binary 的唯一 persistent constructor。
    ///
    /// 缺编译期 identity、unsigned/ad-hoc、entitlement 错配或非 macOS 都在任何
    /// state/Keychain/network mutation 前 fail-close。
    pub fn production() -> Result<Self, PersistentRemoteCompositionError> {
        let expectation = RemoteCliSignatureExpectation::compiled()?;
        let verifier = ProductionRemoteCliSignatureVerifier::new();
        let identity = verify_current_remote_cli_identity(&expectation, &verifier)?;

        #[cfg(not(target_os = "macos"))]
        {
            let _ = identity;
            Err(PersistentRemoteCompositionError::UnsupportedPlatform)
        }

        #[cfg(target_os = "macos")]
        {
            let state_root = remote_state_root_for_current_user()?;
            let key_store = Arc::new(MacOsRemoteKeyStore::new(&identity));
            Ok(Self {
                key_store,
                state_root,
            })
        }
    }

    #[must_use]
    pub fn key_store(&self) -> &dyn RemoteKeyStore {
        self.key_store.as_ref()
    }

    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

/// 当前 EUID 的 canonical persistent remote state root；只解析路径，不创建目录。
pub fn remote_state_root_for_current_user() -> Result<PathBuf, PersistentRemoteCompositionError> {
    let home = CliInstallationStore::os_account_home_path()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("AgentDeck")
        .join("remote")
        .join("cli"))
}

#[derive(Debug, Error)]
pub enum PersistentRemoteCompositionError {
    #[error(transparent)]
    Signature(#[from] RemoteCliSignatureError),
    #[error("persistent remote CLI is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("persistent remote CLI cannot resolve the OS-account state root")]
    Installation(#[from] InstallationError),
}

impl PersistentRemoteCompositionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Signature(error) => error.code(),
            Self::UnsupportedPlatform => "remote.persistent.unsupported",
            Self::Installation(_) => "remote.persistent.state_root_unavailable",
        }
    }
}
