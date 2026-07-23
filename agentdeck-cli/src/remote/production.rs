//! Persistent remote CLI 的 production composition root。
//!
//! 构造顺序是安全边界：先验证当前发行二进制的签名与 CLI-only entitlement，
//! 再解析 passwd-derived state root，最后才构造 Data Protection Keychain adapter。
//! production constructor 本身不创建 remote state 目录、不访问 paired Keychain，也不拨号；
//! high-level operation 只能通过本 composition 的 startup helper 先审计并恢复合法 revoke cleanup。
//! 本模块不接受 CLI/env/config 注入的替代 store。

#![cfg(unix)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::installation::{CliInstallationStore, InstallationError, InstallationId};

use super::keychain::RemoteKeyStore;
#[cfg(target_os = "macos")]
use super::macos_keychain::MacOsRemoteKeyStore;
use super::paired_machine::{
    OpenedPairedMachine, PairedMachineIdentity, PairedMachineStore, PairedMachineSummary,
    PairedPromotionError,
};
#[cfg(debug_assertions)]
use super::signature::CurrentRemoteCliSignatureVerifier;
use super::signature::{
    ProductionRemoteCliSignatureVerifier, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    verify_current_remote_cli_identity,
};

/// 发行签名 persistent CLI 的封闭依赖集合。
pub struct PersistentRemoteComposition {
    key_store: Arc<dyn RemoteKeyStore>,
    state_root: PathBuf,
    installation_id: InstallationId,
}

impl fmt::Debug for PersistentRemoteComposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentRemoteComposition")
            .field("key_store", &"[VERIFIED DATA PROTECTION KEYCHAIN]")
            .field("state_root", &"[PASSWD-DERIVED]")
            .field("installation_id", &"[STABLE UUID]")
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
            let installation_store = CliInstallationStore::for_os_account()?;
            let installation_id = installation_store.load_or_create()?;
            let state_root = remote_state_root_from_home(installation_store.frozen_home_path());
            let key_store = Arc::new(MacOsRemoteKeyStore::new(&identity));
            Ok(Self {
                key_store,
                state_root,
                installation_id,
            })
        }
    }

    /// Automatic/library harness 的显式 composition seam。仅 debug 构建存在；仍先执行与
    /// production 相同的 signature policy，再允许 installation record 首次创建。
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn injected_for_test<V: CurrentRemoteCliSignatureVerifier + ?Sized>(
        expectation: &RemoteCliSignatureExpectation,
        verifier: &V,
        installation_store: CliInstallationStore,
        key_store: Arc<dyn RemoteKeyStore>,
        state_root: PathBuf,
    ) -> Result<Self, PersistentRemoteCompositionError> {
        let _identity = verify_current_remote_cli_identity(expectation, verifier)?;
        let installation_id = installation_store.load_or_create()?;
        if !state_root.is_absolute() {
            return Err(PersistentRemoteCompositionError::InvalidStateRoot);
        }
        Ok(Self {
            key_store,
            state_root,
            installation_id,
        })
    }

    /// Pairing creation path 的 crate-private raw keystore exception；既有 machine 的
    /// list/open/connect 必须使用 [`Self::recovered_paired_machine_store`]。
    #[must_use]
    pub(crate) fn key_store(&self) -> &dyn RemoteKeyStore {
        self.key_store.as_ref()
    }

    /// Pairing creation path 的 crate-private raw state-root exception；既有 machine 的
    /// list/open/connect 必须使用 [`Self::recovered_paired_machine_store`]。
    #[must_use]
    pub(crate) fn state_root(&self) -> &Path {
        &self.state_root
    }

    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// 构造已完成 installation-wide revoke cleanup recovery 的 paired-machine store。
    ///
    /// 这是 persistent high-level operation 的统一启动边界：先对全部 active/ADPC marker
    /// 做零写全审计，审计全部通过后才恢复合法 cleanup journal；任一离线篡改都会
    /// fail-close，且不会返回可继续 list/open/connect 的 store。
    pub fn recovered_paired_machine_store(
        &self,
    ) -> Result<RecoveredPairedMachineStore<'_>, PairedPromotionError> {
        let paired_store = PairedMachineStore::new(
            self.key_store.as_ref(),
            self.installation_id.as_uuid(),
            &self.state_root,
        );
        paired_store.recover_revocation_cleanups()?;
        Ok(RecoveredPairedMachineStore { paired_store })
    }
}

/// 已完成 installation-wide revoke cleanup recovery 的 branded gateway。
///
/// 类型不暴露 raw [`PairedMachineStore`]、keystore 或 state root；persistent high-level
/// list/open/connect 只能消费本 gateway，因此不能在遗漏 startup recovery 时继续执行。
pub struct RecoveredPairedMachineStore<'a> {
    paired_store: PairedMachineStore<'a>,
}

impl fmt::Debug for RecoveredPairedMachineStore<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredPairedMachineStore")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> RecoveredPairedMachineStore<'a> {
    pub fn list(&self) -> Result<Vec<PairedMachineSummary>, PairedPromotionError> {
        self.paired_store.list()
    }

    /// 在同一次 branded startup recovery 之后打开 exact machine；未来 connect 路径不得
    /// 重新从 raw composition fields 构造 store。
    pub fn open_exact(
        &self,
        identity: PairedMachineIdentity,
    ) -> Result<OpenedPairedMachine<'a>, PairedPromotionError> {
        self.paired_store.open_exact(identity)
    }
}

/// 当前 EUID 的 canonical persistent remote state root；只解析路径，不创建目录。
pub fn remote_state_root_for_current_user() -> Result<PathBuf, PersistentRemoteCompositionError> {
    let home = CliInstallationStore::os_account_home_path()?;
    Ok(remote_state_root_from_home(&home))
}

fn remote_state_root_from_home(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("AgentDeck")
        .join("remote")
        .join("cli")
}

#[derive(Debug, Error)]
pub enum PersistentRemoteCompositionError {
    #[error(transparent)]
    Signature(#[from] RemoteCliSignatureError),
    #[error("persistent remote CLI is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("persistent remote CLI cannot resolve the OS-account state root")]
    Installation(#[from] InstallationError),
    #[error("persistent remote CLI state root must be absolute")]
    InvalidStateRoot,
}

impl PersistentRemoteCompositionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Signature(error) => error.code(),
            Self::UnsupportedPlatform => "remote.persistent.unsupported",
            Self::Installation(error) => error.code(),
            Self::InvalidStateRoot => "remote.persistent.state_root_invalid",
        }
    }
}
