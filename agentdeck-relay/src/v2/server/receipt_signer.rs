//! Relay 专用 receipt signer seed 的启动前安全装载。
//!
//! 本模块故意只产出尚未绑定 `RelayServerId` 的公共身份。后续 composition 必须先
//! 完成本 loader，再打开 Store，以 Store 的真实 server identity 构造并持久化完整
//! trust anchor；这里不生成默认/dev key，也不复用 TLS private key。

#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

use agentdeck_crypto::{
    CryptoError, SigningKey, ValidatedRelayReceiptSignerIdentityV1, sign_relay_admin_purge_receipt,
};
use agentdeck_protocol::relay_v2::{RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1};
use zeroize::Zeroizing;

pub(crate) struct LoadedRelayReceiptSigner {
    signing_key: SigningKey,
    identity: ValidatedRelayReceiptSignerIdentityV1,
}

impl LoadedRelayReceiptSigner {
    pub(crate) const fn identity(&self) -> ValidatedRelayReceiptSignerIdentityV1 {
        self.identity
    }

    /// 只接受 Store 冻结的 typed TBS，避免把 Relay 私钥暴露成 raw signing oracle。
    pub(crate) fn sign(
        &self,
        tbs: RelayAdminPurgeReceiptTbsV1,
    ) -> Result<RelayAdminPurgeReceiptV1, CryptoError> {
        let verify_key = self.identity.bind_to_relay(tbs.relay_server_id)?;
        sign_relay_admin_purge_receipt(&self.signing_key, &verify_key, tbs)
    }
}

impl std::fmt::Debug for LoadedRelayReceiptSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedRelayReceiptSigner")
            .field("signing_key", &"<redacted>")
            .field("identity", &self.identity)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayReceiptSignerLoadError {
    #[error("Relay receipt signer seed path is invalid")]
    InvalidPath,
    #[error("Relay receipt signer path inspection failed")]
    PathInspection {
        #[source]
        source: io::Error,
    },
    #[error("Relay receipt signer seed parent could not be opened")]
    ParentOpen {
        #[source]
        source: io::Error,
    },
    #[error("Relay receipt signer seed parent is unsafe")]
    UnsafeParent,
    #[error("Relay receipt signer seed could not be opened")]
    SeedOpen {
        #[source]
        source: io::Error,
    },
    #[error("Relay receipt signer seed file is unsafe")]
    UnsafeSeedFile,
    #[error("Relay receipt signer seed could not be read")]
    SeedRead {
        #[source]
        source: io::Error,
    },
    #[error("Relay receipt signer seed must contain exactly 32 bytes")]
    InvalidSeedLength,
    #[error("Relay receipt signer seed material is invalid")]
    InvalidSeedMaterial,
    #[cfg(not(unix))]
    #[error("Relay receipt signer seed files are unsupported on this platform")]
    UnsupportedPlatform,
}

impl RelayReceiptSignerLoadError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPath => "relay.receipt.signer_path_invalid",
            Self::PathInspection { .. }
            | Self::ParentOpen { .. }
            | Self::SeedOpen { .. }
            | Self::SeedRead { .. } => "relay.receipt.signer_read",
            Self::UnsafeParent => "relay.receipt.signer_parent_unsafe",
            Self::UnsafeSeedFile => "relay.receipt.signer_file_unsafe",
            Self::InvalidSeedLength | Self::InvalidSeedMaterial => {
                "relay.receipt.signer_seed_invalid"
            }
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "relay.receipt.signer_platform_unsupported",
        }
    }
}

pub(crate) fn load_relay_receipt_signer(
    path: &Path,
) -> Result<LoadedRelayReceiptSigner, RelayReceiptSignerLoadError> {
    validate_lexical_path(path)?;
    reject_symlink_components(path)?;
    let seed = read_seed(path)?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(RelayReceiptSignerLoadError::InvalidSeedMaterial);
    }
    let signing_key = SigningKey::from_seed(&seed);
    let identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
        .map_err(|_| RelayReceiptSignerLoadError::InvalidSeedMaterial)?;
    Ok(LoadedRelayReceiptSigner {
        signing_key,
        identity,
    })
}

#[cfg(test)]
pub(crate) fn test_relay_receipt_signer() -> LoadedRelayReceiptSigner {
    let signing_key = SigningKey::from_seed(&[0x71; 32]);
    let identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
        .expect("fixed test receipt signer is valid");
    LoadedRelayReceiptSigner {
        signing_key,
        identity,
    }
}

fn validate_lexical_path(path: &Path) -> Result<(), RelayReceiptSignerLoadError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(RelayReceiptSignerLoadError::InvalidPath);
    }
    let normalized = path.components().collect::<PathBuf>();
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || normalized.as_os_str() != path.as_os_str()
    {
        return Err(RelayReceiptSignerLoadError::InvalidPath);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), RelayReceiptSignerLoadError> {
    for component_path in path.ancestors() {
        match fs::symlink_metadata(component_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RelayReceiptSignerLoadError::InvalidPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(RelayReceiptSignerLoadError::PathInspection { source }),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, RelayReceiptSignerLoadError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let parent_path = path
        .parent()
        .ok_or(RelayReceiptSignerLoadError::InvalidPath)?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let parent = parent_options
        .open(parent_path)
        .map_err(|source| RelayReceiptSignerLoadError::ParentOpen { source })?;
    let expected_uid = current_uid();
    validate_private_parent(
        &parent
            .metadata()
            .map_err(|source| RelayReceiptSignerLoadError::ParentOpen { source })?,
        expected_uid,
    )?;

    let file_name = path
        .file_name()
        .ok_or(RelayReceiptSignerLoadError::InvalidPath)?;
    let file_name =
        CString::new(file_name.as_bytes()).map_err(|_| RelayReceiptSignerLoadError::InvalidPath)?;
    // O_NONBLOCK 防止最终路径在检查后被替换为 FIFO 时阻塞启动；O_NOFOLLOW
    // 保证最终组件本身永不被跟随。same-UID 在线替换仍属于既定 residual risk。
    let raw_fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw_fd < 0 {
        return Err(RelayReceiptSignerLoadError::SeedOpen {
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: successful openat returns one newly-owned file descriptor.
    let mut file = unsafe { File::from_raw_fd(raw_fd) };
    validate_seed_file(
        &file
            .metadata()
            .map_err(|source| RelayReceiptSignerLoadError::SeedOpen { source })?,
        expected_uid,
    )?;
    read_exact_seed(&mut file)
}

#[cfg(not(unix))]
fn read_seed(_path: &Path) -> Result<Zeroizing<[u8; 32]>, RelayReceiptSignerLoadError> {
    Err(RelayReceiptSignerLoadError::UnsupportedPlatform)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and only reads current process credentials.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn validate_private_parent(
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<(), RelayReceiptSignerLoadError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(RelayReceiptSignerLoadError::UnsafeParent);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_seed_file(
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<(), RelayReceiptSignerLoadError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(RelayReceiptSignerLoadError::UnsafeSeedFile);
    }
    Ok(())
}

fn read_exact_seed(file: &mut File) -> Result<Zeroizing<[u8; 32]>, RelayReceiptSignerLoadError> {
    let mut bounded = Zeroizing::new([0_u8; 33]);
    let mut read = 0_usize;
    while read < bounded.len() {
        match file.read(&mut bounded[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(source) if source.kind() == ErrorKind::Interrupted => {}
            Err(source) => return Err(RelayReceiptSignerLoadError::SeedRead { source }),
        }
    }
    if read != 32 {
        return Err(RelayReceiptSignerLoadError::InvalidSeedLength);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&bounded[..32]);
    Ok(seed)
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use agentdeck_crypto::SigningKey;
    use agentdeck_protocol::relay_v2::{
        PublicKeyBytes, RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP,
        RelayReceiptKeyId,
    };
    use tempfile::TempDir;

    use super::*;

    fn private_temp() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("create signer tempdir");
        let root = fs::canonicalize(temp.path()).expect("canonical signer tempdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("set private signer tempdir");
        (temp, root)
    }

    fn write_seed(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, bytes).expect("write signer seed fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set signer seed mode");
        path
    }

    #[test]
    fn valid_exact_seed_derives_deterministic_proven_identity_and_redacted_debug() {
        let (_temp, root) = private_temp();
        let path = write_seed(&root, "receipt.seed", &[0x42; 32]);

        let loaded = load_relay_receipt_signer(&path).expect("load valid receipt signer");
        let expected = SigningKey::from_seed(&[0x42; 32]);
        let expected_public = PublicKeyBytes(expected.verifying_key().to_bytes());
        assert_eq!(
            loaded.identity.receipt_format_version(),
            RELAY_RECEIPT_FORMAT_VERSION
        );
        assert_eq!(
            loaded.identity.key_generation(),
            RELAY_RECEIPT_KEY_GENERATION_MVP
        );
        assert_eq!(loaded.identity.public_key(), expected_public);
        assert_eq!(
            loaded.identity.key_id(),
            RelayReceiptKeyId::from_public_key(&expected_public)
        );
        assert_eq!(
            loaded.signing_key.verifying_key().to_bytes(),
            loaded.identity.public_key().0
        );
        let debug = format!("{loaded:?}");
        assert!(!debug.contains(path.to_string_lossy().as_ref()));
        assert!(!debug.contains("42424242"));
    }

    #[test]
    fn missing_relative_and_lexically_noncanonical_paths_are_typed_and_redacted() {
        let (_temp, root) = private_temp();
        let missing = root.join("missing.seed");
        let error = load_relay_receipt_signer(&missing).expect_err("missing seed must fail");
        assert_eq!(error.code(), "relay.receipt.signer_read");
        assert!(!format!("{error:?}").contains(missing.to_string_lossy().as_ref()));
        assert!(
            !error
                .to_string()
                .contains(missing.to_string_lossy().as_ref())
        );

        let relative = Path::new("receipt.seed");
        let error = load_relay_receipt_signer(relative).expect_err("relative seed must fail");
        assert_eq!(error.code(), "relay.receipt.signer_path_invalid");

        let noncanonical = root.join("child").join("..").join("receipt.seed");
        let error = load_relay_receipt_signer(&noncanonical)
            .expect_err("parent component must be rejected");
        assert_eq!(error.code(), "relay.receipt.signer_path_invalid");
    }

    #[test]
    fn every_symlink_component_is_rejected() {
        let (_temp, root) = private_temp();
        let real = root.join("real");
        fs::create_dir(&real).expect("create real parent");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))
            .expect("set real parent mode");
        let real_seed = write_seed(&real, "receipt.seed", &[0x31; 32]);

        let final_link = root.join("final-link.seed");
        symlink(&real_seed, &final_link).expect("create final symlink");
        let error =
            load_relay_receipt_signer(&final_link).expect_err("final symlink must be rejected");
        assert_eq!(error.code(), "relay.receipt.signer_path_invalid");

        let parent_link = root.join("parent-link");
        symlink(&real, &parent_link).expect("create parent symlink");
        let error = load_relay_receipt_signer(&parent_link.join("receipt.seed"))
            .expect_err("intermediate symlink must be rejected");
        assert_eq!(error.code(), "relay.receipt.signer_path_invalid");
    }

    #[test]
    fn parent_and_seed_metadata_are_fail_closed() {
        let (_temp, root) = private_temp();
        let seed = write_seed(&root, "receipt.seed", &[0x17; 32]);

        let different_uid = current_uid().wrapping_add(1);
        assert!(matches!(
            validate_private_parent(
                &fs::metadata(&root).expect("inspect parent fixture"),
                different_uid,
            ),
            Err(RelayReceiptSignerLoadError::UnsafeParent)
        ));
        assert!(matches!(
            validate_seed_file(
                &fs::metadata(&seed).expect("inspect seed fixture"),
                different_uid,
            ),
            Err(RelayReceiptSignerLoadError::UnsafeSeedFile)
        ));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).expect("widen parent mode");
        let error = load_relay_receipt_signer(&seed).expect_err("shared parent must fail");
        assert_eq!(error.code(), "relay.receipt.signer_parent_unsafe");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore parent mode");

        fs::set_permissions(&seed, fs::Permissions::from_mode(0o640)).expect("widen seed mode");
        let error = load_relay_receipt_signer(&seed).expect_err("non-0600 seed must fail");
        assert_eq!(error.code(), "relay.receipt.signer_file_unsafe");
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).expect("restore seed mode");

        let hardlink = root.join("receipt-hardlink.seed");
        fs::hard_link(&seed, &hardlink).expect("create hard link");
        let error = load_relay_receipt_signer(&seed).expect_err("multi-link seed must fail");
        assert_eq!(error.code(), "relay.receipt.signer_file_unsafe");

        fs::remove_file(&hardlink).expect("remove hard link");
        let directory = root.join("seed-directory");
        fs::create_dir(&directory).expect("create directory fixture");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o600))
            .expect("set directory fixture mode");
        let error = load_relay_receipt_signer(&directory)
            .expect_err("directory must not be read as a seed");
        assert_eq!(error.code(), "relay.receipt.signer_file_unsafe");

        let fifo = root.join("receipt-fifo.seed");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
        // SAFETY: the CString is NUL-terminated and points to a private temporary path.
        let created = unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) };
        assert_eq!(created, 0, "create FIFO fixture");
        let error = load_relay_receipt_signer(&fifo)
            .expect_err("FIFO must be rejected without blocking startup");
        assert_eq!(error.code(), "relay.receipt.signer_file_unsafe");
    }

    #[test]
    fn seed_length_is_bounded_to_exactly_32_bytes() {
        let (_temp, root) = private_temp();
        for (name, bytes) in [
            ("short.seed", vec![0x51; 31]),
            ("long.seed", vec![0x52; 33]),
        ] {
            let path = write_seed(&root, name, &bytes);
            let error =
                load_relay_receipt_signer(&path).expect_err("non-exact seed length must fail");
            assert_eq!(error.code(), "relay.receipt.signer_seed_invalid");
        }

        let zero = write_seed(&root, "zero.seed", &[0; 32]);
        let error = load_relay_receipt_signer(&zero)
            .expect_err("globally predictable all-zero seed must fail closed");
        assert!(matches!(
            error,
            RelayReceiptSignerLoadError::InvalidSeedMaterial
        ));
        assert_eq!(error.code(), "relay.receipt.signer_seed_invalid");
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn unsupported_platform_is_typed_before_secret_file_io() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("receipt-signer.seed");
        let error =
            load_relay_receipt_signer(&absolute).expect_err("non-Unix loader must fail closed");
        assert!(matches!(
            error,
            RelayReceiptSignerLoadError::UnsupportedPlatform
        ));
        assert_eq!(error.code(), "relay.receipt.signer_platform_unsupported");
    }
}
