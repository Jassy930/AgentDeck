//! CLI binary 的 shared-daemon Runtime v3 connector。
//!
//! Production 只调用 `RuntimeUnixClient::connect_stable()`；没有 daemon spawn、stdio
//! 或 diagnostics fallback。Debug smoke 只有一个 hidden private-TMPDIR root seam：它
//! 自行发现并验证唯一 `ad-<UUID>/s`，不接受 socket 参数或环境覆盖。

use crate::output::CliError;
use agentdeck_cli::unix_transport::{RuntimeUnixClient, UnixClientError};

#[derive(Debug, Default)]
pub struct RuntimeConnectOptions {
    #[cfg(debug_assertions)]
    pub temp_root_for_test: Option<std::path::PathBuf>,
}

pub async fn connect(options: &RuntimeConnectOptions) -> Result<RuntimeUnixClient, CliError> {
    #[cfg(debug_assertions)]
    if let Some(root) = options.temp_root_for_test.as_deref() {
        return connect_debug_temp_root(root).await;
    }
    #[cfg(not(debug_assertions))]
    let _ = options;
    RuntimeUnixClient::connect_stable()
        .await
        .map_err(map_unix_error)
}

pub fn map_unix_error(error: UnixClientError) -> CliError {
    CliError::Transport {
        code: Some(error.code().to_owned()),
        message: error.to_string(),
    }
}

#[cfg(debug_assertions)]
async fn connect_debug_temp_root(root: &std::path::Path) -> Result<RuntimeUnixClient, CliError> {
    use agentdeck_cli::installation::CliInstallationStore;
    use agentdeck_cli::unix_transport::InjectedEndpoint;

    validate_private_directory(root, "Runtime smoke TMPDIR root")?;
    let socket = discover_single_runtime_socket(root)?;
    let installation_home = root.join("clients").join("cli");
    ensure_private_directory(&root.join("clients"), "Runtime smoke clients directory")?;
    ensure_private_directory(&installation_home, "Runtime smoke CLI installation home")?;
    let store = CliInstallationStore::injected_for_test(installation_home);
    let installation_id = store
        .load_or_create()
        .map_err(UnixClientError::from)
        .map_err(map_unix_error)?;
    RuntimeUnixClient::connect_injected_with_installation(
        InjectedEndpoint::for_test(socket),
        installation_id,
    )
    .await
    .map_err(map_unix_error)
}

#[cfg(debug_assertions)]
fn discover_single_runtime_socket(root: &std::path::Path) -> Result<std::path::PathBuf, CliError> {
    let mut candidates = Vec::new();
    let entries =
        std::fs::read_dir(root).map_err(|error| unsafe_temp_root(root, error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| unsafe_temp_root(root, error.to_string()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(suffix) = name.strip_prefix("ad-") else {
            continue;
        };
        let parsed = uuid::Uuid::parse_str(suffix).map_err(|_| {
            unsafe_temp_root(root, format!("invalid Runtime namespace name {name}"))
        })?;
        if parsed.hyphenated().to_string() != suffix {
            return Err(unsafe_temp_root(
                root,
                format!("non-canonical Runtime namespace name {name}"),
            ));
        }
        candidates.push(root.join(name).join("s"));
    }
    match candidates.as_slice() {
        [socket] => Ok(socket.clone()),
        [] => Err(CliError::Transport {
            code: Some("daemon.client.socket_missing".to_owned()),
            message: format!(
                "private Runtime smoke root {} contains no ad-<UUID>/s endpoint",
                root.display()
            ),
        }),
        _ => Err(unsafe_temp_root(
            root,
            "private Runtime smoke root contains multiple ad-<UUID>/s endpoints",
        )),
    }
}

#[cfg(debug_assertions)]
fn ensure_private_directory(path: &std::path::Path, label: &'static str) -> Result<(), CliError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(unsafe_temp_root(
                path,
                format!("cannot create {label}: {error}"),
            ));
        }
    }
    validate_private_directory(path, label)
}

#[cfg(debug_assertions)]
fn validate_private_directory(path: &std::path::Path, label: &'static str) -> Result<(), CliError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    if !path.is_absolute() {
        return Err(unsafe_temp_root(path, format!("{label} is not absolute")));
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            unsafe_temp_root(path, format!("cannot open {label} no-follow: {error}"))
        })?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory is a retained descriptor and stat is writable storage.
    if unsafe { libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(unsafe_temp_root(
            path,
            format!("cannot stat {label}: {}", std::io::Error::last_os_error()),
        ));
    }
    // SAFETY: successful fstat initialized stat.
    let stat = unsafe { stat.assume_init() };
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_uid != uid
        || (stat.st_mode & 0o7777) != 0o700
    {
        return Err(unsafe_temp_root(
            path,
            format!("{label} must be a current-EUID exact-0700 directory"),
        ));
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn unsafe_temp_root(path: &std::path::Path, reason: impl Into<String>) -> CliError {
    CliError::Transport {
        code: Some("daemon.client.socket_unsafe".to_owned()),
        message: format!(
            "unsafe Runtime smoke path {}: {}",
            path.display(),
            reason.into()
        ),
    }
}
