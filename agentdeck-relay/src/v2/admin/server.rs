//! 0600、同 UID、单请求 JSONL 的本机 admin Unix socket。

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::command::AdminCommandExecutor;
use super::protocol::{AdminFailure, AdminRequest, AdminResponse, MAX_ADMIN_LINE_BYTES};

const ADMIN_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ADMIN_CONNECTIONS: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AdminServerError {
    #[error("admin socket path is invalid")]
    InvalidPath,
    #[error("admin socket parent is not a secure owner-only directory")]
    InsecureParent,
    #[error("admin socket is already active")]
    AlreadyRunning,
    #[error("admin socket I/O failed")]
    Io(#[source] io::Error),
    #[error("admin task failed")]
    Task,
}

impl AdminServerError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPath => "relay.admin.socket_path_invalid",
            Self::InsecureParent => "relay.admin.socket_parent_insecure",
            Self::AlreadyRunning => "relay.admin.socket_in_use",
            Self::Io(_) => "relay.admin.socket_io",
            Self::Task => "relay.admin.task_failed",
        }
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct AdminServer {
    listener: UnixListener,
    executor: AdminCommandExecutor,
    _guard: SocketGuard,
}

impl std::fmt::Debug for AdminServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminServer")
            .finish_non_exhaustive()
    }
}

impl AdminServer {
    pub async fn bind(
        path: impl Into<PathBuf>,
        executor: AdminCommandExecutor,
    ) -> Result<Self, AdminServerError> {
        let path = secure_socket_path(&path.into())?;
        remove_stale_socket(&path).await?;
        let listener = UnixListener::bind(&path).map_err(AdminServerError::Io)?;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(&path);
            return Err(AdminServerError::Io(error));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(AdminServerError::Io)?;
        let expected_uid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o777 != 0o600
        {
            let _ = std::fs::remove_file(&path);
            return Err(AdminServerError::InsecureParent);
        }
        Ok(Self {
            listener,
            executor,
            _guard: SocketGuard {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> Result<(), AdminServerError> {
        let Self {
            listener,
            executor,
            _guard,
        } = self;
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_CONNECTIONS));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if joined.is_some_and(|result| result.is_err()) {
                        return Err(AdminServerError::Task);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted.map_err(AdminServerError::Io)?;
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let executor = executor.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, executor).await;
                    });
                }
            }
        }
        drop(listener);
        let deadline = tokio::time::sleep(ADMIN_IO_TIMEOUT);
        tokio::pin!(deadline);
        while !tasks.is_empty() {
            tokio::select! {
                _ = &mut deadline => {
                    tasks.abort_all();
                    break;
                }
                _ = tasks.join_next() => {}
            }
        }
        while tasks.join_next().await.is_some() {}
        drop(_guard);
        Ok(())
    }
}

async fn handle_connection(mut stream: UnixStream, executor: AdminCommandExecutor) {
    let response = match stream.peer_cred() {
        Ok(credentials) if peer_uid_allowed(unsafe { libc::geteuid() }, credentials.uid()) => {
            match tokio::time::timeout(ADMIN_IO_TIMEOUT, read_line(&mut stream)).await {
                Ok(Ok(line)) => match serde_json::from_slice::<AdminRequest>(&line) {
                    Ok(request) => executor.execute(request).await,
                    Err(_) => failure("relay.admin.request_invalid"),
                },
                Ok(Err(code)) => failure(code),
                Err(_) => failure("relay.admin.io_timeout"),
            }
        }
        Ok(_) => failure("relay.admin.peer_forbidden"),
        Err(_) => failure("relay.admin.peer_unavailable"),
    };
    let Ok(mut encoded) = serde_json::to_vec(&response) else {
        return;
    };
    if encoded.len() >= MAX_ADMIN_LINE_BYTES {
        encoded = serde_json::to_vec(&failure("relay.admin.response_too_large"))
            .unwrap_or_else(|_| b"{}".to_vec());
    }
    encoded.push(b'\n');
    let _ = tokio::time::timeout(ADMIN_IO_TIMEOUT, async {
        stream.write_all(&encoded).await?;
        stream.shutdown().await
    })
    .await;
}

async fn read_line(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
    let mut line = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "relay.admin.socket_io")?;
        if read == 0 {
            return Err("relay.admin.request_incomplete");
        }
        if let Some(newline) = chunk[..read].iter().position(|byte| *byte == b'\n') {
            if line.len().saturating_add(newline) > MAX_ADMIN_LINE_BYTES {
                return Err("relay.admin.request_too_large");
            }
            if read != newline + 1 {
                return Err("relay.admin.request_invalid");
            }
            line.extend_from_slice(&chunk[..newline]);
            return Ok(line);
        }
        if line.len().saturating_add(read) > MAX_ADMIN_LINE_BYTES {
            return Err("relay.admin.request_too_large");
        }
        line.extend_from_slice(&chunk[..read]);
    }
}

fn failure(code: &'static str) -> AdminResponse {
    AdminResponse::Error {
        error: AdminFailure {
            code: code.to_owned(),
        },
    }
}

pub(crate) fn peer_uid_allowed(expected: u32, observed: u32) -> bool {
    expected == observed
}

pub(crate) fn secure_socket_path(path: &Path) -> Result<PathBuf, AdminServerError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(AdminServerError::InvalidPath);
    }
    let parent = path.parent().ok_or(AdminServerError::InvalidPath)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(AdminServerError::Io)?;
    let expected_uid = unsafe { libc::geteuid() };
    let mut ancestors = canonical_parent.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(AdminServerError::Io)?;
        let mode = metadata.mode();
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != expected_uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(AdminServerError::InsecureParent);
        }
    }
    let metadata = std::fs::symlink_metadata(&canonical_parent).map_err(AdminServerError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(AdminServerError::InsecureParent);
    }
    Ok(canonical_parent.join(path.file_name().ok_or(AdminServerError::InvalidPath)?))
}

async fn remove_stale_socket(path: &Path) -> Result<(), AdminServerError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AdminServerError::Io(error)),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(AdminServerError::InsecureParent);
    }
    match tokio::time::timeout(Duration::from_millis(250), UnixStream::connect(path)).await {
        Ok(Ok(_)) => Err(AdminServerError::AlreadyRunning),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            let current = match std::fs::symlink_metadata(path) {
                Ok(current) => current,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(AdminServerError::Io(error)),
            };
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(AdminServerError::AlreadyRunning);
            }
            std::fs::remove_file(path).map_err(AdminServerError::Io)
        }
        Ok(Err(error)) => Err(AdminServerError::Io(error)),
        Err(_) => Err(AdminServerError::AlreadyRunning),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_gate_is_exact() {
        assert!(peer_uid_allowed(501, 501));
        assert!(!peer_uid_allowed(501, 0));
        assert!(!peer_uid_allowed(501, 502));
    }

    #[test]
    fn socket_path_rejects_a_non_sticky_writable_ancestor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let writable = temp.path().join("writable");
        let private = writable.join("private");
        std::fs::create_dir(&writable).expect("writable ancestor");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
            .expect("make ancestor replaceable");
        std::fs::create_dir(&private).expect("private parent");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("secure immediate parent");
        assert!(matches!(
            secure_socket_path(&private.join("relay.sock")),
            Err(AdminServerError::InsecureParent)
        ));
    }
}
