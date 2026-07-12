//! 同 binary 管理子命令使用的 bounded Unix-socket client。

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::protocol::{AdminRequest, AdminResponse, MAX_ADMIN_LINE_BYTES};
use super::server::secure_socket_path;

const ADMIN_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    #[error("admin socket path is invalid")]
    InvalidSocket,
    #[error("admin request is too large")]
    RequestTooLarge,
    #[error("admin response is invalid")]
    InvalidResponse,
    #[error("admin request timed out")]
    Timeout,
    #[error("admin socket I/O failed")]
    Io(#[source] io::Error),
    #[error("admin server peer is not the expected owner")]
    PeerForbidden,
}

impl AdminClientError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSocket => "relay.admin.socket_invalid",
            Self::RequestTooLarge => "relay.admin.request_too_large",
            Self::InvalidResponse => "relay.admin.response_invalid",
            Self::Timeout => "relay.admin.io_timeout",
            Self::Io(_) => "relay.admin.socket_io",
            Self::PeerForbidden => "relay.admin.peer_forbidden",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminClient {
    socket_path: PathBuf,
}

impl AdminClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn request(&self, request: &AdminRequest) -> Result<AdminResponse, AdminClientError> {
        let socket_path =
            secure_socket_path(&self.socket_path).map_err(|_| AdminClientError::InvalidSocket)?;
        validate_socket(&socket_path)?;
        let mut encoded =
            serde_json::to_vec(request).map_err(|_| AdminClientError::InvalidResponse)?;
        if encoded.len() >= MAX_ADMIN_LINE_BYTES {
            return Err(AdminClientError::RequestTooLarge);
        }
        encoded.push(b'\n');
        tokio::time::timeout(ADMIN_CLIENT_TIMEOUT, async {
            let mut stream = UnixStream::connect(&socket_path)
                .await
                .map_err(AdminClientError::Io)?;
            let peer = stream.peer_cred().map_err(AdminClientError::Io)?;
            if peer.uid() != unsafe { libc::geteuid() } {
                return Err(AdminClientError::PeerForbidden);
            }
            stream
                .write_all(&encoded)
                .await
                .map_err(AdminClientError::Io)?;
            let line = read_response(&mut stream).await?;
            serde_json::from_slice(&line).map_err(|_| AdminClientError::InvalidResponse)
        })
        .await
        .map_err(|_| AdminClientError::Timeout)?
    }
}

fn validate_socket(path: &Path) -> Result<(), AdminClientError> {
    if !path.is_absolute() {
        return Err(AdminClientError::InvalidSocket);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(AdminClientError::Io)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(AdminClientError::InvalidSocket);
    }
    Ok(())
}

async fn read_response(stream: &mut UnixStream) -> Result<Vec<u8>, AdminClientError> {
    let mut line = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(AdminClientError::Io)?;
        if read == 0 {
            return Err(AdminClientError::InvalidResponse);
        }
        if let Some(newline) = chunk[..read].iter().position(|byte| *byte == b'\n') {
            if read != newline + 1 || line.len().saturating_add(newline) > MAX_ADMIN_LINE_BYTES {
                return Err(AdminClientError::InvalidResponse);
            }
            line.extend_from_slice(&chunk[..newline]);
            return Ok(line);
        }
        if line.len().saturating_add(read) > MAX_ADMIN_LINE_BYTES {
            return Err(AdminClientError::InvalidResponse);
        }
        line.extend_from_slice(&chunk[..read]);
    }
}
