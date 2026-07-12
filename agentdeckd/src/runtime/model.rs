//! Runtime 持久化层的平台无关内部模型。
//!
//! 这些类型不进入 RuntimeEnvelope wire；P3.4 RuntimeCore 负责把内部精确状态/
//! failure 映射成客户端可见 receipt 与 `RuntimeFailure`。

use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;

use super::store::cipher::CipherError;

pub const DEFAULT_RUNTIME_STORE_COMMAND_CAPACITY: usize = 32;
pub const DEFAULT_RUNTIME_BUSY_TIMEOUT_MS: u64 = 5_000;
pub const MAX_RUNTIME_STORE_COMMAND_CAPACITY: usize = 1_024;
pub const MAX_RUNTIME_BUSY_TIMEOUT_MS: u64 = 30_000;
pub const RUNTIME_STORE_SHUTDOWN_GRACE_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStoreOperation {
    InitializeBeforePublish,
    Inspect,
    RecordEnrollmentReceipt,
}

pub trait RuntimeStoreFaultInjector: Send + Sync {
    fn before_operation(&self, _operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        Ok(())
    }
}

#[derive(Debug)]
struct NoRuntimeStoreFaults;

impl RuntimeStoreFaultInjector for NoRuntimeStoreFaults {}

#[derive(Clone)]
pub struct RuntimeStoreConfig {
    pub storage_path: PathBuf,
    pub command_capacity: usize,
    pub busy_timeout_ms: u64,
    pub fault_injector: Arc<dyn RuntimeStoreFaultInjector>,
}

impl RuntimeStoreConfig {
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            command_capacity: DEFAULT_RUNTIME_STORE_COMMAND_CAPACITY,
            busy_timeout_ms: DEFAULT_RUNTIME_BUSY_TIMEOUT_MS,
            fault_injector: Arc::new(NoRuntimeStoreFaults),
        }
    }

    #[must_use]
    pub fn with_command_capacity(mut self, command_capacity: usize) -> Self {
        self.command_capacity = command_capacity;
        self
    }

    #[must_use]
    pub fn with_fault_injector(
        mut self,
        fault_injector: Arc<dyn RuntimeStoreFaultInjector>,
    ) -> Self {
        self.fault_injector = fault_injector;
        self
    }
}

impl std::fmt::Debug for RuntimeStoreConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeStoreConfig")
            .field("storage_path", &self.storage_path)
            .field("command_capacity", &self.command_capacity)
            .field("busy_timeout_ms", &self.busy_timeout_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStoreSnapshot {
    pub schema_family: String,
    pub schema_version: u32,
    pub schema_signature: [u8; 32],
    pub database_id: [u8; 16],
    pub key_generation: u32,
    pub table_names: Vec<String>,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub busy_timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineEnrollmentReceiptRecord {
    pub relay_server_id: [u8; 16],
    pub machine_route: [u8; 16],
    pub root_fingerprint: [u8; 32],
}

#[derive(Debug, Error)]
pub enum RuntimeStoreError {
    #[error("runtime store path must be absolute")]
    PathNotAbsolute,
    #[error("runtime store symbolic link is forbidden: {path}")]
    SymlinkRejected { path: PathBuf },
    #[error("runtime store path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("runtime store file has unsafe ownership, mode, or link count: {path}")]
    UnsafeFile { path: PathBuf },
    #[error("runtime schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("runtime schema is unknown, incomplete, or corrupt")]
    UnknownOrCorruptSchema,
    #[error("runtime schema changed during read-only inspection")]
    SchemaInspectionRaced,
    #[error("runtime SQLite pragma {name} read back {actual}, expected {expected}")]
    PragmaMismatch {
        name: &'static str,
        expected: String,
        actual: String,
    },
    #[error("runtime store is already open in this process")]
    StoreAlreadyOpen,
    #[error("runtime enrollment rescue receipt conflicts with the existing root fingerprint")]
    RescueReceiptConflict,
    #[error("runtime store command queue is full")]
    WorkerBusy,
    #[error("runtime store worker stopped before replying")]
    WorkerStopped,
    #[error("runtime store worker did not shut down before its hard deadline")]
    ShutdownTimedOut,
    #[error("runtime store configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("runtime store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime store SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("runtime store encryption failed: {0}")]
    Cipher(#[from] CipherError),
}

impl RuntimeStoreError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PathNotAbsolute
            | Self::SymlinkRejected { .. }
            | Self::NotRegularFile { .. }
            | Self::UnsafeFile { .. }
            | Self::InvalidConfig(_) => "daemon.runtime.store_invalid",
            Self::SchemaTooNew { .. }
            | Self::UnknownOrCorruptSchema
            | Self::SchemaInspectionRaced => "daemon.runtime.schema_incompatible",
            Self::PragmaMismatch { .. }
            | Self::StoreAlreadyOpen
            | Self::RescueReceiptConflict
            | Self::WorkerStopped
            | Self::ShutdownTimedOut
            | Self::Io(_)
            | Self::Sqlite(_) => "daemon.runtime.store_unavailable",
            Self::WorkerBusy => "daemon.runtime.store_busy",
            Self::Cipher(_) => "daemon.runtime.crypto_failed",
        }
    }
}
