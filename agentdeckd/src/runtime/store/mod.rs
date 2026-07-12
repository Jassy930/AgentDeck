//! Runtime SQLite journal：单 worker、严格 schema 与行级加密。

pub mod cipher;
mod recovery;
mod schema;
mod sqlite;
mod worker;

pub use crate::runtime::model::{
    MachineEnrollmentReceiptRecord, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreFaultInjector, RuntimeStoreOperation, RuntimeStoreSnapshot,
};
pub use recovery::RuntimeRescueIndex;
pub use schema::{RUNTIME_SCHEMA_FAMILY, RUNTIME_SCHEMA_VERSION};
pub use worker::RuntimeStoreHandle;
