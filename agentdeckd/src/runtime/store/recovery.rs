//! 不依赖 StorageKEK 的最小 rescue index。
//!
//! 这条路径只允许读取 Relay server、machine route 和 MachineRoot fingerprint；
//! 它不会创建数据库、迁移 schema、解包行密钥或生成新的 machine identity。

use std::path::Path;

use crate::runtime::model::{MachineEnrollmentReceiptRecord, RuntimeStoreError};

use super::{sqlite, worker};

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeRescueIndex;

impl RuntimeRescueIndex {
    pub fn read(
        storage_path: impl AsRef<Path>,
    ) -> Result<Vec<MachineEnrollmentReceiptRecord>, RuntimeStoreError> {
        let storage_path = sqlite::normalize_storage_path(storage_path.as_ref())?;
        let _lease = worker::claim_store_path(&storage_path)?;
        sqlite::read_rescue_index(&storage_path)
    }
}
