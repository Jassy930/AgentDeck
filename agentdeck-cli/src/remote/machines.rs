//! Persistent `remote machines` 的纯本地服务。
//!
//! 唯一数据源是当前 composition 的 stable installation identity 与
//! [`RecoveredPairedMachineStore`]。启动时唯一允许的 mutation 是恢复已经通过全库审计的
//! durable revoke cleanup journal；随后 inventory 本身保持只读。本模块没有 Relay、Runtime UDS
//! 或网络依赖。

#![cfg(unix)]

use std::fmt;

use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId};
use agentdeck_protocol::runtime::MachineRootFingerprint;
use serde::Serialize;
use thiserror::Error;

use crate::installation::InstallationId;

use super::paired_machine::PairedPromotionError;
use super::production::{PersistentRemoteComposition, RecoveredPairedMachineStore};

/// `remote machines` 的无 secret、稳定 JSON 行投影。
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentRemoteMachineProjection {
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    machine_display_name: String,
}

impl fmt::Debug for PersistentRemoteMachineProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistentRemoteMachineProjection([REDACTED ROUTES])")
    }
}

/// 持有已完成 startup cleanup recovery 的 paired-store view；inventory 不打开 device lease
/// 或建立任何连接。
pub struct PersistentRemoteMachinesService<'a> {
    installation_id: InstallationId,
    paired_store: RecoveredPairedMachineStore<'a>,
}

impl<'a> PersistentRemoteMachinesService<'a> {
    pub fn from_composition(
        composition: &'a PersistentRemoteComposition,
    ) -> Result<Self, PersistentRemoteMachinesError> {
        let installation_id = composition.installation_id();
        Ok(Self {
            installation_id,
            paired_store: composition.recovered_paired_machine_store()?,
        })
    }

    pub fn list(
        &self,
    ) -> Result<Vec<PersistentRemoteMachineProjection>, PersistentRemoteMachinesError> {
        self.paired_store
            .list()?
            .into_iter()
            .map(|summary| {
                let identity = summary.identity();
                Ok(PersistentRemoteMachineProjection {
                    machine_root_fingerprint: identity.machine_root_fingerprint(),
                    machine_route: identity.machine_route(),
                    device_route: summary.device_route(),
                    machine_display_name: summary.machine_display_name().to_owned(),
                })
            })
            .collect()
    }

    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }
}

/// Library handler：生成 CLI 可直接渲染的 typed JSON projection，不执行输出或拨号。
pub fn list_persistent_remote_machines(
    composition: &PersistentRemoteComposition,
) -> Result<serde_json::Value, PersistentRemoteMachinesError> {
    let service = PersistentRemoteMachinesService::from_composition(composition)?;
    let machines = service.list()?;
    Ok(serde_json::json!({
        "operation": "remote.machines",
        "result": {
            "installationId": service.installation_id().to_string(),
            "machines": machines,
        }
    }))
}

#[derive(Debug, Error)]
pub enum PersistentRemoteMachinesError {
    #[error("persistent remote machine inventory failed")]
    Paired(#[from] PairedPromotionError),
}

impl PersistentRemoteMachinesError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Paired(error) => error.code(),
        }
    }
}
