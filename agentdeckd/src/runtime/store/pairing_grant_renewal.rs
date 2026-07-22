//! 同一 DeviceSign fingerprint 的 grant renewal 全局 key transition。
//!
//! renewal 复用既有 device route，同时单调推进 directory/catalog/command/reply 轴；
//! 其他设备的 command/reply key 必须逐字保持。

#[cfg(test)]
use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::DeviceRouteId;

use crate::runtime::model::RuntimeStoreError;
use crate::security::SecretBytes;

use super::pairing_grant::{DeviceTransportKey, GlobalKeyStateV1, InternalKey, MAX_DEVICES};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyAxesForTest {
    pub(crate) catalog_epoch: u64,
    pub(crate) catalog_hash: [u8; 32],
    pub(crate) command_epoch: u64,
    pub(crate) command_hash: [u8; 32],
    pub(crate) reply_epoch: u64,
    pub(crate) reply_hash: [u8; 32],
}

impl GlobalKeyStateV1 {
    /// 消费旧 singleton，轮换 Catalog 与目标设备双向 key；其他设备 key 原样保留。
    pub(crate) fn renew_for_device(
        mut self,
        device_route: DeviceRouteId,
        catalog_key: SecretBytes,
        command_key: SecretBytes,
        reply_key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        if self.catalogs.len() >= MAX_DEVICES {
            return Err(RuntimeStoreError::PairingLimit);
        }
        let device_index = self
            .devices
            .iter()
            .position(|device| device.device_route == device_route && device.is_active())
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let device = &self.devices[device_index];
        let current_command = device
            .command
            .key
            .as_ref()
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let current_reply = device
            .reply
            .key
            .as_ref()
            .ok_or(RuntimeStoreError::PairingConflict)?;
        if catalog_key.expose_secret() == current_command.expose_secret()
            || catalog_key.expose_secret() == current_reply.expose_secret()
            || command_key.expose_secret() == current_command.expose_secret()
            || command_key.expose_secret() == current_reply.expose_secret()
            || reply_key.expose_secret() == current_command.expose_secret()
            || reply_key.expose_secret() == current_reply.expose_secret()
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let next_command_epoch = device.command.epoch.checked_add(1).ok_or(
            RuntimeStoreError::CapacityArithmeticOverflow {
                field: "device_command_key_epoch",
            },
        )?;
        let next_reply_epoch = device.reply.epoch.checked_add(1).ok_or(
            RuntimeStoreError::CapacityArithmeticOverflow {
                field: "device_reply_key_epoch",
            },
        )?;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_key_directory_revision",
                })?;
        let current_catalog = self
            .catalogs
            .last_mut()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let next_catalog_epoch = current_catalog.epoch.checked_add(1).ok_or(
            RuntimeStoreError::CapacityArithmeticOverflow {
                field: "catalog_key_epoch",
            },
        )?;
        current_catalog.retire_with_unknown_legacy_time()?;
        self.catalogs
            .push(InternalKey::new(next_catalog_epoch, catalog_key)?);
        self.devices[device_index].command =
            DeviceTransportKey::new(next_command_epoch, command_key)?;
        self.devices[device_index].reply = DeviceTransportKey::new(next_reply_epoch, reply_key)?;
        self.validate()?;
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn key_axes_for_test(&self, device_route: DeviceRouteId) -> Option<KeyAxesForTest> {
        let catalog = self.catalogs.last()?;
        let device = self.device(device_route)?;
        let command = device.command.key.as_ref()?;
        let reply = device.reply.key.as_ref()?;
        Some(KeyAxesForTest {
            catalog_epoch: catalog.epoch,
            catalog_hash: sha256(catalog.key.expose_secret()),
            command_epoch: device.command.epoch,
            command_hash: sha256(command.expose_secret()),
            reply_epoch: device.reply.epoch,
            reply_hash: sha256(reply.expose_secret()),
        })
    }
}
