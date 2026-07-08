// agentdeck-relay/src/auth/store.rs
//! 身份数据模型（Account/Device/Challenge）+ RelayStore trait + 内存实现。
//! 纯数据结构，不含密码学、不含网络。

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Machine,
    Device,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub account_id: String,
    pub owner_sign_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub account_id: String,
    pub role: DeviceRole,
    pub credential_hash: String,
    pub sign_pubkey: String,
    pub box_pubkey: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub device_sign_pubkey: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub used: bool,
}

/// enroll 逻辑所需的存储接口——由 `InMemoryRelayStore` 实现；Task 9 起可换持久化实现。
pub(crate) trait RelayStore {
    fn put_challenge(&mut self, challenge: Challenge);
    /// 单次消费：命中且未过期未使用 → 返回并从存储中移除（等价于原子 mark_used）；否则 None。
    fn take_challenge(&mut self, device_sign_pubkey: &str, now_ms: i64) -> Option<Challenge>;
    fn singleton_account(&self) -> Option<&Account>;
    fn create_account(&mut self, account: Account);
    fn put_device(&mut self, device: Device);
    fn device(&self, device_id: &str) -> Option<&Device>;
    /// WS 握手鉴权用：客户端只携带 bearer credential（非 device_id），需要反查
    /// 命中的 `Device`。`InMemoryRelayStore` 未维护额外反向索引，线性扫描
    /// `devices`——内存 fake relay 场景设备规模小，可接受。
    fn device_by_credential_hash(&self, credential_hash: &str) -> Option<&Device>;
    fn account_count(&self) -> usize;
    /// Task 9 起用于设备撤销流程；本 task 无消费方，靠 crate 顶层 `#[allow(dead_code)]` 静默。
    fn mark_revoked(&mut self, device_id: &str);
}

/// 起 Task 9 起为 `pub`——`agentdeck-relay` 二进制（main.rs，独立 crate）需要
/// 直接构造它并传给 `server::serve`。字段仍私有，只能通过 `Default` 构造。
#[derive(Debug, Default)]
pub struct InMemoryRelayStore {
    challenges: HashMap<String, Challenge>,
    account: Option<Account>,
    devices: HashMap<String, Device>,
}

impl RelayStore for InMemoryRelayStore {
    fn put_challenge(&mut self, challenge: Challenge) {
        self.challenges.insert(challenge.device_sign_pubkey.clone(), challenge);
    }

    fn take_challenge(&mut self, device_sign_pubkey: &str, now_ms: i64) -> Option<Challenge> {
        let still_valid = matches!(
            self.challenges.get(device_sign_pubkey),
            Some(c) if !c.used && c.expires_at_ms > now_ms
        );
        if still_valid {
            self.challenges.remove(device_sign_pubkey)
        } else {
            None
        }
    }

    fn singleton_account(&self) -> Option<&Account> {
        self.account.as_ref()
    }

    fn create_account(&mut self, account: Account) {
        self.account = Some(account);
    }

    fn put_device(&mut self, device: Device) {
        self.devices.insert(device.device_id.clone(), device);
    }

    fn device(&self, device_id: &str) -> Option<&Device> {
        self.devices.get(device_id)
    }

    fn device_by_credential_hash(&self, credential_hash: &str) -> Option<&Device> {
        self.devices.values().find(|d| d.credential_hash == credential_hash)
    }

    fn account_count(&self) -> usize {
        if self.account.is_some() { 1 } else { 0 }
    }

    fn mark_revoked(&mut self, device_id: &str) {
        if let Some(d) = self.devices.get_mut(device_id) {
            d.revoked = true;
        }
    }
}
