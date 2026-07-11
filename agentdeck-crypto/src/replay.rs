//! 每个 key 独立的接收 replay window 纯状态机。

use std::collections::BTreeMap;

use agentdeck_protocol::e2ee::E2eeError;

use crate::error::CryptoError;

/// 接收 replay window 保留的 counter 数量。
pub const REPLAY_WINDOW_SIZE: u64 = 4_096;

/// 在接收 replay 状态中观察 ciphertext tuple 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDisposition {
    Fresh,
    ExactDuplicate,
    Stale,
}

/// 每个 key 独立滑动的 `counter -> ciphertext hash` 保留映射。
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    high_water: Option<u64>,
    floor: u64,
    hashes: BTreeMap<u64, [u8; 32]>,
}

impl ReplayWindow {
    /// 从空 replay window 开始。
    pub fn new() -> Self {
        Self::default()
    }

    /// 观察一个 `(counter, ciphertext_hash)` tuple。
    ///
    /// 低于当前 floor 的 counter 直接判为 stale，不再比较历史 hash；保留窗口内用 hash 区分
    /// 精确重传与 nonce reuse；窗口内未见过的 counter 作为乱序 fresh delivery 接受。
    pub fn observe(
        &mut self,
        counter: u64,
        ciphertext_hash: [u8; 32],
    ) -> Result<ReplayDisposition, CryptoError> {
        if counter < self.floor {
            return Ok(ReplayDisposition::Stale);
        }

        if let Some(previous_hash) = self.hashes.get(&counter) {
            return if *previous_hash == ciphertext_hash {
                Ok(ReplayDisposition::ExactDuplicate)
            } else {
                Err(CryptoError::E2ee(E2eeError::NonceReuse))
            };
        }

        let advances_high_water = match self.high_water {
            Some(high_water) => counter > high_water,
            None => true,
        };
        if advances_high_water {
            self.high_water = Some(counter);
            self.floor = counter.saturating_sub(REPLAY_WINDOW_SIZE - 1);
            self.hashes = self.hashes.split_off(&self.floor);
        }

        self.hashes.insert(counter, ciphertext_hash);
        Ok(ReplayDisposition::Fresh)
    }
}
