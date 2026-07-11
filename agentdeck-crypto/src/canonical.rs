//! Canonical helpers。canonical TBS / OuterContext AAD / HPKE info 的确定性编码由
//! `agentdeck-protocol::e2ee`（P1.2）拥有；本模块只提供 crypto 侧共用的 SHA-256。

use sha2::{Digest, Sha256};

/// SHA-256 摘要（golden vectors 与 sealed-blob TBS 复用）。
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
