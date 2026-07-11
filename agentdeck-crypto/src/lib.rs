//! `agentdeck-crypto` —— AgentDeck Relay E2EE 的 Rust 密码学实现（design §7）。
//!
//! 固定密码套件（design §7.1，**禁止手写 X25519/HKDF box**）：
//! - 身份签名：Ed25519（`ed25519-dalek`）。
//! - key wrap / pairing：RFC 9180 HPKE **Base mode**，suite X25519 + HKDF-SHA256 +
//!   ChaCha20-Poly1305（`hpke` crate，唯一高层 HPKE 实现）。
//! - 高频内容：RFC 8439 ChaCha20-Poly1305（`chacha20poly1305`）。
//!
//! 依赖方向固定 `agentdeck-crypto -> agentdeck-protocol`：canonical TBS / OuterContext AAD /
//! HPKE info 的确定性编码由 protocol（P1.2）拥有，本 crate 只做真实密码学并复用那些 bytes。
//! deterministic golden vectors 见 `tests/golden_vectors.rs` 与
//! `protocol/agentdeck/crypto-vectors-v1.json`（P1.6 Swift 镜像的共享事实源）。
//!
//! 所有 secret wrapper（私钥、对称 key）zeroize-on-drop，`Debug` 不输出密钥材料。

pub mod aead;
pub mod canonical;
pub mod error;
pub mod hpke;
pub mod sealed_blob;
pub mod signature;

/// 重导出 `hpke` 使用的 `rand_core`，供调用方为 [`hpke::hpke_seal_base`] 实现 `CryptoRng`
/// （测试用固定 seed RNG 得到确定性 HPKE KAT）。
pub use ::hpke::rand_core;

pub use aead::{
    AeadReceivingKey, AeadSendingKey, SecretAeadKey, SenderCounter, open_symmetric, seal_symmetric,
};
pub use canonical::sha256;
pub use error::CryptoError;
pub use hpke::{HpkeEnvelopeV1, HpkePrivateKey, HpkePublicKey, hpke_open_base, hpke_seal_base};
pub use sealed_blob::{sign_sealed, verify_sealed};
pub use signature::{SignatureBytes, SigningKey, VerifyingKey, sign_tbs, verify_tbs};
