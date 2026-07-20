//! HPKE Base mode key wrap（design §7.1 / §7.2）——RFC 9180 Base mode，固定 suite
//! X25519 + HKDF-SHA256 + ChaCha20-Poly1305。仅用成熟 `hpke` crate，**禁止手写
//! X25519/HKDF box**。发送方身份由 §7.3 的 Ed25519 外部签名提供，不用 HPKE Auth mode。
//!
//! HPKE 只封装小型对称 key（design §7.2）；事件/命令内容走对称 AEAD（见 `aead`）。
//!
//! 私钥 wrapper 依赖内层 x25519 `StaticSecret` 的 zeroize-on-drop，`Debug` 脱敏。

use ::hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

use crate::error::CryptoError;

// 固定密码套件（design §7.1）。
type Kem = ::hpke::kem::X25519HkdfSha256;
type Kdf = ::hpke::kdf::HkdfSha256;
type Aead = ::hpke::aead::ChaCha20Poly1305;

type KemPublicKey = <Kem as KemTrait>::PublicKey;
type KemPrivateKey = <Kem as KemTrait>::PrivateKey;
type KemEncappedKey = <Kem as KemTrait>::EncappedKey;

/// HPKE recipient 公钥（X25519）。
#[derive(Clone)]
pub struct HpkePublicKey(KemPublicKey);

impl std::fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HpkePublicKey").field(&"..").finish()
    }
}

impl HpkePublicKey {
    /// 原始序列化字节（X25519 公钥，32 bytes）。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// 从原始字节反序列化；非法点返回 [`CryptoError::InvalidKey`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        KemPublicKey::from_bytes(bytes)
            .map(HpkePublicKey)
            .map_err(|_| CryptoError::InvalidKey("hpke public key"))
    }
}

/// HPKE recipient 私钥（X25519）。zeroize-on-drop（内层 x25519 StaticSecret）；`Debug` 脱敏。
pub struct HpkePrivateKey(KemPrivateKey);

impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HpkePrivateKey")
            .field(&"<redacted>")
            .finish()
    }
}

impl HpkePrivateKey {
    /// 确定性从 IKM 派生 recipient keypair（RFC 9180 DeriveKeyPair，无 RNG）。
    pub fn derive_keypair(ikm: &[u8]) -> (HpkePrivateKey, HpkePublicKey) {
        let (sk, pk) = Kem::derive_keypair(ikm);
        (HpkePrivateKey(sk), HpkePublicKey(pk))
    }

    /// 原始序列化字节（**仅供 KAT/测试**；生产私钥留在 Keychain）。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// 从原始字节反序列化；非法点返回 [`CryptoError::InvalidKey`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        KemPrivateKey::from_bytes(bytes)
            .map(HpkePrivateKey)
            .map_err(|_| CryptoError::InvalidKey("hpke private key"))
    }

    /// 从已导入的 X25519 私钥确定性投影对应公钥。
    #[must_use]
    pub fn public_key(&self) -> HpkePublicKey {
        HpkePublicKey(<Kem as KemTrait>::sk_to_pk(&self.0))
    }
}

/// HPKE Base 封装结果：`enc`（encapsulated ephemeral 公钥）+ AEAD `ciphertext`（含 tag）。
#[derive(Clone, PartialEq, Eq)]
pub struct HpkeEnvelopeV1 {
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for HpkeEnvelopeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HpkeEnvelopeV1")
            .field("encrypted_material", &"<redacted>")
            .finish()
    }
}

/// HPKE Base mode 单发封装（design §7.1）。`rng` 为 `hpke` 重导出的 `rand_core::CryptoRng`；
/// 测试传入固定 seed RNG 得到 byte-for-byte KAT。
pub fn hpke_seal_base<R: ::hpke::rand_core::CryptoRng>(
    recipient: &HpkePublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<HpkeEnvelopeV1, CryptoError> {
    let (encapped, ciphertext) = ::hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient.0,
        info,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Hpke("seal"))?;
    Ok(HpkeEnvelopeV1 {
        enc: encapped.to_bytes().to_vec(),
        ciphertext,
    })
}

/// HPKE Base mode 单发解封装。密文/tag/info/aad 任一不匹配返回 [`CryptoError::BadCiphertext`]。
pub fn hpke_open_base(
    recipient: &HpkePrivateKey,
    info: &[u8],
    aad: &[u8],
    envelope: &HpkeEnvelopeV1,
) -> Result<Vec<u8>, CryptoError> {
    let encapped = KemEncappedKey::from_bytes(&envelope.enc)
        .map_err(|_| CryptoError::Hpke("bad encapsulated key"))?;
    ::hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient.0,
        &encapped,
        info,
        &envelope.ciphertext,
        aad,
    )
    .map_err(|_| CryptoError::BadCiphertext)
}
