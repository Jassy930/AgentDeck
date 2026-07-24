//! 高频对称内容加密（design §7.1 / §7.4）——RFC 8439 ChaCha20-Poly1305。
//!
//! 每个对称发送 key 只有一个发送方向；nonce = `32-bit key-derived pseudorandom prefix ||
//! 64-bit big-endian sender counter`（design §7.4）。AAD 用 P1.2 的
//! [`OuterContextV1::encode_aad`] 确定性编码。
//!
//! 对称 key wrapper zeroize-on-drop，`Debug` 不输出材料。

use agentdeck_protocol::e2ee::context::OuterContextV1;
use agentdeck_protocol::e2ee::key_control::{KeyControlRequestV1, KeySyncRequestV1};
use agentdeck_protocol::e2ee::keys::{KeyId, KeyPurpose};
use agentdeck_protocol::e2ee::payload::{
    SealedPayloadKind, SealedPayloadV1, UnsignedSealedBlobV1, VerifiedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::RequestRouteId;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

const NONCE_PREFIX_DERIVATION_DOMAIN: &[u8] = b"AgentDeck/AEADNoncePrefix/v1\0";

/// 32-byte 对称 AEAD key。zeroize-on-drop；`Debug` 脱敏。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretAeadKey([u8; 32]);

impl std::fmt::Debug for SecretAeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretAeadKey").field(&"<redacted>").finish()
    }
}

impl SecretAeadKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretAeadKey(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 从双方已经持有的 256-bit 随机 AEAD key 稳定派生 32-bit nonce prefix。
///
/// 这是 domain-separated HMAC-SHA256 的确定性伪随机投影，不改变 wrapped-key wire，
/// 也不把 raw key 暴露给调用方。相同 key 的两端必然得到相同 prefix；不同 key 即使
/// 偶然得到相同 32-bit prefix，也属于不同 ChaCha20-Poly1305 nonce domain。调用方仍须
/// 让同一 key 生命周期内的 durable sender counter 永不回退或复用。
#[must_use]
pub fn derive_nonce_prefix(key: &SecretAeadKey) -> [u8; 4] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts a 32-byte AEAD key");
    mac.update(NONCE_PREFIX_DERIVATION_DOMAIN);
    let projection = mac.finalize().into_bytes();
    [projection[0], projection[1], projection[2], projection[3]]
}

/// 64-bit sender counter（design §7.4）；填入 nonce 后 8 字节（big-endian）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderCounter(pub u64);

/// 单方向发送 key：key 身份 + epoch + key-directory revision + nonce prefix + 秘密 key。
///
/// # 安全（nonce 唯一性）
///
/// nonce = `nonce_prefix || counter`（design §7.4），因此**同一 key 下 counter 复用等价于
/// nonce 复用**——对 ChaCha20-Poly1305 是灾难性的（泄漏 keystream 与认证密钥）。counter 的
/// 唯一性由上层 CounterGuard / counter block reservation（P1.5，design §7.4）负责：预留先
/// 提升 Keychain high-water，崩溃恢复允许跳号但绝不复用；本类型与 [`seal_symmetric`]
/// **不做任何复用防护**。
#[derive(Debug)]
pub struct AeadSendingKey {
    pub key_id: KeyId,
    pub epoch: u64,
    pub key_directory_revision: u64,
    pub nonce_prefix: [u8; 4],
    key: SecretAeadKey,
}

impl AeadSendingKey {
    /// 显式 nonce prefix 构造器，仅供协议 golden vector、跨语言 synthetic fixture 与测试使用。
    /// Production wrapped-key 路径必须使用 [`Self::with_derived_nonce_prefix`]，避免两端各自生成
    /// 或硬编码不一致的 prefix。
    #[must_use]
    pub fn new(
        key_id: KeyId,
        epoch: u64,
        key_directory_revision: u64,
        nonce_prefix: [u8; 4],
        key: SecretAeadKey,
    ) -> Self {
        Self {
            key_id,
            epoch,
            key_directory_revision,
            nonce_prefix,
            key,
        }
    }

    /// Production constructor：从 wrapped-key 中已有的随机 AEAD key 双端派生稳定 prefix。
    #[must_use]
    pub fn with_derived_nonce_prefix(
        key_id: KeyId,
        epoch: u64,
        key_directory_revision: u64,
        key: SecretAeadKey,
    ) -> Self {
        let nonce_prefix = derive_nonce_prefix(&key);
        Self::new(key_id, epoch, key_directory_revision, nonce_prefix, key)
    }
}

/// 单方向接收 key（open 使用 blob 内 nonce，故不需 nonce prefix）。
#[derive(Debug)]
pub struct AeadReceivingKey {
    pub key_id: KeyId,
    pub epoch: u64,
    key: SecretAeadKey,
}

impl AeadReceivingKey {
    pub fn new(key_id: KeyId, epoch: u64, key: SecretAeadKey) -> Self {
        Self { key_id, epoch, key }
    }
}

/// 组装 nonce = `nonce_prefix(4) || counter.to_be_bytes()(8)`（design §7.4）。
fn assemble_nonce(prefix: &[u8; 4], counter: SenderCounter) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&counter.0.to_be_bytes());
    nonce
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey("aead key"))?;
    let nonce = Nonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::BadCiphertext)
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey("aead key"))?;
    let nonce = Nonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::BadCiphertext)
}

/// 对称封装明文，产出未签名 sealed blob（design §7.3/§7.4）。AAD 绑定 `context`，nonce 由
/// key prefix + counter 组装。`payload_kind` 与业务 bytes 先编码进 `SealedPayloadV1`，再整体
/// AEAD 加密；外层 sealed blob 不暴露业务类型。`key_directory_revision` 来自发送 key 的目录状态。
///
/// # 安全（调用方契约）
///
/// 调用方**必须保证同一 `key` 下 `counter` 永不复用**：(key, counter) 复用即 nonce 复用，
/// 对 ChaCha20-Poly1305 是灾难性的。本函数**不校验**复用——唯一性由上层 CounterGuard /
/// counter block reservation（P1.5，design §7.4）负责；counter 接近上界时上层必须强制新
/// epoch，不允许 wrap。
pub fn seal_symmetric(
    key: &AeadSendingKey,
    context: &OuterContextV1,
    payload_kind: SealedPayloadKind,
    plaintext: &[u8],
    counter: SenderCounter,
) -> Result<UnsignedSealedBlobV1, CryptoError> {
    let nonce = assemble_nonce(&key.nonce_prefix, counter);
    let aad = context.encode_aad();
    let inner = SealedPayloadV1::new(payload_kind, plaintext.to_vec()).to_plaintext_bytes()?;
    let ciphertext = seal(key.key.as_bytes(), &nonce, &aad, &inner)?;
    Ok(UnsignedSealedBlobV1::new(
        key.key_id,
        key.epoch,
        key.key_directory_revision,
        nonce,
        ciphertext,
    ))
}

/// 使用当前 DeviceCommandTx capability 封装 exact-next `KeySync` probe。
///
/// 该控制请求的 sealed header revision 必须声明请求的 exact-next directory revision，
/// 使 daemon 能在不解析 Relay outer 的前提下选择 key-control 路径；加密材料仍只能来自
/// 当前已安装的 DeviceCommandTx key。调用方不能传裸 revision 或任意 AAD：known/current、
/// exact-next requested revision、authority 与 uplink context 都由 typed request 在这里闭合。
pub fn seal_key_sync_probe(
    key: &AeadSendingKey,
    request_route: RequestRouteId,
    request: &KeySyncRequestV1,
    counter: SenderCounter,
) -> Result<(UnsignedSealedBlobV1, OuterContextV1), CryptoError> {
    request.validate()?;
    if request_route.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidKey("KeySync request route"));
    }
    let exact_next = request
        .known_key_directory_revision
        .next()
        .map_err(|_| CryptoError::InvalidKey("KeySync directory revision"))?;
    if key.key_id.purpose != KeyPurpose::DeviceCommandTx
        || key.key_id.epoch != key.epoch
        || key.key_directory_revision != request.known_key_directory_revision.value()
        || request.requested_key_directory_revision != exact_next
    {
        return Err(CryptoError::InvalidKey("KeySync DeviceCommandTx binding"));
    }

    let control = KeyControlRequestV1::key_sync(request.clone());
    let plaintext = control.canonical_bytes()?;
    let context = OuterContextV1::uplink_send(
        request.machine_route,
        request.device_route,
        request_route,
        key.epoch,
    );
    context.validate().map_err(|_| CryptoError::BadCiphertext)?;
    let nonce = assemble_nonce(&key.nonce_prefix, counter);
    let aad = context.encode_aad();
    let inner =
        SealedPayloadV1::new(control.sealed_payload_kind(), plaintext).to_plaintext_bytes()?;
    let ciphertext = seal(key.key.as_bytes(), &nonce, &aad, &inner)?;
    Ok((
        UnsignedSealedBlobV1::new(
            key.key_id,
            key.epoch,
            request.requested_key_directory_revision.value(),
            nonce,
            ciphertext,
        ),
        context,
    ))
}

/// 对已验证 sealed blob 做 AEAD 解密取明文（type-state 保证已验签发送方）。AAD 必须与
/// 发送方 `context` 逐字节一致，否则 tag 校验失败返回 [`CryptoError::BadCiphertext`]。
///
/// # key 选择（上层职责）
///
/// 本函数**不交叉校验** [`AeadReceivingKey`] 的 `key_id`/`epoch` 与 blob 头
/// （`key_id`/`key_epoch`/`key_directory_revision`）的一致性——按 blob 头选取正确接收 key
/// 属上层（key directory / replay state，design §7.2/§7.5）职责；传错 key 由 AEAD tag
/// 校验失败兜底（[`CryptoError::BadCiphertext`]），不会静默解出错误明文。
pub fn open_sealed_payload(
    key: &AeadReceivingKey,
    context: &OuterContextV1,
    blob: VerifiedSealedBlobV1,
) -> Result<SealedPayloadV1, CryptoError> {
    let inner = &blob.sealed().inner;
    let aad = context.encode_aad();
    let plaintext = open(key.key.as_bytes(), &inner.nonce, &aad, &inner.ciphertext)?;
    SealedPayloadV1::from_plaintext_bytes(&plaintext).map_err(CryptoError::from)
}

/// 兼容只消费业务 bytes 的调用点；新 runtime dispatch 应使用 [`open_sealed_payload`] 先读取
/// 密文内 kind，再按 endpoint schema 分派。
pub fn open_symmetric(
    key: &AeadReceivingKey,
    context: &OuterContextV1,
    blob: VerifiedSealedBlobV1,
) -> Result<Vec<u8>, CryptoError> {
    Ok(open_sealed_payload(key, context, blob)?.payload)
}
