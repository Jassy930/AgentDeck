//! Runtime SQLite 敏感列的行级加密与确定性盲索引。
//!
//! `StorageKek` 只包装本数据库的 key bundle；普通行只使用 bundle 中的
//! `RuntimeRowDEK`。所有密文都携带固定 v1 header，真正的行位置通过规范化、
//! 长度前缀 AAD 绑定，因而跨行、跨列或跨数据库搬运密文都会认证失败。

use std::fmt;
use std::sync::{Arc, Mutex};

#[cfg(test)]
use std::cell::RefCell;

use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload, Tag};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::security::{SecretBytes, StorageKek};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_MAGIC_LEN: usize = 4;
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_CHACHA20_POLY1305: u8 = 1;
const KEY_PLAINTEXT_LEN: usize = 4 + 4 + KEY_LEN + KEY_LEN;

const KEY_BLOB_MAGIC: &[u8; HEADER_MAGIC_LEN] = b"ADKB";
const KEY_PLAINTEXT_MAGIC: &[u8; HEADER_MAGIC_LEN] = b"ADK1";
const ROW_BLOB_MAGIC: &[u8; HEADER_MAGIC_LEN] = b"ADRB";
const KEY_WRAP_DOMAIN: &[u8] = b"agentdeck.runtime.key-bundle";
const ROW_DOMAIN: &[u8] = b"agentdeck.runtime.row";
const BLIND_INDEX_DOMAIN: &[u8] = b"agentdeck.runtime.blind-index";

/// 两类 v1 blob 共用的固定 header：magic(4)、version(1)、algorithm(1)、
/// reserved(2)、generation(4)、nonce(12)。
pub const ROW_BLOB_V1_HEADER_LEN: usize = HEADER_MAGIC_LEN + 1 + 1 + 2 + 4 + NONCE_LEN;
pub const ROW_BLOB_V1_OVERHEAD_LEN: usize = ROW_BLOB_V1_HEADER_LEN + TAG_LEN;
pub const MAX_RUNTIME_ROW_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// 包装 key bundle 的固定 v1 编码长度。
pub const WRAPPED_KEY_BUNDLE_V1_LEN: usize = ROW_BLOB_V1_HEADER_LEN + KEY_PLAINTEXT_LEN + TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CipherAllocationObservation {
    peak_retained_bytes: usize,
}

#[cfg(test)]
impl CipherAllocationObservation {
    pub(crate) const fn peak_retained_bytes(self) -> usize {
        self.peak_retained_bytes
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct CipherAllocationProbeState {
    retained_bytes: usize,
    peak_retained_bytes: usize,
}

#[cfg(test)]
thread_local! {
    static CIPHER_ALLOCATION_PROBE: RefCell<Option<CipherAllocationProbeState>> = const {
        RefCell::new(None)
    };
}

/// 单线程 store/cipher 单测使用的容量观测器。它只统计当前实现真实创建的
/// 大型 `Vec` capacity，不分配 side table，也不进入 production build。
#[cfg(test)]
pub(crate) struct CipherAllocationProbeGuard;

#[cfg(test)]
impl CipherAllocationProbeGuard {
    pub(crate) fn finish(self) -> CipherAllocationObservation {
        let state = CIPHER_ALLOCATION_PROBE.with(|probe| {
            probe
                .borrow_mut()
                .take()
                .expect("cipher allocation probe must be active")
        });
        CipherAllocationObservation {
            peak_retained_bytes: state.peak_retained_bytes,
        }
    }
}

#[cfg(test)]
pub(crate) fn begin_cipher_allocation_probe(retained_bytes: usize) -> CipherAllocationProbeGuard {
    CIPHER_ALLOCATION_PROBE.with(|probe| {
        let previous = probe.borrow_mut().replace(CipherAllocationProbeState {
            retained_bytes,
            peak_retained_bytes: retained_bytes,
        });
        assert!(previous.is_none(), "cipher allocation probes cannot nest");
    });
    CipherAllocationProbeGuard
}

#[cfg(test)]
struct ObservedCipherAllocation {
    capacity: usize,
    active: bool,
}

#[cfg(test)]
impl Drop for ObservedCipherAllocation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        CIPHER_ALLOCATION_PROBE.with(|probe| {
            if let Some(state) = probe.borrow_mut().as_mut() {
                state.retained_bytes = state
                    .retained_bytes
                    .checked_sub(self.capacity)
                    .expect("cipher allocation probe accounting underflow");
            }
        });
    }
}

#[cfg(test)]
fn observe_cipher_allocation(capacity: usize) -> ObservedCipherAllocation {
    let active = CIPHER_ALLOCATION_PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        let Some(state) = probe.as_mut() else {
            return false;
        };
        state.retained_bytes = state
            .retained_bytes
            .checked_add(capacity)
            .expect("cipher allocation probe accounting overflow");
        state.peak_retained_bytes = state.peak_retained_bytes.max(state.retained_bytes);
        true
    });
    ObservedCipherAllocation { capacity, active }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherError {
    #[error("runtime key generation must be non-zero")]
    InvalidGeneration,
    #[error("operating-system entropy source is unavailable")]
    EntropyUnavailable,
    #[error("runtime cipher input has an invalid encoding")]
    InvalidEncoding,
    #[error("runtime cipher version {actual} is unsupported")]
    UnsupportedVersion { actual: u8 },
    #[error("runtime row key generation mismatch: expected {expected}, found {actual}")]
    GenerationMismatch { expected: u32, actual: u32 },
    #[error("runtime cipher context field is empty or invalid: {0}")]
    InvalidContext(&'static str),
    #[error("runtime cipher context exceeds the v1 encoding limit")]
    ContextTooLarge,
    #[error("runtime cipher input exceeds the configured plaintext limit")]
    InputTooLarge,
    #[error("runtime encryption failed")]
    EncryptionFailed,
    #[error("runtime ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("runtime read crypto capability is closed")]
    ReadCapabilityClosed,
    #[error("runtime read crypto capability lock is poisoned")]
    ReadCapabilityPoisoned,
}

impl CipherError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidGeneration => "daemon.runtime.cipher.invalid_generation",
            Self::EntropyUnavailable => "daemon.runtime.cipher.entropy_unavailable",
            Self::InvalidEncoding | Self::UnsupportedVersion { .. } => {
                "daemon.runtime.cipher.invalid_encoding"
            }
            Self::GenerationMismatch { .. } => "daemon.runtime.cipher.generation_mismatch",
            Self::InvalidContext(_) | Self::ContextTooLarge => {
                "daemon.runtime.cipher.invalid_context"
            }
            Self::InputTooLarge => "daemon.runtime.cipher.input_too_large",
            Self::EncryptionFailed => "daemon.runtime.cipher.encrypt_failed",
            Self::AuthenticationFailed => "daemon.runtime.cipher.authentication_failed",
            Self::ReadCapabilityClosed | Self::ReadCapabilityPoisoned => {
                "daemon.runtime.cipher.read_capability_unavailable"
            }
        }
    }
}

/// 一份 Runtime DB 自有的行密钥、盲索引密钥与单调 generation。
///
/// 该类型不实现 `Clone`，并在销毁时清零两把裸密钥。
pub struct RuntimeKeyBundle {
    generation: u32,
    row_dek: [u8; KEY_LEN],
    blind_index_key: [u8; KEY_LEN],
}

/// StorageKEK wrapping 的稳定 schema/database context。
#[derive(Clone, Copy)]
pub struct KeyWrapAad<'a> {
    pub schema_family: &'a [u8],
    pub schema_version: u32,
    pub database_id: &'a [u8],
}

impl fmt::Debug for KeyWrapAad<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "KeyWrapAad {{ schema_version: {}, fields: [REDACTED] }}",
            self.schema_version
        )
    }
}

impl KeyWrapAad<'_> {
    fn validate(&self) -> Result<(), CipherError> {
        validate_nonempty("schema family", self.schema_family)?;
        if self.schema_version == 0 {
            return Err(CipherError::InvalidContext("schema version"));
        }
        validate_nonempty("database id", self.database_id)
    }
}

impl RuntimeKeyBundle {
    /// 为全新数据库或显式轮换 generation 生成两把相互独立的随机密钥。
    pub fn fresh(generation: u32) -> Result<Self, CipherError> {
        if generation == 0 {
            return Err(CipherError::InvalidGeneration);
        }
        let mut material = Zeroizing::new([0_u8; KEY_LEN * 2]);
        getrandom::fill(material.as_mut()).map_err(|_| CipherError::EntropyUnavailable)?;
        let mut row_dek = [0_u8; KEY_LEN];
        let mut blind_index_key = [0_u8; KEY_LEN];
        row_dek.copy_from_slice(&material[..KEY_LEN]);
        blind_index_key.copy_from_slice(&material[KEY_LEN..]);
        Ok(Self {
            generation,
            row_dek,
            blind_index_key,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// 用仅存在于 Keychain 的 `StorageKek` 包装两把 Runtime key。
    /// 每次调用都生成新 nonce，输出可直接写入 `runtime_meta`。
    pub fn wrap(
        &self,
        storage_kek: &StorageKek,
        context: &KeyWrapAad<'_>,
    ) -> Result<Vec<u8>, CipherError> {
        context.validate()?;
        let header = fresh_header(KEY_BLOB_MAGIC, self.generation)?;
        let aad = Zeroizing::new(key_wrap_aad(context, &header)?);
        let mut plaintext = Zeroizing::new(vec![0_u8; KEY_PLAINTEXT_LEN]);
        plaintext[..4].copy_from_slice(KEY_PLAINTEXT_MAGIC);
        plaintext[4..8].copy_from_slice(&self.generation.to_be_bytes());
        plaintext[8..40].copy_from_slice(&self.row_dek);
        plaintext[40..72].copy_from_slice(&self.blind_index_key);
        let ciphertext = encrypt(
            storage_kek.expose_secret(),
            nonce_from_header(&header),
            aad.as_ref(),
            plaintext.as_ref(),
        )?;
        let mut wrapped = Vec::with_capacity(WRAPPED_KEY_BUNDLE_V1_LEN);
        wrapped.extend_from_slice(&header);
        wrapped.extend_from_slice(&ciphertext);
        debug_assert_eq!(wrapped.len(), WRAPPED_KEY_BUNDLE_V1_LEN);
        Ok(wrapped)
    }

    /// 从 `runtime_meta` 固定 v1 blob 恢复 key bundle。任何 header、KEK、
    /// database id 或 tag 不匹配都 fail-close。
    pub fn unwrap(
        storage_kek: &StorageKek,
        context: &KeyWrapAad<'_>,
        wrapped: &[u8],
    ) -> Result<Self, CipherError> {
        context.validate()?;
        if wrapped.len() != WRAPPED_KEY_BUNDLE_V1_LEN {
            return Err(CipherError::InvalidEncoding);
        }
        let header = parse_header(wrapped, KEY_BLOB_MAGIC)?;
        let aad = Zeroizing::new(key_wrap_aad(context, header.bytes)?);
        let plaintext = Zeroizing::new(decrypt(
            storage_kek.expose_secret(),
            &header.nonce,
            aad.as_ref(),
            &wrapped[ROW_BLOB_V1_HEADER_LEN..],
        )?);
        if plaintext.len() != KEY_PLAINTEXT_LEN
            || &plaintext[..4] != KEY_PLAINTEXT_MAGIC
            || plaintext[4..8] != header.generation.to_be_bytes()
        {
            return Err(CipherError::InvalidEncoding);
        }
        let mut row_dek = [0_u8; KEY_LEN];
        let mut blind_index_key = [0_u8; KEY_LEN];
        row_dek.copy_from_slice(&plaintext[8..40]);
        blind_index_key.copy_from_slice(&plaintext[40..72]);
        Ok(Self {
            generation: header.generation,
            row_dek,
            blind_index_key,
        })
    }

    #[must_use]
    pub const fn row_cipher(&self) -> RowCipher<'_> {
        RowCipher { bundle: self }
    }

    /// 计算确定性的 HMAC-SHA256 盲索引。调用方必须提供完整、稳定的用途域，
    /// 例如 `command.idempotency`；域与值均采用长度前缀，不能跨用途碰撞。
    pub fn blind_index(&self, domain: &[u8], value: &[u8]) -> Result<BlindIndex, CipherError> {
        validate_nonempty("blind-index domain", domain)?;
        let mut message = Zeroizing::new(Vec::with_capacity(
            BLIND_INDEX_DOMAIN.len() + domain.len() + value.len(),
        ));
        push_field(&mut message, BLIND_INDEX_DOMAIN)?;
        push_field(&mut message, domain)?;
        push_field(&mut message, value)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.blind_index_key)
            .map_err(|_| CipherError::InvalidEncoding)?;
        mac.update(message.as_ref());
        // HMAC 直接写入最终 Drop-zeroize owner 的同一 32-byte 存储；`from_mut_slice`
        // 只创建借用视图，不产生普通 `Output` 或第二份 `[u8; 32]` secret 临时值。
        let mut index = BlindIndex([0_u8; KEY_LEN]);
        mac.finalize_into(hmac::digest::Output::<HmacSha256>::from_mut_slice(
            &mut index.0,
        ));
        Ok(index)
    }

    pub(crate) fn read_only_capability(&self) -> RuntimeReadCryptoCapability {
        RuntimeReadCryptoCapability {
            inner: Arc::new(RuntimeReadCryptoInner {
                key_bundle: Mutex::new(Some(Self {
                    generation: self.generation,
                    row_dek: self.row_dek,
                    blind_index_key: self.blind_index_key,
                })),
            }),
        }
    }
}

/// 只允许 open/verify 的共享读能力。它不暴露 `RuntimeKeyBundle`、RowCipher seal
/// 或 HMAC 输出；daemon shutdown 会 `close()` 并从共享 slot 取走 key material，
/// 即使仍有 `RuntimeStoreHandle` clone，所有 clone 也只观察 closed capability。
#[derive(Clone)]
pub(crate) struct RuntimeReadCryptoCapability {
    inner: Arc<RuntimeReadCryptoInner>,
}

struct RuntimeReadCryptoInner {
    key_bundle: Mutex<Option<RuntimeKeyBundle>>,
}

impl RuntimeReadCryptoCapability {
    pub(crate) fn open_bounded(
        &self,
        context: &RowAad<'_>,
        blob: &[u8],
        maximum_plaintext_len: usize,
    ) -> Result<SecretBytes, CipherError> {
        let key = self
            .inner
            .key_bundle
            .lock()
            .map_err(|_| CipherError::ReadCapabilityPoisoned)?;
        let key = key.as_ref().ok_or(CipherError::ReadCapabilityClosed)?;
        key.row_cipher()
            .open_bounded(context, blob, maximum_plaintext_len)
    }

    pub(crate) fn open_bounded_in_place(
        &self,
        context: &RowAad<'_>,
        blob: &mut Vec<u8>,
        maximum_plaintext_len: usize,
    ) -> Result<(), CipherError> {
        let key = self
            .inner
            .key_bundle
            .lock()
            .map_err(|_| CipherError::ReadCapabilityPoisoned)?;
        let key = key.as_ref().ok_or(CipherError::ReadCapabilityClosed)?;
        key.row_cipher()
            .open_bounded_in_place(context, blob, maximum_plaintext_len)
    }

    pub(crate) fn verify_blind_index(
        &self,
        domain: &[u8],
        value: &[u8],
        expected: &[u8],
    ) -> Result<bool, CipherError> {
        let key = self
            .inner
            .key_bundle
            .lock()
            .map_err(|_| CipherError::ReadCapabilityPoisoned)?;
        let key = key.as_ref().ok_or(CipherError::ReadCapabilityClosed)?;
        Ok(key.blind_index(domain, value)?.as_bytes() == expected)
    }

    pub(crate) fn close(&self) {
        if let Ok(mut key) = self.inner.key_bundle.lock() {
            // `RuntimeKeyBundle::drop` zeroizes both copied read keys here.
            let _zeroized_on_drop = key.take();
        }
    }
}

impl fmt::Debug for RuntimeReadCryptoCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeReadCryptoCapability([REDACTED])")
    }
}

impl fmt::Debug for RuntimeKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RuntimeKeyBundle {{ generation: {}, keys: [REDACTED] }}",
            self.generation
        )
    }
}

impl Drop for RuntimeKeyBundle {
    fn drop(&mut self) {
        self.row_dek.zeroize();
        self.blind_index_key.zeroize();
    }
}

/// 密文认证所绑定的规范行位置。所有 byte 字段均按原样、长度前缀进入 AAD；
/// `primary_key` 必须由 store 使用稳定 canonical bytes 构造。
#[derive(Clone, Copy)]
pub struct RowAad<'a> {
    pub schema_family: &'a [u8],
    pub schema_version: u32,
    pub database_id: &'a [u8],
    pub table: &'a [u8],
    pub primary_key: &'a [u8],
    pub column: &'a [u8],
}

impl fmt::Debug for RowAad<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RowAad {{ schema_version: {}, fields: [REDACTED] }}",
            self.schema_version
        )
    }
}

impl RowAad<'_> {
    fn validate(&self) -> Result<(), CipherError> {
        validate_nonempty("schema family", self.schema_family)?;
        if self.schema_version == 0 {
            return Err(CipherError::InvalidContext("schema version"));
        }
        validate_nonempty("database id", self.database_id)?;
        validate_nonempty("table", self.table)?;
        validate_nonempty("primary key", self.primary_key)?;
        validate_nonempty("column", self.column)
    }
}

/// 借用 key bundle 的行级 ChaCha20-Poly1305 facade。
pub struct RowCipher<'a> {
    bundle: &'a RuntimeKeyBundle,
}

impl RowCipher<'_> {
    /// 使用随机 nonce 加密敏感列。调用方 plaintext 会先复制进自动清零的临时
    /// buffer；本方法不会把明文放进返回值或错误文本。
    pub fn seal(&self, context: &RowAad<'_>, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.seal_bounded(context, plaintext, MAX_RUNTIME_ROW_PLAINTEXT_LEN)
    }

    pub fn seal_bounded(
        &self,
        context: &RowAad<'_>,
        plaintext: &[u8],
        maximum_plaintext_len: usize,
    ) -> Result<Vec<u8>, CipherError> {
        context.validate()?;
        validate_plaintext_length(plaintext.len(), maximum_plaintext_len)?;
        let header = fresh_header(ROW_BLOB_MAGIC, self.bundle.generation)?;
        let aad = Zeroizing::new(row_aad(context, &header)?);
        let plaintext = Zeroizing::new(plaintext.to_vec());
        #[cfg(test)]
        let _plaintext_allocation = observe_cipher_allocation(plaintext.capacity());
        let ciphertext = encrypt(
            &self.bundle.row_dek,
            nonce_from_header(&header),
            aad.as_ref(),
            plaintext.as_ref(),
        )?;
        #[cfg(test)]
        let _ciphertext_allocation = observe_cipher_allocation(ciphertext.capacity());
        let mut blob = Vec::with_capacity(header.len() + ciphertext.len());
        #[cfg(test)]
        let _blob_allocation = observe_cipher_allocation(blob.capacity());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// 在调用方唯一拥有的 plaintext allocation 上原地 seal。调用方必须预留
    /// 固定 row header/tag 空间；本方法不会为 payload 创建第二个大型 `Vec`。
    pub(crate) fn seal_bounded_in_place(
        &self,
        context: &RowAad<'_>,
        plaintext: &mut Vec<u8>,
        maximum_plaintext_len: usize,
    ) -> Result<(), CipherError> {
        context.validate()?;
        validate_plaintext_length(plaintext.len(), maximum_plaintext_len)?;
        let plaintext_len = plaintext.len();
        let sealed_len = plaintext_len
            .checked_add(ROW_BLOB_V1_OVERHEAD_LEN)
            .ok_or(CipherError::InputTooLarge)?;
        if plaintext.capacity() < sealed_len {
            return Err(CipherError::InputTooLarge);
        }
        let header = fresh_header(ROW_BLOB_MAGIC, self.bundle.generation)?;
        let aad = Zeroizing::new(row_aad(context, &header)?);

        plaintext.resize(plaintext_len + ROW_BLOB_V1_HEADER_LEN, 0);
        plaintext.copy_within(0..plaintext_len, ROW_BLOB_V1_HEADER_LEN);
        plaintext[..ROW_BLOB_V1_HEADER_LEN].copy_from_slice(&header);
        let tag = match ChaCha20Poly1305::new((&self.bundle.row_dek).into()).encrypt_inout_detached(
            nonce_from_header(&header),
            aad.as_ref(),
            (&mut plaintext[ROW_BLOB_V1_HEADER_LEN..]).into(),
        ) {
            Ok(tag) => tag,
            Err(_) => {
                plaintext.copy_within(ROW_BLOB_V1_HEADER_LEN.., 0);
                plaintext[plaintext_len..].zeroize();
                plaintext.truncate(plaintext_len);
                return Err(CipherError::EncryptionFailed);
            }
        };
        plaintext.extend_from_slice(tag.as_slice());
        debug_assert_eq!(plaintext.len(), sealed_len);
        Ok(())
    }

    /// 认证并打开敏感列。成功结果使用 `SecretBytes` 持有，离开作用域时清零。
    pub fn open(&self, context: &RowAad<'_>, blob: &[u8]) -> Result<SecretBytes, CipherError> {
        self.open_bounded(context, blob, MAX_RUNTIME_ROW_PLAINTEXT_LEN)
    }

    pub fn open_bounded(
        &self,
        context: &RowAad<'_>,
        blob: &[u8],
        maximum_plaintext_len: usize,
    ) -> Result<SecretBytes, CipherError> {
        context.validate()?;
        if blob.len() < ROW_BLOB_V1_HEADER_LEN + TAG_LEN {
            return Err(CipherError::InvalidEncoding);
        }
        validate_plaintext_length(
            blob.len() - ROW_BLOB_V1_HEADER_LEN - TAG_LEN,
            maximum_plaintext_len,
        )?;
        let header = parse_header(blob, ROW_BLOB_MAGIC)?;
        if header.generation != self.bundle.generation {
            return Err(CipherError::GenerationMismatch {
                expected: self.bundle.generation,
                actual: header.generation,
            });
        }
        let aad = Zeroizing::new(row_aad(context, header.bytes)?);
        let plaintext = decrypt(
            &self.bundle.row_dek,
            &header.nonce,
            aad.as_ref(),
            &blob[ROW_BLOB_V1_HEADER_LEN..],
        )?;
        Ok(SecretBytes::new(plaintext))
    }

    /// 消费同一 owned row allocation 的密文区并原地打开；成功后 buffer
    /// 只保留 plaintext，header/tag 尾部在 truncate 前清零。
    pub(crate) fn open_bounded_in_place(
        &self,
        context: &RowAad<'_>,
        blob: &mut Vec<u8>,
        maximum_plaintext_len: usize,
    ) -> Result<(), CipherError> {
        context.validate()?;
        if blob.len() < ROW_BLOB_V1_OVERHEAD_LEN {
            return Err(CipherError::InvalidEncoding);
        }
        let plaintext_len = blob.len() - ROW_BLOB_V1_OVERHEAD_LEN;
        validate_plaintext_length(plaintext_len, maximum_plaintext_len)?;
        let header = parse_header(blob, ROW_BLOB_MAGIC)?;
        if header.generation != self.bundle.generation {
            return Err(CipherError::GenerationMismatch {
                expected: self.bundle.generation,
                actual: header.generation,
            });
        }
        let nonce = header.nonce;
        let aad = Zeroizing::new(row_aad(context, header.bytes)?);
        let tag_start = blob.len() - TAG_LEN;
        let tag = Tag::<ChaCha20Poly1305>::try_from(&blob[tag_start..])
            .map_err(|_| CipherError::InvalidEncoding)?;
        ChaCha20Poly1305::new((&self.bundle.row_dek).into())
            .decrypt_inout_detached(
                (&nonce).into(),
                aad.as_ref(),
                (&mut blob[ROW_BLOB_V1_HEADER_LEN..tag_start]).into(),
                &tag,
            )
            .map_err(|_| CipherError::AuthenticationFailed)?;
        blob.copy_within(ROW_BLOB_V1_HEADER_LEN..tag_start, 0);
        blob[plaintext_len..].zeroize();
        blob.truncate(plaintext_len);
        Ok(())
    }
}

impl fmt::Debug for RowCipher<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RowCipher {{ generation: {}, key: [REDACTED] }}",
            self.bundle.generation
        )
    }
}

/// 可直接作为 SQLite BLOB lookup key 使用的 32-byte 盲索引。
#[derive(PartialEq, Eq)]
pub struct BlindIndex([u8; KEY_LEN]);

impl BlindIndex {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for BlindIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlindIndex([REDACTED])")
    }
}

impl Drop for BlindIndex {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ParsedHeader<'a> {
    bytes: &'a [u8],
    generation: u32,
    nonce: [u8; NONCE_LEN],
}

fn fresh_header(
    magic: &[u8; HEADER_MAGIC_LEN],
    generation: u32,
) -> Result<[u8; ROW_BLOB_V1_HEADER_LEN], CipherError> {
    let mut header = [0_u8; ROW_BLOB_V1_HEADER_LEN];
    header[..4].copy_from_slice(magic);
    header[4] = FORMAT_VERSION;
    header[5] = ALGORITHM_CHACHA20_POLY1305;
    header[8..12].copy_from_slice(&generation.to_be_bytes());
    getrandom::fill(&mut header[12..24]).map_err(|_| CipherError::EntropyUnavailable)?;
    Ok(header)
}

fn parse_header<'a>(
    blob: &'a [u8],
    expected_magic: &[u8; HEADER_MAGIC_LEN],
) -> Result<ParsedHeader<'a>, CipherError> {
    if blob.len() < ROW_BLOB_V1_HEADER_LEN || &blob[..4] != expected_magic {
        return Err(CipherError::InvalidEncoding);
    }
    if blob[4] != FORMAT_VERSION {
        return Err(CipherError::UnsupportedVersion { actual: blob[4] });
    }
    if blob[5] != ALGORITHM_CHACHA20_POLY1305 || blob[6] != 0 || blob[7] != 0 {
        return Err(CipherError::InvalidEncoding);
    }
    let generation = u32::from_be_bytes(
        blob[8..12]
            .try_into()
            .map_err(|_| CipherError::InvalidEncoding)?,
    );
    if generation == 0 {
        return Err(CipherError::InvalidGeneration);
    }
    let nonce = blob[12..24]
        .try_into()
        .map_err(|_| CipherError::InvalidEncoding)?;
    Ok(ParsedHeader {
        bytes: &blob[..ROW_BLOB_V1_HEADER_LEN],
        generation,
        nonce,
    })
}

fn nonce_from_header(header: &[u8; ROW_BLOB_V1_HEADER_LEN]) -> &Nonce {
    let nonce: &[u8; NONCE_LEN] = header[12..24]
        .try_into()
        .expect("fixed header always contains a 12-byte nonce");
    nonce.into()
}

fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CipherError::EncryptionFailed)
}

fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CipherError::AuthenticationFailed)
}

fn key_wrap_aad(context: &KeyWrapAad<'_>, header: &[u8]) -> Result<Vec<u8>, CipherError> {
    let mut aad = Vec::new();
    push_field(&mut aad, KEY_WRAP_DOMAIN)?;
    push_field(&mut aad, context.schema_family)?;
    push_field(&mut aad, &context.schema_version.to_be_bytes())?;
    push_field(&mut aad, context.database_id)?;
    push_field(&mut aad, b"runtime_meta")?;
    push_field(&mut aad, b"key_bundle.v1")?;
    push_field(&mut aad, b"wrapped_value")?;
    push_field(&mut aad, header)?;
    Ok(aad)
}

fn row_aad(context: &RowAad<'_>, header: &[u8]) -> Result<Vec<u8>, CipherError> {
    let mut aad = Vec::new();
    push_field(&mut aad, ROW_DOMAIN)?;
    push_field(&mut aad, context.schema_family)?;
    push_field(&mut aad, &context.schema_version.to_be_bytes())?;
    push_field(&mut aad, context.database_id)?;
    push_field(&mut aad, context.table)?;
    push_field(&mut aad, context.primary_key)?;
    push_field(&mut aad, context.column)?;
    push_field(&mut aad, header)?;
    Ok(aad)
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), CipherError> {
    let length = u32::try_from(value.len()).map_err(|_| CipherError::ContextTooLarge)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn validate_nonempty(name: &'static str, value: &[u8]) -> Result<(), CipherError> {
    if value.is_empty() {
        Err(CipherError::InvalidContext(name))
    } else {
        Ok(())
    }
}

fn validate_plaintext_length(actual: usize, configured_maximum: usize) -> Result<(), CipherError> {
    if configured_maximum > MAX_RUNTIME_ROW_PLAINTEXT_LEN || actual > configured_maximum {
        Err(CipherError::InputTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod read_capability_tests {
    use super::*;

    #[test]
    fn close_zeroizes_shared_read_slot_even_while_clones_exist() {
        let key = RuntimeKeyBundle::fresh(1).expect("fresh key");
        let aad = RowAad {
            schema_family: b"agentdeck.runtime",
            schema_version: 1,
            database_id: &[0x11; 16],
            table: b"fixture",
            primary_key: b"row",
            column: b"payload",
        };
        let sealed = key
            .row_cipher()
            .seal_bounded(&aad, b"read-only", 64)
            .expect("seal fixture");
        let capability = key.read_only_capability();
        let surviving_clone = capability.clone();
        assert_eq!(
            surviving_clone
                .open_bounded(&aad, &sealed, 64)
                .expect("read before close")
                .expose_secret(),
            b"read-only"
        );
        capability.close();
        assert!(matches!(
            surviving_clone.open_bounded(&aad, &sealed, 64),
            Err(CipherError::ReadCapabilityClosed)
        ));
        assert!(matches!(
            surviving_clone.verify_blind_index(b"fixture", b"value", &[0; 32]),
            Err(CipherError::ReadCapabilityClosed)
        ));
    }

    #[test]
    fn poisoned_read_slot_is_distinct_from_persisted_cipher_corruption() {
        let key = RuntimeKeyBundle::fresh(1).expect("fresh key");
        let capability = key.read_only_capability();
        let poison_target = capability.inner.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poison_target
                .key_bundle
                .lock()
                .expect("lock read capability before poison");
            panic!("poison read capability fixture");
        }));
        let aad = RowAad {
            schema_family: b"agentdeck.runtime",
            schema_version: 1,
            database_id: &[0x22; 16],
            table: b"fixture",
            primary_key: b"row",
            column: b"payload",
        };

        assert!(matches!(
            capability.open_bounded(&aad, &[], 64),
            Err(CipherError::ReadCapabilityPoisoned)
        ));
    }
}
