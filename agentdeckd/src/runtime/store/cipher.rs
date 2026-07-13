//! Runtime SQLite 敏感列的行级加密与确定性盲索引。
//!
//! `StorageKek` 只包装本数据库的 key bundle；普通行只使用 bundle 中的
//! `RuntimeRowDEK`。所有密文都携带固定 v1 header，真正的行位置通过规范化、
//! 长度前缀 AAD 绑定，因而跨行、跨列或跨数据库搬运密文都会认证失败。

use std::fmt;
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
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
pub const MAX_RUNTIME_ROW_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// 包装 key bundle 的固定 v1 编码长度。
pub const WRAPPED_KEY_BUNDLE_V1_LEN: usize = ROW_BLOB_V1_HEADER_LEN + KEY_PLAINTEXT_LEN + TAG_LEN;

type HmacSha256 = Hmac<Sha256>;

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
        let output = mac.finalize().into_bytes();
        let bytes: [u8; KEY_LEN] = output.into();
        Ok(BlindIndex(bytes))
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
            .map_err(|_| CipherError::InvalidEncoding)?;
        let key = key.as_ref().ok_or(CipherError::InvalidContext(
            "read crypto capability is closed",
        ))?;
        key.row_cipher()
            .open_bounded(context, blob, maximum_plaintext_len)
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
            .map_err(|_| CipherError::InvalidEncoding)?;
        let key = key.as_ref().ok_or(CipherError::InvalidContext(
            "read crypto capability is closed",
        ))?;
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
        let ciphertext = encrypt(
            &self.bundle.row_dek,
            nonce_from_header(&header),
            aad.as_ref(),
            plaintext.as_ref(),
        )?;
        let mut blob = Vec::with_capacity(header.len() + ciphertext.len());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
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
            Err(CipherError::InvalidContext(
                "read crypto capability is closed"
            ))
        ));
        assert!(matches!(
            surviving_clone.verify_blind_index(b"fixture", b"value", &[0; 32]),
            Err(CipherError::InvalidContext(
                "read crypto capability is closed"
            ))
        ));
    }
}
