//! Catalog opaque cursor 编解码与 principal 绑定。

use agentdeck_protocol::runtime::StreamCursor;
use agentdeck_protocol::runtime::identity::CatalogPageCursor;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{
    CATALOG_PAGE_CURSOR_TTL_MS, CatalogPageReference, CatalogPageSourceKind,
    CatalogSnapshotProviderError,
};
use crate::runtime::connection::AuthenticatedPrincipal;
use crate::runtime::events::RuntimeStreamTarget;
use crate::runtime::store::ReadySnapshotReference;

const CURSOR_MAGIC: &[u8; 5] = b"ADCP1";
const CURSOR_PREFIX: &str = "adcp1.";
const CURSOR_MAC_BYTES: usize = 32;
const MAX_CURSOR_KEY_BYTES: usize = 1024;

type HmacSha256 = Hmac<Sha256>;

pub(super) struct CursorMacKey([u8; 32]);

impl CursorMacKey {
    pub(super) fn random() -> Result<Self, CatalogSnapshotProviderError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| CatalogSnapshotProviderError::EntropyUnavailable)?;
        if key == [0; 32] {
            return Err(CatalogSnapshotProviderError::EntropyUnavailable);
        }
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(super) fn for_test(key: [u8; 32]) -> Self {
        assert_ne!(key, [0; 32]);
        Self(key)
    }
}

impl Drop for CursorMacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) struct CursorClaims {
    pub(super) reference: CatalogPageReference,
    pub(super) next_key: String,
    pub(super) issued_at_ms: u64,
    pub(super) expires_at_ms: u64,
    pub(super) principal_binding: [u8; 32],
}

pub(super) fn encode_cursor(
    key: &CursorMacKey,
    claims: &CursorClaims,
) -> Result<CatalogPageCursor, CatalogSnapshotProviderError> {
    let next_key = claims.next_key.as_bytes();
    if next_key.is_empty() || next_key.len() > MAX_CURSOR_KEY_BYTES {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let key_len =
        u16::try_from(next_key.len()).map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    if claims.issued_at_ms.checked_add(CATALOG_PAGE_CURSOR_TTL_MS) != Some(claims.expires_at_ms) {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let mut body = Vec::with_capacity(160 + next_key.len());
    body.extend_from_slice(CURSOR_MAGIC);
    body.push(claims.reference.kind.wire());
    body.extend_from_slice(&claims.reference.snapshot.snapshot_id);
    encode_stream_cursor(&mut body, claims.reference.snapshot.base);
    body.extend_from_slice(&claims.reference.snapshot.item_count.to_be_bytes());
    body.extend_from_slice(&claims.reference.snapshot.logical_bytes.to_be_bytes());
    body.extend_from_slice(&claims.reference.snapshot.content_sha256);
    body.extend_from_slice(&claims.issued_at_ms.to_be_bytes());
    body.extend_from_slice(&claims.expires_at_ms.to_be_bytes());
    body.extend_from_slice(&claims.principal_binding);
    body.extend_from_slice(&key_len.to_be_bytes());
    body.extend_from_slice(next_key);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0)
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    mac.update(&body);
    body.extend_from_slice(&mac.finalize().into_bytes());
    Ok(CatalogPageCursor::new(format!(
        "{CURSOR_PREFIX}{}",
        encode_hex(&body)
    )))
}

pub(super) fn decode_cursor(
    key: &CursorMacKey,
    cursor: &CatalogPageCursor,
    principal_binding: [u8; 32],
    now_ms: u64,
) -> Result<CursorClaims, CatalogSnapshotProviderError> {
    let encoded = cursor
        .as_str()
        .strip_prefix(CURSOR_PREFIX)
        .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
    let bytes = decode_hex(encoded)?;
    if bytes.len() < CURSOR_MAC_BYTES + 128 {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let body_len = bytes
        .len()
        .checked_sub(CURSOR_MAC_BYTES)
        .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
    let (body, expected_mac) = bytes.split_at(body_len);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0)
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    mac.update(body);
    mac.verify_slice(expected_mac)
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;

    let mut reader = CursorReader::new(body);
    if reader.take(5)? != CURSOR_MAGIC {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let kind = CatalogPageSourceKind::from_wire(reader.u8()?)?;
    let snapshot_id: [u8; 16] = reader
        .take(16)?
        .try_into()
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    if snapshot_id == [0; 16] {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let base = decode_stream_cursor(&mut reader)?;
    let item_count = reader.u64()?;
    let logical_bytes = reader.u64()?;
    let content_sha256 = reader
        .take(32)?
        .try_into()
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    let issued_at_ms = reader.u64()?;
    let expires_at_ms = reader.u64()?;
    let encoded_principal: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?;
    let key_len = usize::from(reader.u16()?);
    if key_len == 0 || key_len > MAX_CURSOR_KEY_BYTES {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let next_key = std::str::from_utf8(reader.take(key_len)?)
        .map_err(|_| CatalogSnapshotProviderError::InvalidCursor)?
        .to_owned();
    if !reader.is_empty()
        || issued_at_ms.checked_add(CATALOG_PAGE_CURSOR_TTL_MS) != Some(expires_at_ms)
    {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    if encoded_principal != principal_binding {
        return Err(CatalogSnapshotProviderError::PrincipalMismatch);
    }
    if now_ms < issued_at_ms {
        return Err(CatalogSnapshotProviderError::ClockRegressed);
    }
    if now_ms >= expires_at_ms {
        return Err(CatalogSnapshotProviderError::CursorExpired);
    }
    Ok(CursorClaims {
        reference: CatalogPageReference {
            kind,
            snapshot: ReadySnapshotReference {
                snapshot_id,
                target: RuntimeStreamTarget::Catalog,
                base,
                item_count,
                logical_bytes,
                content_sha256,
            },
        },
        next_key,
        issued_at_ms,
        expires_at_ms,
        principal_binding,
    })
}

pub(super) fn principal_binding(principal: &AuthenticatedPrincipal) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(160);
    canonical.extend_from_slice(b"catalog.cursor.principal.v1");
    principal.append_authorization_identity_binding(&mut canonical);
    Sha256::digest(canonical).into()
}

fn encode_stream_cursor(target: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor {
        StreamCursor::BeforeFirst => {
            target.push(0);
            target.extend_from_slice(&0_u64.to_be_bytes());
        }
        StreamCursor::At(value) => {
            target.push(1);
            target.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_stream_cursor(
    reader: &mut CursorReader<'_>,
) -> Result<StreamCursor, CatalogSnapshotProviderError> {
    match (reader.u8()?, reader.u64()?) {
        (0, 0) => Ok(StreamCursor::BeforeFirst),
        (1, value) => Ok(StreamCursor::At(value)),
        _ => Err(CatalogSnapshotProviderError::InvalidCursor),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, CatalogSnapshotProviderError> {
    if !encoded.len().is_multiple_of(2) {
        return Err(CatalogSnapshotProviderError::InvalidCursor);
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, CatalogSnapshotProviderError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CatalogSnapshotProviderError::InvalidCursor),
    }
}

struct CursorReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CursorReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CatalogSnapshotProviderError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(CatalogSnapshotProviderError::InvalidCursor)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CatalogSnapshotProviderError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CatalogSnapshotProviderError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| CatalogSnapshotProviderError::InvalidCursor,
        )?))
    }

    fn u64(&mut self) -> Result<u64, CatalogSnapshotProviderError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| CatalogSnapshotProviderError::InvalidCursor,
        )?))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
