//! 设备授权账本的 durable payload、认证元数据与逐行加载边界。

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::DeviceAuthorizationV1;
use agentdeck_protocol::relay_v2::{DeviceRevocation, DeviceRouteId, GrantSerial, RelayGrant};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;
use crate::security::SecretBytes;

use super::cipher::RuntimeKeyBundle;
use super::pairing_grant::{exact_install_frame, open_row};
use super::pairing_revocation::{MAX_REVOCATION_PLAINTEXT_BYTES, exact_revoke_frame};

const AUTHORIZATION_PAYLOAD_MAGIC: &[u8; 5] = b"ADAL1";
const AUTH_TABLE: &[u8] = b"remote_authorization_ledger";
const AUTH_COLUMN: &[u8] = b"sealed_authorization";
const AUTH_REVOCATION_COLUMN: &[u8] = b"sealed_revocation";
const AUTH_METADATA_DOMAIN: &[u8] = b"remote.authorization.metadata.v1";
const AUTH_REVOCATION_METADATA_DOMAIN: &[u8] = b"remote.authorization.revocation.metadata.v1";
pub(super) const MAX_AUTHORIZATION_PLAINTEXT_BYTES: usize = 256 * 1024;
pub(super) const MAX_AUTHORIZATIONS: u64 = 256;
pub(super) const MAX_AUTHORIZATION_SEALED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorizationLifecycle {
    GrantPreparing,
    Active,
    Superseded,
    Revoking,
    Revoked,
}

impl AuthorizationLifecycle {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::GrantPreparing => "grantPreparing",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoking => "revoking",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "grantPreparing" => Ok(Self::GrantPreparing),
            "active" => Ok(Self::Active),
            "superseded" => Ok(Self::Superseded),
            "revoking" => Ok(Self::Revoking),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

pub(super) struct AuthenticatedAuthorization {
    pub(super) device_route: DeviceRouteId,
    pub(super) grant_serial: GrantSerial,
    pub(super) lifecycle: AuthorizationLifecycle,
    pub(super) device_sign_fingerprint: [u8; 32],
    pub(super) grant_hash: [u8; 32],
    pub(super) authorization_hash: [u8; 32],
    pub(super) key_directory_revision: u64,
    pub(super) grant: RelayGrant,
    pub(super) canonical_relay_grant: Vec<u8>,
    pub(super) canonical_install_frame: Vec<u8>,
    pub(super) authorization: DeviceAuthorizationV1,
    pub(super) canonical_authorization: SecretBytes,
    pub(super) revocation_hash: Option<[u8; 32]>,
    pub(super) revocation: Option<DeviceRevocation>,
    pub(super) canonical_revocation_frame: Option<Vec<u8>>,
    pub(super) sealed_bytes: u64,
    pub(super) sealed_revocation_bytes: Option<u64>,
    pub(super) created_at_ms: u64,
    pub(super) state_changed_at_ms: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) fn encode_authorization_payload(
    canonical_relay_grant: &[u8],
    canonical_install_frame: &[u8],
    canonical_authorization: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let fields = [
        canonical_relay_grant,
        canonical_install_frame,
        canonical_authorization,
    ];
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(AUTHORIZATION_PAYLOAD_MAGIC);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    if encoded.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

fn decode_authorization_payload(encoded: &[u8]) -> Result<[&[u8]; 3], RuntimeStoreError> {
    if encoded.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES
        || encoded.get(..AUTHORIZATION_PAYLOAD_MAGIC.len()) != Some(AUTHORIZATION_PAYLOAD_MAGIC)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = AUTHORIZATION_PAYLOAD_MAGIC.len();
    let mut fields = [&[][..]; 3];
    for field in &mut fields {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            encoded
                .get(cursor..length_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let end = cursor
            .checked_add(
                usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        *field = encoded
            .get(cursor..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        cursor = end;
    }
    if cursor != encoded.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn sequence(value: &str) -> Result<u64, RuntimeStoreError> {
    if value.len() != 20 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if parsed == 0 || super::sequence::encode_sequence(parsed) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(parsed)
}

fn authorization_primary_key(device_route: DeviceRouteId, serial: GrantSerial) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[..16].copy_from_slice(device_route.as_bytes());
    value[16..].copy_from_slice(&serial.value().to_be_bytes());
    value
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    lifecycle: AuthorizationLifecycle,
    fingerprint: [u8; 32],
    grant_hash: [u8; 32],
    authorization_hash: [u8; 32],
    revision: u64,
    sealed: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash = sha256(sealed);
    super::stream::metadata_mac(
        key_bundle,
        AUTH_METADATA_DOMAIN,
        &[
            &database_id,
            device_route.as_bytes(),
            &grant_serial.value().to_be_bytes(),
            lifecycle.as_str().as_bytes(),
            &fingerprint,
            &grant_hash,
            &authorization_hash,
            &revision.to_be_bytes(),
            &sealed_len.to_be_bytes(),
            &sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_revocation_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    lifecycle: AuthorizationLifecycle,
    fingerprint: [u8; 32],
    grant_hash: [u8; 32],
    authorization_hash: [u8; 32],
    revision: u64,
    sealed_authorization: &[u8],
    revocation_hash: [u8; 32],
    sealed_revocation: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    if !matches!(
        lifecycle,
        AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked
    ) || revocation_hash == [0; 32]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let authorization_len = u64::try_from(sealed_authorization.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let revocation_len = u64::try_from(sealed_revocation.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authorization_sealed_hash = sha256(sealed_authorization);
    let revocation_sealed_hash = sha256(sealed_revocation);
    super::stream::metadata_mac(
        key_bundle,
        AUTH_REVOCATION_METADATA_DOMAIN,
        &[
            &database_id,
            device_route.as_bytes(),
            &grant_serial.value().to_be_bytes(),
            lifecycle.as_str().as_bytes(),
            &fingerprint,
            &grant_hash,
            &authorization_hash,
            &revision.to_be_bytes(),
            &authorization_len.to_be_bytes(),
            &authorization_sealed_hash,
            &revocation_hash,
            &revocation_len.to_be_bytes(),
            &revocation_sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

pub(super) fn load_authorizations(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedAuthorization>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT device_route, grant_serial, lifecycle, database_id,
                device_sign_fingerprint, grant_hash, authorization_hash,
                key_directory_revision, sealed_authorization, sealed_authorization_bytes,
                revocation_hash, sealed_revocation, sealed_revocation_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_authorization_ledger ORDER BY device_route, grant_serial",
    )?;
    let raws = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Option<i64>>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, Vec<u8>>(15)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raws.into_iter()
        .map(|raw| {
            let device_route = DeviceRouteId::from_bytes(fixed(raw.0)?);
            let grant_serial = GrantSerial::new(sequence(&raw.1)?);
            let lifecycle = AuthorizationLifecycle::parse(&raw.2)?;
            let row_database_id = fixed(raw.3)?;
            let fingerprint = fixed(raw.4)?;
            let grant_hash = fixed(raw.5)?;
            let authorization_hash = fixed(raw.6)?;
            let revision = sequence(&raw.7)?;
            let sealed_bytes = nonnegative(raw.9)?;
            let revocation_hash = raw
                .10
                .as_ref()
                .map(|value| fixed(value.clone()))
                .transpose()?;
            let sealed_revocation_bytes = raw.12.map(nonnegative).transpose()?;
            let created_at_ms = nonnegative(raw.13)?;
            let state_changed_at_ms = nonnegative(raw.14)?;
            let metadata_token = fixed(raw.15)?;
            let primary_key = authorization_primary_key(device_route, grant_serial);
            let metadata_matches = match lifecycle {
                AuthorizationLifecycle::GrantPreparing
                | AuthorizationLifecycle::Active
                | AuthorizationLifecycle::Superseded
                    if revocation_hash.is_none()
                        && raw.11.is_none()
                        && sealed_revocation_bytes.is_none() =>
                {
                    authorization_token(
                        key_bundle,
                        database_id,
                        device_route,
                        grant_serial,
                        lifecycle,
                        fingerprint,
                        grant_hash,
                        authorization_hash,
                        revision,
                        &raw.8,
                        created_at_ms,
                        state_changed_at_ms,
                    )? == metadata_token
                }
                AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked => {
                    match (revocation_hash, raw.11.as_deref(), sealed_revocation_bytes) {
                        (Some(revocation_hash), Some(sealed_revocation), Some(_)) => {
                            authorization_revocation_token(
                                key_bundle,
                                database_id,
                                device_route,
                                grant_serial,
                                lifecycle,
                                fingerprint,
                                grant_hash,
                                authorization_hash,
                                revision,
                                &raw.8,
                                revocation_hash,
                                sealed_revocation,
                                created_at_ms,
                                state_changed_at_ms,
                            )? == metadata_token
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            if row_database_id != database_id
                || state_changed_at_ms < created_at_ms
                || (lifecycle == AuthorizationLifecycle::GrantPreparing
                    && created_at_ms != state_changed_at_ms)
                || sealed_bytes != u64::try_from(raw.8.len()).unwrap_or(u64::MAX)
                || !metadata_matches
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let payload = open_row(
                key_bundle,
                database_id,
                AUTH_TABLE,
                &primary_key,
                AUTH_COLUMN,
                &raw.8,
                MAX_AUTHORIZATION_PLAINTEXT_BYTES,
            )?;
            let fields = decode_authorization_payload(payload.expose_secret())?;
            let (grant, observed_grant_hash) = exact_install_frame(fields[1])?;
            let authorization = DeviceAuthorizationV1::from_canonical_bytes(fields[2])
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if authorization.canonical_sha256().ok() != Some(authorization_hash)
                || authorization.device_route != device_route
                || authorization.grant_serial != grant_serial
                || authorization.device_sign_fingerprint != fingerprint
                || grant.device_route != device_route
                || grant.grant_serial != grant_serial
                || observed_grant_hash != grant_hash
                || grant.canonical_bytes().as_slice() != fields[0]
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let (revocation, canonical_revocation_frame) = match (
                lifecycle,
                revocation_hash,
                raw.11.as_deref(),
                sealed_revocation_bytes,
            ) {
                (
                    AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked,
                    Some(expected_hash),
                    Some(sealed_revocation),
                    Some(expected_bytes),
                ) if expected_bytes
                    == u64::try_from(sealed_revocation.len()).unwrap_or(u64::MAX) =>
                {
                    let canonical = open_row(
                        key_bundle,
                        database_id,
                        AUTH_TABLE,
                        &primary_key,
                        AUTH_REVOCATION_COLUMN,
                        sealed_revocation,
                        MAX_REVOCATION_PLAINTEXT_BYTES,
                    )?;
                    let (revocation, observed_hash) =
                        exact_revoke_frame(canonical.expose_secret())?;
                    if observed_hash != expected_hash
                        || revocation.device_route != device_route
                        || revocation.grant_serial != grant_serial
                    {
                        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                    }
                    (Some(revocation), Some(canonical.expose_secret().to_vec()))
                }
                (
                    AuthorizationLifecycle::GrantPreparing
                    | AuthorizationLifecycle::Active
                    | AuthorizationLifecycle::Superseded,
                    None,
                    None,
                    None,
                ) => (None, None),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            Ok(AuthenticatedAuthorization {
                device_route,
                grant_serial,
                lifecycle,
                device_sign_fingerprint: fingerprint,
                grant_hash,
                authorization_hash,
                key_directory_revision: revision,
                grant,
                canonical_relay_grant: fields[0].to_vec(),
                canonical_install_frame: fields[1].to_vec(),
                authorization,
                canonical_authorization: SecretBytes::new(fields[2].to_vec()),
                revocation_hash,
                revocation,
                canonical_revocation_frame,
                sealed_bytes,
                sealed_revocation_bytes,
                created_at_ms,
                state_changed_at_ms,
                metadata_token,
            })
        })
        .collect()
}
