//! Persistent remote CLI 的 pending PairRequest 事务。
//!
//! 首次允许网络发送前，本层先以独立 Keychain item 冻结 DeviceSign seed、DeviceHPKE
//! private key 与完整 `enc+ciphertext+proof`。record 是这组三项的 commit marker；marker
//! 已存在时任一 private item 缺失均 fail-close，不会生成替代身份。PairResponse 验证与
//! paired promotion 属后续子片，不在这里提前实现。

use std::fmt;

use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_crypto::{
    CryptoError, HpkePrivateKey, HpkePublicKey, SigningKey, VerifyingKey, seal_pair_request,
    verify_pair_request_envelope,
};
use agentdeck_protocol::e2ee::{
    AuthorizationRequestV1, E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind, PairInviteV1,
    PairRequestInfoV1, PairRequestPlaintextV1, PairRequestV1, PairingError,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::PublicKeyBytes;
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::keychain::{
    PendingRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};

const RECORD_MAGIC: &[u8; 4] = b"ADPR";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_LEN: usize = 8;
const RECORD_HASH_LEN: usize = 32;
const MAX_RECORD_FIELD_LEN: usize = 128 * 1024;
const RECORD_FIXED_BODY_LEN: usize = 5 * RECORD_HASH_LEN + 8 + 4;
const MAX_RECORD_LEN: usize = RECORD_HEADER_LEN + RECORD_FIXED_BODY_LEN + MAX_RECORD_FIELD_LEN;

#[derive(Debug, Error)]
pub enum PendingPairingError {
    #[error("pending pairing invite is invalid")]
    InvalidInvite(#[source] PairingError),
    #[error("pending pairing authorization is invalid")]
    InvalidAuthorization(#[source] PairingError),
    #[error("pending pairing crypto operation failed")]
    Crypto(#[source] CryptoError),
    #[error("pending pairing persistence failed")]
    Persistence(#[source] RemoteKeyStoreError),
    #[error("pending pairing entropy source is unavailable")]
    EntropyUnavailable,
    #[error("pending pairing record is invalid")]
    InvalidRecord,
    #[error("pending pairing commit marker is missing a required private item")]
    IncompleteState,
    #[error("pending pairing record conflicts with the requested invite or authorization")]
    ImmutableConflict,
}

impl PendingPairingError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInvite(_) => "remote.pairing.invite_invalid",
            Self::InvalidAuthorization(_) => "remote.pairing.authorization_invalid",
            Self::Crypto(_) => "remote.pairing.crypto_failed",
            Self::Persistence(_) => "remote.pairing.pending_persistence_failed",
            Self::EntropyUnavailable => "remote.pairing.entropy_unavailable",
            Self::InvalidRecord => "remote.pairing.pending_invalid",
            Self::IncompleteState => "remote.pairing.pending_incomplete",
            Self::ImmutableConflict => "remote.pairing.pending_conflict",
        }
    }
}

/// 可交给 Relay PairData 的已持久化 carrier；不持有 private key 或 invite secret。
pub struct PreparedPairRequest {
    canonical_request: Vec<u8>,
    request_hash: [u8; 32],
    device_sign_public_key: [u8; 32],
    device_hpke_public_key: [u8; 32],
}

impl fmt::Debug for PreparedPairRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedPairRequest([REDACTED])")
    }
}

impl PreparedPairRequest {
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub const fn device_sign_public_key(&self) -> [u8; 32] {
        self.device_sign_public_key
    }

    #[must_use]
    pub const fn device_hpke_public_key(&self) -> [u8; 32] {
        self.device_hpke_public_key
    }
}

/// 单个 installation 的 pending transaction coordinator。
///
/// `RemoteKeyStore` 只能由 library composition 显式注入；production CLI 后续会固定传入
/// Data Protection Keychain adapter，不提供 env/config file-keystore selector。
pub struct PendingPairingCoordinator<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
}

impl fmt::Debug for PendingPairingCoordinator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPairingCoordinator")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> PendingPairingCoordinator<'a> {
    #[must_use]
    pub const fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid) -> Self {
        Self {
            store,
            installation_id,
        }
    }

    /// 冻结或读回同一份 PairRequest。成功返回即表示三项 Keychain item 已完成 exact readback，
    /// 调用方才可发送 `canonical_request`。
    pub fn prepare<R: CryptoRng>(
        &self,
        invite: &PairInviteV1,
        authorization: &AuthorizationRequestV1,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<PreparedPairRequest, PendingPairingError> {
        invite
            .validate(now_ms)
            .map_err(PendingPairingError::InvalidInvite)?;
        authorization
            .validate()
            .map_err(PendingPairingError::InvalidAuthorization)?;
        let invite_hash = invite
            .canonical_sha256()
            .map_err(PendingPairingError::InvalidInvite)?;
        let authorization_hash = authorization_hash(authorization)?;
        let accounts = PendingAccounts::new(self.installation_id, invite_hash);

        if let Some(record_secret) = self
            .store
            .load(&accounts.record)
            .map_err(PendingPairingError::Persistence)?
        {
            let (device_sign, device_hpke) = self.load_committed_keys(&accounts)?;
            return validate_record(
                record_secret.expose_secret(),
                invite,
                authorization,
                &device_sign,
                &device_hpke,
            );
        }

        // record absent 的 crash-resume 只允许扩展全部已存在 private item 都可解析的 partial。
        // 先完成双项只读 preflight，避免一侧已损坏时写出另一项并扩大坏状态。
        self.validate_existing_partial_keys(&accounts)?;
        let device_sign = self.load_or_create_secret(&accounts.device_sign, rng, |rng| {
            let mut seed = [0_u8; 32];
            rng.try_fill_bytes(&mut seed)
                .map_err(|_| PendingPairingError::EntropyUnavailable)?;
            let secret = RemoteSecret::new(seed.to_vec());
            seed.zeroize();
            Ok(secret)
        })?;
        let signing_key = signing_key_from_secret(&device_sign)?;
        let device_hpke = self.load_or_create_secret(&accounts.device_hpke, rng, |rng| {
            let mut ikm = [0_u8; 32];
            rng.try_fill_bytes(&mut ikm)
                .map_err(|_| PendingPairingError::EntropyUnavailable)?;
            let (private, _) = HpkePrivateKey::derive_keypair(&ikm);
            ikm.zeroize();
            Ok(RemoteSecret::new(private.to_bytes()))
        })?;
        let hpke_private = hpke_key_from_secret(&device_hpke)?;

        // 另一进程可能在本进程加载 record absent 后已提交；优先读回 winner，禁止再 seal。
        if let Some(record_secret) = self
            .store
            .load(&accounts.record)
            .map_err(PendingPairingError::Persistence)?
        {
            return validate_record(
                record_secret.expose_secret(),
                invite,
                authorization,
                &device_sign,
                &device_hpke,
            );
        }

        let device_sign_public_key = signing_key.verifying_key().to_bytes();
        let device_hpke_public_key: [u8; 32] = hpke_private
            .public_key()
            .to_bytes()
            .try_into()
            .map_err(|_| PendingPairingError::InvalidRecord)?;
        let info = request_info(invite, invite_hash);
        let context = request_context(invite);
        let plaintext = SensitivePairRequestPlaintext(PairRequestPlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            invite_secret: invite.invite_secret,
            device_sign_pubkey: PublicKeyBytes(device_sign_public_key),
            device_hpke_pubkey: PublicKeyBytes(device_hpke_public_key),
            authorization_request: authorization.clone(),
        });
        let invite_public = HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0)
            .map_err(PendingPairingError::Crypto)?;
        let request = seal_pair_request(
            &invite_public,
            &info,
            &context,
            &plaintext.0,
            &signing_key,
            rng,
        )
        .map_err(PendingPairingError::Crypto)?;
        let request_hash = request
            .canonical_sha256()
            .map_err(|_| PendingPairingError::InvalidRecord)?;
        let record = PendingPairingRecord {
            invite_hash,
            expiry_ms: invite.expires_at_ms,
            authorization_hash,
            device_sign_public_key,
            device_hpke_public_key,
            request,
            request_hash,
        };
        let encoded = RemoteSecret::new(record.encode()?);
        match self.store.persist_immutable(&accounts.record, &encoded) {
            Ok(_) => validate_record(
                encoded.expose_secret(),
                invite,
                authorization,
                &device_sign,
                &device_hpke,
            ),
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => {
                let winner = self
                    .store
                    .load(&accounts.record)
                    .map_err(PendingPairingError::Persistence)?
                    .ok_or(PendingPairingError::InvalidRecord)?;
                validate_record(
                    winner.expose_secret(),
                    invite,
                    authorization,
                    &device_sign,
                    &device_hpke,
                )
            }
            Err(error) => Err(PendingPairingError::Persistence(error)),
        }
    }

    fn load_committed_keys(
        &self,
        accounts: &PendingAccounts,
    ) -> Result<(RemoteSecret, RemoteSecret), PendingPairingError> {
        let device_sign = self
            .store
            .load(&accounts.device_sign)
            .map_err(PendingPairingError::Persistence)?
            .ok_or(PendingPairingError::IncompleteState)?;
        let device_hpke = self
            .store
            .load(&accounts.device_hpke)
            .map_err(PendingPairingError::Persistence)?
            .ok_or(PendingPairingError::IncompleteState)?;
        Ok((device_sign, device_hpke))
    }

    fn validate_existing_partial_keys(
        &self,
        accounts: &PendingAccounts,
    ) -> Result<(), PendingPairingError> {
        if let Some(device_sign) = self
            .store
            .load(&accounts.device_sign)
            .map_err(PendingPairingError::Persistence)?
        {
            signing_key_from_secret(&device_sign)?;
        }
        if let Some(device_hpke) = self
            .store
            .load(&accounts.device_hpke)
            .map_err(PendingPairingError::Persistence)?
        {
            hpke_key_from_secret(&device_hpke)?;
        }
        Ok(())
    }

    fn load_or_create_secret<R, F>(
        &self,
        account: &RemoteKeyAccount,
        rng: &mut R,
        create: F,
    ) -> Result<RemoteSecret, PendingPairingError>
    where
        R: CryptoRng,
        F: FnOnce(&mut R) -> Result<RemoteSecret, PendingPairingError>,
    {
        if let Some(existing) = self
            .store
            .load(account)
            .map_err(PendingPairingError::Persistence)?
        {
            return Ok(existing);
        }
        let candidate = create(rng)?;
        match self.store.persist_immutable(account, &candidate) {
            Ok(_) => Ok(candidate),
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => self
                .store
                .load(account)
                .map_err(PendingPairingError::Persistence)?
                .ok_or(PendingPairingError::InvalidRecord),
            Err(error) => Err(PendingPairingError::Persistence(error)),
        }
    }
}

struct PendingAccounts {
    record: RemoteKeyAccount,
    device_sign: RemoteKeyAccount,
    device_hpke: RemoteKeyAccount,
}

impl PendingAccounts {
    fn new(installation_id: Uuid, invite_hash: [u8; 32]) -> Self {
        Self {
            record: RemoteKeyAccount::pending(
                installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::PairingRecord,
            ),
            device_sign: RemoteKeyAccount::pending(
                installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceSignPrivateKey,
            ),
            device_hpke: RemoteKeyAccount::pending(
                installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
            ),
        }
    }
}

struct PendingPairingRecord {
    invite_hash: [u8; 32],
    expiry_ms: u64,
    authorization_hash: [u8; 32],
    device_sign_public_key: [u8; 32],
    device_hpke_public_key: [u8; 32],
    request: PairRequestV1,
    request_hash: [u8; 32],
}

struct SensitivePairRequestPlaintext(PairRequestPlaintextV1);

impl Drop for SensitivePairRequestPlaintext {
    fn drop(&mut self) {
        self.0.invite_secret.zeroize();
    }
}

impl PendingPairingRecord {
    fn encode(&self) -> Result<Vec<u8>, PendingPairingError> {
        let request = self
            .request
            .canonical_bytes()
            .map_err(|_| PendingPairingError::InvalidRecord)?;
        if request.len() > MAX_RECORD_FIELD_LEN {
            return Err(PendingPairingError::InvalidRecord);
        }
        let mut encoded =
            Vec::with_capacity(RECORD_HEADER_LEN + RECORD_FIXED_BODY_LEN + request.len());
        encoded.extend_from_slice(RECORD_MAGIC);
        encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.invite_hash);
        encoded.extend_from_slice(&self.expiry_ms.to_be_bytes());
        encoded.extend_from_slice(&self.authorization_hash);
        encoded.extend_from_slice(&self.device_sign_public_key);
        encoded.extend_from_slice(&self.device_hpke_public_key);
        encoded.extend_from_slice(&self.request_hash);
        put_field(&mut encoded, &request)?;
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PendingPairingError> {
        if bytes.len() < RECORD_HEADER_LEN + RECORD_FIXED_BODY_LEN || bytes.len() > MAX_RECORD_LEN {
            return Err(PendingPairingError::InvalidRecord);
        }
        if &bytes[..4] != RECORD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != RECORD_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PendingPairingError::InvalidRecord);
        }
        let mut cursor = RECORD_HEADER_LEN;
        let invite_hash = take_fixed(bytes, &mut cursor)?;
        let expiry_ms = u64::from_be_bytes(take_fixed(bytes, &mut cursor)?);
        let authorization_hash = take_fixed(bytes, &mut cursor)?;
        let device_sign_public_key = take_fixed(bytes, &mut cursor)?;
        let device_hpke_public_key = take_fixed(bytes, &mut cursor)?;
        let request_hash = take_fixed(bytes, &mut cursor)?;
        let request = PairRequestV1::from_canonical_bytes(take_field(bytes, &mut cursor)?)
            .map_err(|_| PendingPairingError::InvalidRecord)?;
        if cursor != bytes.len() {
            return Err(PendingPairingError::InvalidRecord);
        }
        let record = Self {
            invite_hash,
            expiry_ms,
            authorization_hash,
            device_sign_public_key,
            device_hpke_public_key,
            request,
            request_hash,
        };
        if record.encode()? != bytes {
            return Err(PendingPairingError::InvalidRecord);
        }
        Ok(record)
    }
}

fn validate_record(
    bytes: &[u8],
    expected_invite: &PairInviteV1,
    expected_authorization: &AuthorizationRequestV1,
    device_sign_secret: &RemoteSecret,
    device_hpke_secret: &RemoteSecret,
) -> Result<PreparedPairRequest, PendingPairingError> {
    let record = PendingPairingRecord::decode(bytes)?;
    let invite_hash = expected_invite
        .canonical_sha256()
        .map_err(PendingPairingError::InvalidInvite)?;
    if record.invite_hash != invite_hash
        || record.expiry_ms != expected_invite.expires_at_ms
        || record.authorization_hash != authorization_hash(expected_authorization)?
    {
        return Err(PendingPairingError::ImmutableConflict);
    }

    let signing_key = signing_key_from_secret(device_sign_secret)?;
    let hpke_private = hpke_key_from_secret(device_hpke_secret)?;
    let device_sign_public_key = signing_key.verifying_key().to_bytes();
    let device_hpke_public_key: [u8; 32] = hpke_private
        .public_key()
        .to_bytes()
        .try_into()
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    if record.device_sign_public_key != device_sign_public_key
        || record.device_hpke_public_key != device_hpke_public_key
    {
        return Err(PendingPairingError::IncompleteState);
    }

    let info = request_info(expected_invite, invite_hash);
    let context = request_context(expected_invite);
    let verifying_key =
        VerifyingKey::from_bytes(&device_sign_public_key).map_err(PendingPairingError::Crypto)?;
    verify_pair_request_envelope(&verifying_key, &info, &context, &record.request)
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    let canonical_request = record
        .request
        .canonical_bytes()
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    if record.request_hash != agentdeck_crypto::sha256(&canonical_request) {
        return Err(PendingPairingError::InvalidRecord);
    }
    Ok(PreparedPairRequest {
        canonical_request,
        request_hash: record.request_hash,
        device_sign_public_key,
        device_hpke_public_key,
    })
}

fn signing_key_from_secret(secret: &RemoteSecret) -> Result<SigningKey, PendingPairingError> {
    let mut seed: [u8; 32] = secret
        .expose_secret()
        .try_into()
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    let key = SigningKey::from_seed(&seed);
    seed.zeroize();
    Ok(key)
}

fn hpke_key_from_secret(secret: &RemoteSecret) -> Result<HpkePrivateKey, PendingPairingError> {
    HpkePrivateKey::from_bytes(secret.expose_secret())
        .map_err(|_| PendingPairingError::InvalidRecord)
}

fn authorization_hash(
    authorization: &AuthorizationRequestV1,
) -> Result<[u8; 32], PendingPairingError> {
    authorization
        .canonical_bytes()
        .map(|bytes| agentdeck_crypto::sha256(&bytes))
        .map_err(PendingPairingError::InvalidAuthorization)
}

fn request_info(invite: &PairInviteV1, invite_hash: [u8; 32]) -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash,
        expiry_ms: invite.expires_at_ms,
    }
}

fn request_context(invite: &PairInviteV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairRequest,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(invite.pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn put_field(encoded: &mut Vec<u8>, field: &[u8]) -> Result<(), PendingPairingError> {
    let length = u32::try_from(field.len()).map_err(|_| PendingPairingError::InvalidRecord)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(field);
    Ok(())
}

fn take_field<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], PendingPairingError> {
    let length_end = cursor
        .checked_add(4)
        .ok_or(PendingPairingError::InvalidRecord)?;
    let length_bytes: [u8; 4] = bytes
        .get(*cursor..length_end)
        .ok_or(PendingPairingError::InvalidRecord)?
        .try_into()
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    if length > MAX_RECORD_FIELD_LEN {
        return Err(PendingPairingError::InvalidRecord);
    }
    let field_end = length_end
        .checked_add(length)
        .ok_or(PendingPairingError::InvalidRecord)?;
    let field = bytes
        .get(length_end..field_end)
        .ok_or(PendingPairingError::InvalidRecord)?;
    *cursor = field_end;
    Ok(field)
}

fn take_fixed<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], PendingPairingError> {
    let end = cursor
        .checked_add(N)
        .ok_or(PendingPairingError::InvalidRecord)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(PendingPairingError::InvalidRecord)?
        .try_into()
        .map_err(|_| PendingPairingError::InvalidRecord)?;
    *cursor = end;
    Ok(value)
}
