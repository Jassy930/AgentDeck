//! P1.4 deterministic golden vectors —— Relay E2EE Rust 密码学的固定事实源。
//!
//! 这些 vectors 是 P1.6 Swift 镜像的**共享事实源**：结构为 hex 字符串字段，每个 vector
//! 带 `name`/`description`。默认只比较已提交的 `protocol/agentdeck/crypto-vectors-v1.json`；
//! `UPDATE_CRYPTO_VECTORS=1` 时重新生成。
//!
//! 覆盖（design §7.1/§7.3/§7.4）：
//! - canonical TBS/OuterContext AAD/HPKE info（复用 P1.2 protocol 确定性编码）。
//! - SHA-256、Ed25519 确定性签名。
//! - HPKE Base KAT（固定 seed RNG，只有 Rust 能 byte-for-byte 复现 seal）。
//! - ChaCha20-Poly1305 AEAD ciphertext/tag。
//! - nonce 逐字节 = `32-bit prefix || 64-bit big-endian counter`。
//! - sealed blob type-state（seal → sign → verify → open）。
//!
//! 负向：nonce reuse 确定性、tamper 任一 route/version/epoch/counter/hash/AAD/签名 → typed error。

use std::convert::Infallible;
use std::path::Path;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    AeadReceivingKey, AeadSendingKey, CryptoError, HpkeEnvelopeV1, HpkePrivateKey, SecretAeadKey,
    SenderCounter, SignatureBytes, SigningKey, VerifyingKey, hpke_open_base, hpke_seal_base,
    open_symmetric, seal_symmetric, sha256, sign_sealed, sign_tbs, verify_sealed, verify_tbs,
};
use agentdeck_protocol::e2ee::context::{OuterContextV1, OuterFrameKind};
use agentdeck_protocol::e2ee::keys::{KeyId, KeyPurpose, KeyUpdateInfoV1};
use agentdeck_protocol::e2ee::pairing::{PairRequestInfoV1, PairResponseInfoV1};
use agentdeck_protocol::e2ee::payload::SealedPayloadKind;
use agentdeck_protocol::e2ee::tbs::{SignedObjectType, ToBeSignedV1};
use agentdeck_protocol::relay_v2::StreamCursor;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, PairRouteId, RelayServerId,
    RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch,
};
use serde_json::json;

// —— 固定 seed 确定性 RNG（仅测试；非安全，只为 HPKE Base byte-for-byte KAT）——
//
// 通过 SHA-256(domain || seed || counter_be) 的分块扩展产生无界确定性字节流。实现
// crypto crate 重导出的 rand_core 0.10 trait（`hpke::rand_core`）。
struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buf: [0u8; 32],
            pos: 32,
        }
    }
    fn refill(&mut self) {
        let mut input = Vec::with_capacity(9 + 32 + 8);
        input.extend_from_slice(b"AD/DetRng");
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.counter.to_be_bytes());
        self.buf = sha256(&input);
        self.counter += 1;
        self.pos = 0;
    }
    fn fill(&mut self, dst: &mut [u8]) {
        for byte in dst.iter_mut() {
            if self.pos >= 32 {
                self.refill();
            }
            *byte = self.buf[self.pos];
            self.pos += 1;
        }
    }
}

// rand_core 0.10：实现基础 `TryRng`（Infallible）+ `TryCryptoRng` 标记；`Rng`/`CryptoRng`
// 由 rand_core 的 blanket impl 自动提供（hpke `single_shot_seal_with_rng` 只需 `CryptoRng`）。
impl TryRng for DeterministicRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

// —— hex helper ——

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// —— 固定 fixtures ——

const ED_SEED: [u8; 32] = [0x01; 32];
const AEAD_KEY: [u8; 32] = [0x11; 32];
const NONCE_PREFIX: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
const SENDER_COUNTER: u64 = 0x0102_0304_0506_0708;
const HPKE_IKM: [u8; 32] = [0x42; 32];
const HPKE_RNG_SEED: [u8; 32] = [0x24; 32];

fn mr() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}
fn dr() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}
fn pr() -> PairRouteId {
    PairRouteId::from_bytes([0x55; 16])
}
fn rs() -> RelayServerId {
    RelayServerId::from_bytes([0x88; 16])
}
fn rk() -> RootKeyId {
    RootKeyId::from_bytes([0x77; 16])
}

fn tbs_sample() -> ToBeSignedV1 {
    ToBeSignedV1 {
        object_type: SignedObjectType::RelayGrant,
        signature_format_version: 1,
        relay_protocol_version: 2,
        runtime_protocol_version: 1,
        e2ee_format_version: 1,
        relay_server_id: rs(),
        machine_route: mr(),
        device_route: Some(dr()),
        stream_route: None,
        request_route: None,
        stream_generation: None,
        stream_cursor: None,
        role_scope: "device".into(),
        signing_key_fingerprint: [0x0F; 32],
        root_key_id: rk(),
        trust_epoch: TrustEpoch::new(3),
        serial_or_generation: 9,
        not_after_ms: None,
        signed_object_sha256: [0x0E; 32],
    }
}

fn outer_sample() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::ConversationPublish,
        relay_protocol_version: 2,
        e2ee_format_version: 1,
        machine_route: Some(mr()),
        device_route: None,
        stream_route: Some(StreamRouteId::from_bytes([0x33; 16])),
        request_route: None,
        stream_generation: Some(StreamGenerationId::from_bytes([0x66; 16])),
        stream_cursor: Some(StreamCursor::At(7)),
        stream_seq: Some(7),
        message_key_epoch: 4,
    }
}

fn key_id() -> KeyId {
    KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 4,
    }
}

fn sending_key() -> AeadSendingKey {
    AeadSendingKey::new(
        key_id(),
        4,
        2,
        NONCE_PREFIX,
        SecretAeadKey::from_bytes(AEAD_KEY),
    )
}

fn receiving_key() -> AeadReceivingKey {
    AeadReceivingKey::new(key_id(), 4, SecretAeadKey::from_bytes(AEAD_KEY))
}

fn pair_request_info() -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        expiry_ms: 1_700_000_000_000,
    }
}

fn pair_response_info() -> PairResponseInfoV1 {
    PairResponseInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        relay_server_id: rs(),
        pair_route: pr(),
        invite_hash: [0x01; 32],
        request_hash: [0x02; 32],
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
    }
}

fn key_update_info() -> KeyUpdateInfoV1 {
    KeyUpdateInfoV1 {
        e2ee_format_version: 1,
        runtime_protocol_version: 1,
        machine_route: mr(),
        device_route: dr(),
        grant_serial: GrantSerial::new(9),
        root_trust_epoch: TrustEpoch::new(3),
        key_directory_revision: KeyDirectoryRevision::new(2),
        key_purpose: KeyPurpose::ConversationDek,
        key_epoch: 4,
    }
}

const AEAD_PLAINTEXT: &[u8] = b"agentdeck-relay-e2ee";
const HPKE_PLAINTEXT: &[u8] = &[0x33; 32]; // 被 HPKE 封装的对称 key（design §7.2）

fn nonce_bytes() -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&NONCE_PREFIX);
    n[4..].copy_from_slice(&SENDER_COUNTER.to_be_bytes());
    n
}

/// 构造所有 vectors 的 canonical JSON（确定性；与已提交快照逐字节比对）。
fn build_vectors() -> serde_json::Value {
    // Ed25519
    let signing = SigningKey::from_seed(&ED_SEED);
    let verifying = signing.verifying_key();
    let ed_msg = tbs_sample().encode();
    let ed_sig = sign_tbs(&signing, &tbs_sample());

    // SHA-256
    let sha_input = b"agentdeck/crypto-vectors-v1";

    // canonical TBS / AAD / HPKE infos
    let tbs = tbs_sample().encode();
    let aad = outer_sample().encode_aad();

    // ChaCha20-Poly1305 AEAD（通过 seal_symmetric，nonce=prefix||counter）
    let unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .expect("seal_symmetric");

    // sealed blob type-state：sign → wire
    let signed = sign_sealed(unsigned.clone(), &signing, &outer_sample());
    let blob_tbs = unsigned.sealed_blob_tbs(&outer_sample());
    let wire = signed.to_wire_bytes();

    // HPKE Base KAT（固定 seed RNG）
    let (hpke_priv, hpke_pub) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let hpke_info = key_update_info().encode();
    let hpke_aad = outer_sample_for_key_update().encode_aad();
    let mut rng = DeterministicRng::new(HPKE_RNG_SEED);
    let envelope = hpke_seal_base(&hpke_pub, &hpke_info, &hpke_aad, HPKE_PLAINTEXT, &mut rng)
        .expect("hpke_seal_base");

    json!({
        "version": 1,
        "description": "AgentDeck Relay E2EE deterministic golden vectors v1 (Rust source of truth; Swift mirror in P1.6). Fixed cipher suite: Ed25519; HPKE Base X25519+HKDF-SHA256+ChaCha20Poly1305; RFC 8439 ChaCha20-Poly1305.",
        "sha256": {
            "name": "sha256",
            "description": "SHA-256 of a fixed ASCII input.",
            "inputHex": hex(sha_input),
            "digestHex": hex(&sha256(sha_input)),
        },
        "tbs_canonical": {
            "name": "tbs_canonical",
            "description": "ToBeSignedV1 canonical length-prefixed encoding (P1.2) and its SHA-256.",
            "encodedHex": hex(&tbs),
            "sha256Hex": hex(&sha256(&tbs)),
        },
        "outer_context_aad": {
            "name": "outer_context_aad",
            "description": "OuterContextV1 canonical AAD encoding (P1.2); excludes ciphertext/signature/hash.",
            "aadHex": hex(&aad),
        },
        "hpke_infos": {
            "name": "hpke_infos",
            "description": "Canonical HPKE info encodings for pairing/key-update (P1.2).",
            "pairRequestInfoHex": hex(&pair_request_info().encode()),
            "pairResponseInfoHex": hex(&pair_response_info().encode()),
            "keyUpdateInfoHex": hex(&key_update_info().encode()),
        },
        "ed25519": {
            "name": "ed25519",
            "description": "Deterministic Ed25519 signature over the canonical ToBeSignedV1 bytes.",
            "seedHex": hex(&ED_SEED),
            "publicKeyHex": hex(&verifying.to_bytes()),
            "messageHex": hex(&ed_msg),
            "signatureHex": hex(&ed_sig.0),
        },
        "chacha20poly1305": {
            "name": "chacha20poly1305",
            "description": "RFC 8439 ChaCha20-Poly1305 seal via seal_symmetric; AAD = OuterContextV1; nonce = 4-byte prefix || 8-byte big-endian counter.",
            "keyHex": hex(&AEAD_KEY),
            "nonceHex": hex(&unsigned.nonce),
            "aadHex": hex(&aad),
            "plaintextHex": hex(AEAD_PLAINTEXT),
            "ciphertextHex": hex(&unsigned.ciphertext),
        },
        "nonce_assembly": {
            "name": "nonce_assembly",
            "description": "nonce = 32-bit random key prefix || 64-bit big-endian sender counter (design §7.4).",
            "prefixHex": hex(&NONCE_PREFIX),
            "counter": SENDER_COUNTER,
            "nonceHex": hex(&nonce_bytes()),
        },
        "hpke_base_kat": {
            "name": "hpke_base_kat",
            "description": "HPKE Base mode KAT with fixed-seed RNG. Only Rust can reproduce seal byte-for-byte; Swift verifies via open using recipientPriv.",
            "kem": "X25519HkdfSha256",
            "kdf": "HkdfSha256",
            "aead": "ChaCha20Poly1305",
            "recipientIkmHex": hex(&HPKE_IKM),
            "recipientPrivHex": hex(&hpke_priv.to_bytes()),
            "recipientPubHex": hex(&hpke_pub.to_bytes()),
            "rngSeedHex": hex(&HPKE_RNG_SEED),
            "infoHex": hex(&hpke_info),
            "aadHex": hex(&hpke_aad),
            "plaintextHex": hex(HPKE_PLAINTEXT),
            "encHex": hex(&envelope.enc),
            "ciphertextHex": hex(&envelope.ciphertext),
        },
        "sealed_blob": {
            "name": "sealed_blob",
            "description": "Sealed blob type-state: seal_symmetric -> sign_sealed. tbs binds outer context + key fields + nonce + ciphertext SHA-256 (design §7.3).",
            "payloadKind": "conversationEvent",
            "tbsHex": hex(&blob_tbs),
            "tbsSha256Hex": hex(&sha256(&blob_tbs)),
            "signatureHex": hex(&signed.signature.0),
            "nonceHex": hex(&signed.inner.nonce),
            "ciphertextHex": hex(&signed.inner.ciphertext),
            "wireHex": hex(&wire),
        },
    })
}

// HPKE KAT 用一个 KeyUpdate 用途的 outer context 作为 AAD。
fn outer_sample_for_key_update() -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: 2,
        e2ee_format_version: 1,
        machine_route: Some(mr()),
        device_route: Some(dr()),
        stream_route: None,
        request_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 4,
    }
}

// —— snapshot ——

#[test]
fn crypto_vectors_match_committed_snapshot() {
    let generated = serde_json::to_string_pretty(&build_vectors()).unwrap() + "\n";
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../protocol/agentdeck/crypto-vectors-v1.json");
    if std::env::var("UPDATE_CRYPTO_VECTORS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "crypto vectors snapshot missing; run `UPDATE_CRYPTO_VECTORS=1 cargo test -p agentdeck-crypto --test golden_vectors crypto_vectors_match_committed_snapshot`"
        )
    });
    assert_eq!(
        generated, committed,
        "crypto vectors drifted; run `UPDATE_CRYPTO_VECTORS=1 cargo test -p agentdeck-crypto --test golden_vectors` to regenerate"
    );
}

// —— nonce 逐字节 ——

#[test]
fn nonce_is_prefix_then_be_counter() {
    let unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    assert_eq!(unsigned.nonce, nonce_bytes());
    assert_eq!(&unsigned.nonce[..4], &NONCE_PREFIX);
    assert_eq!(&unsigned.nonce[4..], &SENDER_COUNTER.to_be_bytes());
}

// —— Ed25519 round trip / tamper ——

#[test]
fn sign_tbs_round_trips_and_rejects_tamper() {
    let signing = SigningKey::from_seed(&ED_SEED);
    let verifying = signing.verifying_key();
    let sig = sign_tbs(&signing, &tbs_sample());
    verify_tbs(&verifying, &tbs_sample(), &sig).expect("valid signature");

    // 篡改签名 → BadSignature。
    let mut bad = sig.0;
    bad[0] ^= 0x01;
    assert!(matches!(
        verify_tbs(&verifying, &tbs_sample(), &SignatureBytes(bad)),
        Err(CryptoError::BadSignature)
    ));

    // 篡改被签对象 → BadSignature。
    let mut other = tbs_sample();
    other.serial_or_generation = 10;
    assert!(matches!(
        verify_tbs(&verifying, &other, &sig),
        Err(CryptoError::BadSignature)
    ));

    // 错误公钥 → BadSignature。
    let other_key = SigningKey::from_seed(&[0x02; 32]).verifying_key();
    assert!(matches!(
        verify_tbs(&other_key, &tbs_sample(), &sig),
        Err(CryptoError::BadSignature)
    ));
}

// —— ChaCha20-Poly1305 确定性 + round trip + tamper ——

#[test]
fn seal_is_deterministic_for_same_key_counter_plaintext() {
    let a = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    let b = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    assert_eq!(
        a.ciphertext, b.ciphertext,
        "same key+counter+plaintext must be byte-deterministic"
    );
    assert_eq!(a.nonce, b.nonce);
}

#[test]
fn seal_open_round_trip() {
    let signing = SigningKey::from_seed(&ED_SEED);
    let unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    let signed = sign_sealed(unsigned, &signing, &outer_sample());
    let verified = verify_sealed(signed, &signing.verifying_key(), &outer_sample()).unwrap();
    let plaintext = open_symmetric(&receiving_key(), &outer_sample(), verified).unwrap();
    assert_eq!(plaintext, AEAD_PLAINTEXT);
}

#[test]
fn open_rejects_ciphertext_tamper() {
    let signing = SigningKey::from_seed(&ED_SEED);
    let mut unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    // 篡改密文 → verify（tbs 绑定 ciphertext hash）与 open（AEAD tag）都必须失败。
    unsigned.ciphertext[0] ^= 0x01;
    let signed = sign_sealed(unsigned, &signing, &outer_sample());
    // 用未篡改 tbs 的签名对篡改 blob 验证 → 由 sign 后再篡改无法覆盖；这里改为
    // 先签名再篡改的路径见下方 verify_sealed_rejects_* 测试。
    let verified = verify_sealed(signed, &signing.verifying_key(), &outer_sample())
        .expect("signed over tampered ciphertext still self-consistent");
    assert!(matches!(
        open_symmetric(&receiving_key(), &outer_sample(), verified),
        Err(CryptoError::BadCiphertext)
    ));
}

#[test]
fn open_rejects_aad_context_mismatch() {
    let signing = SigningKey::from_seed(&ED_SEED);
    let unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    let signed = sign_sealed(unsigned, &signing, &outer_sample());
    // open 用不同 AAD context（stream_seq 变了）→ AEAD tag 失败。
    let mut tampered_ctx = outer_sample();
    tampered_ctx.stream_seq = Some(8);
    let verified = verify_sealed(signed, &signing.verifying_key(), &outer_sample()).unwrap();
    assert!(matches!(
        open_symmetric(&receiving_key(), &tampered_ctx, verified),
        Err(CryptoError::BadCiphertext)
    ));
}

// —— sealed blob 签名：tamper 任一 route/version/epoch/counter/hash/签名 → BadSignature ——

fn signed_sealed_sample() -> agentdeck_protocol::e2ee::payload::SignedSealedBlobV1 {
    let signing = SigningKey::from_seed(&ED_SEED);
    let unsigned = seal_symmetric(
        &sending_key(),
        &outer_sample(),
        SealedPayloadKind::ConversationEvent,
        AEAD_PLAINTEXT,
        SenderCounter(SENDER_COUNTER),
    )
    .unwrap();
    sign_sealed(unsigned, &signing, &outer_sample())
}

fn vk() -> VerifyingKey {
    SigningKey::from_seed(&ED_SEED).verifying_key()
}

#[test]
fn verify_sealed_accepts_untampered() {
    let signed = signed_sealed_sample();
    verify_sealed(signed, &vk(), &outer_sample()).expect("untampered sealed blob verifies");
}

#[test]
fn verify_sealed_rejects_signature_tamper() {
    let mut signed = signed_sealed_sample();
    signed.signature.0[0] ^= 0x01;
    assert!(matches!(
        verify_sealed(signed, &vk(), &outer_sample()),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verify_sealed_rejects_route_tamper() {
    let signed = signed_sealed_sample();
    let mut ctx = outer_sample();
    ctx.machine_route = Some(MachineRouteId::from_bytes([0x99; 16]));
    assert!(matches!(
        verify_sealed(signed, &vk(), &ctx),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verify_sealed_rejects_version_tamper() {
    let signed = signed_sealed_sample();
    let mut ctx = outer_sample();
    ctx.relay_protocol_version = 3;
    assert!(matches!(
        verify_sealed(signed, &vk(), &ctx),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verify_sealed_rejects_epoch_tamper() {
    let mut signed = signed_sealed_sample();
    signed.inner.key_epoch = 5;
    assert!(matches!(
        verify_sealed(signed, &vk(), &outer_sample()),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verify_sealed_rejects_counter_tamper() {
    let mut signed = signed_sealed_sample();
    // counter 位于 nonce 的后 8 字节，tbs 绑定 nonce → 篡改必被验证捕获。
    signed.inner.nonce[5] ^= 0x01;
    assert!(matches!(
        verify_sealed(signed, &vk(), &outer_sample()),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verify_sealed_rejects_ciphertext_hash_tamper() {
    let mut signed = signed_sealed_sample();
    signed.inner.ciphertext[0] ^= 0x01;
    assert!(matches!(
        verify_sealed(signed, &vk(), &outer_sample()),
        Err(CryptoError::BadSignature)
    ));
}

// —— HPKE Base：round trip + tamper ——

#[test]
fn hpke_seal_open_round_trip() {
    let (priv_key, pub_key) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let info = key_update_info().encode();
    let aad = outer_sample_for_key_update().encode_aad();
    let mut rng = DeterministicRng::new(HPKE_RNG_SEED);
    let envelope = hpke_seal_base(&pub_key, &info, &aad, HPKE_PLAINTEXT, &mut rng).unwrap();
    let recovered = hpke_open_base(&priv_key, &info, &aad, &envelope).unwrap();
    assert_eq!(recovered, HPKE_PLAINTEXT);
}

#[test]
fn hpke_is_deterministic_with_fixed_rng() {
    let (_priv_key, pub_key) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let info = key_update_info().encode();
    let aad = outer_sample_for_key_update().encode_aad();
    let mut rng_a = DeterministicRng::new(HPKE_RNG_SEED);
    let mut rng_b = DeterministicRng::new(HPKE_RNG_SEED);
    let a = hpke_seal_base(&pub_key, &info, &aad, HPKE_PLAINTEXT, &mut rng_a).unwrap();
    let b = hpke_seal_base(&pub_key, &info, &aad, HPKE_PLAINTEXT, &mut rng_b).unwrap();
    assert_eq!(a.enc, b.enc, "fixed-seed RNG must produce identical enc");
    assert_eq!(a.ciphertext, b.ciphertext);
}

#[test]
fn hpke_open_rejects_tampered_ciphertext_and_info() {
    let (priv_key, pub_key) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let info = key_update_info().encode();
    let aad = outer_sample_for_key_update().encode_aad();
    let mut rng = DeterministicRng::new(HPKE_RNG_SEED);
    let mut envelope = hpke_seal_base(&pub_key, &info, &aad, HPKE_PLAINTEXT, &mut rng).unwrap();

    // 篡改密文。
    let mut tampered = envelope.clone();
    tampered.ciphertext[0] ^= 0x01;
    assert!(hpke_open_base(&priv_key, &info, &aad, &tampered).is_err());

    // 篡改 info（HPKE context 绑定）→ open 失败。
    let mut bad_info = info.clone();
    bad_info[0] ^= 0x01;
    assert!(hpke_open_base(&priv_key, &bad_info, &aad, &envelope).is_err());

    // 篡改 AAD → open 失败。
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x01;
    assert!(hpke_open_base(&priv_key, &info, &bad_aad, &envelope).is_err());

    // enc 篡改（envelope 可变借用回收后）。
    envelope.enc[0] ^= 0x01;
    assert!(hpke_open_base(&priv_key, &info, &aad, &envelope).is_err());
}

// —— secret wrapper：Debug 不泄漏材料 ——

#[test]
fn secret_wrappers_redact_debug() {
    let signing = SigningKey::from_seed(&ED_SEED);
    let dbg = format!("{signing:?}");
    assert!(
        !dbg.contains(&hex(&ED_SEED)),
        "SigningKey Debug must not contain seed bytes: {dbg}"
    );

    let secret = SecretAeadKey::from_bytes(AEAD_KEY);
    let dbg = format!("{secret:?}");
    assert!(
        !dbg.contains(&hex(&AEAD_KEY)),
        "SecretAeadKey Debug must not contain key bytes: {dbg}"
    );

    // AeadSendingKey 派生 Debug，但内嵌 SecretAeadKey 必须已脱敏。
    let dbg = format!("{:?}", sending_key());
    assert!(
        !dbg.contains(&hex(&AEAD_KEY)),
        "AeadSendingKey Debug must not leak key bytes: {dbg}"
    );

    let (priv_key, _pub) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let dbg = format!("{priv_key:?}");
    assert!(
        !dbg.contains(&hex(&priv_key.to_bytes())),
        "HpkePrivateKey Debug must not contain private key bytes: {dbg}"
    );
}

// —— HpkeEnvelopeV1 结构可用 ——

#[test]
fn hpke_envelope_carries_enc_and_ciphertext() {
    let (_priv, pub_key) = HpkePrivateKey::derive_keypair(&HPKE_IKM);
    let mut rng = DeterministicRng::new(HPKE_RNG_SEED);
    let e: HpkeEnvelopeV1 = hpke_seal_base(&pub_key, b"i", b"a", b"p", &mut rng).unwrap();
    assert!(!e.enc.is_empty());
    assert!(!e.ciphertext.is_empty());
}
