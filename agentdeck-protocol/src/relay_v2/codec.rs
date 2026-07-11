//! Relay v2 生产 WS outer frame 的固定长度前缀二进制 codec（design §7.3）。
//!
//! 布局：`ADRV2`(5 magic) + big-endian `u16` version + `u16` frameKind + 逐字段长度前缀
//! 编码。`sealedBlob` 直接作为 length-prefixed bytes 携带（不 base64）。这样 3.5 MiB part
//! 加上外层 overhead 仍落在 4 MiB WebSocket 硬上限内。
//!
//! 解析前先以 4 MiB 上限拒绝 oversize（**在读取任何字段前**）；bad-frame（截断、错误
//! magic、未知 version/kind、长度前缀越界、尾部多余字节）全部返回 typed [`CodecError`]，
//! 不 panic。该二进制 codec **不参与签名 canonicalization**（TBS/AAD 使用 `e2ee` 的独立
//! 确定性编码）。

use crate::relay_v2::RELAY_PROTOCOL_VERSION;
use crate::relay_v2::auth::{
    CertRole, DeviceRevocation, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use crate::relay_v2::cursor::StreamCursor;
use crate::relay_v2::failure::RelayFailure;
use crate::relay_v2::frame::*;
use crate::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RequestRouteId, RootKeyId, StreamGenerationId, StreamRouteId, TrustEpoch,
};

/// 5-byte magic：`ADRV2`。
pub const RELAY_FRAME_MAGIC: &[u8; 5] = b"ADRV2";

/// 单 frame 硬上限（4 MiB WebSocket message 上限）。
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// 二进制 codec 失败（全部 typed，不 panic）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("frame exceeds 4 MiB limit")]
    Oversize,
    #[error("input truncated / too short")]
    ShortInput,
    #[error("bad ADRV2 magic")]
    BadMagic,
    #[error("unsupported relay protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown frame kind {0}")]
    UnknownKind(u16),
    #[error("length prefix out of bounds")]
    LengthOutOfBounds,
    #[error("trailing bytes after frame")]
    TrailingBytes,
    #[error("invalid stream cursor tag {0}")]
    InvalidCursorTag(u8),
    #[error("invalid enum tag {0}")]
    InvalidEnumTag(u8),
    #[error("invalid utf-8 in string field")]
    InvalidUtf8,
}

// ————————————————————————— Writer —————————————————————————

struct W(Vec<u8>);

impl W {
    fn new() -> Self {
        W(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u16_len_or_u32(b.len());
        self.0.extend_from_slice(b);
    }
    /// 长度前缀固定用 u32（big-endian），支持到 4 GiB，实际受 4 MiB frame 上限约束。
    fn u16_len_or_u32(&mut self, len: usize) {
        self.0.extend_from_slice(&(len as u32).to_be_bytes());
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn opt_str(&mut self, s: &Option<String>) {
        match s {
            Some(x) => {
                self.u8(1);
                self.str(x);
            }
            None => self.u8(0),
        }
    }
    fn cursor(&mut self, c: &StreamCursor) {
        match c {
            StreamCursor::BeforeFirst => self.u8(0),
            StreamCursor::At(n) => {
                self.u8(1);
                self.u64(*n);
            }
        }
    }
    fn blob(&mut self, b: &SealedBlob) {
        self.bytes(&b.0);
    }
    fn cert(&mut self, c: &SignedCertificate) {
        self.raw(&c.subject_pubkey.0);
        self.u8(match c.cert_role {
            CertRole::Link => 0,
            CertRole::Data => 1,
        });
        self.u64(c.generation.0);
        self.raw(&c.root_key_id.0);
        self.u64(c.trust_epoch.0);
        match c.not_after_ms {
            Some(v) => {
                self.u8(1);
                self.u64(v);
            }
            None => self.u8(0),
        }
        self.raw(&c.signature.0);
    }
    fn grant(&mut self, g: &RelayGrant) {
        self.raw(&g.machine_route.0);
        self.raw(&g.device_route.0);
        self.raw(&g.device_sign_pubkey.0);
        self.u64(g.grant_serial.0);
        self.raw(&g.root_key_id.0);
        self.u64(g.trust_epoch.0);
        self.raw(&g.signature.0);
    }
    fn revocation(&mut self, r: &DeviceRevocation) {
        self.raw(&r.machine_route.0);
        self.raw(&r.device_route.0);
        self.u64(r.grant_serial.0);
        self.raw(&r.root_key_id.0);
        self.u64(r.trust_epoch.0);
        self.raw(&r.signature.0);
    }
}

// ————————————————————————— Reader —————————————————————————

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn need(&self, n: usize) -> Result<(), CodecError> {
        // checked_add：消除 32-bit usize 上 `p + n` 回绕绕过越界检查的平台假设。
        match self.p.checked_add(n) {
            Some(end) if end <= self.b.len() => Ok(()),
            _ => Err(CodecError::ShortInput),
        }
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        self.need(1)?;
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.b[self.p], self.b[self.p + 1]]);
        self.p += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        self.need(4)?;
        let v = u32::from_be_bytes([
            self.b[self.p],
            self.b[self.p + 1],
            self.b[self.p + 2],
            self.b[self.p + 3],
        ]);
        self.p += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.b[self.p..self.p + 8]);
        self.p += 8;
        Ok(u64::from_be_bytes(a))
    }
    fn raw(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        self.need(n)?;
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn arr16(&mut self) -> Result<[u8; 16], CodecError> {
        Ok(self.raw(16)?.try_into().expect("16"))
    }
    fn arr32(&mut self) -> Result<[u8; 32], CodecError> {
        Ok(self.raw(32)?.try_into().expect("32"))
    }
    fn arr64(&mut self) -> Result<[u8; 64], CodecError> {
        Ok(self.raw(64)?.try_into().expect("64"))
    }
    /// 长度前缀 bytes：先读 u32 长度，越界返回 `LengthOutOfBounds`（不 panic）。
    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.u32()? as usize;
        // checked_add：同 `need`，防 32-bit usize 回绕绕过越界检查。
        let end = match self.p.checked_add(n) {
            Some(end) if end <= self.b.len() => end,
            _ => return Err(CodecError::LengthOutOfBounds),
        };
        let s = self.b[self.p..end].to_vec();
        self.p = end;
        Ok(s)
    }
    fn str(&mut self) -> Result<String, CodecError> {
        let raw = self.bytes()?;
        String::from_utf8(raw).map_err(|_| CodecError::InvalidUtf8)
    }
    fn opt_str(&mut self) -> Result<Option<String>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.str()?)),
            other => Err(CodecError::InvalidEnumTag(other)),
        }
    }
    fn opt_u64(&mut self) -> Result<Option<u64>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            other => Err(CodecError::InvalidEnumTag(other)),
        }
    }
    fn cursor(&mut self) -> Result<StreamCursor, CodecError> {
        match self.u8()? {
            0 => Ok(StreamCursor::BeforeFirst),
            1 => Ok(StreamCursor::At(self.u64()?)),
            other => Err(CodecError::InvalidCursorTag(other)),
        }
    }
    fn blob(&mut self) -> Result<SealedBlob, CodecError> {
        Ok(SealedBlob(self.bytes()?))
    }
    fn cert_role(&mut self) -> Result<CertRole, CodecError> {
        match self.u8()? {
            0 => Ok(CertRole::Link),
            1 => Ok(CertRole::Data),
            other => Err(CodecError::InvalidEnumTag(other)),
        }
    }
    fn cert(&mut self) -> Result<SignedCertificate, CodecError> {
        Ok(SignedCertificate {
            subject_pubkey: PublicKeyBytes(self.arr32()?),
            cert_role: self.cert_role()?,
            generation: LinkGeneration::new(self.u64()?),
            root_key_id: RootKeyId::from_bytes(self.arr16()?),
            trust_epoch: TrustEpoch::new(self.u64()?),
            not_after_ms: self.opt_u64()?,
            signature: Ed25519Signature(self.arr64()?),
        })
    }
    fn grant(&mut self) -> Result<RelayGrant, CodecError> {
        Ok(RelayGrant {
            machine_route: MachineRouteId::from_bytes(self.arr16()?),
            device_route: DeviceRouteId::from_bytes(self.arr16()?),
            device_sign_pubkey: PublicKeyBytes(self.arr32()?),
            grant_serial: GrantSerial::new(self.u64()?),
            root_key_id: RootKeyId::from_bytes(self.arr16()?),
            trust_epoch: TrustEpoch::new(self.u64()?),
            signature: Ed25519Signature(self.arr64()?),
        })
    }
    fn revocation(&mut self) -> Result<DeviceRevocation, CodecError> {
        Ok(DeviceRevocation {
            machine_route: MachineRouteId::from_bytes(self.arr16()?),
            device_route: DeviceRouteId::from_bytes(self.arr16()?),
            grant_serial: GrantSerial::new(self.u64()?),
            root_key_id: RootKeyId::from_bytes(self.arr16()?),
            trust_epoch: TrustEpoch::new(self.u64()?),
            signature: Ed25519Signature(self.arr64()?),
        })
    }
    fn finish(&self) -> Result<(), CodecError> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

// ————————————————————————— encode —————————————————————————

/// 编码一个 [`OpaqueRouteFrame`] 为 `ADRV2` 二进制 wire。
pub fn encode(frame: &OpaqueRouteFrame) -> Vec<u8> {
    let mut w = W::new();
    w.raw(RELAY_FRAME_MAGIC);
    w.u16(frame.version);
    w.u16(frame.body.kind());
    encode_body(&mut w, &frame.body);
    w.0
}

fn encode_body(w: &mut W, body: &RelayFrameBody) {
    match body {
        RelayFrameBody::Hello(x) => w.u16(x.protocol_version),
        RelayFrameBody::Challenge(x) => {
            w.raw(&x.relay_server_id.0);
            w.raw(&x.connection_instance.0);
            w.raw(&x.challenge_nonce);
        }
        RelayFrameBody::Authenticate(x) => {
            match &x.proof {
                AuthProof::MachineLink {
                    machine_route,
                    link_cert,
                } => {
                    w.u8(0);
                    w.raw(&machine_route.0);
                    w.cert(link_cert);
                }
                AuthProof::Device { relay_grant } => {
                    w.u8(1);
                    w.grant(relay_grant);
                }
            }
            w.raw(&x.signature.0);
        }
        RelayFrameBody::Authenticated(x) => w.u16(x.heartbeat_interval_secs),
        RelayFrameBody::OpenPairRoute(x) => {
            w.raw(&x.machine_route.0);
            w.raw(&x.pair_route.0);
            w.u64(x.absolute_expiry_ms);
        }
        RelayFrameBody::PairRouteOpened(x) => {
            w.raw(&x.machine_route.0);
            w.raw(&x.pair_route.0);
            w.u64(x.absolute_expiry_ms);
        }
        RelayFrameBody::PairData(x) => {
            w.raw(&x.pair_route.0);
            w.blob(&x.sealed_blob);
        }
        RelayFrameBody::ClosePairRoute(x) => {
            w.raw(&x.machine_route.0);
            w.raw(&x.pair_route.0);
        }
        RelayFrameBody::PairRouteClosed(x) => {
            w.raw(&x.pair_route.0);
            w.u8(match x.outcome {
                PairRouteCloseOutcome::Closed => 0,
                PairRouteCloseOutcome::AlreadyAbsent => 1,
            });
        }
        RelayFrameBody::RegisterStream(x) => {
            w.raw(&x.machine_route.0);
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
        }
        RelayFrameBody::Publish(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
            w.u64(x.stream_seq);
            w.blob(&x.sealed_blob);
        }
        RelayFrameBody::Subscribe(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
            w.cursor(&x.cursor);
        }
        RelayFrameBody::Unsubscribe(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
        }
        RelayFrameBody::Ack(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
            w.u64(x.up_to_seq);
        }
        RelayFrameBody::Gap(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
            w.u64(x.need_stream_seq);
            w.u64(x.oldest_stream_seq);
        }
        RelayFrameBody::ReplayComplete(x) => {
            w.raw(&x.stream_route.0);
            w.raw(&x.generation.0);
            w.cursor(&x.current_cursor);
        }
        RelayFrameBody::Send(x) => {
            w.raw(&x.device_route.0);
            w.raw(&x.request_route.0);
            w.blob(&x.sealed_blob);
        }
        RelayFrameBody::Reply(x) => {
            w.raw(&x.device_route.0);
            w.raw(&x.request_route.0);
            w.blob(&x.sealed_blob);
        }
        RelayFrameBody::InstallGrant(x) => w.grant(&x.grant),
        RelayFrameBody::GrantCommitted(x) => {
            w.raw(&x.device_route.0);
            w.u64(x.grant_serial.0);
            w.raw(&x.grant_hash);
        }
        RelayFrameBody::RevokeDevice(x) => w.revocation(&x.revocation),
        RelayFrameBody::RevocationCommitted(x) => {
            w.raw(&x.device_route.0);
            w.u64(x.grant_serial.0);
            w.revocation(&x.signed_revocation);
        }
        RelayFrameBody::RetireMachine(x) => {
            w.raw(&x.machine_route.0);
            w.raw(&x.root_key_id.0);
            w.u64(x.trust_epoch.0);
            w.raw(&x.signature.0);
        }
        RelayFrameBody::Ping(x) => w.u64(x.nonce),
        RelayFrameBody::Pong(x) => w.u64(x.nonce),
        RelayFrameBody::RouteAccepted(x) => match &x.accepted {
            AcceptedRef::Request { request_route } => {
                w.u8(0);
                w.raw(&request_route.0);
            }
            AcceptedRef::StreamFrame {
                stream_route,
                stream_seq,
            } => {
                w.u8(1);
                w.raw(&stream_route.0);
                w.u64(*stream_seq);
            }
            AcceptedRef::PairFrame { pair_route } => {
                w.u8(2);
                w.raw(&pair_route.0);
            }
        },
        RelayFrameBody::Error(x) => {
            w.str(&x.code);
            w.str(&x.message);
            w.opt_str(&x.in_reply_to);
        }
        RelayFrameBody::ServerRestarting(x) => w.u64(x.drain_deadline_ms),
        RelayFrameBody::RetirementCommitted(x) => {
            w.raw(&x.machine_route.0);
            w.u64(x.trust_epoch.0);
            w.raw(&x.retire_hash);
        }
    }
}

// ————————————————————————— decode —————————————————————————

/// 解码 `ADRV2` 二进制 wire 为一个 [`OpaqueRouteFrame`]。解析前先拒绝 oversize。
pub fn decode(input: &[u8]) -> Result<OpaqueRouteFrame, CodecError> {
    // 4 MiB+1 必须在读取任何字段前拒绝。
    if input.len() > MAX_FRAME_BYTES {
        return Err(CodecError::Oversize);
    }
    let mut r = R { b: input, p: 0 };
    let magic = r.raw(5)?;
    if magic != RELAY_FRAME_MAGIC {
        return Err(CodecError::BadMagic);
    }
    let version = r.u16()?;
    if version != RELAY_PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    let kind = r.u16()?;
    let body = decode_body(kind, &mut r)?;
    r.finish()?;
    Ok(OpaqueRouteFrame { version, body })
}

fn decode_body(kind: u16, r: &mut R) -> Result<RelayFrameBody, CodecError> {
    Ok(match kind {
        0 => RelayFrameBody::Hello(Hello {
            protocol_version: r.u16()?,
        }),
        1 => RelayFrameBody::Challenge(Challenge {
            relay_server_id: RelayServerId::from_bytes(r.arr16()?),
            connection_instance: ConnectionInstanceId::from_bytes(r.arr16()?),
            challenge_nonce: r.arr32()?,
        }),
        2 => {
            let proof = match r.u8()? {
                0 => AuthProof::MachineLink {
                    machine_route: MachineRouteId::from_bytes(r.arr16()?),
                    link_cert: r.cert()?,
                },
                1 => AuthProof::Device {
                    relay_grant: r.grant()?,
                },
                other => return Err(CodecError::InvalidEnumTag(other)),
            };
            RelayFrameBody::Authenticate(Authenticate {
                proof,
                signature: Ed25519Signature(r.arr64()?),
            })
        }
        3 => RelayFrameBody::Authenticated(Authenticated {
            heartbeat_interval_secs: r.u16()?,
        }),
        4 => RelayFrameBody::OpenPairRoute(OpenPairRoute {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            pair_route: PairRouteId::from_bytes(r.arr16()?),
            absolute_expiry_ms: r.u64()?,
        }),
        5 => RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            pair_route: PairRouteId::from_bytes(r.arr16()?),
            absolute_expiry_ms: r.u64()?,
        }),
        6 => RelayFrameBody::PairData(PairData {
            pair_route: PairRouteId::from_bytes(r.arr16()?),
            sealed_blob: r.blob()?,
        }),
        7 => RelayFrameBody::ClosePairRoute(ClosePairRoute {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            pair_route: PairRouteId::from_bytes(r.arr16()?),
        }),
        8 => {
            let pair_route = PairRouteId::from_bytes(r.arr16()?);
            let outcome = match r.u8()? {
                0 => PairRouteCloseOutcome::Closed,
                1 => PairRouteCloseOutcome::AlreadyAbsent,
                other => return Err(CodecError::InvalidEnumTag(other)),
            };
            RelayFrameBody::PairRouteClosed(PairRouteClosed {
                pair_route,
                outcome,
            })
        }
        9 => RelayFrameBody::RegisterStream(RegisterStream {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
        }),
        10 => RelayFrameBody::Publish(Publish {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
            stream_seq: r.u64()?,
            sealed_blob: r.blob()?,
        }),
        11 => RelayFrameBody::Subscribe(Subscribe {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
            cursor: r.cursor()?,
        }),
        12 => RelayFrameBody::Unsubscribe(Unsubscribe {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
        }),
        13 => RelayFrameBody::Ack(Ack {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
            up_to_seq: r.u64()?,
        }),
        14 => RelayFrameBody::Gap(Gap {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
            need_stream_seq: r.u64()?,
            oldest_stream_seq: r.u64()?,
        }),
        15 => RelayFrameBody::ReplayComplete(ReplayComplete {
            stream_route: StreamRouteId::from_bytes(r.arr16()?),
            generation: StreamGenerationId::from_bytes(r.arr16()?),
            current_cursor: r.cursor()?,
        }),
        16 => RelayFrameBody::Send(Send {
            device_route: DeviceRouteId::from_bytes(r.arr16()?),
            request_route: RequestRouteId::from_bytes(r.arr16()?),
            sealed_blob: r.blob()?,
        }),
        17 => RelayFrameBody::Reply(Reply {
            device_route: DeviceRouteId::from_bytes(r.arr16()?),
            request_route: RequestRouteId::from_bytes(r.arr16()?),
            sealed_blob: r.blob()?,
        }),
        18 => RelayFrameBody::InstallGrant(InstallGrant { grant: r.grant()? }),
        19 => RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: DeviceRouteId::from_bytes(r.arr16()?),
            grant_serial: GrantSerial::new(r.u64()?),
            grant_hash: r.arr32()?,
        }),
        20 => RelayFrameBody::RevokeDevice(RevokeDevice {
            revocation: r.revocation()?,
        }),
        21 => RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: DeviceRouteId::from_bytes(r.arr16()?),
            grant_serial: GrantSerial::new(r.u64()?),
            signed_revocation: r.revocation()?,
        }),
        22 => RelayFrameBody::RetireMachine(RetireMachine {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            root_key_id: RootKeyId::from_bytes(r.arr16()?),
            trust_epoch: TrustEpoch::new(r.u64()?),
            signature: Ed25519Signature(r.arr64()?),
        }),
        23 => RelayFrameBody::Ping(Ping { nonce: r.u64()? }),
        24 => RelayFrameBody::Pong(Pong { nonce: r.u64()? }),
        25 => {
            let accepted = match r.u8()? {
                0 => AcceptedRef::Request {
                    request_route: RequestRouteId::from_bytes(r.arr16()?),
                },
                1 => AcceptedRef::StreamFrame {
                    stream_route: StreamRouteId::from_bytes(r.arr16()?),
                    stream_seq: r.u64()?,
                },
                2 => AcceptedRef::PairFrame {
                    pair_route: PairRouteId::from_bytes(r.arr16()?),
                },
                other => return Err(CodecError::InvalidEnumTag(other)),
            };
            RelayFrameBody::RouteAccepted(RouteAccepted { accepted })
        }
        26 => RelayFrameBody::Error(RelayFailure {
            code: r.str()?,
            message: r.str()?,
            in_reply_to: r.opt_str()?,
        }),
        27 => RelayFrameBody::ServerRestarting(ServerRestarting {
            drain_deadline_ms: r.u64()?,
        }),
        28 => RelayFrameBody::RetirementCommitted(RetirementCommitted {
            machine_route: MachineRouteId::from_bytes(r.arr16()?),
            trust_epoch: TrustEpoch::new(r.u64()?),
            retire_hash: r.arr32()?,
        }),
        other => return Err(CodecError::UnknownKind(other)),
    })
}
