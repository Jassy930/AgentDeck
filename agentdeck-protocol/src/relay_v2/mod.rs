//! Relay v2 opaque wire 契约（design §10，严格最小可见 RC-6）。
//!
//! 本模块与现有 Relay v1 namespace（`crate::remote`，`RELAY_PROTOCOL_VERSION = 1`）
//! **并列**存在、彼此独立、版本轴不联动：Relay v2 固定 `RELAY_PROTOCOL_VERSION = 2`；
//! P1.2 只定义并列契约，不触碰 v1 路径（design §15 P1 / 实施计划 Global Constraints）。
//!
//! Relay 只理解通用 opaque route/stream/request 语义；wire/schema/日志中不存在机器名、
//! session title、cwd、agent kind、conversation/thread/turn/approval/vendor 业务字段
//! （由 `tests/relay_v2_neutrality` 守护）。所有业务内容在 `e2ee` 的 sealed blob 内。
//!
//! 关键不变量：
//! - 128-bit 随机 route/generation ID 不可比较、不可复用（`id`，编译期证明）。
//! - u64 单调值到 MAX 拒绝 wrap，要求 reset/rekey（`id::MonotonicError`）。
//! - 生产 WS outer frame 是固定 `ADRV2` 二进制 codec（`codec`），`sealedBlob` 直接 bytes。

pub mod auth;
pub mod codec;
pub mod cursor;
pub mod enrollment;
pub mod failure;
pub mod frame;
pub mod id;
pub mod schema;

/// Relay 目标线协议版本；独立于 local IPC `PROTOCOL_VERSION`、Relay v1
/// `remote::RELAY_PROTOCOL_VERSION` 与 `runtime::RUNTIME_PROTOCOL_VERSION`。
pub const RELAY_PROTOCOL_VERSION: u16 = 2;

pub use auth::{
    AUTH_SIGNATURE_FORMAT_VERSION, AuthenticationRole, AuthenticationTranscriptV1, CertRole,
    DeviceRevocation, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
pub use codec::{CodecError, MAX_FRAME_BYTES, RELAY_FRAME_MAGIC, decode, encode};
pub use cursor::StreamCursor;
pub use enrollment::{
    EnrollmentCode, MachineEnrollmentRequestV1, MachineEnrollmentResponseV1,
    enrollment_receipt_hash,
};
pub use failure::RelayFailure;
pub use frame::{OpaqueRouteFrame, PairingHello, RelayFrameBody};
pub use id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration,
    MachineRouteId, MonotonicError, PairRouteId, RelayServerId, RequestRouteId, RootKeyId,
    StreamGenerationId, StreamRouteId, TrustEpoch,
};
pub use schema::relay_v2_schema;
