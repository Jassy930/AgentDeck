//! RuntimeEnvelope v1 —— UDS 与解密后远程链路的共同**中立业务 wire**（design §8.2）。
//!
//! 本模块与现有 local IPC（`PROTOCOL_VERSION = 2`，见 crate 根）以及 Relay v1
//! （`src/remote/`）**并列**存在，彼此独立、版本轴不联动：`RUNTIME_PROTOCOL_VERSION`
//! 与 `PROTOCOL_VERSION` 不得联动 bump（design §15 P0 / 实施计划 Global Constraints）。
//!
//! 本 task（P1.1）只定义契约与构造校验，不接线任何运行时行为；现有 local IPC 与
//! Relay v1 路径原样保留。
//!
//! 关键不变量（由 `tests/runtime_*` 守护）：
//! - 稳定中立身份 newtypes（`identity`）——禁止 vendor thread/session 身份（RC-9）。
//! - `StreamCursor::BeforeFirst | At(u64)`，绝不把 `-1` 编进 unsigned wire（§9.1）。
//! - snapshot 必须先交付 `SessionCapabilities` 再交付 `AgentItem`（RC-16）。
//! - 限制值均为具名常量 + 构造校验，超限返回 typed error（不 panic）。

pub mod catalog;
pub mod command;
pub mod envelope;
pub mod event;
pub mod failure;
pub mod identity;
pub mod receipt;
pub mod schema;
pub mod sync;
pub mod transfer;

/// Runtime 契约产物版本；独立于 local IPC `PROTOCOL_VERSION` 与 Relay
/// `RELAY_PROTOCOL_VERSION`。改动 Runtime wire 形态时手动 +1 并重生成快照。
pub const RUNTIME_PROTOCOL_VERSION: u16 = 1;

pub use catalog::{CatalogChange, CatalogDelta, CatalogError, CatalogSnapshot, ConversationEntry};
pub use command::{
    LocalOnlyAdministration, PromptError, PromptPayload, RuntimeRequest, MAX_PROMPT_BYTES,
};
pub use envelope::{
    ensure_request_within_limit, PairInvite, PendingPairing, RuntimeEnvelope, RuntimeMessage,
    RuntimeReply, RuntimeSizeError, RuntimeStreamItem, MAX_RUNTIME_REQUEST_BYTES,
};
pub use event::{RuntimeEvent, RuntimeEventBody};
pub use failure::RuntimeFailure;
pub use receipt::{ApprovalDeliveryState, ApprovalReceipt, CommandReceipt, RevocationReceipt};
pub use schema::runtime_schema;
pub use sync::{
    BackfillChunk, ConversationSnapshot, RuntimeSyncComplete, SnapshotError, SnapshotItem,
    StreamCursor,
};
pub use transfer::{
    TransferEnvelope, TransferError, TransferProgress, TransferReassembler, MAX_PART_BYTES,
    MAX_REASSEMBLY_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, TRANSFER_TTL_MS,
};
