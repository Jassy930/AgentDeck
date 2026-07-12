//! RuntimeEnvelope v1 —— UDS 与解密后远程链路的共同**中立业务 wire**（design §8.2）。
//!
//! 本模块与 local IPC（`PROTOCOL_VERSION = 2`，见 crate 根）及 Relay v2
//! 彼此独立、版本轴不联动：`RUNTIME_PROTOCOL_VERSION` 与
//! `PROTOCOL_VERSION` / `relay_v2::RELAY_PROTOCOL_VERSION` 不得联动 bump。
//!
//! Runtime 只定义中立业务契约与构造校验，不承载 Relay 运输细节。
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
    ConversationStart, LocalOnlyAdministration, MAX_PROMPT_BYTES, PromptError, PromptPayload,
    QueryReceiptSelector, RuntimeRequest, SendPromptRequest,
};
pub use envelope::{
    MAX_RUNTIME_REQUEST_BYTES, PairInvite, PendingPairing, RuntimeEnvelope, RuntimeMessage,
    RuntimeReply, RuntimeSizeError, RuntimeStreamItem, ensure_request_within_limit,
};
pub use event::{RuntimeEvent, RuntimeEventBody};
pub use failure::RuntimeFailure;
pub use receipt::{
    ApprovalDeliveryState, ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatus,
    CommandStatusReceipt, ConversationStartReceipt, RevocationReceipt,
};
pub use schema::runtime_schema;
pub use sync::{
    BackfillChunk, ConversationSnapshot, RuntimeSyncComplete, SnapshotError, SnapshotItem,
    StreamCursor,
};
pub use transfer::{
    MAX_PART_BYTES, MAX_REASSEMBLY_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, TRANSFER_TTL_MS,
    TransferEnvelope, TransferError, TransferProgress, TransferReassembler,
};
