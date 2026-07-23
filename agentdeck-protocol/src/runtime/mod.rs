//! RuntimeEnvelope v4 —— UDS 与解密后远程链路的共同**中立业务 wire**（design §8.2）。
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
pub mod configuration;
pub mod durable_transfer;
pub mod envelope;
pub mod event;
pub mod failure;
pub mod identity;
pub mod metadata;
pub mod receipt;
pub mod schema;
pub mod sync;
pub mod transfer;
pub mod upgrade;

/// Runtime 契约产物版本；独立于 local IPC `PROTOCOL_VERSION` 与 Relay
/// `RELAY_PROTOCOL_VERSION`。改动 Runtime wire 形态时手动 +1 并重生成快照。
pub const RUNTIME_PROTOCOL_VERSION: u16 = 5;

pub use crate::relay_v2::RelayAdminPurgeReceiptV1;
pub use catalog::{CatalogChange, CatalogDelta, CatalogError, CatalogSnapshot, ConversationEntry};
pub use command::{
    ConversationStart, CreatePairInviteRequest, HelloParams, LocalOnlyAdministration,
    MAX_PROMPT_BYTES, MachineEnrollRequest, PAIR_INVITE_TTL_SECS, PromptError, PromptPayload,
    QueryReceiptSelector, RuntimeRequest, SendPromptRequest, TrustResetRequest,
    UNINSTALL_PURGE_PLAN_VERSION, UninstallPurgePlanError, UninstallPurgePlanV1,
};
pub use configuration::{
    AgentDescription, AgentDescriptions, ClaudeCodeConversationConfiguration,
    CodexConversationConfiguration, ConfigurationError, ConfigurationReceipt,
    ConfigureConversationRequest, ConversationConfiguration, ConversationConfigurationState,
    VendorConfigurationSnapshot,
};
pub use durable_transfer::{
    DurableStreamObjectId, DurableStreamTransferIdentity, DurableStreamTransferIdentityError,
    DurableStreamTransferSource, MAX_DURABLE_CATALOG_REVISIONS,
};
pub use envelope::{
    MAX_RUNTIME_JSON_FRAME_BYTES, MAX_RUNTIME_REQUEST_BYTES, MachineRemoteFailureCode,
    MachineRemoteLifecycle, MachineRemoteStatus, MachineRemoteStatusError, MachineRootFingerprint,
    PairInvite, PendingPairing, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeSizeError,
    RuntimeStreamItem, ensure_request_within_limit,
};
pub use event::{RuntimeEvent, RuntimeEventBody, RuntimeEventError};
pub use failure::RuntimeFailure;
pub use identity::{ConversationId, IdempotencyKey};
pub use metadata::{
    ConversationMetadataMutation, ConversationMetadataMutationRequest, ConversationMetadataReceipt,
    MetadataError,
};
pub use receipt::{
    ApprovalDeliveryState, ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatus,
    CommandStatusReceipt, ConversationStartReceipt, PairingDecision, PairingReceipt, PairingState,
    RevocationReceipt,
};
pub use schema::runtime_schema;
pub use sync::{
    BackfillChunk, BackfillError, BackfillRange, BackfillRequest, ConversationSnapshot,
    RuntimeInnerCursor, RuntimeSubscriptionTarget, RuntimeSyncComplete, SnapshotError,
    SnapshotItem, StreamCursor, StreamCursorError, SubscriptionReceipt,
};
pub use transfer::{
    MAX_ACTIVE_TRANSFERS, MAX_COMPLETED_TRANSFER_TOMBSTONES, MAX_JSON_PART_BYTES,
    MAX_JSON_TRANSFER_PARTS, MAX_PART_BYTES, MAX_REASSEMBLY_BYTES, MAX_TRANSFER_BYTES,
    MAX_TRANSFER_CARRIER_BYTES, MAX_TRANSFER_PARTS, RuntimeTransferCarrierError,
    RuntimeTransferCarrierV1, RuntimeTransferChannel, TRANSFER_TTL_MS, TransferEnvelope,
    TransferError, TransferProgress, TransferReassembler,
};
pub use upgrade::{ArtifactSha256, StageUpgradeReceipt, StageUpgradeRequest, UpgradeContractError};
