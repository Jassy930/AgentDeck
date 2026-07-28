import AgentDeckCore
import AgentDeckSessionSource
import Foundation

/// `MachineConnection` 向 source 暴露的唯一入站观察 seam。
/// raw Relay frame、`RuntimeEnvelopeV2` 与未验签 sealed blob 均不得进入此协议。
protocol MachineConnectionUpdateSource: Sendable {
  func updates() async -> AsyncStream<MachineConnectionUpdate>
  /// claim update stream 后的 exact actor readback；用于消除 owner 已经 ready、consumer
  /// 尚未开始迭代之间的启动窗口。readyScope 只能为 nil 或等于 connectionScope。
  func readinessSnapshot() async -> MachineConnectionReadinessSnapshot
  func commit(_ delivery: VerifiedRuntimeDelivery) async throws
  func discard(_ delivery: VerifiedRuntimeDelivery) async
  func shutdown() async
}

struct MachineConnectionReadinessSnapshot: Equatable, Sendable {
  let connectionScope: TransferAssemblyScope?
  let readyScope: TransferAssemblyScope?
}

enum MachineConnectionUpdate: Sendable {
  case connectionState(SessionConnectionState)
  /// 当前已认证的 physical connection + transport generation。Source 只能把同一
  /// exact scope 的 `businessReady` 当作业务订阅许可；reconnect 会先清空该 scope。
  case connectionScope(TransferAssemblyScope?)
  /// resume/control ACK 已全部真实写入 transport 后的一次性业务就绪边界。
  case businessReady(TransferAssemblyScope)
  case delivery(VerifiedRuntimeDelivery)
  case streamRecoveryRequired(target: VerifiedRuntimeTarget, reason: SessionLagReason)
}

/// outer/request correlation 已由 connection 验证后的 source 路由目标。
enum VerifiedRuntimeTarget: Sendable {
  case catalog(subscriptionRequestID: RuntimeMessageID)
  case conversation(
    conversationID: RuntimeConversationID,
    subscriptionRequestID: RuntimeMessageID
  )
  case request(RuntimeMessageID)
  case pairing
}

/// 已完成 outer bounds/domain/trust/serial/revision、MachineDataSign、replay、
/// AEAD 与 Runtime decode 的值。Source/reducer 只能消费此类型。
struct VerifiedRuntimeDelivery: Sendable {
  let machineID: String
  let target: VerifiedRuntimeTarget
  let streamGeneration: RuntimeStreamGeneration
  let outerCursor: RuntimeStreamCursorV1
  let payload: VerifiedRuntimePayload
  let ingressPermit: MachineVerifiedDeliveryPermit?

  /// 只供 module-internal fixture 注入已经独立建立可信基线、且不拥有 durable ingress
  /// candidate 的 delivery。production verified ingress 必须使用带 permit 的 initializer。
  init(
    fixtureMachineID machineID: String,
    target: VerifiedRuntimeTarget,
    streamGeneration: RuntimeStreamGeneration,
    outerCursor: RuntimeStreamCursorV1,
    payload: VerifiedRuntimePayload
  ) {
    self.machineID = machineID
    self.target = target
    self.streamGeneration = streamGeneration
    self.outerCursor = outerCursor
    self.payload = payload
    ingressPermit = nil
  }

  init(
    machineID: String,
    target: VerifiedRuntimeTarget,
    streamGeneration: RuntimeStreamGeneration,
    outerCursor: RuntimeStreamCursorV1,
    payload: VerifiedRuntimePayload,
    ingressPermit: MachineVerifiedDeliveryPermit
  ) {
    self.machineID = machineID
    self.target = target
    self.streamGeneration = streamGeneration
    self.outerCursor = outerCursor
    self.payload = payload
    self.ingressPermit = ingressPermit
  }
}

struct MachineVerifiedDeliveryPermit: Hashable, Sendable {
  fileprivate let rawValue: UUID

  init() {
    rawValue = UUID()
  }
}

/// Verified Runtime ingress 的穷举 payload。Snapshot/Backfill 与 barrier 保留为
/// 独立 case，避免 Source 从通用 reply 中猜测 bootstrap 顺序。
enum VerifiedRuntimePayload: Sendable {
  case catalogSnapshot(RuntimeCatalogSnapshotV2)
  case catalogBackfill(RuntimeBackfillChunkV2)
  case catalogDelta(RuntimeCatalogDeltaV2)
  case conversationSnapshot(ConversationSnapshotV2)
  case conversationBackfill(RuntimeBackfillChunkV2)
  case conversationEvent(RuntimeEventV2)
  case commandState(CommandStatusReceiptV2)
  case syncComplete(RuntimeSyncCompleteV1)
  case typedReply(RuntimeReplyV2)
}
