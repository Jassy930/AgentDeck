import AgentDeckCore
import Foundation

enum MachineRequestCorrelationError: Error, Equatable, Sendable {
  case invalidRoute
  case invalidMessageID
  case invalidGrantSerial
  case invalidConfigurationRevision
  case invalidApprovalID
  case capacityExceeded
  case routeCollision
  case messageIDCollision
  case unknownRoute
  case messageIDMismatch
  case unexpectedReply
  case invalidSubscriptionOrder
  case subscriptionMismatch
  case preparedMutationPending
  case generationEnded
}

enum MachineDirectedReplyContract: Equatable, Sendable {
  case command(expectedConfigurationRevision: UInt64)
  case approval(expectedApprovalID: RuntimeApprovalID, isRetry: Bool)
  case revocation(expectedGrantSerial: UInt64)
  case unsubscribe
}

enum MachineRequestCorrelationDisposition: Sendable {
  case active(MachineCorrelatedRuntimeReply)
  case superseded
}

enum MachinePreparedCorrelationDisposition: Sendable {
  case active(MachinePreparedRequestCorrelation)
  case superseded
}

enum MachinePreparedStreamBindingDisposition: Sendable {
  case active(MachinePreparedStreamBindingCorrelation)
  case superseded
}

enum MachineStreamBindingCorrelationDisposition: Sendable {
  case active(MachineCorrelatedStreamBinding)
  case superseded
}

/// Runtime reply 已完成 correlation 校验、但尚未推进 request/subscription owner 的
/// opaque mutation permit。production ingress 只有在 durable delivery commit 后才可
/// `commitPreparedCorrelation`；discard 只销毁本 permit，owner 状态保持不变。
struct MachinePreparedRequestCorrelation: Sendable {
  fileprivate let token: UUID
  let correlated: MachineCorrelatedRuntimeReply
}

/// signed StreamBinding 已完成 request/sync-cut 校验、但尚未取得 durable install
/// readback 的 opaque permit。production ingress 必须按
/// `prepare -> durable install -> commit` 顺序消费；discard 不推进 owner。
struct MachinePreparedStreamBindingCorrelation: Sendable {
  fileprivate let token: UUID
  let correlated: MachineCorrelatedStreamBinding
}

/// control request 对业务 requestRoute 命名空间的 generation-scoped 原子占用。
/// opaque token 防止迟到 release 误删同 route 的后继 claim。
struct MachineControlRequestRouteClaim: Hashable, Sendable {
  fileprivate let token: UUID
  let requestRoute: Data
}

enum MachineRouteAcceptanceDisposition: Sendable {
  case accepted(VerifiedRuntimeTarget)
  case superseded
}

enum MachineStreamCorrelationDisposition: Sendable {
  case active(MachineCorrelatedRuntimeStream)
  case superseded
}

enum MachineStreamControlDisposition: Sendable {
  case active(VerifiedRuntimeTarget)
  case superseded
}

struct MachineCorrelatedRuntimeReply: Sendable {
  let target: VerifiedRuntimeTarget
  let reply: RuntimeReplyV2
  let streamGeneration: RuntimeStreamGeneration?
  let outerStreamBinding: MachineOuterStreamBinding?
  let completesRequest: Bool
}

struct MachineCorrelatedRuntimeStream: Sendable {
  let target: VerifiedRuntimeTarget
  let streamGeneration: RuntimeStreamGeneration
  let outerCursor: RuntimeStreamCursorV1
  let item: RuntimeStreamItemV2
}

struct MachineCorrelatedStreamBinding: Sendable {
  let target: VerifiedRuntimeTarget
  let streamGeneration: RuntimeStreamGeneration
  let binding: MachineOuterStreamBinding
  let bindingCursor: StreamCursor
  let synchronizedOuterCursor: RuntimeStreamCursorV1
  let synchronizedInnerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
  let retiredBinding: MachineOuterStreamBinding?
}

struct MachineOuterStreamBinding: Hashable, Sendable {
  let streamRoute: Data
  let streamGeneration: Data
}

struct MachineDrainedRequestOwner: Sendable {
  let requestRoute: Data
  let messageID: RuntimeMessageID
  let target: VerifiedRuntimeTarget
}

struct MachineDrainedStreamOwner: Sendable {
  let binding: MachineOuterStreamBinding
  let target: VerifiedRuntimeTarget
}

struct MachineRequestCorrelationDrain: Sendable {
  let requests: [MachineDrainedRequestOwner]
  let streams: [MachineDrainedStreamOwner]

  static let empty = MachineRequestCorrelationDrain(requests: [], streams: [])
}

struct MachineUnregisteredSubscription: Sendable {
  let requestRoutes: [Data]
  let outerBinding: MachineOuterStreamBinding?
  let requiresGenerationRollover: Bool

  static let empty = MachineUnregisteredSubscription(
    requestRoutes: [],
    outerBinding: nil,
    requiresGenerationRollover: false
  )
}

/// 单个 authenticated generation 的 requestRoute/messageId owner。
///
/// Relay 的 `RouteAccepted` 只确认 writer admission；只有通过 MachineDataSign、replay、
/// AEAD 与 Runtime decode 的 Reply 才能进入这里。subscription replacement 会留下有界
/// tombstone，使已经在途的旧 reply 被安全忽略，而不是误归属给新请求或击穿连接。
actor MachineRequestCorrelationOwner {
  static let maximumPendingRoutes = 512
  static let maximumSupersededRoutes = 512
  static let maximumTrackedStreamBindings = 512
  static let maximumControlRouteClaims = 512

  private enum SubscriptionSlot: Hashable, Sendable {
    case catalog
    case conversation(RuntimeConversationID)
  }

  private enum Contract: Equatable, Sendable {
    case directed(MachineDirectedReplyContract)
    case subscription(SubscriptionSlot)
  }

  private struct SubscriptionSyncCut: Equatable, Sendable {
    let streamGeneration: RuntimeStreamGeneration
    let streamCursor: RuntimeStreamCursorV1
    let innerCursor: RuntimeInnerCursorV1
    let keyDirectoryRevision: UInt64
  }

  private struct ActiveStream: Sendable {
    let slot: SubscriptionSlot
    let binding: MachineOuterStreamBinding
    let requestRoute: Data
    let messageID: RuntimeMessageID
    let target: VerifiedRuntimeTarget
    let runtimeGeneration: RuntimeStreamGeneration
  }

  private struct Pending: Sendable {
    let requestRoute: Data
    let messageID: RuntimeMessageID
    let target: VerifiedRuntimeTarget
    let contract: Contract
    var routeAccepted = false
    var streamGeneration: RuntimeStreamGeneration?
    var syncCut: SubscriptionSyncCut?
  }

  private struct PreparedMutation: Sendable {
    let expected: Pending
    let replacement: Pending?
    let correlated: MachineCorrelatedRuntimeReply
  }

  private struct PreparedSubscriptionReply: Sendable {
    let replacement: Pending?
    let correlatedStreamGeneration: RuntimeStreamGeneration?
    let completesRequest: Bool
  }

  private struct PreparedStreamBindingMutation: Sendable {
    let expected: Pending
    let activeStream: ActiveStream
    let retiredBinding: MachineOuterStreamBinding?
    let replacesSameBinding: Bool
    let correlated: MachineCorrelatedStreamBinding
  }

  private var pendingByRoute: [Data: Pending] = [:]
  private var routeByMessageID: [RuntimeMessageID: Data] = [:]
  private var routeBySubscription: [SubscriptionSlot: Data] = [:]
  private var streamByBinding: [MachineOuterStreamBinding: ActiveStream] = [:]
  private var streamBindingBySubscription: [SubscriptionSlot: MachineOuterStreamBinding] = [:]
  private var supersededRoutes: Set<Data> = []
  private var supersededStreamBindings: Set<MachineOuterStreamBinding> = []
  private var preparedByToken: [UUID: PreparedMutation] = [:]
  private var preparedTokenByRoute: [Data: UUID] = [:]
  private var preparedStreamBindingByToken: [UUID: PreparedStreamBindingMutation] = [:]
  private var preparedStreamBindingTokenByRoute: [Data: UUID] = [:]
  private var controlRouteClaimByToken: [UUID: Data] = [:]
  private var controlRouteClaimTokenByRoute: [Data: UUID] = [:]
  private var ended = false

  var pendingCount: Int { pendingByRoute.count }
  var supersededCount: Int { supersededRoutes.count }
  var activeStreamCount: Int { streamByBinding.count }
  var supersededStreamBindingCount: Int { supersededStreamBindings.count }
  var controlRouteClaimCount: Int { controlRouteClaimByToken.count }
  var isEnded: Bool { ended }

  /// 为 control request 原子占用一个尚未被业务 pending/tombstone 使用的 route。
  /// claim 与业务 registry 同属本 actor，因此不存在 availability-check 后被抢占的窗口。
  func claimControlRequestRoute(
    _ requestRoute: Data
  ) throws -> MachineControlRequestRouteClaim {
    try ensureActiveGeneration()
    try Self.validate(requestRoute: requestRoute)
    guard pendingByRoute[requestRoute] == nil,
      !supersededRoutes.contains(requestRoute),
      controlRouteClaimTokenByRoute[requestRoute] == nil
    else {
      throw MachineRequestCorrelationError.routeCollision
    }
    guard controlRouteClaimByToken.count < Self.maximumControlRouteClaims else {
      throw MachineRequestCorrelationError.capacityExceeded
    }
    let token = UUID()
    controlRouteClaimByToken[token] = requestRoute
    controlRouteClaimTokenByRoute[requestRoute] = token
    return MachineControlRequestRouteClaim(token: token, requestRoute: requestRoute)
  }

  /// token-specific、幂等 release；generation teardown 后的迟到 release 也是安全 no-op。
  func releaseControlRequestRoute(
    _ claim: MachineControlRequestRouteClaim
  ) {
    guard controlRouteClaimByToken[claim.token] == claim.requestRoute,
      controlRouteClaimTokenByRoute[claim.requestRoute] == claim.token
    else {
      return
    }
    controlRouteClaimByToken.removeValue(forKey: claim.token)
    controlRouteClaimTokenByRoute.removeValue(forKey: claim.requestRoute)
  }

  func registerDirectedRequest(
    requestRoute: Data,
    messageID: RuntimeMessageID,
    contract: MachineDirectedReplyContract
  ) throws {
    try ensureActiveGeneration()
    switch contract {
    case .command(let expectedConfigurationRevision):
      guard expectedConfigurationRevision > 0 else {
        throw MachineRequestCorrelationError.invalidConfigurationRevision
      }
    case .approval(let expectedApprovalID, _):
      guard !expectedApprovalID.rawValue.isEmpty,
        expectedApprovalID.rawValue.utf8.count <= 8 * 1_024
      else {
        throw MachineRequestCorrelationError.invalidApprovalID
      }
    case .revocation(let expectedGrantSerial):
      guard expectedGrantSerial > 0 else {
        throw MachineRequestCorrelationError.invalidGrantSerial
      }
    case .unsubscribe:
      break
    }
    try register(
      Pending(
        requestRoute: requestRoute,
        messageID: messageID,
        target: .request(messageID),
        contract: .directed(contract)
      ),
      replacing: nil
    )
  }

  /// 注册尚未知晓 daemon StreamBinding 的 subscription request。真实 outer binding
  /// 只能在 signed StreamBinding 通过 durable install 后由 prepared permit 提升为 live；
  /// 禁止为提前注册 Relay Subscribe 伪造 placeholder route/generation。
  ///
  /// 返回被替换的 pending requestRoute；调用方可据此取消旧 bootstrap waiter，但不
  /// 复用旧 route。已有 live stream 会保留到 replacement binding durable commit。
  @discardableResult
  func registerPendingSubscription(
    requestRoute: Data,
    messageID: RuntimeMessageID,
    target: RuntimeSubscriptionTargetV1
  ) throws -> Data? {
    try ensureActiveGeneration()
    let slot: SubscriptionSlot
    let verifiedTarget: VerifiedRuntimeTarget
    switch target {
    case .catalog:
      slot = .catalog
      verifiedTarget = .catalog(subscriptionRequestID: messageID)
    case .conversation(let conversationID):
      slot = .conversation(conversationID)
      verifiedTarget = .conversation(
        conversationID: conversationID,
        subscriptionRequestID: messageID
      )
    }
    let replaced = routeBySubscription[slot]
    if let replaced,
      preparedTokenByRoute[replaced] != nil
        || preparedStreamBindingTokenByRoute[replaced] != nil
    {
      throw MachineRequestCorrelationError.preparedMutationPending
    }
    try register(
      Pending(
        requestRoute: requestRoute,
        messageID: messageID,
        target: verifiedTarget,
        contract: .subscription(slot)
      ),
      replacing: replaced
    )
    routeBySubscription[slot] = requestRoute
    return replaced
  }

  func acceptRoute(_ requestRoute: Data) throws -> MachineRouteAcceptanceDisposition {
    try ensureActiveGeneration()
    if supersededRoutes.contains(requestRoute) {
      return .superseded
    }
    guard var pending = pendingByRoute[requestRoute] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    pending.routeAccepted = true
    pendingByRoute[requestRoute] = pending
    return .accepted(pending.target)
  }

  func correlate(
    requestRoute: Data,
    envelope: RuntimeEnvelopeV2
  ) throws -> MachineRequestCorrelationDisposition {
    switch try prepareCorrelation(requestRoute: requestRoute, envelope: envelope) {
    case .superseded:
      return .superseded
    case .active(let prepared):
      return try commitPreparedCorrelation(prepared)
    }
  }

  func prepareCorrelation(
    requestRoute: Data,
    envelope: RuntimeEnvelopeV2
  ) throws -> MachinePreparedCorrelationDisposition {
    try ensureActiveGeneration()
    if supersededRoutes.contains(requestRoute) {
      return .superseded
    }
    guard preparedTokenByRoute[requestRoute] == nil else {
      throw MachineRequestCorrelationError.preparedMutationPending
    }
    guard let pending = pendingByRoute[requestRoute] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    guard envelope.messageID == pending.messageID else {
      throw MachineRequestCorrelationError.messageIDMismatch
    }
    guard case .reply(let reply) = envelope.body else {
      throw MachineRequestCorrelationError.unexpectedReply
    }

    let replacement: Pending?
    let correlatedStreamGeneration: RuntimeStreamGeneration?
    let completesRequest: Bool
    switch pending.contract {
    case .directed(let expected):
      guard Self.reply(reply, satisfies: expected) else {
        throw MachineRequestCorrelationError.unexpectedReply
      }
      replacement = nil
      correlatedStreamGeneration = pending.streamGeneration
      completesRequest = true

    case .subscription(let slot):
      let prepared = try prepareSubscriptionReply(
        reply,
        slot: slot,
        pending: pending
      )
      replacement = prepared.replacement
      correlatedStreamGeneration = prepared.correlatedStreamGeneration
      completesRequest = prepared.completesRequest
    }

    let correlated = MachineCorrelatedRuntimeReply(
      target: pending.target,
      reply: reply,
      streamGeneration: correlatedStreamGeneration,
      outerStreamBinding: nil,
      completesRequest: completesRequest
    )
    if completesRequest {
      try ensureTombstoneCapacity(for: requestRoute)
    }
    let token = UUID()
    guard preparedByToken.count < Self.maximumPendingRoutes else {
      throw MachineRequestCorrelationError.capacityExceeded
    }
    preparedByToken[token] = PreparedMutation(
      expected: pending,
      replacement: replacement,
      correlated: correlated
    )
    preparedTokenByRoute[requestRoute] = token
    return .active(
      MachinePreparedRequestCorrelation(token: token, correlated: correlated)
    )
  }

  func commitPreparedCorrelation(
    _ prepared: MachinePreparedRequestCorrelation
  ) throws -> MachineRequestCorrelationDisposition {
    try ensureActiveGeneration()
    guard let mutation = removePreparedMutation(prepared.token) else {
      throw MachineRequestCorrelationError.invalidSubscriptionOrder
    }
    let requestRoute = mutation.expected.requestRoute
    if supersededRoutes.contains(requestRoute) {
      return .superseded
    }
    guard let current = pendingByRoute[requestRoute] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    guard Self.sameCorrelationIdentity(current, mutation.expected) else {
      throw MachineRequestCorrelationError.subscriptionMismatch
    }

    if let replacement = mutation.replacement {
      pendingByRoute[requestRoute] = replacement
    } else {
      try ensureTombstoneCapacity(for: requestRoute)
      removePending(current)
      supersededRoutes.insert(requestRoute)
    }
    return .active(mutation.correlated)
  }

  func discardPreparedCorrelation(
    _ prepared: MachinePreparedRequestCorrelation
  ) {
    _ = removePreparedMutation(prepared.token)
  }

  /// verified StreamBinding 的纯 owner preflight。这里校验 request、Runtime
  /// SyncComplete cut、canonical UUID generation 与 durable binding 的 monotonic 对应，并
  /// 预留 request/stream tombstone 容量；调用方只有拿到 permit 后才可写 durable state。
  func prepareStreamBinding(
    requestRoute: Data,
    binding durableBinding: DeviceDurableStreamBindingV1
  ) throws -> MachinePreparedStreamBindingDisposition {
    try ensureActiveGeneration()
    if supersededRoutes.contains(requestRoute) {
      return .superseded
    }
    guard preparedTokenByRoute[requestRoute] == nil,
      preparedStreamBindingTokenByRoute[requestRoute] == nil
    else {
      throw MachineRequestCorrelationError.preparedMutationPending
    }
    guard let pending = pendingByRoute[requestRoute],
      case .subscription(let slot) = pending.contract,
      let runtimeGeneration = pending.streamGeneration,
      let syncCut = pending.syncCut
    else {
      throw MachineRequestCorrelationError.invalidSubscriptionOrder
    }
    let binding = try Self.validateStreamBinding(
      streamRoute: durableBinding.streamRoute,
      generation: durableBinding.streamGeneration
    )
    guard
      Self.streamBinding(
        durableBinding,
        matches: slot,
        runtimeGeneration: runtimeGeneration,
        syncCut: syncCut
      )
    else {
      throw MachineRequestCorrelationError.subscriptionMismatch
    }
    guard !supersededStreamBindings.contains(binding) else {
      throw MachineRequestCorrelationError.routeCollision
    }

    let replacesSameBinding: Bool
    if let existing = streamByBinding[binding] {
      guard existing.slot == slot,
        streamBindingBySubscription[slot] == binding
      else {
        throw MachineRequestCorrelationError.routeCollision
      }
      replacesSameBinding = true
    } else {
      replacesSameBinding = false
    }

    let retiredBinding: MachineOuterStreamBinding?
    if let currentBinding = streamBindingBySubscription[slot] {
      if currentBinding == binding {
        retiredBinding = nil
      } else {
        guard let retired = streamByBinding[currentBinding], retired.slot == slot else {
          throw MachineRequestCorrelationError.subscriptionMismatch
        }
        retiredBinding = currentBinding
      }
    } else {
      retiredBinding = nil
    }
    try ensureTombstoneCapacity(for: requestRoute)
    let reservedNewBindings = preparedStreamBindingByToken.values.filter {
      !$0.replacesSameBinding
    }.count
    let additionalBinding = replacesSameBinding ? 0 : 1
    let tracked =
      streamByBinding.count + supersededStreamBindings.count
      + reservedNewBindings + additionalBinding
    guard
      tracked <= Self.maximumTrackedStreamBindings
    else {
      throw MachineRequestCorrelationError.capacityExceeded
    }

    let active = ActiveStream(
      slot: slot,
      binding: binding,
      requestRoute: requestRoute,
      messageID: pending.messageID,
      target: pending.target,
      runtimeGeneration: runtimeGeneration
    )
    let correlated = MachineCorrelatedStreamBinding(
      target: pending.target,
      streamGeneration: runtimeGeneration,
      binding: binding,
      bindingCursor: durableBinding.streamCursor,
      synchronizedOuterCursor: syncCut.streamCursor,
      synchronizedInnerCursor: syncCut.innerCursor,
      keyDirectoryRevision: syncCut.keyDirectoryRevision,
      retiredBinding: retiredBinding
    )
    let token = UUID()
    preparedStreamBindingByToken[token] = PreparedStreamBindingMutation(
      expected: pending,
      activeStream: active,
      retiredBinding: retiredBinding,
      replacesSameBinding: replacesSameBinding,
      correlated: correlated
    )
    preparedStreamBindingTokenByRoute[requestRoute] = token
    return .active(
      MachinePreparedStreamBindingCorrelation(token: token, correlated: correlated)
    )
  }

  /// durable StreamBinding exact readback 后的 non-await owner swap。所有可失败的
  /// shape/capacity 检查都已在 prepare 阶段完成；若 request 已被 generation teardown
  /// supersede，只返回 `.superseded`，绝不把旧 binding 归属给新 request。
  func commitPreparedStreamBinding(
    _ prepared: MachinePreparedStreamBindingCorrelation
  ) throws -> MachineStreamBindingCorrelationDisposition {
    try ensureActiveGeneration()
    guard let mutation = removePreparedStreamBindingMutation(prepared.token) else {
      throw MachineRequestCorrelationError.invalidSubscriptionOrder
    }
    let requestRoute = mutation.expected.requestRoute
    if supersededRoutes.contains(requestRoute) {
      return .superseded
    }
    guard let current = pendingByRoute[requestRoute],
      Self.sameCorrelationIdentity(current, mutation.expected),
      !supersededStreamBindings.contains(mutation.activeStream.binding)
    else {
      throw MachineRequestCorrelationError.subscriptionMismatch
    }
    if mutation.replacesSameBinding {
      guard
        let existing = streamByBinding[mutation.activeStream.binding],
        existing.slot == mutation.activeStream.slot,
        streamBindingBySubscription[existing.slot] == mutation.activeStream.binding
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
    } else {
      guard streamByBinding[mutation.activeStream.binding] == nil else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
    }
    if let retiredBinding = mutation.retiredBinding {
      guard let retired = streamByBinding[retiredBinding],
        retired.slot == mutation.activeStream.slot,
        streamBindingBySubscription[retired.slot] == retiredBinding
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      retireStream(slot: retired.slot, binding: retiredBinding)
    }
    streamByBinding[mutation.activeStream.binding] = mutation.activeStream
    streamBindingBySubscription[mutation.activeStream.slot] = mutation.activeStream.binding
    removePending(current)
    supersededRoutes.insert(requestRoute)
    return .active(mutation.correlated)
  }

  func discardPreparedStreamBinding(
    _ prepared: MachinePreparedStreamBindingCorrelation
  ) {
    _ = removePreparedStreamBindingMutation(prepared.token)
  }

  func correlateStream(
    streamRoute: Data,
    relayGeneration: Data,
    streamSeq: UInt64,
    envelope: RuntimeEnvelopeV2
  ) throws -> MachineStreamCorrelationDisposition {
    try ensureActiveGeneration()
    let binding = try Self.validateStreamBinding(
      streamRoute: streamRoute,
      generation: relayGeneration
    )
    if supersededStreamBindings.contains(binding) {
      return .superseded
    }
    guard let stream = streamByBinding[binding] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    guard case .stream(let item) = envelope.body,
      Self.streamItem(item, matches: stream.slot)
    else {
      throw MachineRequestCorrelationError.unexpectedReply
    }
    return .active(
      MachineCorrelatedRuntimeStream(
        target: stream.target,
        streamGeneration: stream.runtimeGeneration,
        outerCursor: .at(streamSeq),
        item: item
      )
    )
  }

  /// Gap/ReplayComplete 等 relay-visible stream control 也必须命中 exact live binding；
  /// superseded binding 只能被忽略，未知 binding 不能伪造成 reconnect/resume 信号。
  func correlateStreamControl(
    streamRoute: Data,
    relayGeneration: Data
  ) throws -> MachineStreamControlDisposition {
    try ensureActiveGeneration()
    let binding = try Self.validateStreamBinding(
      streamRoute: streamRoute,
      generation: relayGeneration
    )
    if supersededStreamBindings.contains(binding) {
      return .superseded
    }
    guard let stream = streamByBinding[binding] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    return .active(stream.target)
  }

  /// send failure/timeout 的 exact request teardown。route 立即转为 tombstone，迟到
  /// RouteAccepted/Reply 只能得到 superseded，不能击中后续 fresh request owner。
  @discardableResult
  func unregisterDirectedRequest(
    requestRoute: Data
  ) throws -> MachineDrainedRequestOwner? {
    try ensureActiveGeneration()
    if supersededRoutes.contains(requestRoute) {
      return nil
    }
    guard let pending = pendingByRoute[requestRoute] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    guard case .directed = pending.contract else {
      throw MachineRequestCorrelationError.capacityExceeded
    }
    try ensureTombstoneCapacity(for: requestRoute)
    removePending(pending)
    supersededRoutes.insert(requestRoute)
    return MachineDrainedRequestOwner(
      requestRoute: pending.requestRoute,
      messageID: pending.messageID,
      target: pending.target
    )
  }

  /// subscription request 在 StreamBinding durable 前的 exact teardown。已有 live
  /// replacement stream 不受影响；仅 pending requestRoute 进入 tombstone。
  @discardableResult
  func unregisterPendingSubscription(
    requestRoute: Data
  ) throws -> MachineDrainedRequestOwner? {
    try ensureActiveGeneration()
    if supersededRoutes.contains(requestRoute) {
      return nil
    }
    guard preparedTokenByRoute[requestRoute] == nil,
      preparedStreamBindingTokenByRoute[requestRoute] == nil
    else {
      throw MachineRequestCorrelationError.preparedMutationPending
    }
    guard let pending = pendingByRoute[requestRoute],
      case .subscription = pending.contract
    else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    try ensureTombstoneCapacity(for: requestRoute)
    removePending(pending)
    supersededRoutes.insert(requestRoute)
    return MachineDrainedRequestOwner(
      requestRoute: pending.requestRoute,
      messageID: pending.messageID,
      target: pending.target
    )
  }

  /// 显式注销 exact live/pending subscription，并把 request/stream binding 都转成
  /// generation-scoped tombstone；迟到 frame 只能得到 `.superseded`。
  @discardableResult
  func unregisterSubscription(
    streamRoute: Data,
    relayGeneration: Data
  ) throws -> Data? {
    try ensureActiveGeneration()
    let binding = try Self.validateStreamBinding(
      streamRoute: streamRoute,
      generation: relayGeneration
    )
    if supersededStreamBindings.contains(binding) {
      return nil
    }
    guard let stream = streamByBinding[binding] else {
      throw MachineRequestCorrelationError.unknownRoute
    }
    let requestRoute = stream.requestRoute
    try ensureTombstoneCapacity(for: requestRoute)
    if let pending = pendingByRoute[requestRoute] {
      removePending(pending)
    }
    supersededRoutes.insert(requestRoute)
    retireStream(slot: stream.slot, binding: binding)
    return requestRoute
  }

  /// Runtime `Unsubscribed` 已确认后的 target-scoped owner cut。pending replacement
  /// 与 live binding 必须在同一 actor turn 一并退休，避免只关一侧后让迟到 reply
  /// 重新安装 physical binding。达到 no-evict tombstone 上界时通知 connection 在
  /// outer Unsubscribe flush 后轮换 exact transport generation。
  func unregisterSubscription(
    target: RuntimeSubscriptionTargetV1
  ) throws -> MachineUnregisteredSubscription {
    try ensureActiveGeneration()
    let slot: SubscriptionSlot
    switch target {
    case .catalog:
      slot = .catalog
    case .conversation(let conversationID):
      slot = .conversation(conversationID)
    }

    let pendingRoute = routeBySubscription[slot]
    let outerBinding = streamBindingBySubscription[slot]
    guard pendingRoute != nil || outerBinding != nil else { return .empty }

    if let pendingRoute {
      guard preparedTokenByRoute[pendingRoute] == nil,
        preparedStreamBindingTokenByRoute[pendingRoute] == nil,
        let pending = pendingByRoute[pendingRoute],
        case .subscription(let pendingSlot) = pending.contract,
        pendingSlot == slot
      else {
        throw MachineRequestCorrelationError.preparedMutationPending
      }
      try ensureTombstoneCapacity(for: pendingRoute)
    }
    let activeStream: ActiveStream?
    if let outerBinding {
      guard let active = streamByBinding[outerBinding], active.slot == slot else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      try ensureTombstoneCapacity(for: active.requestRoute)
      activeStream = active
    } else {
      activeStream = nil
    }

    var retiredRoutes: [Data] = []
    if let pendingRoute, let pending = pendingByRoute[pendingRoute] {
      removePending(pending)
      supersededRoutes.insert(pendingRoute)
      retiredRoutes.append(pendingRoute)
    }
    if let outerBinding, let activeStream {
      supersededRoutes.insert(activeStream.requestRoute)
      retireStream(slot: slot, binding: outerBinding)
      if !retiredRoutes.contains(activeStream.requestRoute) {
        retiredRoutes.append(activeStream.requestRoute)
      }
    }
    retiredRoutes.sort { $0.lexicographicallyPrecedes($1) }
    return MachineUnregisteredSubscription(
      requestRoutes: retiredRoutes,
      outerBinding: outerBinding,
      requiresGenerationRollover:
        supersededRoutes.count == Self.maximumSupersededRoutes
        || supersededStreamBindings.count == Self.maximumTrackedStreamBindings
    )
  }

  /// teardown 是不可逆线性化点；返回 exact owner 清单供调用方终止 waiter/stream。
  @discardableResult
  func generationEnded() -> MachineRequestCorrelationDrain {
    guard !ended else { return .empty }
    ended = true
    let requests = pendingByRoute.values
      .map {
        MachineDrainedRequestOwner(
          requestRoute: $0.requestRoute,
          messageID: $0.messageID,
          target: $0.target
        )
      }
      .sorted { $0.requestRoute.lexicographicallyPrecedes($1.requestRoute) }
    let streams = streamByBinding.values
      .map { MachineDrainedStreamOwner(binding: $0.binding, target: $0.target) }
      .sorted {
        if $0.binding.streamRoute != $1.binding.streamRoute {
          return $0.binding.streamRoute.lexicographicallyPrecedes($1.binding.streamRoute)
        }
        return $0.binding.streamGeneration.lexicographicallyPrecedes(
          $1.binding.streamGeneration
        )
      }
    pendingByRoute.removeAll(keepingCapacity: false)
    routeByMessageID.removeAll(keepingCapacity: false)
    routeBySubscription.removeAll(keepingCapacity: false)
    streamByBinding.removeAll(keepingCapacity: false)
    streamBindingBySubscription.removeAll(keepingCapacity: false)
    supersededRoutes.removeAll(keepingCapacity: false)
    supersededStreamBindings.removeAll(keepingCapacity: false)
    preparedByToken.removeAll(keepingCapacity: false)
    preparedTokenByRoute.removeAll(keepingCapacity: false)
    preparedStreamBindingByToken.removeAll(keepingCapacity: false)
    preparedStreamBindingTokenByRoute.removeAll(keepingCapacity: false)
    controlRouteClaimByToken.removeAll(keepingCapacity: false)
    controlRouteClaimTokenByRoute.removeAll(keepingCapacity: false)
    return MachineRequestCorrelationDrain(requests: requests, streams: streams)
  }

  private func register(_ pending: Pending, replacing oldRoute: Data?) throws {
    try Self.validate(requestRoute: pending.requestRoute, messageID: pending.messageID)
    guard pendingByRoute[pending.requestRoute] == nil,
      !supersededRoutes.contains(pending.requestRoute),
      controlRouteClaimTokenByRoute[pending.requestRoute] == nil
    else {
      throw MachineRequestCorrelationError.routeCollision
    }
    guard routeByMessageID[pending.messageID] == nil else {
      throw MachineRequestCorrelationError.messageIDCollision
    }

    let growsPending = oldRoute == nil
    guard !growsPending || pendingByRoute.count < Self.maximumPendingRoutes else {
      throw MachineRequestCorrelationError.capacityExceeded
    }
    if let oldRoute {
      try ensureTombstoneCapacity(for: oldRoute)
      guard let old = pendingByRoute[oldRoute] else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      removePending(old)
      supersededRoutes.insert(oldRoute)
    }
    pendingByRoute[pending.requestRoute] = pending
    routeByMessageID[pending.messageID] = pending.requestRoute
  }

  private func prepareSubscriptionReply(
    _ reply: RuntimeReplyV2,
    slot: SubscriptionSlot,
    pending: Pending
  ) throws -> PreparedSubscriptionReply {
    switch reply {
    case .subscription(.subscribed(let generation)):
      guard pending.streamGeneration == nil,
        pending.syncCut == nil
      else {
        throw MachineRequestCorrelationError.invalidSubscriptionOrder
      }
      var replacement = pending
      replacement.streamGeneration = generation
      return PreparedSubscriptionReply(
        replacement: replacement,
        correlatedStreamGeneration: generation,
        completesRequest: false
      )

    case .catalog:
      guard case .catalog = slot,
        pending.streamGeneration != nil,
        pending.syncCut == nil
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      return retainedSubscriptionReply(pending)

    case .snapshot(let snapshot):
      guard case .conversation(let conversationID) = slot,
        snapshot.conversationID == conversationID,
        pending.streamGeneration != nil,
        pending.syncCut == nil
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      return retainedSubscriptionReply(pending)

    case .backfill(let chunk):
      guard pending.streamGeneration != nil,
        pending.syncCut == nil,
        Self.backfill(chunk, matches: slot)
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      return retainedSubscriptionReply(pending)

    case .syncComplete(let sync):
      guard pending.streamGeneration == sync.streamGeneration,
        pending.syncCut == nil,
        sync.keyDirectoryRevision > 0,
        Self.innerCursor(sync.innerCursor, matches: slot)
      else {
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
      var replacement = pending
      replacement.syncCut = SubscriptionSyncCut(
        streamGeneration: sync.streamGeneration,
        streamCursor: sync.streamCursor,
        innerCursor: sync.innerCursor,
        keyDirectoryRevision: sync.keyDirectoryRevision
      )
      return PreparedSubscriptionReply(
        replacement: replacement,
        correlatedStreamGeneration: pending.streamGeneration,
        completesRequest: false
      )

    case .transferPart:
      guard pending.streamGeneration != nil,
        pending.syncCut == nil
      else {
        throw MachineRequestCorrelationError.invalidSubscriptionOrder
      }
      return retainedSubscriptionReply(pending)

    case .failure:
      return PreparedSubscriptionReply(
        replacement: nil,
        correlatedStreamGeneration: pending.streamGeneration,
        completesRequest: true
      )

    case .subscription(.unsubscribed), .hello, .agents, .configuration,
      .conversationMetadata, .stageUpgrade, .command, .commandStatus,
      .conversationStart, .cancellation, .approval, .revocation, .pairInvite,
      .pendingPairings, .pairing, .machineRemoteStatus:
      throw MachineRequestCorrelationError.unexpectedReply
    }
  }

  private func retainedSubscriptionReply(
    _ pending: Pending
  ) -> PreparedSubscriptionReply {
    PreparedSubscriptionReply(
      replacement: pending,
      correlatedStreamGeneration: pending.streamGeneration,
      completesRequest: false
    )
  }

  private func removePreparedMutation(
    _ token: UUID
  ) -> PreparedMutation? {
    guard let mutation = preparedByToken.removeValue(forKey: token) else {
      return nil
    }
    if preparedTokenByRoute[mutation.expected.requestRoute] == token {
      preparedTokenByRoute.removeValue(forKey: mutation.expected.requestRoute)
    }
    return mutation
  }

  private func removePreparedStreamBindingMutation(
    _ token: UUID
  ) -> PreparedStreamBindingMutation? {
    guard let mutation = preparedStreamBindingByToken.removeValue(forKey: token) else {
      return nil
    }
    if preparedStreamBindingTokenByRoute[mutation.expected.requestRoute] == token {
      preparedStreamBindingTokenByRoute.removeValue(forKey: mutation.expected.requestRoute)
    }
    return mutation
  }

  private func ensureTombstoneCapacity(for requestRoute: Data) throws {
    if supersededRoutes.contains(requestRoute) { return }
    var reservedRoutes = Set(
      preparedByToken.values.compactMap { mutation in
        mutation.replacement == nil
          && !supersededRoutes.contains(mutation.expected.requestRoute)
          ? mutation.expected.requestRoute
          : nil
      }
    )
    reservedRoutes.formUnion(
      preparedStreamBindingByToken.values.map(\.expected.requestRoute)
    )
    if reservedRoutes.contains(requestRoute) { return }
    guard
      supersededRoutes.count + reservedRoutes.count
        < Self.maximumSupersededRoutes
    else {
      throw MachineRequestCorrelationError.capacityExceeded
    }
  }

  private func removePending(_ pending: Pending) {
    pendingByRoute.removeValue(forKey: pending.requestRoute)
    routeByMessageID.removeValue(forKey: pending.messageID)
    if case .subscription(let slot) = pending.contract,
      routeBySubscription[slot] == pending.requestRoute
    {
      routeBySubscription.removeValue(forKey: slot)
    }
  }

  private func retireStream(
    slot: SubscriptionSlot,
    binding: MachineOuterStreamBinding
  ) {
    streamByBinding.removeValue(forKey: binding)
    if streamBindingBySubscription[slot] == binding {
      streamBindingBySubscription.removeValue(forKey: slot)
    }
    supersededStreamBindings.insert(binding)
  }

  private func ensureActiveGeneration() throws {
    guard !ended else {
      throw MachineRequestCorrelationError.generationEnded
    }
  }

  private static func sameCorrelationIdentity(
    _ lhs: Pending,
    _ rhs: Pending
  ) -> Bool {
    lhs.requestRoute == rhs.requestRoute
      && lhs.messageID == rhs.messageID
      && lhs.target.matches(rhs.target)
      && lhs.contract == rhs.contract
      && lhs.streamGeneration == rhs.streamGeneration
      && lhs.syncCut == rhs.syncCut
  }

  private static func validate(
    requestRoute: Data,
    messageID: RuntimeMessageID
  ) throws {
    try validate(requestRoute: requestRoute)
    guard !messageID.rawValue.isEmpty,
      messageID.rawValue.utf8.count <= RuntimeMessageIDKind.maximumWireUTF8Bytes!
    else {
      throw MachineRequestCorrelationError.invalidMessageID
    }
  }

  private static func validate(requestRoute: Data) throws {
    guard requestRoute.count == 16,
      requestRoute.contains(where: { $0 != 0 })
    else {
      throw MachineRequestCorrelationError.invalidRoute
    }
  }

  private static func validateStreamBinding(
    streamRoute: Data,
    generation: Data
  ) throws -> MachineOuterStreamBinding {
    guard streamRoute.count == 16,
      streamRoute.contains(where: { $0 != 0 }),
      generation.count == 16,
      generation.contains(where: { $0 != 0 })
    else {
      throw MachineRequestCorrelationError.invalidRoute
    }
    return MachineOuterStreamBinding(
      streamRoute: streamRoute,
      streamGeneration: generation
    )
  }

  private static func streamBinding(
    _ binding: DeviceDurableStreamBindingV1,
    matches slot: SubscriptionSlot,
    runtimeGeneration: RuntimeStreamGeneration,
    syncCut: SubscriptionSyncCut
  ) -> Bool {
    guard canonicalUUIDBytes(runtimeGeneration) == binding.streamGeneration,
      syncCut.streamGeneration == runtimeGeneration,
      runtimeCursor(binding.streamCursor) == syncCut.streamCursor,
      binding.keyDirectoryRevision == syncCut.keyDirectoryRevision
    else {
      return false
    }
    switch (slot, binding.innerCursor, syncCut.innerCursor, binding.keyID.purpose) {
    case (
      .catalog,
      .catalog(let durableCursor),
      .catalog(let runtimeCursor),
      .catalog
    ):
      return Self.runtimeCursor(runtimeCursor, isAtOrAfter: durableCursor)
    case (
      .conversation(let expectedConversation),
      .conversation(let durableConversation, let durableCursor),
      .conversation(let runtimeConversation, let runtimeCursor),
      .conversationDEK
    ):
      return durableConversation == expectedConversation.rawValue
        && runtimeConversation == expectedConversation
        && Self.runtimeCursor(runtimeCursor, isAtOrAfter: durableCursor)
    default:
      return false
    }
  }

  private static func runtimeCursor(_ cursor: StreamCursor) -> RuntimeStreamCursorV1 {
    switch cursor {
    case .beforeFirst:
      return .beforeFirst
    case .at(let value):
      return .at(value)
    }
  }

  /// daemon 可在 durable StreamBinding capture 与 SyncComplete 之间继续应用 inner
  /// runtime items，因此 synchronized cursor 只需保持同 target 且不早于 durable cut。
  /// `beforeFirst` 是严格最小值；不会把未来 durable cursor 错认成已同步。
  private static func runtimeCursor(
    _ synchronized: RuntimeStreamCursorV1,
    isAtOrAfter durable: StreamCursor
  ) -> Bool {
    switch (durable, synchronized) {
    case (.beforeFirst, .beforeFirst), (.beforeFirst, .at):
      return true
    case (.at, .beforeFirst):
      return false
    case (.at(let durableValue), .at(let synchronizedValue)):
      return synchronizedValue >= durableValue
    }
  }

  /// Mirrors daemon `canonical_uuid_matches`: accepted IDs must be lowercase canonical
  /// hyphenated UUID strings and must map byte-for-byte to the outer generation.
  private static func canonicalUUIDBytes(
    _ generation: RuntimeStreamGeneration
  ) -> Data? {
    let raw = generation.rawValue
    guard let value = UUID(uuidString: raw),
      value.uuidString.lowercased() == raw
    else {
      return nil
    }
    var bytes = value.uuid
    return withUnsafeBytes(of: &bytes) { Data($0) }
  }

  private static func reply(
    _ reply: RuntimeReplyV2,
    satisfies contract: MachineDirectedReplyContract
  ) -> Bool {
    if case .failure = reply { return true }
    switch (contract, reply) {
    case (
      .command(let expectedConfigurationRevision),
      .command(.accepted(_, _, let configurationRevision))
    ),
      (
        .command(let expectedConfigurationRevision),
        .command(.replayed(_, let configurationRevision))
      ):
      return configurationRevision == expectedConfigurationRevision
    case (.command, .command(.failed)):
      return true
    case (
      .approval(let expectedApprovalID, let isRetry),
      .approval(let receipt)
    ):
      return approvalID(receipt) == expectedApprovalID
        && (!isRetry || retryApprovalReceiptIsAllowed(receipt))
    case (
      .revocation(let expectedGrantSerial),
      .revocation(.committed(let committedGrantSerial))
    ):
      return committedGrantSerial.rawValue == expectedGrantSerial
    case (.revocation, .revocation(.failed)):
      return true
    case (.unsubscribe, .subscription(.unsubscribed)):
      return true
    default:
      return false
    }
  }

  private static func approvalID(
    _ receipt: ApprovalReceiptV1
  ) -> RuntimeApprovalID {
    switch receipt {
    case .claimed(let approvalID), .applied(let approvalID),
      .alreadyHandled(let approvalID, _, _), .deliveryFailed(let approvalID),
      .expired(let approvalID):
      return approvalID
    }
  }

  private static func retryApprovalReceiptIsAllowed(
    _ receipt: ApprovalReceiptV1
  ) -> Bool {
    switch receipt {
    case .applied, .deliveryFailed, .expired:
      return true
    case .alreadyHandled(_, _, let state):
      return state == .claimed || state == .applying || state == .expired
    case .claimed:
      return false
    }
  }

  private static func backfill(
    _ chunk: RuntimeBackfillChunkV2,
    matches slot: SubscriptionSlot
  ) -> Bool {
    switch (slot, chunk) {
    case (.catalog, .catalog):
      return true
    case (.conversation(let expected), .conversation(let actual, _, _, _)):
      return expected == actual
    default:
      return false
    }
  }

  private static func innerCursor(
    _ cursor: RuntimeInnerCursorV1,
    matches slot: SubscriptionSlot
  ) -> Bool {
    switch (slot, cursor) {
    case (.catalog, .catalog):
      return true
    case (.conversation(let expected), .conversation(let actual, _)):
      return expected == actual
    default:
      return false
    }
  }

  private static func streamItem(
    _ item: RuntimeStreamItemV2,
    matches slot: SubscriptionSlot
  ) -> Bool {
    switch (slot, item) {
    case (.catalog, .catalogDelta), (.catalog, .transferPart):
      return true
    case (.conversation(let expected), .event(let event)):
      return event.conversationID == expected
    case (.conversation, .transferPart):
      return true
    case (.catalog, .event), (.catalog, .pairingPending),
      (.conversation, .catalogDelta), (.conversation, .pairingPending):
      return false
    }
  }
}

extension VerifiedRuntimeTarget {
  fileprivate func matches(_ other: VerifiedRuntimeTarget) -> Bool {
    switch (self, other) {
    case (.catalog(let lhs), .catalog(let rhs)),
      (.request(let lhs), .request(let rhs)):
      return lhs == rhs
    case (
      .conversation(let lhsConversation, let lhsRequest),
      .conversation(let rhsConversation, let rhsRequest)
    ):
      return lhsConversation == rhsConversation && lhsRequest == rhsRequest
    case (.pairing, .pairing):
      return true
    default:
      return false
    }
  }
}
