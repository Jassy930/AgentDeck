import Foundation

public enum RuntimeConversationStateError: Error, Equatable, Sendable {
  case emptyConversationID
  case emptyTurnID
  case emptyApprovalID
  case emptyCommandID
  case emptyApprovalRequestID
  case conversationMismatch(
    expected: RuntimeConversationID,
    actual: RuntimeConversationID
  )
  case capabilitiesRequired
  case capabilitiesAgentMismatch(expected: AgentKind, actual: AgentKind)
  case backfillScopeMismatch
  case backfillRangeMismatch(
    expected: RuntimeStreamCursorV1,
    actual: RuntimeStreamCursorV1
  )
  case configurationRevisionMismatch(expected: UInt64, actual: UInt64)
  case configurationRevisionExhausted
  case activeTurnConflict
  case turnStartRequired
  case turnIdentityMismatch
  case commandIdentityMismatch
  case pendingApprovalConflict
  case approvalIdentityMismatch
  case approvalDecisionMismatch
  case approvalStateTransitionInvalid
  case unresolvedPendingApproval
}

public struct RuntimeConversationActiveTurn: Equatable, Sendable {
  public let turnID: RuntimeTurnID
  public let commandID: RuntimeCommandID
}

public struct RuntimeConversationPendingApproval: Sendable {
  public let turnID: RuntimeTurnID
  public let commandID: RuntimeCommandID
  public let approvalID: RuntimeApprovalID
  public let requestID: String
  public let request: RuntimeActionRequestV1
}

public struct RuntimeConversationApprovalResolution: Sendable {
  public let turnID: RuntimeTurnID
  public let commandID: RuntimeCommandID
  public let approvalID: RuntimeApprovalID
  public let requestID: String?
  public let decision: ActionDecisionKind?
  public let deliveryState: ApprovalDeliveryStateV1
}

public enum RuntimeConversationTurnTerminal: Sendable {
  case completed(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID,
    summary: RuntimeTurnSummaryV1
  )
  case interrupted(turnID: RuntimeTurnID, commandID: RuntimeCommandID)
  case failed(
    turnID: RuntimeTurnID?,
    commandID: RuntimeCommandID,
    failure: RuntimeFailureV1
  )
}

public struct RuntimeConversationFailure: Sendable {
  public let turnID: RuntimeTurnID?
  public let commandID: RuntimeCommandID?
  public let value: RuntimeFailureV1
}

private enum RuntimeConversationBaselineTurnInferenceState {
  case unavailable
  case available
  case bound
  case consumed
}

/// 单个 Runtime conversation 的进程内 canonical 投影。
///
/// 该类型只接受 daemon 签发的 conversation/event/item/entity/command identity，不创建
/// `session-*`、`thread-*` 或 `ai-N` 替代身份。每个入口都先在值副本上完整归约，成功后才
/// swap，因此 cursor、item 与 lifecycle state 不会在失败时产生半更新。
public struct RuntimeConversationState {
  private static let maximumApprovalIdentitiesPerTurn = 32

  public let conversationID: RuntimeConversationID

  public private(set) var capabilities: RuntimeSessionCapabilitiesV1?
  public private(set) var configurationState: RuntimeConversationConfigurationStateV2?
  public private(set) var cursorState: RuntimeCanonicalEventCursorState
  public private(set) var canonicalItemIdentities: [RuntimeCanonicalItemIdentity] = []
  public private(set) var activeTurn: RuntimeConversationActiveTurn?
  public private(set) var pendingApprovals: [RuntimeConversationPendingApproval] = []
  public private(set) var lastApprovalResolution: RuntimeConversationApprovalResolution?
  public private(set) var turnTerminal: RuntimeConversationTurnTerminal?
  public private(set) var failure: RuntimeConversationFailure?

  private var itemStore = AgentItemStore()
  private var itemIdentityState = RuntimeCanonicalIdentityState()
  private var identityIndexByItemID: [RuntimeItemID: Int] = [:]
  private var pendingApprovalIndexByID: [RuntimeApprovalID: Int] = [:]
  private var approvalResolutionsByID: [RuntimeApprovalID: RuntimeConversationApprovalResolution] =
    [:]
  private var baselineTurnInference: RuntimeConversationBaselineTurnInferenceState = .unavailable

  public var items: [UIItem] { itemStore.items }
  public var pendingApproval: RuntimeConversationPendingApproval? { pendingApprovals.first }

  public init(conversationID: RuntimeConversationID) throws {
    guard !conversationID.rawValue.isEmpty else {
      throw RuntimeConversationStateError.emptyConversationID
    }
    self.conversationID = conversationID
    cursorState = try RuntimeCanonicalEventCursorState(
      conversationID: conversationID,
      baseCursor: .beforeFirst
    )
  }

  /// Snapshot 是完整 baseline：成功时原子替换旧 transcript/cursor/lifecycle 投影。
  public mutating func apply(_ snapshot: ConversationSnapshotV2) throws {
    guard snapshot.conversationID == conversationID else {
      throw RuntimeConversationStateError.conversationMismatch(
        expected: conversationID,
        actual: snapshot.conversationID
      )
    }

    var next = try Self(conversationID: conversationID)
    next.configurationState = snapshot.configurationState
    next.cursorState = try RuntimeCanonicalEventCursorState(
      conversationID: conversationID,
      baseCursor: snapshot.baseEventCursor
    )
    if case .at = snapshot.baseEventCursor {
      next.baselineTurnInference = .available
    }

    for (index, snapshotItem) in snapshot.items.enumerated() {
      switch snapshotItem {
      case .capabilities(let value):
        guard index == 0, next.capabilities == nil else {
          throw RuntimeConversationStateError.capabilitiesRequired
        }
        try next.reduceCapabilities(value)
      case .item:
        guard next.capabilities != nil else {
          throw RuntimeConversationStateError.capabilitiesRequired
        }
        try next.reduceSnapshotItem(snapshotItem)
      }
    }
    guard next.capabilities != nil else {
      throw RuntimeConversationStateError.capabilitiesRequired
    }
    try next.validateConfigurationAgent()
    self = next
  }

  /// 只消费当前 inner cursor 后的 conversation backfill；catalog、错 scope、错 range 均拒绝。
  public mutating func apply(_ backfill: RuntimeBackfillChunkV2) throws {
    var next = self
    switch backfill {
    case .catalog:
      throw RuntimeConversationStateError.backfillScopeMismatch
    case .conversation(let actualID, let preamble, let range, let events):
      guard actualID == conversationID else {
        throw RuntimeConversationStateError.conversationMismatch(
          expected: conversationID,
          actual: actualID
        )
      }
      guard range.after == cursorState.cursor else {
        throw RuntimeConversationStateError.backfillRangeMismatch(
          expected: cursorState.cursor,
          actual: range.after
        )
      }
      try next.reduceCapabilities(preamble)
      for event in events {
        try next.reduce(event)
      }
      guard next.cursorState.cursor == range.through else {
        throw RuntimeConversationStateError.backfillRangeMismatch(
          expected: range.through,
          actual: next.cursorState.cursor
        )
      }
    }
    self = next
  }

  /// 消费 exact-next live event；任何 body/cursor/identity 失败都保留调用前状态。
  public mutating func apply(_ event: RuntimeEventV2) throws {
    var next = self
    try next.reduce(event)
    self = next
  }

  public func identity(for itemID: RuntimeItemID) -> RuntimeCanonicalItemIdentity? {
    guard let index = identityIndexByItemID[itemID],
      canonicalItemIdentities.indices.contains(index)
    else {
      return nil
    }
    return canonicalItemIdentities[index]
  }

  private mutating func reduce(_ event: RuntimeEventV2) throws {
    let nextCursor = try cursorState.reducing(event)
    if event.commandID?.rawValue.isEmpty == true {
      throw RuntimeConversationStateError.emptyCommandID
    }
    if case .capabilities(let value) = event.body {
      try reduceCapabilities(value)
      cursorState = nextCursor
      return
    }
    guard capabilities != nil else {
      throw RuntimeConversationStateError.capabilitiesRequired
    }

    switch event.body {
    case .capabilities:
      preconditionFailure("handled above")
    case .configurationChanged(let state):
      try reduceConfiguration(state)
    case .vendorPanelEvent(let panel):
      try validateAgentKind(panel.agentKind)
    case .item:
      try reduceItemEvent(event)
    case .turnStarted(let turnID):
      let commandID = try requiredCommandID(event.commandID)
      try validateTurnID(turnID)
      guard activeTurn == nil else {
        throw RuntimeConversationStateError.activeTurnConflict
      }
      activeTurn = RuntimeConversationActiveTurn(turnID: turnID, commandID: commandID)
      baselineTurnInference = .consumed
      pendingApprovals.removeAll(keepingCapacity: true)
      pendingApprovalIndexByID.removeAll(keepingCapacity: true)
      approvalResolutionsByID.removeAll(keepingCapacity: true)
      lastApprovalResolution = nil
      turnTerminal = nil
      failure = nil
    case .actionRequest(let turnID, let approvalID, let request):
      let commandID = try requiredCommandID(event.commandID)
      try reduceActionRequest(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        request: request
      )
    case .approvalResolved(let turnID, let approvalID, let decision, let state):
      let commandID = try requiredCommandID(event.commandID)
      try reduceApprovalResolution(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        decision: decision,
        deliveryState: state
      )
    case .turnCompleted(let turnID, let summary):
      let commandID = try requiredCommandID(event.commandID)
      try reduceTerminal(turnID: turnID, commandID: commandID)
      turnTerminal = .completed(
        turnID: turnID,
        commandID: commandID,
        summary: summary
      )
      failure = nil
    case .turnInterrupted(let turnID):
      let commandID = try requiredCommandID(event.commandID)
      try reduceTerminal(turnID: turnID, commandID: commandID)
      turnTerminal = .interrupted(turnID: turnID, commandID: commandID)
      failure = nil
    case .error(let value):
      if let eventCommandID = event.commandID {
        let commandID = try requiredCommandID(eventCommandID)
        let turnID = try reduceFailed(commandID: commandID)
        turnTerminal = .failed(turnID: turnID, commandID: commandID, failure: value)
        failure = RuntimeConversationFailure(
          turnID: turnID,
          commandID: commandID,
          value: value
        )
      } else {
        failure = RuntimeConversationFailure(
          turnID: nil,
          commandID: nil,
          value: value
        )
      }
    }
    cursorState = nextCursor
  }

  private mutating func reduceCapabilities(
    _ value: RuntimeSessionCapabilitiesV1
  ) throws {
    if let current = capabilities {
      guard current.agentKind == value.agentKind else {
        throw RuntimeConversationStateError.capabilitiesAgentMismatch(
          expected: current.agentKind,
          actual: value.agentKind
        )
      }
    }
    if let configuredKind = configurationState?.configuration?.agentKind {
      guard configuredKind == value.agentKind else {
        throw RuntimeConversationStateError.capabilitiesAgentMismatch(
          expected: configuredKind,
          actual: value.agentKind
        )
      }
    }
    capabilities = value
  }

  private mutating func reduceConfiguration(
    _ state: RuntimeConversationConfigurationStateV2
  ) throws {
    if let current = configurationState {
      guard current.configurationRevision < UInt64.max else {
        throw RuntimeConversationStateError.configurationRevisionExhausted
      }
      let expected = current.configurationRevision + 1
      guard state.configurationRevision == expected else {
        throw RuntimeConversationStateError.configurationRevisionMismatch(
          expected: expected,
          actual: state.configurationRevision
        )
      }
    }
    if let kind = state.configuration?.agentKind {
      try validateAgentKind(kind)
    }
    configurationState = state
  }

  private mutating func reduceSnapshotItem(_ item: SnapshotItemV1) throws {
    let projection = try RuntimeCanonicalItemProjection(snapshotItem: item)
    try projection.applySnapshot(
      into: &itemStore,
      identities: &itemIdentityState
    )
    identityIndexByItemID[projection.identity.itemID] = canonicalItemIdentities.count
    canonicalItemIdentities.append(projection.identity)
  }

  private mutating func reduceItemEvent(_ event: RuntimeEventV2) throws {
    let projection = try RuntimeCanonicalItemProjection(event: event)
    let itemID = projection.identity.itemID
    let knownIndex = identityIndexByItemID[itemID]
    if let knownIndex {
      detachItemBuffers(at: knownIndex)
    }
    try projection.applyEvent(
      into: &itemStore,
      identities: &itemIdentityState
    )
    if let knownIndex {
      guard canonicalItemIdentities.indices.contains(knownIndex) else {
        preconditionFailure("canonical identity index drifted from item store")
      }
    } else {
      identityIndexByItemID[itemID] = canonicalItemIdentities.count
      canonicalItemIdentities.append(projection.identity)
    }
  }

  /// `UIItem` 内含引用型 StreamingTextBuffer；更新已有 slot 前只复制该 slot 的三个
  /// buffer，保留 O(1) cumulative update，同时避免失败 backfill 泄漏到调用前 state。
  private mutating func detachItemBuffers(at index: Int) {
    guard itemStore.items.indices.contains(index) else {
      preconditionFailure("canonical identity index drifted from item store")
    }
    var item = itemStore.items[index]
    item.textBuffer = detachedBuffer(from: item.textBuffer)
    item.outputBuffer = detachedBuffer(from: item.outputBuffer)
    item.diffBuffer = detachedBuffer(from: item.diffBuffer)
    itemStore.items[index] = item
  }

  private func detachedBuffer(from source: StreamingTextBuffer) -> StreamingTextBuffer {
    let detached = StreamingTextBuffer()
    detached.replace(with: source.text)
    return detached
  }

  private mutating func reduceActionRequest(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID,
    approvalID: RuntimeApprovalID,
    request: RuntimeActionRequestV1
  ) throws {
    try validateTurnID(turnID)
    try validateApprovalID(approvalID)
    guard !request.requestID.isEmpty else {
      throw RuntimeConversationStateError.emptyApprovalRequestID
    }
    try bindLifecycleTurn(turnID: turnID, commandID: commandID)
    guard approvalIdentityCount < Self.maximumApprovalIdentitiesPerTurn,
      pendingApprovalIndexByID[approvalID] == nil,
      approvalResolutionsByID[approvalID] == nil,
      !pendingApprovals.contains(where: {
        $0.turnID == turnID && $0.requestID == request.requestID
      }),
      !approvalResolutionsByID.values.contains(where: {
        $0.turnID == turnID && $0.requestID == request.requestID
      })
    else {
      throw RuntimeConversationStateError.pendingApprovalConflict
    }
    let pending = RuntimeConversationPendingApproval(
      turnID: turnID,
      commandID: commandID,
      approvalID: approvalID,
      requestID: request.requestID,
      request: request
    )
    pendingApprovalIndexByID[approvalID] = pendingApprovals.count
    pendingApprovals.append(pending)
    lastApprovalResolution = nil
  }

  private mutating func reduceApprovalResolution(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID,
    approvalID: RuntimeApprovalID,
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    try validateTurnID(turnID)
    try validateApprovalID(approvalID)
    try bindLifecycleTurn(turnID: turnID, commandID: commandID)

    let resolution: RuntimeConversationApprovalResolution
    if let pendingIndex = pendingApprovalIndexByID[approvalID] {
      let pendingApproval = pendingApprovals[pendingIndex]
      guard pendingApproval.turnID == turnID,
        pendingApproval.commandID == commandID,
        pendingApproval.approvalID == approvalID
      else {
        throw RuntimeConversationStateError.approvalIdentityMismatch
      }
      try validateInitialApprovalResolution(
        decision: decision,
        deliveryState: deliveryState
      )
      resolution = RuntimeConversationApprovalResolution(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        requestID: pendingApproval.requestID,
        decision: decision,
        deliveryState: deliveryState
      )
      pendingApprovals.remove(at: pendingIndex)
      rebuildPendingApprovalIndex(startingAt: pendingIndex)
    } else if let previous = approvalResolutionsByID[approvalID] {
      guard previous.turnID == turnID,
        previous.commandID == commandID,
        previous.approvalID == approvalID
      else {
        throw RuntimeConversationStateError.approvalIdentityMismatch
      }
      try validateApprovalTransition(
        from: previous,
        decision: decision,
        deliveryState: deliveryState
      )
      resolution = RuntimeConversationApprovalResolution(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        requestID: previous.requestID,
        decision: decision,
        deliveryState: deliveryState
      )
    } else {
      // Snapshot 不携带 lifecycle ledger；baseline 之后首次看到 resolution 时不臆造 requestId。
      guard baselineTurnInference == .bound else {
        throw RuntimeConversationStateError.approvalIdentityMismatch
      }
      guard approvalIdentityCount < Self.maximumApprovalIdentitiesPerTurn else {
        throw RuntimeConversationStateError.pendingApprovalConflict
      }
      try validateInferredApprovalResolution(
        decision: decision,
        deliveryState: deliveryState
      )
      resolution = RuntimeConversationApprovalResolution(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        requestID: nil,
        decision: decision,
        deliveryState: deliveryState
      )
    }
    approvalResolutionsByID[approvalID] = resolution
    lastApprovalResolution = resolution
  }

  private var approvalIdentityCount: Int {
    pendingApprovals.count + approvalResolutionsByID.count
  }

  private mutating func reduceTerminal(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID
  ) throws {
    try validateTurnID(turnID)
    try bindLifecycleTurn(turnID: turnID, commandID: commandID)
    if pendingApprovals.contains(where: {
      $0.turnID == turnID && $0.commandID == commandID
    })
      || approvalResolutionsByID.values.contains(where: {
        $0.turnID == turnID
          && $0.commandID == commandID
          && Self.approvalDeliveryRemainsActive($0.deliveryState)
      })
    {
      throw RuntimeConversationStateError.unresolvedPendingApproval
    }
    if let activeTurn,
      activeTurn.turnID == turnID,
      activeTurn.commandID == commandID
    {
      self.activeTurn = nil
      baselineTurnInference = .consumed
    }
  }

  private mutating func reduceFailed(
    commandID: RuntimeCommandID
  ) throws -> RuntimeTurnID? {
    guard let activeTurn else {
      guard baselineTurnInference == .available else {
        throw RuntimeConversationStateError.turnStartRequired
      }
      baselineTurnInference = .consumed
      return nil
    }
    try reduceTerminal(turnID: activeTurn.turnID, commandID: commandID)
    return activeTurn.turnID
  }

  private mutating func bindLifecycleTurn(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID
  ) throws {
    if activeTurn != nil {
      try validateObservedActiveTurn(turnID: turnID, commandID: commandID)
      return
    }
    guard baselineTurnInference == .available else {
      throw RuntimeConversationStateError.turnStartRequired
    }
    // Snapshot 只冻结 canonical items；快照后的首个 lifecycle event 可为快照前 turn
    // 补齐一次 daemon identity，随后 resolution/terminal 必须复用同一绑定。
    activeTurn = RuntimeConversationActiveTurn(turnID: turnID, commandID: commandID)
    baselineTurnInference = .bound
  }

  private func validateObservedActiveTurn(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID
  ) throws {
    guard let activeTurn else { return }
    guard activeTurn.turnID == turnID else {
      throw RuntimeConversationStateError.turnIdentityMismatch
    }
    guard activeTurn.commandID == commandID else {
      throw RuntimeConversationStateError.commandIdentityMismatch
    }
  }

  private func requiredCommandID(
    _ commandID: RuntimeCommandID?
  ) throws -> RuntimeCommandID {
    guard let commandID, !commandID.rawValue.isEmpty else {
      throw RuntimeConversationStateError.emptyCommandID
    }
    return commandID
  }

  private mutating func rebuildPendingApprovalIndex(startingAt firstIndex: Int) {
    pendingApprovalIndexByID = pendingApprovalIndexByID.filter { $0.value < firstIndex }
    for index in firstIndex..<pendingApprovals.count {
      pendingApprovalIndexByID[pendingApprovals[index].approvalID] = index
    }
  }

  private func validateInitialApprovalResolution(
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    switch deliveryState {
    case .claimed:
      guard decision != nil else {
        throw RuntimeConversationStateError.approvalDecisionMismatch
      }
    case .expired:
      guard decision == nil else {
        throw RuntimeConversationStateError.approvalDecisionMismatch
      }
    case .applying, .applied, .deliveryFailed:
      throw RuntimeConversationStateError.approvalStateTransitionInvalid
    }
  }

  private func validateInferredApprovalResolution(
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    switch deliveryState {
    case .claimed, .applying, .applied, .deliveryFailed:
      guard decision != nil else {
        throw RuntimeConversationStateError.approvalDecisionMismatch
      }
    case .expired:
      break
    }
  }

  private func validateApprovalTransition(
    from previous: RuntimeConversationApprovalResolution,
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    switch (previous.deliveryState, deliveryState) {
    case (.claimed, .applying),
      (.claimed, .expired),
      (.applying, .applied),
      (.applying, .deliveryFailed),
      (.applying, .expired),
      (.deliveryFailed, .applying),
      (.deliveryFailed, .expired):
      break
    default:
      throw RuntimeConversationStateError.approvalStateTransitionInvalid
    }
    guard let winner = previous.decision, decision == winner else {
      throw RuntimeConversationStateError.approvalDecisionMismatch
    }
  }

  private static func approvalDeliveryRemainsActive(
    _ state: ApprovalDeliveryStateV1
  ) -> Bool {
    switch state {
    case .claimed, .applying, .deliveryFailed:
      true
    case .applied, .expired:
      false
    }
  }

  private func validateTurnID(_ turnID: RuntimeTurnID) throws {
    guard !turnID.rawValue.isEmpty else {
      throw RuntimeConversationStateError.emptyTurnID
    }
  }

  private func validateApprovalID(_ approvalID: RuntimeApprovalID) throws {
    guard !approvalID.rawValue.isEmpty else {
      throw RuntimeConversationStateError.emptyApprovalID
    }
  }

  private func validateAgentKind(_ actual: AgentKind) throws {
    guard let expected = capabilities?.agentKind else {
      throw RuntimeConversationStateError.capabilitiesRequired
    }
    guard expected == actual else {
      throw RuntimeConversationStateError.capabilitiesAgentMismatch(
        expected: expected,
        actual: actual
      )
    }
  }

  private func validateConfigurationAgent() throws {
    guard let actual = configurationState?.configuration?.agentKind else { return }
    try validateAgentKind(actual)
  }
}
