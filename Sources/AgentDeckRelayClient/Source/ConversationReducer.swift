import AgentDeckCore
import Foundation

struct RelayPendingApprovalProjection: Equatable, Sendable {
  let turnID: String
  let commandID: String
  let approvalID: String
  let requestID: String
  let summary: String
}

struct ConversationProjection: Sendable {
  let machineID: String
  let conversationID: String
  let cursor: RuntimeStreamCursorV1
  let configurationRevision: UInt64
  let pendingApprovals: [RelayPendingApprovalProjection]
  let completedEventID: String?
  let failedEventID: String?

  /// warm resume 必须携带真实进程内 reducer，而不是只有 cursor 的伪 baseline。
  let resumeReducer: ConversationReducer
}

private struct RelayActiveTurn: Equatable, Sendable {
  let turnID: RuntimeTurnID
  let commandID: RuntimeCommandID
}

private struct RelayPendingApproval: Sendable {
  let turnID: RuntimeTurnID
  let commandID: RuntimeCommandID
  let approvalID: RuntimeApprovalID
  let request: RuntimeActionRequestV1
}

private struct RelayApprovalResolution: Sendable {
  let turnID: RuntimeTurnID
  let commandID: RuntimeCommandID
  let approvalID: RuntimeApprovalID
  let requestID: String?
  let winner: ActionDecisionKind?
  let deliveryState: ApprovalDeliveryStateV1
}

private enum RelayBaselineTurnInferenceState: Sendable {
  case unavailable
  case available
  case bound
  case consumed
}

/// Source-facing conversation reducer。它保留 daemon canonical identity、approval
/// requestID 与 exact-next cursor；不生成 UI 替代 ID，也不接触 raw wire/crypto。
struct ConversationReducer: Sendable {
  private static let maximumApprovalIdentitiesPerTurn = 32
  private static let maximumFingerprints = 4_096

  let machineID: String
  let conversationID: RuntimeConversationID
  private(set) var cursor: RuntimeStreamCursorV1

  private var capabilities: RuntimeSessionCapabilitiesV1
  private var configurationState: RuntimeConversationConfigurationStateV2
  private var activeTurn: RelayActiveTurn?
  private var pendingApprovals: [RuntimeApprovalID: RelayPendingApproval] = [:]
  private var pendingApprovalOrder: [RuntimeApprovalID] = []
  private var approvalResolutions: [RuntimeApprovalID: RelayApprovalResolution] = [:]
  private var baselineTurnInference: RelayBaselineTurnInferenceState
  private var completedEventID: RuntimeEventID?
  private var failedEventID: RuntimeEventID?
  private var eventFingerprints: [UInt64: Data] = [:]
  private var fingerprintOrder: [UInt64] = []

  var projection: ConversationProjection {
    ConversationProjection(
      machineID: machineID,
      conversationID: conversationID.rawValue,
      cursor: cursor,
      configurationRevision: configurationState.configurationRevision,
      pendingApprovals: pendingApprovalOrder.compactMap { approvalID in
        guard let approval = pendingApprovals[approvalID] else { return nil }
        return RelayPendingApprovalProjection(
          turnID: approval.turnID.rawValue,
          commandID: approval.commandID.rawValue,
          approvalID: approval.approvalID.rawValue,
          requestID: approval.request.requestID,
          summary: approval.request.summary
        )
      },
      completedEventID: completedEventID?.rawValue,
      failedEventID: failedEventID?.rawValue,
      resumeReducer: self
    )
  }

  init(machineID: String, snapshot: ConversationSnapshotV2) throws {
    guard !machineID.isEmpty else { throw RelaySourceReducerError.emptyMachineID }
    guard !snapshot.conversationID.rawValue.isEmpty else {
      throw RelaySourceReducerError.emptyConversationID
    }
    guard case .capabilities(let capabilities)? = snapshot.items.first else {
      throw RelaySourceReducerError.capabilitiesRequired
    }

    self.machineID = machineID
    conversationID = snapshot.conversationID
    cursor = snapshot.baseEventCursor
    self.capabilities = capabilities
    configurationState = snapshot.configurationState
    if case .at = snapshot.baseEventCursor {
      baselineTurnInference = .available
    } else {
      baselineTurnInference = .unavailable
    }
  }

  @discardableResult
  mutating func apply(_ event: RuntimeEventV2) throws -> RelayReducerApplyResult {
    guard event.conversationID == conversationID else {
      throw RelaySourceReducerError.conversationMismatch
    }
    guard !event.eventID.rawValue.isEmpty else {
      throw RelaySourceReducerError.emptyEventID
    }
    let fingerprint = try canonicalBytes(event)
    if isAtOrBehindCurrent(event.eventSeq) {
      guard eventFingerprints[event.eventSeq] == fingerprint else {
        throw RelaySourceReducerError.duplicateConflict(sequence: event.eventSeq)
      }
      return .duplicate
    }

    let expected: UInt64
    do {
      expected = try cursor.checkedNext()
    } catch {
      throw RelaySourceReducerError.cursorExhausted
    }
    guard event.eventSeq == expected else {
      throw RelaySourceReducerError.unexpectedCursor(
        expected: .at(expected),
        actual: .at(event.eventSeq)
      )
    }

    var next = self
    try next.reduceBody(event)
    next.cursor = .at(event.eventSeq)
    next.rememberFingerprint(fingerprint, sequence: event.eventSeq)
    self = next
    return .applied
  }

  @discardableResult
  mutating func apply(_ backfill: RuntimeBackfillChunkV2) throws -> RelayReducerApplyResult {
    guard
      case .conversation(
        let actualConversationID,
        let preamble,
        let range,
        let events
      ) = backfill
    else {
      throw RelaySourceReducerError.wrongBackfillScope
    }
    guard actualConversationID == conversationID else {
      throw RelaySourceReducerError.conversationMismatch
    }
    guard range.after == cursor else {
      throw RelaySourceReducerError.unexpectedCursor(expected: cursor, actual: range.after)
    }
    guard try canonicalBytes(preamble) == canonicalBytes(capabilities) else {
      throw RelaySourceReducerError.capabilitiesConflict
    }

    var next = self
    for event in events {
      guard try next.apply(event) == .applied else {
        throw RelaySourceReducerError.duplicateConflict(sequence: event.eventSeq)
      }
    }
    guard next.cursor == range.through else {
      throw RelaySourceReducerError.unexpectedCursor(
        expected: range.through,
        actual: next.cursor
      )
    }
    self = next
    return .applied
  }

  func pendingApprovalRequestID(approvalID: String) -> String? {
    pendingApprovals[RuntimeApprovalID(rawValue: approvalID)]?.request.requestID
  }

  private func isAtOrBehindCurrent(_ sequence: UInt64) -> Bool {
    guard case .at(let current) = cursor else { return false }
    return sequence <= current
  }

  private mutating func reduceBody(_ event: RuntimeEventV2) throws {
    switch event.body {
    case .capabilities(let value):
      guard try canonicalBytes(value) == canonicalBytes(capabilities) else {
        throw RelaySourceReducerError.capabilitiesConflict
      }

    case .configurationChanged(let value):
      let (expected, overflow) = configurationState.configurationRevision.addingReportingOverflow(1)
      guard !overflow, value.configurationRevision == expected else {
        throw RelaySourceReducerError.configurationRevision
      }
      configurationState = value

    case .vendorPanelEvent, .item:
      break

    case .turnStarted(let turnID):
      try Self.validate(turnID)
      let commandID = try Self.requiredCommandID(event)
      guard activeTurn == nil else { throw RelaySourceReducerError.activeTurnConflict }
      activeTurn = RelayActiveTurn(turnID: turnID, commandID: commandID)
      baselineTurnInference = .consumed
      pendingApprovals.removeAll(keepingCapacity: true)
      pendingApprovalOrder.removeAll(keepingCapacity: true)
      approvalResolutions.removeAll(keepingCapacity: true)
      completedEventID = nil
      failedEventID = nil

    case .actionRequest(let turnID, let approvalID, let request):
      try Self.validate(turnID)
      guard !approvalID.rawValue.isEmpty else {
        throw RelaySourceReducerError.emptyApprovalID
      }
      let commandID = try Self.requiredCommandID(event)
      try bindLifecycleTurn(turnID: turnID, commandID: commandID)
      guard !request.requestID.isEmpty else {
        throw RelaySourceReducerError.emptyRequestID
      }
      guard pendingApprovals[approvalID] == nil,
        approvalResolutions[approvalID] == nil,
        !pendingApprovals.values.contains(where: {
          $0.turnID == turnID && $0.request.requestID == request.requestID
        }),
        !approvalResolutions.values.contains(where: {
          $0.turnID == turnID && $0.requestID == request.requestID
        }),
        approvalIdentityCount < Self.maximumApprovalIdentitiesPerTurn
      else {
        throw RelaySourceReducerError.approvalConflict
      }
      pendingApprovals[approvalID] = RelayPendingApproval(
        turnID: turnID,
        commandID: commandID,
        approvalID: approvalID,
        request: request
      )
      pendingApprovalOrder.append(approvalID)

    case .approvalResolved(let turnID, let approvalID, let decision, let deliveryState):
      try Self.validate(turnID)
      guard !approvalID.rawValue.isEmpty else {
        throw RelaySourceReducerError.emptyApprovalID
      }
      let commandID = try Self.requiredCommandID(event)
      try bindLifecycleTurn(turnID: turnID, commandID: commandID)
      let resolution: RelayApprovalResolution
      if let pending = pendingApprovals[approvalID] {
        guard pending.turnID == turnID,
          pending.commandID == commandID,
          pending.approvalID == approvalID
        else {
          throw RelaySourceReducerError.approvalIdentityMismatch
        }
        try Self.validateInitialApprovalResolution(
          decision: decision,
          deliveryState: deliveryState
        )
        resolution = RelayApprovalResolution(
          turnID: turnID,
          commandID: commandID,
          approvalID: approvalID,
          requestID: pending.request.requestID,
          winner: decision,
          deliveryState: deliveryState
        )
        pendingApprovals.removeValue(forKey: approvalID)
        pendingApprovalOrder.removeAll { $0 == approvalID }
      } else if let previous = approvalResolutions[approvalID] {
        guard previous.turnID == turnID,
          previous.commandID == commandID,
          previous.approvalID == approvalID
        else {
          throw RelaySourceReducerError.approvalIdentityMismatch
        }
        try Self.validateApprovalTransition(
          from: previous,
          decision: decision,
          deliveryState: deliveryState
        )
        resolution = RelayApprovalResolution(
          turnID: turnID,
          commandID: commandID,
          approvalID: approvalID,
          requestID: previous.requestID,
          winner: decision,
          deliveryState: deliveryState
        )
      } else {
        guard baselineTurnInference == .bound else {
          throw RelaySourceReducerError.approvalIdentityMismatch
        }
        guard approvalIdentityCount < Self.maximumApprovalIdentitiesPerTurn else {
          throw RelaySourceReducerError.approvalConflict
        }
        try Self.validateInferredApprovalResolution(
          decision: decision,
          deliveryState: deliveryState
        )
        resolution = RelayApprovalResolution(
          turnID: turnID,
          commandID: commandID,
          approvalID: approvalID,
          requestID: nil,
          winner: decision,
          deliveryState: deliveryState
        )
      }
      approvalResolutions[approvalID] = resolution

    case .turnCompleted(let turnID, _), .turnInterrupted(let turnID):
      try Self.validate(turnID)
      let commandID = try Self.requiredCommandID(event)
      try reduceTerminal(turnID: turnID, commandID: commandID)
      completedEventID = event.eventID

    case .error:
      guard event.commandID != nil else { break }
      let commandID = try Self.requiredCommandID(event)
      try reduceFailed(commandID: commandID)
      failedEventID = event.eventID
    }
  }

  private var approvalIdentityCount: Int {
    pendingApprovals.count + approvalResolutions.count
  }

  private mutating func reduceFailed(
    commandID: RuntimeCommandID
  ) throws {
    guard let activeTurn else {
      guard baselineTurnInference == .available else {
        throw RelaySourceReducerError.turnStartRequired
      }
      baselineTurnInference = .consumed
      return
    }
    try reduceTerminal(turnID: activeTurn.turnID, commandID: commandID)
  }

  private mutating func reduceTerminal(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID
  ) throws {
    try bindLifecycleTurn(turnID: turnID, commandID: commandID)
    guard
      !pendingApprovals.values.contains(where: {
        $0.turnID == turnID && $0.commandID == commandID
      }),
      !approvalResolutions.values.contains(where: {
        $0.turnID == turnID
          && $0.commandID == commandID
          && Self.approvalDeliveryRemainsActive($0.deliveryState)
      })
    else {
      throw RelaySourceReducerError.unresolvedApproval
    }
    activeTurn = nil
    baselineTurnInference = .consumed
  }

  private mutating func bindLifecycleTurn(
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID
  ) throws {
    if let activeTurn {
      guard activeTurn == RelayActiveTurn(turnID: turnID, commandID: commandID) else {
        throw RelaySourceReducerError.turnIdentityMismatch
      }
      return
    }
    guard baselineTurnInference == .available else {
      throw RelaySourceReducerError.turnStartRequired
    }
    activeTurn = RelayActiveTurn(turnID: turnID, commandID: commandID)
    baselineTurnInference = .bound
  }

  private mutating func rememberFingerprint(_ fingerprint: Data, sequence: UInt64) {
    eventFingerprints[sequence] = fingerprint
    fingerprintOrder.append(sequence)
    if fingerprintOrder.count > Self.maximumFingerprints {
      let removed = fingerprintOrder.removeFirst()
      eventFingerprints.removeValue(forKey: removed)
    }
  }

  private static func requiredCommandID(_ event: RuntimeEventV2) throws -> RuntimeCommandID {
    guard let commandID = event.commandID, !commandID.rawValue.isEmpty else {
      throw RelaySourceReducerError.emptyCommandID
    }
    return commandID
  }

  private static func validate(_ turnID: RuntimeTurnID) throws {
    guard !turnID.rawValue.isEmpty else { throw RelaySourceReducerError.emptyTurnID }
  }

  private static func validateInitialApprovalResolution(
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    switch deliveryState {
    case .claimed:
      guard decision != nil else {
        throw RelaySourceReducerError.approvalIdentityMismatch
      }
    case .expired:
      guard decision == nil else {
        throw RelaySourceReducerError.approvalIdentityMismatch
      }
    case .applying, .applied, .deliveryFailed:
      throw RelaySourceReducerError.approvalConflict
    }
  }

  private static func validateInferredApprovalResolution(
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1
  ) throws {
    switch deliveryState {
    case .claimed, .applying, .applied, .deliveryFailed:
      guard decision != nil else {
        throw RelaySourceReducerError.approvalIdentityMismatch
      }
    case .expired:
      break
    }
  }

  private static func validateApprovalTransition(
    from previous: RelayApprovalResolution,
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
      throw RelaySourceReducerError.approvalConflict
    }
    guard let winner = previous.winner, decision == winner else {
      throw RelaySourceReducerError.approvalIdentityMismatch
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
}
