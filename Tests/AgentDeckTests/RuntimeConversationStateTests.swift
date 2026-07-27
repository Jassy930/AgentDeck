import Foundation
import XCTest

@testable import AgentDeckCore

final class RuntimeConversationStateTests: XCTestCase {
  func testSnapshotBuildsCanonicalConversationStateWithoutSyntheticIdentity() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    let snapshot = try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .at(4),
      configurationState: unconfiguredState(),
      items: [
        .capabilities(try capabilities()),
        .item(
          itemID: id(RuntimeItemID.self, "item-user"),
          entityID: id(RuntimeEntityID.self, "entity-user"),
          commandID: id(RuntimeCommandID.self, "command-user"),
          item: .userMessage(text: "hello", meta: RuntimeAgentItemMetaV1())
        ),
        .item(
          itemID: id(RuntimeItemID.self, "item-answer"),
          entityID: id(RuntimeEntityID.self, "entity-answer"),
          commandID: id(RuntimeCommandID.self, "command-user"),
          item: .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1())
        ),
      ]
    )

    try state.apply(snapshot)

    XCTAssertEqual(state.conversationID, conversationID)
    XCTAssertEqual(state.cursorState.cursor, .at(4))
    XCTAssertEqual(state.capabilities?.agentKind, .codex)
    XCTAssertEqual(state.configurationState?.configurationRevision, 0)
    XCTAssertEqual(state.items.map(\.id), ["item-user", "item-answer"])
    XCTAssertEqual(state.items.map(\.text), ["hello", "answer"])
    XCTAssertFalse(state.items.contains { $0.id.hasPrefix("ai-") })
    XCTAssertEqual(
      state.canonicalItemIdentities.map { $0.itemID.rawValue },
      ["item-user", "item-answer"]
    )
    XCTAssertEqual(
      state.canonicalItemIdentities.map { $0.entityID.rawValue },
      ["entity-user", "entity-answer"]
    )
    XCTAssertEqual(
      state.canonicalItemIdentities.map { $0.commandID?.rawValue },
      ["command-user", "command-user"]
    )
    XCTAssertNil(state.activeTurn)
    XCTAssertNil(state.pendingApproval)
    XCTAssertNil(state.lastApprovalResolution)
    XCTAssertNil(state.turnTerminal)
    XCTAssertNil(state.failure)
  }

  func testSnapshotFailureDoesNotReplacePriorState() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(
      snapshot(
        conversationID: conversationID,
        baseCursor: .at(2),
        items: [item("item-good", entity: "entity-good", text: "good")]
      )
    )
    let duplicate = try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .at(9),
      configurationState: unconfiguredState(),
      items: [
        .capabilities(try capabilities()),
        item("item-duplicate", entity: "entity-1", text: "first"),
        item("item-duplicate", entity: "entity-2", text: "second"),
      ]
    )

    XCTAssertThrowsError(try state.apply(duplicate)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .duplicateSnapshotItem
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertEqual(state.items.map(\.id), ["item-good"])
    XCTAssertEqual(state.items.map(\.text), ["good"])

    let other = try snapshot(
      conversationID: id(RuntimeConversationID.self, "conversation-other"),
      baseCursor: .at(10),
      items: []
    )
    XCTAssertThrowsError(try state.apply(other)) { error in
      XCTAssertEqual(
        error as? RuntimeConversationStateError,
        .conversationMismatch(
          expected: conversationID,
          actual: id(RuntimeConversationID.self, "conversation-other")
        )
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
  }

  func testConversationBackfillRequiresExactScopeRangeAndContiguousEvents() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(
      snapshot(
        conversationID: conversationID,
        baseCursor: .at(0),
        items: [item("item-1", entity: "entity-1", text: "partial")]
      )
    )
    let events = [
      try event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-1",
        itemID: "item-1",
        entityID: "entity-1",
        body: .item(
          .assistantMessage(text: "complete", meta: RuntimeAgentItemMetaV1())
        )
      ),
      try event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-2",
        itemID: "item-2",
        entityID: "entity-2",
        body: .item(
          .assistantMessage(text: "second", meta: RuntimeAgentItemMetaV1())
        )
      ),
    ]
    let chunk = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .at(0), through: .at(2)),
      events: events
    )

    try state.apply(chunk)

    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertEqual(state.items.map(\.id), ["item-1", "item-2"])
    XCTAssertEqual(state.items.map(\.text), ["complete", "second"])
    XCTAssertEqual(
      state.canonicalItemIdentities.map { $0.entityID.rawValue },
      ["entity-1", "entity-2"]
    )

    let catalog = RuntimeBackfillChunkV2.catalog(
      range: try RuntimeBackfillRangeV1(after: .at(2), through: .at(3)),
      deltas: []
    )
    XCTAssertThrowsError(try state.apply(catalog)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .backfillScopeMismatch)
    }

    let wrongAfter = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .at(1), through: .at(2)),
      events: [events[1]]
    )
    XCTAssertThrowsError(try state.apply(wrongAfter)) { error in
      XCTAssertEqual(
        error as? RuntimeConversationStateError,
        .backfillRangeMismatch(expected: .at(2), actual: .at(1))
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertEqual(state.items.map(\.text), ["complete", "second"])
  }

  func testBackfillFailureIsTransactionalAcrossEarlierValidEvents() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(
      snapshot(
        conversationID: conversationID,
        baseCursor: .beforeFirst,
        items: [item("item-0", entity: "entity-0", text: "before")]
      )
    )
    let first = try itemEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-0",
      itemID: "item-0",
      entityID: "entity-0",
      text: "must roll back"
    )
    let gap = try itemEvent(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-2",
      itemID: "item-2",
      entityID: "entity-2",
      text: "gap"
    )
    let chunk = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(1)),
      events: [first, gap]
    )

    XCTAssertThrowsError(try state.apply(chunk)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 1, actual: 2)
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .beforeFirst)
    XCTAssertEqual(state.items.map(\.text), ["before"])
    XCTAssertEqual(state.items.first?.textBuffer.text, "before")
    XCTAssertEqual(state.canonicalItemIdentities.count, 1)
  }

  func testLiveLifecycleTracksExactCanonicalTurnApprovalAndTerminalIdentity() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    let approvalID = id(RuntimeApprovalID.self, "approval-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertEqual(state.activeTurn?.commandID, commandID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: approvalID,
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    XCTAssertEqual(state.pendingApproval?.turnID, turnID)
    XCTAssertEqual(state.pendingApproval?.commandID, commandID)
    XCTAssertEqual(state.pendingApproval?.approvalID, approvalID)
    XCTAssertEqual(state.pendingApproval?.requestID, "request-1")

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-claimed",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .claimed
        )
      )
    )
    XCTAssertNil(state.pendingApproval)
    XCTAssertEqual(state.lastApprovalResolution?.turnID, turnID)
    XCTAssertEqual(state.lastApprovalResolution?.commandID, commandID)
    XCTAssertEqual(state.lastApprovalResolution?.approvalID, approvalID)
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-1")
    XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .claimed)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 3,
        eventID: "event-applying",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .applying
        )
      )
    )
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-1")
    XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .applying)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 4,
        eventID: "event-applied",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .applied
        )
      )
    )
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .applied)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 5,
        eventID: "event-completed",
        commandID: commandID,
        body: .turnCompleted(turnID: turnID, summary: try turnSummary())
      )
    )
    XCTAssertNil(state.activeTurn)
    guard
      case .completed(let completedTurnID, let completedCommandID, let summary)? =
        state.turnTerminal
    else {
      return XCTFail("expected completed terminal")
    }
    XCTAssertEqual(completedTurnID, turnID)
    XCTAssertEqual(completedCommandID, commandID)
    XCTAssertEqual(summary.elapsedMs, 42)
    XCTAssertEqual(state.cursorState.cursor, .at(5))
  }

  func testCommandlessDiagnosticDoesNotTerminateActiveTurn() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-diagnostic",
        body: .error(RuntimeFailureV1(code: "daemon.adapter.warning", message: "retrying"))
      )
    )
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertNil(state.turnTerminal)
    XCTAssertNil(state.failure?.turnID)
    XCTAssertNil(state.failure?.commandID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-completed",
        commandID: commandID,
        body: .turnCompleted(turnID: turnID, summary: try turnSummary())
      )
    )
    XCTAssertNil(state.activeTurn)
    XCTAssertNil(state.failure)
  }

  func testCommandBoundErrorTerminatesExactTurnAndAllowsNextStart() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-failed",
        commandID: commandID,
        body: .error(terminalFailure())
      )
    )
    XCTAssertNil(state.activeTurn)
    guard
      case .failed(let failedTurnID, let failedCommandID, let failure)? = state.turnTerminal
    else {
      return XCTFail("expected failed terminal")
    }
    XCTAssertEqual(failedTurnID, turnID)
    XCTAssertEqual(failedCommandID, commandID)
    XCTAssertEqual(failure.code, "daemon.runtime.execution_failed")
    XCTAssertEqual(state.failure?.turnID, turnID)
    XCTAssertEqual(state.failure?.commandID, commandID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-next-started",
        commandID: id(RuntimeCommandID.self, "command-2"),
        body: .turnStarted(turnID: id(RuntimeTurnID.self, "turn-2"))
      )
    )
    XCTAssertEqual(state.activeTurn?.turnID.rawValue, "turn-2")
    XCTAssertNil(state.turnTerminal)
    XCTAssertNil(state.failure)
  }

  func testCommandBoundErrorRejectsWrongCommandAndUnresolvedApprovalAtomically() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    let wrongCommand = try event(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-wrong-command",
      commandID: id(RuntimeCommandID.self, "command-other"),
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try state.apply(wrongCommand)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .commandIdentityMismatch)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(0))
    XCTAssertEqual(state.activeTurn?.commandID, commandID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-1"),
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    let unresolvedFailure = try event(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-unresolved-failure",
      commandID: commandID,
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try state.apply(unresolvedFailure)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .unresolvedPendingApproval)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(1))
    XCTAssertEqual(state.pendingApproval?.approvalID.rawValue, "approval-1")
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertNil(state.turnTerminal)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-claimed",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-1"),
          decision: .approve,
          state: .claimed
        )
      )
    )
    let activeDeliveryFailure = try event(
      conversationID: conversationID,
      sequence: 3,
      eventID: "event-active-delivery-failure",
      commandID: commandID,
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try state.apply(activeDeliveryFailure)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .unresolvedPendingApproval)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .claimed)
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertNil(state.turnTerminal)
  }

  func testApprovalIdentityFailureKeepsPendingAndCursorUnchanged() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-1"),
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    let wrongResolution = try event(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-wrong-resolution",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: id(RuntimeApprovalID.self, "approval-other"),
        decision: .deny,
        state: .applied
      )
    )

    XCTAssertThrowsError(try state.apply(wrongResolution)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .approvalIdentityMismatch)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(1))
    XCTAssertEqual(state.pendingApproval?.approvalID.rawValue, "approval-1")
    XCTAssertEqual(state.pendingApproval?.requestID, "request-1")
    XCTAssertNil(state.lastApprovalResolution)
  }

  func testParallelApprovalsRemainBoundToTheirOwnCanonicalRequestIDs() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    for index in 1...2 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: UInt64(index),
          eventID: "event-approval-\(index)",
          commandID: commandID,
          body: .actionRequest(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            request: try actionRequest(requestID: "request-\(index)")
          )
        )
      )
    }

    XCTAssertEqual(state.pendingApprovals.map(\.requestID), ["request-1", "request-2"])
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 3,
        eventID: "event-resolved-2",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-2"),
          decision: nil,
          state: .expired
        )
      )
    )

    XCTAssertEqual(state.pendingApprovals.map(\.requestID), ["request-1"])
    XCTAssertEqual(state.pendingApproval?.approvalID.rawValue, "approval-1")
    XCTAssertEqual(state.lastApprovalResolution?.approvalID.rawValue, "approval-2")
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-2")
    XCTAssertNil(state.lastApprovalResolution?.decision)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .expired)
    XCTAssertEqual(state.cursorState.cursor, .at(3))
  }

  func testApprovalRequestIDCannotBeReusedWhilePendingOrAfterResolution() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    let firstApprovalID = id(RuntimeApprovalID.self, "approval-1")
    let secondApprovalID = id(RuntimeApprovalID.self, "approval-2")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval-1",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: firstApprovalID,
          request: try actionRequest(requestID: "request-shared")
        )
      )
    )

    let duplicateWhilePending = try event(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-duplicate-pending-request",
      commandID: commandID,
      body: .actionRequest(
        turnID: turnID,
        approvalID: secondApprovalID,
        request: try actionRequest(requestID: "request-shared")
      )
    )
    XCTAssertThrowsError(try state.apply(duplicateWhilePending)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .pendingApprovalConflict)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(1))
    XCTAssertEqual(state.pendingApprovals.map(\.approvalID), [firstApprovalID])

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-claimed-1",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: firstApprovalID,
          decision: .approve,
          state: .claimed
        )
      )
    )
    let duplicateAfterResolution = try event(
      conversationID: conversationID,
      sequence: 3,
      eventID: "event-duplicate-resolved-request",
      commandID: commandID,
      body: .actionRequest(
        turnID: turnID,
        approvalID: secondApprovalID,
        request: try actionRequest(requestID: "request-shared")
      )
    )
    XCTAssertThrowsError(try state.apply(duplicateAfterResolution)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .pendingApprovalConflict)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertTrue(state.pendingApprovals.isEmpty)
    XCTAssertEqual(state.lastApprovalResolution?.approvalID, firstApprovalID)
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-shared")
  }

  func testApprovalIdentityLimitCountsPendingAndResolvedWithoutPartialOverflowMutation() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    var nextSequence: UInt64 = 1
    for index in 1...30 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-approval-\(index)",
          commandID: commandID,
          body: .actionRequest(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            request: try actionRequest(requestID: "request-\(index)")
          )
        )
      )
      nextSequence += 1
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-claimed-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            decision: .approve,
            state: .claimed
          )
        )
      )
      nextSequence += 1
    }
    for index in 31...32 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-approval-\(index)",
          commandID: commandID,
          body: .actionRequest(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            request: try actionRequest(requestID: "request-\(index)")
          )
        )
      )
      nextSequence += 1
    }
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: nextSequence,
        eventID: "event-claimed-31",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-31"),
          decision: .approve,
          state: .claimed
        )
      )
    )
    nextSequence += 1

    let overflow = try event(
      conversationID: conversationID,
      sequence: nextSequence,
      eventID: "event-approval-33",
      commandID: commandID,
      body: .actionRequest(
        turnID: turnID,
        approvalID: id(RuntimeApprovalID.self, "approval-33"),
        request: try actionRequest(requestID: "request-33")
      )
    )
    XCTAssertThrowsError(try state.apply(overflow)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .pendingApprovalConflict)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(nextSequence - 1))
    XCTAssertEqual(
      state.pendingApprovals.map(\.approvalID),
      [id(RuntimeApprovalID.self, "approval-32")]
    )
    XCTAssertEqual(state.pendingApproval?.requestID, "request-32")
    XCTAssertEqual(state.lastApprovalResolution?.approvalID.rawValue, "approval-31")
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-31")
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .claimed)
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertEqual(state.activeTurn?.commandID, commandID)

    // 每个已 resolution 的 identity 都仍可沿原 ledger 合法推进，证明 overflow 未替换或清空 ledger。
    for index in 1...31 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-applying-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            decision: .approve,
            state: .applying
          )
        )
      )
      XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-\(index)")
      nextSequence += 1
    }
    XCTAssertEqual(
      state.pendingApprovals.map(\.approvalID),
      [id(RuntimeApprovalID.self, "approval-32")]
    )
  }

  func testSnapshotInferredApprovalIdentityLimitRejectsOverflowTransactionally() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-before-snapshot")
    let turnID = id(RuntimeTurnID.self, "turn-before-snapshot")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .at(10), items: []))

    var nextSequence: UInt64 = 11
    for index in 1...32 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-inferred-claimed-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            decision: .approve,
            state: .claimed
          )
        )
      )
      nextSequence += 1
    }

    let overflow = try event(
      conversationID: conversationID,
      sequence: nextSequence,
      eventID: "event-inferred-claimed-33",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: id(RuntimeApprovalID.self, "approval-33"),
        decision: .approve,
        state: .claimed
      )
    )
    XCTAssertThrowsError(try state.apply(overflow)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .pendingApprovalConflict)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(nextSequence - 1))
    XCTAssertTrue(state.pendingApprovals.isEmpty)
    XCTAssertEqual(state.lastApprovalResolution?.approvalID.rawValue, "approval-32")
    XCTAssertNil(state.lastApprovalResolution?.requestID)
    XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .claimed)
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertEqual(state.activeTurn?.commandID, commandID)

    // Snapshot 推断出的全部 identity 仍保留原绑定；overflow 不能污染 cursor 或 resolution ledger。
    for index in 1...32 {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-inferred-applying-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: id(RuntimeApprovalID.self, "approval-\(index)"),
            decision: .approve,
            state: .applying
          )
        )
      )
      XCTAssertNil(state.lastApprovalResolution?.requestID)
      nextSequence += 1
    }
  }

  func testApprovalDeliveryFailureRetryAndExpiryKeepExactWinnerBinding() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    let approvalID = id(RuntimeApprovalID.self, "approval-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: approvalID,
          request: try actionRequest(requestID: "request-1")
        )
      )
    )

    for (sequence, deliveryState) in [
      (UInt64(2), ApprovalDeliveryStateV1.claimed),
      (UInt64(3), .applying),
      (UInt64(4), .deliveryFailed),
      (UInt64(5), .applying),
    ] {
      try state.apply(
        event(
          conversationID: conversationID,
          sequence: sequence,
          eventID: "event-\(deliveryState.rawValue)-\(sequence)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: approvalID,
            decision: .approve,
            state: deliveryState
          )
        )
      )
      XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-1")
      XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
      XCTAssertEqual(state.lastApprovalResolution?.deliveryState, deliveryState)
    }

    let prematureTerminal = try event(
      conversationID: conversationID,
      sequence: 6,
      eventID: "event-premature-terminal",
      commandID: commandID,
      body: .turnInterrupted(turnID: turnID)
    )
    XCTAssertThrowsError(try state.apply(prematureTerminal))
    XCTAssertEqual(state.cursorState.cursor, .at(5))
    XCTAssertEqual(state.activeTurn?.turnID, turnID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 6,
        eventID: "event-expired",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .expired
        )
      )
    )
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-1")
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .expired)
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 7,
        eventID: "event-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertNil(state.activeTurn)
  }

  func testApprovalWinnerChangeAndBackwardTransitionAreAtomic() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    let approvalID = id(RuntimeApprovalID.self, "approval-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: approvalID,
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-claimed",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .claimed
        )
      )
    )

    let changedWinner = try event(
      conversationID: conversationID,
      sequence: 3,
      eventID: "event-changed-winner",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: approvalID,
        decision: .deny,
        state: .applying
      )
    )
    XCTAssertThrowsError(try state.apply(changedWinner)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .approvalDecisionMismatch)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(2))
    XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .claimed)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 3,
        eventID: "event-applying",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .applying
        )
      )
    )
    let backward = try event(
      conversationID: conversationID,
      sequence: 4,
      eventID: "event-backward",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: approvalID,
        decision: .approve,
        state: .claimed
      )
    )
    XCTAssertThrowsError(try state.apply(backward)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .approvalStateTransitionInvalid)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(3))
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .applying)
  }

  func testLiveItemIdentityConflictAndGapDoNotPartiallyAdvanceState() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(
      snapshot(
        conversationID: conversationID,
        baseCursor: .beforeFirst,
        items: [item("item-1", entity: "entity-1", text: "snapshot")]
      )
    )
    try state.apply(
      itemEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-0",
        itemID: "item-1",
        entityID: "entity-1",
        text: "updated"
      )
    )
    let conflict = try itemEvent(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-1",
      itemID: "item-1",
      entityID: "entity-other",
      text: "tampered"
    )

    XCTAssertThrowsError(try state.apply(conflict)) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .itemIdentityConflict)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(0))
    XCTAssertEqual(state.items.map(\.text), ["updated"])
    XCTAssertEqual(state.canonicalItemIdentities.first?.entityID.rawValue, "entity-1")

    let gap = try itemEvent(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-2",
      itemID: "item-2",
      entityID: "entity-2",
      text: "gap"
    )
    XCTAssertThrowsError(try state.apply(gap)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 1, actual: 2)
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(0))
    XCTAssertEqual(state.items.map(\.id), ["item-1"])
  }

  func testConfigurationAndCapabilitiesStayAgentAndRevisionConsistent() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-config-1",
        body: .configurationChanged(try configuredState(revision: 1))
      )
    )
    XCTAssertEqual(state.configurationState?.configurationRevision, 1)

    let skipped = try event(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-config-3",
      body: .configurationChanged(try configuredState(revision: 3))
    )
    XCTAssertThrowsError(try state.apply(skipped)) { error in
      XCTAssertEqual(
        error as? RuntimeConversationStateError,
        .configurationRevisionMismatch(expected: 2, actual: 3)
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(0))
    XCTAssertEqual(state.configurationState?.configurationRevision, 1)

    let claudeCapabilities = try event(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-claude-capabilities",
      body: .capabilities(try capabilities(agentKind: .claudeCode))
    )
    XCTAssertThrowsError(try state.apply(claudeCapabilities)) { error in
      XCTAssertEqual(
        error as? RuntimeConversationStateError,
        .capabilitiesAgentMismatch(expected: .codex, actual: .claudeCode)
      )
    }
    XCTAssertEqual(state.cursorState.cursor, .at(0))
    XCTAssertEqual(state.capabilities?.agentKind, .codex)
  }

  func testSnapshotBaselineCanObserveTerminalAndDiagnosticWithoutInventingTurnIdentity() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .at(7), items: []))
    let commandID = id(RuntimeCommandID.self, "command-before-snapshot")
    let turnID = id(RuntimeTurnID.self, "turn-before-snapshot")

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 8,
        eventID: "event-interrupted",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    guard
      case .interrupted(let interruptedTurnID, let interruptedCommandID)? =
        state.turnTerminal
    else {
      return XCTFail("expected interrupted terminal")
    }
    XCTAssertEqual(interruptedTurnID, turnID)
    XCTAssertEqual(interruptedCommandID, commandID)
    XCTAssertNil(state.activeTurn)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 9,
        eventID: "event-error",
        body: .error(RuntimeFailureV1(code: "daemon.test", message: "failed"))
      )
    )
    XCTAssertNil(state.failure?.commandID)
    XCTAssertNil(state.failure?.turnID)
    XCTAssertEqual(state.failure?.value.code, "daemon.test")
    XCTAssertEqual(state.failure?.value.message, "failed")
    XCTAssertEqual(state.cursorState.cursor, .at(9))
  }

  func testSnapshotBaselineDirectFailedConsumesInferenceOnlyOnce() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-before-snapshot")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .at(7), items: []))

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 8,
        eventID: "event-direct-failed",
        commandID: commandID,
        body: .error(terminalFailure())
      )
    )
    guard
      case .failed(let failedTurnID, let failedCommandID, let failure)? = state.turnTerminal
    else {
      return XCTFail("expected direct failed terminal")
    }
    XCTAssertNil(failedTurnID)
    XCTAssertEqual(failedCommandID, commandID)
    XCTAssertEqual(failure.message, "agent execution failed")
    XCTAssertNil(state.activeTurn)
    XCTAssertEqual(state.cursorState.cursor, .at(8))

    let duplicateTerminal = try event(
      conversationID: conversationID,
      sequence: 9,
      eventID: "event-second-failed",
      commandID: id(RuntimeCommandID.self, "command-next"),
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try state.apply(duplicateTerminal)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .turnStartRequired)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(8))
  }

  func testSnapshotBaselineInferenceBindsResolutionAndTerminalToOneExactTurn() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-before-snapshot")
    let turnID = id(RuntimeTurnID.self, "turn-before-snapshot")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .at(7), items: []))

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 8,
        eventID: "event-resolution",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: id(RuntimeApprovalID.self, "approval-before-snapshot"),
          decision: .approve,
          state: .applied
        )
      )
    )
    XCTAssertEqual(state.activeTurn?.turnID, turnID)
    XCTAssertEqual(state.activeTurn?.commandID, commandID)
    XCTAssertNil(state.lastApprovalResolution?.requestID)

    let mismatchedTerminal = try event(
      conversationID: conversationID,
      sequence: 9,
      eventID: "event-mismatched-terminal",
      commandID: id(RuntimeCommandID.self, "command-other"),
      body: .turnInterrupted(turnID: id(RuntimeTurnID.self, "turn-other"))
    )
    XCTAssertThrowsError(try state.apply(mismatchedTerminal)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .turnIdentityMismatch)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(8))
    XCTAssertEqual(state.activeTurn?.turnID, turnID)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 9,
        eventID: "event-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertNil(state.activeTurn)

    let actionWithoutNextStart = try event(
      conversationID: conversationID,
      sequence: 10,
      eventID: "event-next-action",
      commandID: id(RuntimeCommandID.self, "command-next"),
      body: .actionRequest(
        turnID: id(RuntimeTurnID.self, "turn-next"),
        approvalID: id(RuntimeApprovalID.self, "approval-next"),
        request: try actionRequest(requestID: "request-next")
      )
    )
    XCTAssertThrowsError(try state.apply(actionWithoutNextStart)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .turnStartRequired)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(9))
    XCTAssertTrue(state.pendingApprovals.isEmpty)
  }

  func testBaselineInferenceIsUnavailableWithoutPriorEventsAndConsumedByTerminal() throws {
    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    let commandID = id(RuntimeCommandID.self, "command-1")
    let turnID = id(RuntimeTurnID.self, "turn-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))

    let actionWithoutStart = try event(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-action",
      commandID: commandID,
      body: .actionRequest(
        turnID: turnID,
        approvalID: id(RuntimeApprovalID.self, "approval-1"),
        request: try actionRequest(requestID: "request-1")
      )
    )
    XCTAssertThrowsError(try state.apply(actionWithoutStart)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .turnStartRequired)
    }
    XCTAssertEqual(state.cursorState.cursor, .beforeFirst)

    try state.apply(snapshot(conversationID: conversationID, baseCursor: .at(4), items: []))
    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 5,
        eventID: "event-baseline-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    let secondTerminal = try event(
      conversationID: conversationID,
      sequence: 6,
      eventID: "event-second-terminal",
      commandID: id(RuntimeCommandID.self, "command-2"),
      body: .turnInterrupted(turnID: id(RuntimeTurnID.self, "turn-2"))
    )
    XCTAssertThrowsError(try state.apply(secondTerminal)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .turnStartRequired)
    }
    XCTAssertEqual(state.cursorState.cursor, .at(5))
  }

  func testEmptyRootAndEventsBeforeCapabilitiesFailClosed() throws {
    XCTAssertThrowsError(
      try RuntimeConversationState(
        conversationID: id(RuntimeConversationID.self, "")
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .emptyConversationID)
    }

    let conversationID = id(RuntimeConversationID.self, "conversation-1")
    var state = try RuntimeConversationState(conversationID: conversationID)
    let unprimedEvent = try itemEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-0",
      itemID: "item-0",
      entityID: "entity-0",
      text: "no preamble"
    )
    XCTAssertThrowsError(try state.apply(unprimedEvent)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .capabilitiesRequired)
    }
    XCTAssertEqual(state.cursorState.cursor, .beforeFirst)
    XCTAssertTrue(state.items.isEmpty)

    try state.apply(snapshot(conversationID: conversationID, baseCursor: .beforeFirst, items: []))
    let emptyCommand = try event(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-empty-command",
      commandID: id(RuntimeCommandID.self, ""),
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try state.apply(emptyCommand)) { error in
      XCTAssertEqual(error as? RuntimeConversationStateError, .emptyCommandID)
    }
    XCTAssertEqual(state.cursorState.cursor, .beforeFirst)
    XCTAssertNil(state.failure)
  }

  private func snapshot(
    conversationID: RuntimeConversationID,
    baseCursor: RuntimeStreamCursorV1,
    items: [SnapshotItemV1]
  ) throws -> ConversationSnapshotV2 {
    try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: baseCursor,
      configurationState: unconfiguredState(),
      items: [.capabilities(try capabilities())] + items
    )
  }

  private func item(
    _ itemID: String,
    entity entityID: String,
    command commandID: String? = nil,
    text: String
  ) -> SnapshotItemV1 {
    .item(
      itemID: id(RuntimeItemID.self, itemID),
      entityID: id(RuntimeEntityID.self, entityID),
      commandID: commandID.map { id(RuntimeCommandID.self, $0) },
      item: .assistantMessage(text: text, meta: RuntimeAgentItemMetaV1())
    )
  }

  private func itemEvent(
    conversationID: RuntimeConversationID,
    sequence: UInt64,
    eventID: String,
    itemID: String,
    entityID: String,
    commandID: RuntimeCommandID? = nil,
    text: String
  ) throws -> RuntimeEventV2 {
    try event(
      conversationID: conversationID,
      sequence: sequence,
      eventID: eventID,
      commandID: commandID,
      itemID: itemID,
      entityID: entityID,
      body: .item(
        .assistantMessage(text: text, meta: RuntimeAgentItemMetaV1())
      )
    )
  }

  private func event(
    conversationID: RuntimeConversationID,
    sequence: UInt64,
    eventID: String,
    commandID: RuntimeCommandID? = nil,
    itemID: String? = nil,
    entityID: String? = nil,
    body: RuntimeEventBodyV2
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: conversationID,
      eventID: id(RuntimeEventID.self, eventID),
      eventSeq: sequence,
      commandID: commandID,
      itemID: itemID.map { id(RuntimeItemID.self, $0) },
      entityID: entityID.map { id(RuntimeEntityID.self, $0) },
      body: body
    )
  }

  private func unconfiguredState() throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    )
  }

  private func configuredState(
    revision: UInt64
  ) throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: revision,
      configuration: RuntimeConversationConfigurationV2(
        vendorControl: .codex(
          RuntimeCodexConversationConfigurationV2(
            approvalPolicy: .onRequest,
            sandbox: .workspaceWrite,
            reasoningEffort: .medium
          )
        )
      )
    )
  }

  private func capabilities(
    agentKind: AgentKind = .codex
  ) throws -> RuntimeSessionCapabilitiesV1 {
    let object: [String: Any]
    switch agentKind {
    case .codex:
      object = [
        "agentKind": "codex",
        "agentVersion": "test",
        "features": [],
        "vendor": [
          "agentKind": "codex",
          "sandboxModes": ["workspace-write"],
          "persistenceSupported": true,
          "reasoningEffortLevels": ["medium"],
        ],
      ]
    case .claudeCode:
      object = [
        "agentKind": "claude_code",
        "agentVersion": "test",
        "features": [],
        "vendor": [
          "agentKind": "claude_code",
          "permissionModes": ["default"],
          "outputStyles": [],
          "hooksSupported": [],
          "cliVersion": "test",
        ],
      ]
    }
    return try decode(RuntimeSessionCapabilitiesV1.self, object)
  }

  private func actionRequest(requestID: String) throws -> RuntimeActionRequestV1 {
    try decode(
      RuntimeActionRequestV1.self,
      [
        "kind": "executeCommand",
        "requestId": requestID,
        "summary": "run",
        "vendor": [
          "agentKind": "codex",
          "sandboxAtDecision": "workspace-write",
          "approvalPolicyAtDecision": "on-request",
          "canPersist": false,
        ],
      ]
    )
  }

  private func turnSummary() throws -> RuntimeTurnSummaryV1 {
    try decode(
      RuntimeTurnSummaryV1.self,
      [
        "elapsedMs": 42,
        "totalInputTokens": NSNull(),
        "totalOutputTokens": NSNull(),
      ]
    )
  }

  private func terminalFailure() -> RuntimeFailureV1 {
    RuntimeFailureV1(
      code: "daemon.runtime.execution_failed",
      message: "agent execution failed"
    )
  }

  private func decode<Value: Decodable>(
    _ type: Value.Type,
    _ object: Any
  ) throws -> Value {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(type, from: data)
  }

  private func id<Kind: RuntimeV1IDKind>(
    _ type: RuntimeV1ID<Kind>.Type,
    _ value: String
  ) -> RuntimeV1ID<Kind> {
    RuntimeV1ID(rawValue: value)
  }
}
