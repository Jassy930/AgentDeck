import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

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
        eventID: "event-resolved",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: approvalID,
          decision: .approve,
          state: .applied
        )
      )
    )
    XCTAssertNil(state.pendingApproval)
    XCTAssertEqual(state.lastApprovalResolution?.turnID, turnID)
    XCTAssertEqual(state.lastApprovalResolution?.commandID, commandID)
    XCTAssertEqual(state.lastApprovalResolution?.approvalID, approvalID)
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-1")
    XCTAssertEqual(state.lastApprovalResolution?.decision, .approve)
    XCTAssertEqual(state.lastApprovalResolution?.deliveryState, .applied)

    try state.apply(
      event(
        conversationID: conversationID,
        sequence: 3,
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
    XCTAssertEqual(state.cursorState.cursor, .at(3))
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
          decision: .deny,
          state: .applied
        )
      )
    )

    XCTAssertEqual(state.pendingApprovals.map(\.requestID), ["request-1"])
    XCTAssertEqual(state.pendingApproval?.approvalID.rawValue, "approval-1")
    XCTAssertEqual(state.lastApprovalResolution?.approvalID.rawValue, "approval-2")
    XCTAssertEqual(state.lastApprovalResolution?.requestID, "request-2")
    XCTAssertEqual(state.cursorState.cursor, .at(3))
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

  func testSnapshotBaselineCanObserveTerminalAndErrorWithoutInventingTurnIdentity() throws {
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
        commandID: commandID,
        body: .error(RuntimeFailureV1(code: "daemon.test", message: "failed"))
      )
    )
    XCTAssertEqual(state.failure?.commandID, commandID)
    XCTAssertNil(state.failure?.turnID)
    XCTAssertEqual(state.failure?.value.code, "daemon.test")
    XCTAssertEqual(state.failure?.value.message, "failed")
    XCTAssertEqual(state.cursorState.cursor, .at(9))
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
      body: .error(RuntimeFailureV1(code: "daemon.test", message: "invalid"))
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
