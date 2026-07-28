import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class RelaySessionSourceTests: XCTestCase {
  func testRelaySessionSourceConformsToSharedFacadeAndConnectionUsesTypedUpdates() {
    requireSessionSource(RelaySessionSource.self)
    requireConnectionUpdateSource(MachineConnection.self)
    requireSendable(VerifiedRuntimeDelivery.self)
    requireSendable(MachineConnectionUpdate.self)
  }

  func testVerifiedRuntimePayloadSwitchIsExhaustiveAndNeverCarriesRawEnvelope() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let snapshot = try conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    let catalog = try catalogSnapshot(base: .beforeFirst)
    let event = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-0",
      body: .capabilities(try capabilities())
    )
    let commandState = CommandStatusReceiptV2(
      conversationID: conversationID,
      commandID: RuntimeCommandID(rawValue: "command-1"),
      configurationRevision: 0,
      status: .accepted,
      turnID: nil
    )
    let syncComplete = try makeSyncComplete(conversationID: conversationID)
    let catalogBackfill = RuntimeBackfillChunkV2.catalog(
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
      deltas: [RuntimeCatalogDeltaV2(catalogRevision: 0, changes: [])]
    )
    let conversationBackfill = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
      events: [event]
    )

    let payloads: [VerifiedRuntimePayload] = [
      .catalogSnapshot(catalog),
      .catalogBackfill(catalogBackfill),
      .catalogDelta(RuntimeCatalogDeltaV2(catalogRevision: 0, changes: [])),
      .conversationSnapshot(snapshot),
      .conversationBackfill(conversationBackfill),
      .conversationEvent(event),
      .commandState(commandState),
      .syncComplete(syncComplete),
      .typedReply(
        .command(
          .replayed(
            commandID: RuntimeCommandID(rawValue: "command-1"),
            configurationRevision: 0
          )
        )
      ),
    ]

    XCTAssertEqual(
      payloads.map(payloadKind),
      [
        "catalogSnapshot", "catalogBackfill", "catalogDelta", "conversationSnapshot",
        "conversationBackfill", "conversationEvent", "commandState", "syncComplete",
        "typedReply",
      ])

    let delivery = VerifiedRuntimeDelivery(
      fixtureMachineID: "machine-1",
      target: .conversation(
        conversationID: conversationID,
        subscriptionRequestID: RuntimeMessageID(rawValue: "subscription-1")
      ),
      streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"),
      outerCursor: .at(0),
      payload: .conversationEvent(event)
    )
    let update = MachineConnectionUpdate.delivery(delivery)
    guard case .delivery(let verified) = update else {
      return XCTFail("Connection -> Source ingress 必须是 verified delivery")
    }
    XCTAssertEqual(verified.machineID, "machine-1")
  }

  func testCatalogReducerAcceptsExactNextAndExactDuplicateButConflictDoesNotAdvance() throws {
    let originalEntry = conversationEntry(
      id: "conversation-1",
      title: "Original",
      entryRevision: 1
    )
    var reducer = try CatalogReducer(
      machineID: "machine-1",
      snapshotPages: [
        try catalogSnapshot(base: .beforeFirst, entries: [originalEntry])
      ]
    )
    let nextEntry = conversationEntry(
      id: "conversation-1",
      title: "Updated",
      entryRevision: 2
    )
    let delta = RuntimeCatalogDeltaV2(
      catalogRevision: 0,
      changes: [.upserted(entry: nextEntry)]
    )

    XCTAssertEqual(try reducer.apply(delta), .applied)
    XCTAssertEqual(reducer.cursor, .at(0))
    XCTAssertEqual(reducer.projection.summaries.map(\.title), ["Updated"])

    XCTAssertEqual(try reducer.apply(delta), .duplicate)
    XCTAssertEqual(reducer.cursor, .at(0))

    let conflict = RuntimeCatalogDeltaV2(
      catalogRevision: 0,
      changes: [
        .upserted(
          entry: conversationEntry(
            id: "conversation-1",
            title: "Forged same revision",
            entryRevision: 3
          )
        )
      ]
    )
    XCTAssertThrowsError(try reducer.apply(conflict))
    XCTAssertEqual(reducer.cursor, .at(0))
    XCTAssertEqual(reducer.projection.summaries.map(\.title), ["Updated"])

    XCTAssertThrowsError(
      try reducer.apply(RuntimeCatalogDeltaV2(catalogRevision: 2, changes: []))
    )
    XCTAssertEqual(reducer.cursor, .at(0), "gap 失败不得半推进 cursor")
  }

  func testConversationReducerDuplicateAndConflictAreAtomicAndRetainApprovalRequestID() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    let approvalID = RuntimeApprovalID(rawValue: "approval-1")
    let started = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-started",
      commandID: commandID,
      body: .turnStarted(turnID: turnID)
    )
    let approval = try runtimeEvent(
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

    XCTAssertEqual(try reducer.apply(started), .applied)
    XCTAssertEqual(try reducer.apply(approval), .applied)
    XCTAssertEqual(reducer.cursor, .at(1))
    XCTAssertEqual(reducer.projection.pendingApprovals.first?.approvalID, "approval-1")
    XCTAssertEqual(reducer.projection.pendingApprovals.first?.requestID, "request-1")

    XCTAssertEqual(try reducer.apply(approval), .duplicate)
    XCTAssertEqual(reducer.cursor, .at(1))
    XCTAssertEqual(reducer.projection.pendingApprovals.count, 1)

    let conflict = try runtimeEvent(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-conflict",
      commandID: commandID,
      body: .turnInterrupted(turnID: turnID)
    )
    XCTAssertThrowsError(try reducer.apply(conflict))
    XCTAssertEqual(reducer.cursor, .at(1))
    XCTAssertEqual(reducer.projection.pendingApprovals.first?.requestID, "request-1")

    let gap = try runtimeEvent(
      conversationID: conversationID,
      sequence: 3,
      eventID: "event-gap",
      commandID: commandID,
      body: .turnInterrupted(turnID: turnID)
    )
    XCTAssertThrowsError(try reducer.apply(gap))
    XCTAssertEqual(reducer.cursor, .at(1))
  }

  func testConversationReducerTracksParallelApprovalChainsAndPendingExpiry() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    let firstApprovalID = RuntimeApprovalID(rawValue: "approval-1")
    let secondApprovalID = RuntimeApprovalID(rawValue: "approval-2")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    for (sequence, approvalID, requestID) in [
      (UInt64(1), firstApprovalID, "request-1"),
      (UInt64(2), secondApprovalID, "request-2"),
    ] {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: sequence,
          eventID: "event-action-\(sequence)",
          commandID: commandID,
          body: .actionRequest(
            turnID: turnID,
            approvalID: approvalID,
            request: try actionRequest(requestID: requestID)
          )
        )
      )
    }

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 3,
        eventID: "event-expired-2",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: secondApprovalID,
          decision: nil,
          state: .expired
        )
      )
    )
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-1"])

    for (sequence, deliveryState) in [
      (UInt64(4), ApprovalDeliveryStateV1.claimed),
      (UInt64(5), .applying),
      (UInt64(6), .applied),
    ] {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: sequence,
          eventID: "event-\(deliveryState.rawValue)-1",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: firstApprovalID,
            decision: .approve,
            state: deliveryState
          )
        )
      )
    }
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 7,
        eventID: "event-completed",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertEqual(reducer.cursor, .at(7))
  }

  func testConversationReducerKeepsRetryWinnerUntilExpiry() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    let approvalID = RuntimeApprovalID(rawValue: "approval-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-action",
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
    ] {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: sequence,
          eventID: "event-\(deliveryState.rawValue)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: approvalID,
            decision: .deny,
            state: deliveryState
          )
        )
      )
    }

    let prematureTerminal = try runtimeEvent(
      conversationID: conversationID,
      sequence: 5,
      eventID: "event-premature-terminal",
      commandID: commandID,
      body: .turnInterrupted(turnID: turnID)
    )
    XCTAssertThrowsError(try reducer.apply(prematureTerminal))
    XCTAssertEqual(reducer.cursor, .at(4))

    for (sequence, deliveryState) in [
      (UInt64(5), ApprovalDeliveryStateV1.applying),
      (UInt64(6), .expired),
    ] {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: sequence,
          eventID: "event-retry-\(deliveryState.rawValue)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: approvalID,
            decision: .deny,
            state: deliveryState
          )
        )
      )
    }
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 7,
        eventID: "event-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertEqual(reducer.cursor, .at(7))
  }

  func testConversationReducerRejectsRequestIDReuseWhilePendingAndResolved() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    let firstApprovalID = RuntimeApprovalID(rawValue: "approval-1")
    let secondApprovalID = RuntimeApprovalID(rawValue: "approval-2")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    _ = try reducer.apply(
      runtimeEvent(
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

    let duplicateWhilePending = try runtimeEvent(
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
    XCTAssertThrowsError(try reducer.apply(duplicateWhilePending)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalConflict)
    }
    XCTAssertEqual(reducer.cursor, .at(1))
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-1"])

    _ = try reducer.apply(
      runtimeEvent(
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
    let duplicateAfterResolution = try runtimeEvent(
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
    XCTAssertThrowsError(try reducer.apply(duplicateAfterResolution)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalConflict)
    }
    XCTAssertEqual(reducer.cursor, .at(2))
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)
  }

  func testConversationReducerRejectsWinnerChangeAndBackwardTransitionAtomically() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    let approvalID = RuntimeApprovalID(rawValue: "approval-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-action",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: approvalID,
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    _ = try reducer.apply(
      runtimeEvent(
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

    let changedWinner = try runtimeEvent(
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
    XCTAssertThrowsError(try reducer.apply(changedWinner)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalIdentityMismatch)
    }
    XCTAssertEqual(reducer.cursor, .at(2))

    _ = try reducer.apply(
      runtimeEvent(
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
    let backward = try runtimeEvent(
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
    XCTAssertThrowsError(try reducer.apply(backward)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalConflict)
    }
    XCTAssertEqual(reducer.cursor, .at(3))
  }

  func testConversationReducerCapsAllApprovalIdentitiesPerTurnAtomically() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    for index in 0..<31 {
      let actionSequence = UInt64(index * 2 + 1)
      let approvalID = RuntimeApprovalID(rawValue: "approval-\(index)")
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: actionSequence,
          eventID: "event-action-\(index)",
          commandID: commandID,
          body: .actionRequest(
            turnID: turnID,
            approvalID: approvalID,
            request: try actionRequest(requestID: "request-\(index)")
          )
        )
      )
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: actionSequence + 1,
          eventID: "event-claimed-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: approvalID,
            decision: .approve,
            state: .claimed
          )
        )
      )
    }

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 63,
        eventID: "event-action-31",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-31"),
          request: try actionRequest(requestID: "request-31")
        )
      )
    )
    XCTAssertEqual(reducer.cursor, .at(63))
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-31"])
    let overflow = try runtimeEvent(
      conversationID: conversationID,
      sequence: 64,
      eventID: "event-action-overflow",
      commandID: commandID,
      body: .actionRequest(
        turnID: turnID,
        approvalID: RuntimeApprovalID(rawValue: "approval-overflow"),
        request: try actionRequest(requestID: "request-overflow")
      )
    )
    XCTAssertThrowsError(try reducer.apply(overflow)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalConflict)
    }
    XCTAssertEqual(reducer.cursor, .at(63))
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-31"])
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.requestID), ["request-31"])

    var nextSequence: UInt64 = 64
    for index in 0..<31 {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-applying-existing-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: RuntimeApprovalID(rawValue: "approval-\(index)"),
            decision: .approve,
            state: .applying
          )
        )
      )
      nextSequence += 1
    }
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-31"])
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: nextSequence,
        eventID: "event-claimed-existing-pending",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-31"),
          decision: .approve,
          state: .claimed
        )
      )
    )
    XCTAssertEqual(reducer.cursor, .at(nextSequence))
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)
  }

  func testConversationReducerSnapshotBaselineInferenceBindsOneExactTurn() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-before-snapshot")
    let turnID = RuntimeTurnID(rawValue: "turn-before-snapshot")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .at(7))
    )

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 8,
        eventID: "event-inferred-resolution",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-before-snapshot"),
          decision: .approve,
          state: .applied
        )
      )
    )
    XCTAssertEqual(reducer.cursor, .at(8))
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)

    let wrongCommand = try runtimeEvent(
      conversationID: conversationID,
      sequence: 9,
      eventID: "event-wrong-command",
      commandID: RuntimeCommandID(rawValue: "command-other"),
      body: .turnInterrupted(turnID: turnID)
    )
    XCTAssertThrowsError(try reducer.apply(wrongCommand)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnIdentityMismatch)
    }
    XCTAssertEqual(reducer.cursor, .at(8))

    let wrongTurn = try runtimeEvent(
      conversationID: conversationID,
      sequence: 9,
      eventID: "event-wrong-turn",
      commandID: commandID,
      body: .turnInterrupted(turnID: RuntimeTurnID(rawValue: "turn-other"))
    )
    XCTAssertThrowsError(try reducer.apply(wrongTurn)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnIdentityMismatch)
    }
    XCTAssertEqual(reducer.cursor, .at(8))

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 9,
        eventID: "event-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertEqual(reducer.cursor, .at(9))
    XCTAssertEqual(reducer.projection.completedEventID, "event-terminal")

    let actionWithoutNextStart = try runtimeEvent(
      conversationID: conversationID,
      sequence: 10,
      eventID: "event-action-without-next-start",
      commandID: RuntimeCommandID(rawValue: "command-next"),
      body: .actionRequest(
        turnID: RuntimeTurnID(rawValue: "turn-next"),
        approvalID: RuntimeApprovalID(rawValue: "approval-next"),
        request: try actionRequest(requestID: "request-next")
      )
    )
    XCTAssertThrowsError(try reducer.apply(actionWithoutNextStart)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnStartRequired)
    }
    XCTAssertEqual(reducer.cursor, .at(9))
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)
  }

  func testConversationReducerSnapshotBaselineInferenceAcceptsDirectTerminalOnlyOnce() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-before-snapshot")
    let turnID = RuntimeTurnID(rawValue: "turn-before-snapshot")
    let terminalBodies: [(name: String, body: RuntimeEventBodyV2)] = [
      (
        "completed",
        .turnCompleted(turnID: turnID, summary: try turnSummary())
      ),
      ("interrupted", .turnInterrupted(turnID: turnID)),
    ]

    for terminal in terminalBodies {
      var reducer = try ConversationReducer(
        machineID: "machine-1",
        snapshot: conversationSnapshot(conversationID: conversationID, base: .at(7))
      )
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: 8,
          eventID: "event-direct-\(terminal.name)",
          commandID: commandID,
          body: terminal.body
        )
      )
      XCTAssertEqual(reducer.cursor, .at(8))
      XCTAssertEqual(reducer.projection.completedEventID, "event-direct-\(terminal.name)")

      let actionWithoutStart = try runtimeEvent(
        conversationID: conversationID,
        sequence: 9,
        eventID: "event-action-without-start-\(terminal.name)",
        commandID: RuntimeCommandID(rawValue: "command-next"),
        body: .actionRequest(
          turnID: RuntimeTurnID(rawValue: "turn-next"),
          approvalID: RuntimeApprovalID(rawValue: "approval-next"),
          request: try actionRequest(requestID: "request-next")
        )
      )
      XCTAssertThrowsError(try reducer.apply(actionWithoutStart)) { error in
        XCTAssertEqual(error as? RelaySourceReducerError, .turnStartRequired)
      }
      XCTAssertEqual(reducer.cursor, .at(8))

      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: 9,
          eventID: "event-next-started-\(terminal.name)",
          commandID: RuntimeCommandID(rawValue: "command-next"),
          body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-next"))
        )
      )
      XCTAssertEqual(reducer.cursor, .at(9))
    }
  }

  func testConversationReducerBaselineInferenceRequiresPriorCursorAndCapsInferredLedger()
    throws
  {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-before-snapshot")
    let turnID = RuntimeTurnID(rawValue: "turn-before-snapshot")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    let resolutionWithoutBaseline = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-resolution-without-baseline",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: RuntimeApprovalID(rawValue: "approval-no-baseline"),
        decision: nil,
        state: .expired
      )
    )
    XCTAssertThrowsError(try reducer.apply(resolutionWithoutBaseline)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnStartRequired)
    }
    XCTAssertEqual(reducer.cursor, .beforeFirst)

    reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .at(4))
    )
    for index in 0..<32 {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: UInt64(index + 5),
          eventID: "event-inferred-claimed-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: RuntimeApprovalID(rawValue: "approval-inferred-\(index)"),
            decision: .approve,
            state: .claimed
          )
        )
      )
    }
    XCTAssertEqual(reducer.cursor, .at(36))

    let overflow = try runtimeEvent(
      conversationID: conversationID,
      sequence: 37,
      eventID: "event-inferred-overflow",
      commandID: commandID,
      body: .approvalResolved(
        turnID: turnID,
        approvalID: RuntimeApprovalID(rawValue: "approval-inferred-overflow"),
        decision: .approve,
        state: .claimed
      )
    )
    XCTAssertThrowsError(try reducer.apply(overflow)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .approvalConflict)
    }
    XCTAssertEqual(reducer.cursor, .at(36))

    var nextSequence: UInt64 = 37
    for index in 0..<32 {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-inferred-applying-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: RuntimeApprovalID(rawValue: "approval-inferred-\(index)"),
            decision: .approve,
            state: .applying
          )
        )
      )
      nextSequence += 1
    }
    for index in 0..<32 {
      _ = try reducer.apply(
        runtimeEvent(
          conversationID: conversationID,
          sequence: nextSequence,
          eventID: "event-inferred-applied-\(index)",
          commandID: commandID,
          body: .approvalResolved(
            turnID: turnID,
            approvalID: RuntimeApprovalID(rawValue: "approval-inferred-\(index)"),
            decision: .approve,
            state: .applied
          )
        )
      )
      nextSequence += 1
    }
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: nextSequence,
        eventID: "event-inferred-terminal",
        commandID: commandID,
        body: .turnInterrupted(turnID: turnID)
      )
    )
    XCTAssertEqual(reducer.cursor, .at(nextSequence))

    let secondTerminal = try runtimeEvent(
      conversationID: conversationID,
      sequence: nextSequence + 1,
      eventID: "event-second-terminal",
      commandID: RuntimeCommandID(rawValue: "command-next"),
      body: .turnInterrupted(turnID: RuntimeTurnID(rawValue: "turn-next"))
    )
    XCTAssertThrowsError(try reducer.apply(secondTerminal)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnStartRequired)
    }
    XCTAssertEqual(reducer.cursor, .at(nextSequence))
  }

  func testConversationReducerCommandlessDiagnosticDoesNotTerminateActiveTurn() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-diagnostic",
        body: .error(RuntimeFailureV1(code: "daemon.adapter.warning", message: "retrying"))
      )
    )
    XCTAssertNil(reducer.projection.failedEventID)

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-failed",
        commandID: commandID,
        body: .error(terminalFailure())
      )
    )
    XCTAssertEqual(reducer.projection.failedEventID, "event-failed")
    XCTAssertNil(reducer.projection.completedEventID)

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 3,
        eventID: "event-next-started",
        commandID: RuntimeCommandID(rawValue: "command-2"),
        body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-2"))
      )
    )
    XCTAssertNil(reducer.projection.failedEventID)
  }

  func testConversationReducerFailedRejectsWrongCommandAndUnresolvedApprovalAtomically() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )

    let wrongCommand = try runtimeEvent(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-wrong-command",
      commandID: RuntimeCommandID(rawValue: "command-other"),
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try reducer.apply(wrongCommand)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnIdentityMismatch)
    }
    XCTAssertEqual(reducer.cursor, .at(0))

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    let unresolvedFailure = try runtimeEvent(
      conversationID: conversationID,
      sequence: 2,
      eventID: "event-unresolved-failure",
      commandID: commandID,
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try reducer.apply(unresolvedFailure)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .unresolvedApproval)
    }
    XCTAssertEqual(reducer.cursor, .at(1))
    XCTAssertEqual(reducer.projection.pendingApprovals.map(\.approvalID), ["approval-1"])
    XCTAssertNil(reducer.projection.failedEventID)

    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 2,
        eventID: "event-claimed",
        commandID: commandID,
        body: .approvalResolved(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          decision: .approve,
          state: .claimed
        )
      )
    )
    let activeDeliveryFailure = try runtimeEvent(
      conversationID: conversationID,
      sequence: 3,
      eventID: "event-active-delivery-failure",
      commandID: commandID,
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try reducer.apply(activeDeliveryFailure)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .unresolvedApproval)
    }
    XCTAssertEqual(reducer.cursor, .at(2))
    XCTAssertTrue(reducer.projection.pendingApprovals.isEmpty)
    XCTAssertNil(reducer.projection.failedEventID)
  }

  func testConversationReducerSnapshotDirectFailedConsumesInferenceOnlyOnce() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    var reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .at(7))
    )
    _ = try reducer.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 8,
        eventID: "event-direct-failed",
        commandID: RuntimeCommandID(rawValue: "command-before-snapshot"),
        body: .error(terminalFailure())
      )
    )
    XCTAssertEqual(reducer.projection.failedEventID, "event-direct-failed")

    let duplicateTerminal = try runtimeEvent(
      conversationID: conversationID,
      sequence: 9,
      eventID: "event-second-failed",
      commandID: RuntimeCommandID(rawValue: "command-next"),
      body: .error(terminalFailure())
    )
    XCTAssertThrowsError(try reducer.apply(duplicateTerminal)) { error in
      XCTAssertEqual(error as? RelaySourceReducerError, .turnStartRequired)
    }
    XCTAssertEqual(reducer.cursor, .at(8))
    XCTAssertEqual(reducer.projection.failedEventID, "event-direct-failed")
  }

  func testInboxIsDerivedOnlyFromVerifiedCatalogAndConversationProjections() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let catalog = try CatalogReducer(
      machineID: "machine-1",
      snapshotPages: [
        try catalogSnapshot(
          base: .beforeFirst,
          entries: [
            conversationEntry(
              id: conversationID.rawValue,
              title: "Needs approval",
              entryRevision: 1
            )
          ]
        )
      ]
    )
    var conversation = try ConversationReducer(
      machineID: "machine-1",
      snapshot: conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    )
    let commandID = RuntimeCommandID(rawValue: "command-1")
    let turnID = RuntimeTurnID(rawValue: "turn-1")
    _ = try conversation.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 0,
        eventID: "event-started",
        commandID: commandID,
        body: .turnStarted(turnID: turnID)
      )
    )
    _ = try conversation.apply(
      runtimeEvent(
        conversationID: conversationID,
        sequence: 1,
        eventID: "event-approval",
        commandID: commandID,
        body: .actionRequest(
          turnID: turnID,
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          request: try actionRequest(requestID: "request-1")
        )
      )
    )

    let items = InboxReducer.derive(
      catalog: catalog.projection,
      conversations: [conversation.projection]
    )

    XCTAssertEqual(items.count, 1)
    XCTAssertEqual(items[0].id, "machine-1/conversation-1/approval-1")
    XCTAssertEqual(items[0].machineID, "machine-1")
    XCTAssertEqual(items[0].conversationID, "conversation-1")
    XCTAssertEqual(items[0].kind, .waitingApproval)
    XCTAssertEqual(items[0].title, "Needs approval")
  }

  func testCatalogSnapshotAccumulatorRejectsBeforeRetainingPageEntryOrByteOverflow() throws {
    let emptyPage = try catalogSnapshot(base: .beforeFirst)
    let oneEntryPage = try catalogSnapshot(
      base: .beforeFirst,
      entries: [conversationEntry(id: "conversation-1", title: "one", entryRevision: 1)]
    )

    var pageBound = CatalogSnapshotAccumulator(
      maximumPages: 1,
      maximumEntries: 10,
      maximumBytes: 1_024 * 1_024
    )
    try pageBound.append(emptyPage)
    XCTAssertThrowsError(try pageBound.append(emptyPage))
    XCTAssertEqual(pageBound.pages.count, 1)

    var entryBound = CatalogSnapshotAccumulator(
      maximumPages: 2,
      maximumEntries: 1,
      maximumBytes: 1_024 * 1_024
    )
    try entryBound.append(oneEntryPage)
    XCTAssertThrowsError(try entryBound.append(oneEntryPage))
    XCTAssertEqual(entryBound.pages.count, 1)
    XCTAssertEqual(entryBound.entryCount, 1)

    let exactBytes = try canonicalBytes(emptyPage).count
    var byteBound = CatalogSnapshotAccumulator(
      maximumPages: 2,
      maximumEntries: 10,
      maximumBytes: exactBytes
    )
    try byteBound.append(emptyPage)
    XCTAssertThrowsError(try byteBound.append(emptyPage))
    XCTAssertEqual(byteBound.pages.count, 1)
    XCTAssertEqual(byteBound.encodedBytes, exactBytes)
  }

  func testMachineScopeOpensStartsAndSubscribesOnlySelectedMachine() async throws {
    let firstConnection = AssemblySpyConnection(machineID: "machine-1")
    let secondConnection = AssemblySpyConnection(machineID: "machine-2")
    let provider = AssemblySpyProvider(
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        ),
        PairedMachine(
          id: "machine-2",
          name: "Two",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 2, count: 32)
        ),
      ],
      connections: [
        "machine-1": firstConnection,
        "machine-2": secondConnection,
      ]
    )
    let commands = AssemblySpyCommandClient()
    let source = try await RelaySessionSource.assemble(
      scope: .machine("machine-1"),
      provider: provider,
      commandClient: commands
    )

    _ = await source.machines()

    let opened = await provider.openedMachineIDs()
    let subscribed = await commands.subscribedMachineIDs()
    let firstClaims = await firstConnection.claimCount()
    let secondClaims = await secondConnection.claimCount()
    XCTAssertEqual(opened, ["machine-1"])
    XCTAssertEqual(subscribed, ["machine-1"])
    XCTAssertEqual(firstClaims, 1)
    XCTAssertEqual(secondClaims, 0)
  }

  func testCatalogSubscriptionWaitsForExactBusinessReadyScopeAndIgnoresStaleReady()
    async throws
  {
    let connection = AssemblySpyConnection(startsBusinessReady: false)
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )

    _ = await source.conversations(machineID: "machine-1")
    var subscriptionCount = await commands.catalogSubscriptionCount()
    XCTAssertEqual(subscriptionCount, 0)

    let first = TransferAssemblyScope(
      connectionID: UUID(),
      generation: RelayTransportGeneration(rawValue: 1)
    )
    await connection.send(.connectionScope(first))
    await connection.send(.connectionState(.connected))
    for _ in 0..<100 { await Task.yield() }
    subscriptionCount = await commands.catalogSubscriptionCount()
    XCTAssertEqual(
      subscriptionCount,
      0,
      "transport connected 不能冒充 control ACK 已 flush"
    )

    await connection.send(.businessReady(first))
    let firstReady = await eventually { await commands.catalogSubscriptionCount() == 1 }
    XCTAssertTrue(firstReady)
    await connection.send(.businessReady(first))
    for _ in 0..<100 { await Task.yield() }
    subscriptionCount = await commands.catalogSubscriptionCount()
    XCTAssertEqual(subscriptionCount, 1, "duplicate ready 必须幂等")

    let second = TransferAssemblyScope(
      connectionID: UUID(),
      generation: RelayTransportGeneration(rawValue: 1)
    )
    await connection.send(.connectionScope(second))
    await connection.send(.businessReady(first))
    for _ in 0..<100 { await Task.yield() }
    subscriptionCount = await commands.catalogSubscriptionCount()
    XCTAssertEqual(
      subscriptionCount,
      1,
      "旧 connectionID 的 ready 不能越过 fresh transport generation"
    )

    await connection.send(.businessReady(second))
    let secondReady = await eventually { await commands.catalogSubscriptionCount() == 2 }
    XCTAssertTrue(secondReady)
    await source.shutdown()
  }

  func testLateConversationObservationReplaysCurrentConnectedState() async throws {
    let connection = AssemblySpyConnection()
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )

    var machines = await source.machines().makeAsyncIterator()
    await connection.send(.connectionState(.connected))
    var observedConnectedMachine = false
    for _ in 0..<2 {
      guard let state = await machines.next() else { break }
      if case .ready(let summaries, _) = state,
        summaries.first?.connectionState == .connected
      {
        observedConnectedMachine = true
        break
      }
    }
    XCTAssertTrue(observedConnectedMachine)

    let stream = await source.conversation(conversationID: "late-connected-conversation")
    var iterator = stream.makeAsyncIterator()
    guard case .connectionState(.connected)? = await iterator.next() else {
      return XCTFail("late conversation observer 必须立即读到 current connected")
    }
    await source.shutdown()
  }

  func testMultiMachineAssemblyFailureShutsDownAndJoinsAlreadyStartedOwners() async throws {
    let firstConnection = AssemblySpyConnection(machineID: "machine-1", blockShutdown: true)
    let provider = AssemblySpyProvider(
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        ),
        PairedMachine(
          id: "machine-2",
          name: "Two",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 2, count: 32)
        ),
      ],
      connections: ["machine-1": firstConnection]
    )
    let completion = AssemblyCompletionProbe()
    let assembly = Task {
      let failed: Bool
      do {
        _ = try await RelaySessionSource.assemble(
          scope: .allPairedMachines,
          provider: provider,
          commandClient: AssemblySpyCommandClient()
        )
        failed = false
      } catch {
        failed = true
      }
      await completion.markCompleted()
      return failed
    }

    let shutdownEntered = await eventually {
      await firstConnection.shutdownCount() == 1
    }
    XCTAssertTrue(shutdownEntered, "第二台 open 失败后必须立即 teardown 第一台 started owner")
    let completedBeforeJoin = await completion.completedValue()
    XCTAssertFalse(completedBeforeJoin, "assembly failure 返回前必须 join owner shutdown")

    await firstConnection.releaseShutdowns()
    let failed = await assembly.value
    XCTAssertTrue(failed)
    let completedAfterJoin = await completion.completedValue()
    XCTAssertTrue(completedAfterJoin)
  }

  func testSourcePublishesColdSnapshotThenVerifiedBackfillEventsAfterBarrier() async throws {
    let connection = AssemblySpyConnection()
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    let stream = await source.conversation(conversationID: "conversation-1")
    let recordedRequestID = await commands.latestConversationSubscriptionRequestID(
      "conversation-1"
    )
    let subscriptionRequestID = try XCTUnwrap(recordedRequestID)
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let generation = RuntimeStreamGeneration(rawValue: "generation-1")
    let snapshot = try conversationSnapshot(conversationID: conversationID, base: .beforeFirst)
    let event = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-backfill-0",
      body: .capabilities(try capabilities())
    )
    let backfill = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
      events: [event]
    )

    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: subscriptionRequestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .typedReply(.subscription(.subscribed(streamGeneration: generation)))
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: subscriptionRequestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .conversationSnapshot(snapshot)
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: subscriptionRequestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .conversationBackfill(backfill)
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: subscriptionRequestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .syncComplete(
            try makeSyncComplete(conversationID: conversationID, outerCursor: .at(10))
          )
        )
      )
    )

    var iterator = stream.makeAsyncIterator()
    let first = await iterator.next()
    let second = await iterator.next()
    guard case .snapshot(let observedSnapshot)? = first else {
      return XCTFail("barrier 后第一项必须是 snapshot")
    }
    guard case .event(let observedEvent)? = second else {
      return XCTFail("snapshot 后必须按序交付 backfill event")
    }
    XCTAssertEqual(observedSnapshot.baseEventCursor, .beforeFirst)
    XCTAssertEqual(observedEvent.eventID.rawValue, "event-backfill-0")
    let retainedBootstrapItems = await source.debugRetainedConversationBootstrapItemCount(
      "conversation-1"
    )
    XCTAssertEqual(retainedBootstrapItems, 0)
  }

  func testDurableCommitFailureDiscardsPermitBeforeReducerOrBroadcastProgress() async throws {
    let connection = AssemblySpyConnection(failPreparedCommit: true)
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    let conversationID = RuntimeConversationID(rawValue: "conversation-commit")
    let stream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let requestID = try XCTUnwrap(recordedRequestID)
    let generation = RuntimeStreamGeneration(rawValue: "generation-commit")
    await sendConversationSnapshotBarrier(
      connection: connection,
      conversationID: conversationID,
      requestID: requestID,
      generation: generation,
      base: .beforeFirst
    )
    var iterator = stream.makeAsyncIterator()
    guard case .snapshot? = await iterator.next() else {
      return XCTFail("commit failure 测试必须先建立 committed baseline")
    }

    let event = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-commit-fails",
      body: .capabilities(try capabilities())
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          machineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: requestID
          ),
          streamGeneration: generation,
          outerCursor: .at(11),
          payload: .conversationEvent(event),
          ingressPermit: MachineVerifiedDeliveryPermit()
        )
      )
    )

    let discarded = await eventually { await connection.discardedPreparedCount() == 1 }
    XCTAssertTrue(discarded)
    let cursor = await source.debugConversationCursor(conversationID.rawValue)
    XCTAssertEqual(cursor, .beforeFirst)
    guard case .connectionState(.securityError)? = await iterator.next() else {
      return XCTFail("durable commit 失败必须 fail-close，不能发布 staged event")
    }
    let committedPrepared = await connection.committedPreparedCount()
    XCTAssertEqual(committedPrepared, 0)
  }

  func testCommitReentrancyCannotOverwriteReplacementOrDiscardCommittedPermit() async throws {
    let connection = AssemblySpyConnection(blockPreparedCommit: true)
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    let conversationID = RuntimeConversationID(rawValue: "conversation-reentrant-commit")
    let firstStream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedFirstRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let firstRequestID = try XCTUnwrap(recordedFirstRequestID)
    let generation = RuntimeStreamGeneration(rawValue: "generation-reentrant-commit")
    await sendConversationSnapshotBarrier(
      connection: connection,
      conversationID: conversationID,
      requestID: firstRequestID,
      generation: generation,
      base: .beforeFirst
    )
    var firstIterator = firstStream.makeAsyncIterator()
    guard case .snapshot? = await firstIterator.next() else {
      return XCTFail("reentrancy test 需要先建立 committed baseline")
    }

    let event = try runtimeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-reentrant-commit",
      body: .capabilities(try capabilities())
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          machineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: firstRequestID
          ),
          streamGeneration: generation,
          outerCursor: .at(11),
          payload: .conversationEvent(event),
          ingressPermit: MachineVerifiedDeliveryPermit()
        )
      )
    )
    let commitStarted = await eventually {
      await connection.startedPreparedCommitCount() == 1
    }
    XCTAssertTrue(commitStarted, "prepared commit 必须先悬挂在跨 actor await")

    await source.debugForceConversationRecovery(conversationID.rawValue)
    let recordedReplacementRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let replacementRequestID = try XCTUnwrap(recordedReplacementRequestID)
    XCTAssertNotEqual(replacementRequestID, firstRequestID)

    await connection.releasePreparedCommits()
    let committed = await eventually { await connection.committedPreparedCount() == 1 }
    XCTAssertTrue(committed)
    let discarded = await connection.discardedPreparedCount()
    XCTAssertEqual(discarded, 0)
    let currentRequestID = await source.debugConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    XCTAssertEqual(
      currentRequestID,
      replacementRequestID,
      "旧 scratch 不得回滚 replacement request/generation"
    )
    let currentCursor = await source.debugConversationCursor(conversationID.rawValue)
    XCTAssertEqual(
      currentCursor,
      .beforeFirst,
      "旧 scratch 不得把事件 reducer 复活到 fresh recovery"
    )
    await source.shutdown()
  }

  func testRelaySessionSourceShutdownJoinsConsumersAndConnections() async throws {
    let (source, connection, commands) = try makeSourceHarness()
    _ = await source.machines()

    await source.shutdown()

    let shutdownCount = await connection.shutdownCount()
    XCTAssertEqual(shutdownCount, 1)
    let commandShutdownCount = await commands.shutdownCount()
    XCTAssertEqual(commandShutdownCount, 1)
  }

  func testConcurrentShutdownWaitsForSameBarrierAndPostShutdownCannotResubscribe() async throws {
    let connection = AssemblySpyConnection(blockShutdown: true)
    let commands = AssemblySpyCommandClient(blockShutdown: true)
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    _ = await source.machines()

    let firstCompletion = AssemblyCompletionProbe()
    let secondCompletion = AssemblyCompletionProbe()
    let first = Task {
      await source.shutdown()
      await firstCompletion.markCompleted()
    }
    let shutdownEntered = await eventually {
      let connectionCount = await connection.shutdownCount()
      let commandCount = await commands.shutdownCount()
      return connectionCount == 1 && commandCount == 1
    }
    XCTAssertTrue(shutdownEntered)
    let second = Task {
      await source.shutdown()
      await secondCompletion.markCompleted()
    }
    for _ in 0..<100 { await Task.yield() }
    let secondCompletedEarly = await secondCompletion.completedValue()
    XCTAssertFalse(secondCompletedEarly)

    await connection.releaseShutdowns()
    for _ in 0..<100 { await Task.yield() }
    let completedBeforeCommandJoin = await firstCompletion.completedValue()
    XCTAssertFalse(
      completedBeforeCommandJoin,
      "connection 已退出时，source 仍必须等待 command/pairing teardown"
    )
    await commands.releaseShutdowns()
    let bothCompleted = await eventually {
      let firstDone = await firstCompletion.completedValue()
      let secondDone = await secondCompletion.completedValue()
      return firstDone && secondDone
    }
    XCTAssertTrue(bothCompleted, "所有 shutdown caller 必须等待同一个 teardown completion")
    _ = await first.value
    _ = await second.value

    let catalogCountBefore = await commands.catalogSubscriptionCount()
    let conversation = await source.conversation(conversationID: "after-shutdown")
    var iterator = conversation.makeAsyncIterator()
    guard case .connectionState(.machineOffline)? = await iterator.next() else {
      return XCTFail("shutdown 后 observation 必须立即 terminal")
    }
    let terminal = await iterator.next()
    XCTAssertNil(terminal)
    let catalogCountAfter = await commands.catalogSubscriptionCount()
    XCTAssertEqual(catalogCountAfter, catalogCountBefore)
  }

  func testSubscriptionFailureDuringBarrierIsObservableAndReconnectRetriesFreshRequest()
    async throws
  {
    let connection = AssemblySpyConnection()
    let commands = AssemblySpyCommandClient(conversationSubscriptionFailure: .machineOffline)
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    let stream = await source.conversation(conversationID: "conversation-retry")
    var iterator = stream.makeAsyncIterator()
    guard case .connectionState(.machineOffline)? = await iterator.next() else {
      return XCTFail("subscribe failure 必须越过 awaitingBarrier 成为可观察状态")
    }
    let firstCount = await commands.conversationSubscriptionCount("conversation-retry")
    XCTAssertEqual(firstCount, 0, "failed subscription is not recorded as successful")

    await commands.setConversationSubscriptionFailure(nil)
    let reconnectScope = TransferAssemblyScope(
      connectionID: UUID(),
      generation: RelayTransportGeneration(rawValue: 2)
    )
    await connection.send(.connectionScope(reconnectScope))
    await connection.send(.connectionState(.connected))
    await connection.send(.businessReady(reconnectScope))
    guard case .connectionState(.lagged(reason: .snapshotRequired))? = await iterator.next() else {
      return XCTFail("reconnect 必须轮换 generation 并重试 fresh snapshot")
    }
    let retried = await eventually {
      await commands.conversationSubscriptionCount("conversation-retry") == 1
    }
    XCTAssertTrue(retried)
    await source.shutdown()
  }

  func testFatalSubscriptionFailureTerminatesObservation() async throws {
    let connection = AssemblySpyConnection(blockShutdown: true)
    let commands = AssemblySpyCommandClient(conversationSubscriptionFailure: .revoked)
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands
    )
    let stream = await source.conversation(conversationID: "conversation-revoked")
    var iterator = stream.makeAsyncIterator()
    guard case .connectionState(.revoked)? = await iterator.next() else {
      return XCTFail("fatal subscribe failure 必须可观察")
    }
    let terminal = await iterator.next()
    XCTAssertNil(terminal)

    let shutdownStarted = await eventually {
      await connection.shutdownCount() == 1
    }
    XCTAssertTrue(shutdownStarted, "fatal latch 必须关闭 exact connection owner")
    let subscriptionCount = await commands.conversationSubscriptionCount(
      "conversation-revoked"
    )

    await commands.setConversationSubscriptionFailure(nil)
    await connection.send(.connectionState(.connected))
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          machineID: "machine-1",
          target: .request(RuntimeMessageID(rawValue: "late-after-revoked")),
          streamGeneration: RuntimeStreamGeneration(rawValue: "late-generation"),
          outerCursor: .beforeFirst,
          payload: .typedReply(
            .failure(
              RuntimeFailureV1(
                code: "remote.late",
                message: "must be discarded after fatal latch"
              )
            )
          ),
          ingressPermit: MachineVerifiedDeliveryPermit()
        )
      )
    )
    let lateDiscarded = await eventually {
      await connection.discardedPreparedCount() == 1
    }
    XCTAssertTrue(lateDiscarded, "fatal 后迟到 verified delivery 必须 exact discard")

    let repeated = await source.conversation(conversationID: "conversation-revoked")
    var repeatedIterator = repeated.makeAsyncIterator()
    guard case .connectionState(.revoked)? = await repeatedIterator.next() else {
      return XCTFail("existing observation API 不得复活 finished broadcaster")
    }
    let repeatedTerminal = await repeatedIterator.next()
    XCTAssertNil(repeatedTerminal)
    let fresh = await source.conversation(conversationID: "conversation-after-revoked")
    var freshIterator = fresh.makeAsyncIterator()
    guard case .connectionState(.revoked)? = await freshIterator.next() else {
      return XCTFail("fatal machine 上的新 observation 必须立即返回同一 terminal")
    }
    let freshTerminal = await freshIterator.next()
    XCTAssertNil(freshTerminal)
    let subscriptionCountAfter = await commands.conversationSubscriptionCount(
      "conversation-revoked"
    )
    XCTAssertEqual(subscriptionCountAfter, subscriptionCount)

    await connection.releaseShutdowns()
    await source.shutdown()
  }

  func testLateObserverCapacityIsTargetedAndDoesNotRestartExistingObservation() async throws {
    let (source, connection, commands) = try makeSourceHarness()
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let firstStream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedFirstRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let firstRequestID = try XCTUnwrap(recordedFirstRequestID)
    let firstGeneration = RuntimeStreamGeneration(rawValue: "generation-first")
    await sendConversationSnapshotBarrier(
      connection: connection,
      conversationID: conversationID,
      requestID: firstRequestID,
      generation: firstGeneration
    )
    var firstIterator = firstStream.makeAsyncIterator()
    guard case .snapshot? = await firstIterator.next() else {
      return XCTFail("首个 observer 必须先取得 snapshot baseline")
    }

    let secondStream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedSecondRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    XCTAssertEqual(recordedSecondRequestID, firstRequestID)
    let subscriptionCount = await commands.conversationSubscriptionCount(
      conversationID.rawValue
    )
    XCTAssertEqual(subscriptionCount, 1, "late observer 不得 replacement/resubscribe 共享远端流")

    var secondIterator = secondStream.makeAsyncIterator()
    guard
      case .connectionState(.lagged(reason: .snapshotRequired))? =
        await secondIterator.next()
    else {
      return XCTFail("cap/+1 只给迟到 observer 返回定向 snapshot-required")
    }
    let secondTerminal = await secondIterator.next()
    XCTAssertNil(secondTerminal)

    let event = try runtimeEvent(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-after-late-observer",
      body: .capabilities(try capabilities())
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: firstRequestID
          ),
          streamGeneration: firstGeneration,
          outerCursor: .at(11),
          payload: .conversationEvent(event)
        )
      )
    )
    guard case .event(let delivered)? = await firstIterator.next() else {
      return XCTFail("迟到 observer 不得清空或轮换既有 observer")
    }
    XCTAssertEqual(delivered.eventID.rawValue, event.eventID.rawValue)
    await source.shutdown()
  }

  func testConversationObservationGlobalCapAcceptsExactLimitAndRejectsPlusOne() async throws {
    let connection = AssemblySpyConnection()
    let commands = AssemblySpyCommandClient()
    let source = try RelaySessionSource(
      scope: .machine("machine-1"),
      machines: [
        PairedMachine(
          id: "machine-1",
          name: "One",
          relayHost: "relay.example",
          rootFingerprint: Data(repeating: 1, count: 32)
        )
      ],
      connections: ["machine-1": connection],
      commandClient: commands,
      maximumConversationObservations: 2,
      maximumConversationObservationsPerMachine: 2
    )

    let first = await source.conversation(conversationID: "conversation-cap-1")
    let second = await source.conversation(conversationID: "conversation-cap-2")
    _ = first
    _ = second
    let rejected = await source.conversation(conversationID: "conversation-cap-3")

    let retained = await source.debugConversationObservationCount()
    let firstCount = await commands.conversationSubscriptionCount("conversation-cap-1")
    let secondCount = await commands.conversationSubscriptionCount("conversation-cap-2")
    let rejectedCount = await commands.conversationSubscriptionCount("conversation-cap-3")
    XCTAssertEqual(retained, 2)
    XCTAssertEqual(firstCount, 1)
    XCTAssertEqual(secondCount, 1)
    XCTAssertEqual(rejectedCount, 0)
    var rejectedIterator = rejected.makeAsyncIterator()
    guard
      case .connectionState(.lagged(reason: .snapshotRequired))? =
        await rejectedIterator.next()
    else {
      return XCTFail("global cap/+1 必须只拒绝 offending observation")
    }
    let rejectedTerminal = await rejectedIterator.next()
    XCTAssertNil(rejectedTerminal)
    await source.shutdown()
  }

  func testCatalogOldGenerationCannotReduceAndStartsFreshRecovery() async throws {
    let (source, connection, commands) = try makeSourceHarness()
    let catalogStream = await source.conversations(machineID: "machine-1")
    let recordedRequestID = await commands.latestCatalogSubscriptionRequestID()
    let requestID = try XCTUnwrap(recordedRequestID)
    let generation = RuntimeStreamGeneration(rawValue: "catalog-current")
    var catalogIterator = catalogStream.makeAsyncIterator()
    guard case .loading? = await catalogIterator.next() else {
      return XCTFail("首次 catalog observation 必须先发布 loading")
    }
    await sendCatalogSnapshotBarrier(
      connection: connection,
      requestID: requestID,
      generation: generation
    )
    guard case .ready(let initial, _)? = await catalogIterator.next() else {
      return XCTFail("catalog barrier 后必须 ready")
    }
    XCTAssertTrue(initial.isEmpty)

    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .catalog(subscriptionRequestID: requestID),
          streamGeneration: RuntimeStreamGeneration(rawValue: "catalog-old"),
          outerCursor: .at(11),
          payload: .catalogDelta(
            RuntimeCatalogDeltaV2(
              catalogRevision: 0,
              changes: [
                .upserted(
                  entry: conversationEntry(
                    id: "forged-old-generation",
                    title: "must not reduce",
                    entryRevision: 1
                  )
                )
              ]
            )
          )
        )
      )
    )
    let restarted = await eventually {
      await commands.catalogSubscriptionCount() == 2
    }
    XCTAssertTrue(restarted)

    let readback = await source.conversations(machineID: "machine-1")
    var readbackIterator = readback.makeAsyncIterator()
    guard case .ready(let summaries, _)? = await readbackIterator.next() else {
      return XCTFail("旧 generation 后应保留最后 committed catalog")
    }
    XCTAssertTrue(summaries.isEmpty, "旧 generation delta 不得推进 reducer")
  }

  func testCatalogCursorGapPublishesStaleAndFreshSnapshotRecoversSameObservation()
    async throws
  {
    let (source, connection, commands) = try makeSourceHarness()
    let catalogStream = await source.conversations(machineID: "machine-1")
    let recordedRequestID = await commands.latestCatalogSubscriptionRequestID()
    let originalRequestID = try XCTUnwrap(recordedRequestID)
    let originalGeneration = RuntimeStreamGeneration(rawValue: "catalog-before-gap")
    let originalEntry = conversationEntry(
      id: "conversation-before-gap",
      title: "Before gap",
      entryRevision: 1
    )
    var iterator = catalogStream.makeAsyncIterator()
    guard case .loading? = await iterator.next() else {
      return XCTFail("首次 catalog observation 必须先发布 loading")
    }
    await sendCatalogSnapshotBarrier(
      connection: connection,
      requestID: originalRequestID,
      generation: originalGeneration,
      entries: [originalEntry]
    )
    guard case .ready(let originalProjection, _)? = await iterator.next() else {
      return XCTFail("cursor gap 测试必须先建立 ready catalog projection")
    }
    XCTAssertEqual(originalProjection.map(\.id), ["conversation-before-gap"])

    await connection.send(
      .streamRecoveryRequired(
        target: .catalog(subscriptionRequestID: originalRequestID),
        reason: .cursorGap
      )
    )
    guard case .stale(let staleProjection, let staleReason)? = await iterator.next() else {
      return XCTFail("catalog cursor gap 必须先把已提交 projection 发布为 stale")
    }
    XCTAssertEqual(staleProjection, originalProjection)
    XCTAssertEqual(staleReason, .lagged(reason: .cursorGap))

    let resubscribed = await eventually {
      await commands.catalogSubscriptionCount() == 2
    }
    XCTAssertTrue(resubscribed, "catalog cursor gap 必须触发 fresh snapshot subscribe")
    let recordedReplacementRequestID = await commands.latestCatalogSubscriptionRequestID()
    let replacementRequestID = try XCTUnwrap(recordedReplacementRequestID)
    XCTAssertNotEqual(replacementRequestID, originalRequestID)

    // superseded request 的重复 recovery marker 必须被 correlation guard 吞掉；随后按
    // 同一 update stream 发送 fresh barrier，以它成功发布来证明旧 marker 已经处理完毕。
    await connection.send(
      .streamRecoveryRequired(
        target: .catalog(subscriptionRequestID: originalRequestID),
        reason: .cursorGap
      )
    )
    let recoveredEntry = conversationEntry(
      id: "conversation-after-gap",
      title: "After gap",
      entryRevision: 1
    )
    await sendCatalogSnapshotBarrier(
      connection: connection,
      requestID: replacementRequestID,
      generation: RuntimeStreamGeneration(rawValue: "catalog-after-gap"),
      entries: [recoveredEntry]
    )
    guard case .ready(let recoveredProjection, _)? = await iterator.next() else {
      return XCTFail("fresh catalog snapshot/barrier 必须在原 observation 上恢复 ready")
    }
    XCTAssertEqual(recoveredProjection.map(\.id), ["conversation-after-gap"])
    let subscriptionCount = await commands.catalogSubscriptionCount()
    XCTAssertEqual(subscriptionCount, 2, "旧 request recovery 不得重复订阅")
    let latestRequestID = await commands.latestCatalogSubscriptionRequestID()
    XCTAssertEqual(latestRequestID, replacementRequestID)
    await source.shutdown()
  }

  func testConnectionStateOverflowRecoversAndFatalRemainsObservable() async throws {
    let (source, connection, commands) = try makeSourceHarness()
    let conversationID = RuntimeConversationID(rawValue: "conversation-overflow")
    let stream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let requestID = try XCTUnwrap(recordedRequestID)
    let generation = RuntimeStreamGeneration(rawValue: "generation-overflow")
    await sendConversationSnapshotBarrier(
      connection: connection,
      conversationID: conversationID,
      requestID: requestID,
      generation: generation,
      base: .beforeFirst
    )
    var iterator = stream.makeAsyncIterator()
    guard case .snapshot? = await iterator.next() else {
      return XCTFail("overflow test 需要先建立 baseline")
    }

    for sequence in 0..<512 {
      let event = try runtimeEvent(
        conversationID: conversationID,
        sequence: UInt64(sequence),
        eventID: "overflow-\(sequence)",
        body: .capabilities(try capabilities())
      )
      await connection.send(
        .delivery(
          VerifiedRuntimeDelivery(
            fixtureMachineID: "machine-1",
            target: .conversation(
              conversationID: conversationID,
              subscriptionRequestID: requestID
            ),
            streamGeneration: generation,
            outerCursor: .at(UInt64(sequence)),
            payload: .conversationEvent(event)
          )
        )
      )
      let applied = await eventually {
        await source.debugConversationCursor(conversationID.rawValue) == .at(UInt64(sequence))
      }
      XCTAssertTrue(applied)
    }

    await connection.send(.connectionState(.relayUnavailable))
    let recovered = await eventually {
      await commands.conversationSubscriptionCount(conversationID.rawValue) == 2
    }
    XCTAssertTrue(recovered)
    guard case .connectionState(.lagged(reason: .bufferDropped))? = await iterator.next() else {
      return XCTFail("control update overflow 必须统一进入 lagged recovery")
    }

    await connection.send(.connectionState(.securityError))
    guard case .connectionState(.securityError)? = await iterator.next() else {
      return XCTFail("awaiting barrier 时 fatal marker 仍必须可观察")
    }
    let terminal = await iterator.next()
    XCTAssertNil(terminal)
  }

  func testFatalDuringGenerationRotationTerminatesAndCannotResubscribe() async throws {
    let (source, connection, commands) = try makeSourceHarness()
    let conversationID = RuntimeConversationID(rawValue: "conversation-fatal-generation-race")
    let stream = await source.conversation(conversationID: conversationID.rawValue)
    let recordedRequestID = await commands.latestConversationSubscriptionRequestID(
      conversationID.rawValue
    )
    let requestID = try XCTUnwrap(recordedRequestID)
    await sendConversationSnapshotBarrier(
      connection: connection,
      conversationID: conversationID,
      requestID: requestID,
      generation: RuntimeStreamGeneration(rawValue: "generation-fatal-race"),
      base: .beforeFirst
    )
    var iterator = stream.makeAsyncIterator()
    guard case .snapshot? = await iterator.next() else {
      return XCTFail("fatal race test 需要先建立 baseline")
    }

    let interlock = RecoveryGenerationInterlock()
    let recovery = Task {
      await source.debugForceConversationRecovery(
        conversationID.rawValue,
        afterInvalidatingGeneration: {
          await interlock.blockAfterInvalidation()
        }
      )
    }
    await interlock.waitUntilInvalidated()
    await connection.send(.connectionState(.securityError))

    guard case .connectionState(.lagged(reason: .snapshotRequired))? = await iterator.next() else {
      return XCTFail("generation 换代 marker 必须先可观察")
    }
    guard case .connectionState(.securityError)? = await iterator.next() else {
      return XCTFail("换代窗口中的 fatal 必须以 broadcaster 当前 generation 送达")
    }
    let terminal = await iterator.next()
    XCTAssertNil(terminal)

    await interlock.release()
    await recovery.value
    let subscriptionsAfterFatal = await commands.conversationSubscriptionCount(
      conversationID.rawValue
    )
    XCTAssertEqual(subscriptionsAfterFatal, 1, "fatal latch 后悬挂 recovery 不得发起 fresh subscribe")
    await source.debugForceConversationRecovery(conversationID.rawValue)
    let subscriptionsAfterRetry = await commands.conversationSubscriptionCount(
      conversationID.rawValue
    )
    XCTAssertEqual(subscriptionsAfterRetry, 1, "fatal latch 后显式 recovery 也不得重新订阅")
    await source.shutdown()
  }

  func testCancelingLastObserversReleasesAllConversationState() async throws {
    let (source, _, _) = try makeSourceHarness()
    var tasks: [Task<Void, Never>] = []
    for index in 0..<32 {
      let stream = await source.conversation(conversationID: "conversation-\(index)")
      tasks.append(
        Task {
          var iterator = stream.makeAsyncIterator()
          _ = await iterator.next()
        }
      )
    }
    let retainedCount = await source.debugConversationObservationCount()
    XCTAssertEqual(retainedCount, 32)

    for task in tasks { task.cancel() }
    for task in tasks { await task.value }
    let released = await eventually {
      await source.debugConversationObservationCount() == 0
    }
    XCTAssertTrue(released, "最后 observer 取消后必须释放 reducer/broadcaster/buffer")
  }

  func testFiveHundredTwelveSequentialObserverTerminationsUnsubscribeExactly() async throws {
    let (source, _, commands) = try makeSourceHarness()
    for index in 0..<512 {
      let conversationID = "conversation-sequential-\(index)"
      let stream = await source.conversation(conversationID: conversationID)
      let waiter = Task {
        var iterator = stream.makeAsyncIterator()
        _ = await iterator.next()
      }
      waiter.cancel()
      await waiter.value
      let retired = await eventually {
        let observationCount = await source.debugConversationObservationCount()
        let unsubscriptionCount = await commands.conversationUnsubscriptionCount()
        return observationCount == 0 && unsubscriptionCount == index + 1
      }
      XCTAssertTrue(retired, "第 \(index + 1) 个 observation 必须完成 typed unsubscribe")
    }
    let targets = await commands.conversationUnsubscriptionIDs()
    XCTAssertEqual(targets.count, 512)
    XCTAssertEqual(Set(targets).count, 512)
    await source.shutdown()
  }

  func testLastObserverRetirementBlocksSameConversationReplacementUntilUnsubscribeCompletes()
    async throws
  {
    let (source, _, commands) = try makeSourceHarness(
      blockConversationUnsubscribe: true
    )
    let conversationID = "conversation-retirement-aba"
    let firstStream = await source.conversation(conversationID: conversationID)
    let initialSubscriptionCount = await commands.conversationSubscriptionCount(conversationID)
    XCTAssertEqual(initialSubscriptionCount, 1)

    let firstObserver = Task {
      var iterator = firstStream.makeAsyncIterator()
      _ = await iterator.next()
    }
    firstObserver.cancel()
    await firstObserver.value
    let unsubscribeIsBlocked = await eventually {
      let unsubscribeCount = await commands.conversationUnsubscriptionCount()
      let retirementCount = await source.debugConversationRetirementCount()
      return unsubscribeCount == 1 && retirementCount == 1
    }
    XCTAssertTrue(unsubscribeIsBlocked, "last observer teardown 必须先占住 retirement barrier")

    let rejected = await source.conversation(conversationID: conversationID)
    let blockedSubscriptionCount = await commands.conversationSubscriptionCount(conversationID)
    XCTAssertEqual(
      blockedSubscriptionCount,
      1,
      "旧 target-scoped unsubscribe 未完成时不得准入 replacement subscribe"
    )
    let blockedObservationCount = await source.debugConversationObservationCount()
    let blockedRetirementCount = await source.debugConversationRetirementCount()
    XCTAssertEqual(blockedObservationCount, 0)
    XCTAssertEqual(blockedRetirementCount, 1)
    var rejectedIterator = rejected.makeAsyncIterator()
    guard
      case .connectionState(.lagged(reason: .snapshotRequired))? =
        await rejectedIterator.next()
    else {
      return XCTFail("retirement 窗口内的 offending observer 必须收到可重试拒绝")
    }
    let rejectedEnd = await rejectedIterator.next()
    XCTAssertNil(rejectedEnd)

    await commands.releaseConversationUnsubscribes()
    let retirementCompleted = await eventually {
      await source.debugConversationRetirementCount() == 0
    }
    XCTAssertTrue(retirementCompleted, "authoritative unsubscribe 返回后必须释放 retirement barrier")

    let freshStream = await source.conversation(conversationID: conversationID)
    let freshSubscriptionCount = await commands.conversationSubscriptionCount(conversationID)
    let freshObservationCount = await source.debugConversationObservationCount()
    XCTAssertEqual(freshSubscriptionCount, 2)
    XCTAssertEqual(freshObservationCount, 1)
    _ = freshStream
    await source.shutdown()
  }

  private func requireSessionSource<Value: SessionSource>(_: Value.Type) {}
  private func requireConnectionUpdateSource<Value: MachineConnectionUpdateSource>(_: Value.Type) {}
  private func requireSendable<Value: Sendable>(_: Value.Type) {}
}

private func makeSourceHarness(
  blockConversationUnsubscribe: Bool = false
) throws -> (
  RelaySessionSource,
  AssemblySpyConnection,
  AssemblySpyCommandClient
) {
  let connection = AssemblySpyConnection()
  let commands = AssemblySpyCommandClient(
    blockConversationUnsubscribe: blockConversationUnsubscribe
  )
  let source = try RelaySessionSource(
    scope: .machine("machine-1"),
    machines: [
      PairedMachine(
        id: "machine-1",
        name: "One",
        relayHost: "relay.example",
        rootFingerprint: Data(repeating: 1, count: 32)
      )
    ],
    connections: ["machine-1": connection],
    commandClient: commands
  )
  return (source, connection, commands)
}

private func sendConversationSnapshotBarrier(
  connection: AssemblySpyConnection,
  conversationID: RuntimeConversationID,
  requestID: RuntimeMessageID,
  generation: RuntimeStreamGeneration,
  base: RuntimeStreamCursorV1 = .at(0)
) async {
  do {
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: requestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .typedReply(.subscription(.subscribed(streamGeneration: generation)))
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: requestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .conversationSnapshot(
            try conversationSnapshot(conversationID: conversationID, base: base)
          )
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .conversation(
            conversationID: conversationID,
            subscriptionRequestID: requestID
          ),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .syncComplete(
            try makeSyncComplete(
              conversationID: conversationID,
              outerCursor: .at(10),
              generation: generation,
              innerCursor: base
            )
          )
        )
      )
    )
  } catch {
    XCTFail("conversation bootstrap fixture 构造失败: \(error)")
  }
}

private func sendCatalogSnapshotBarrier(
  connection: AssemblySpyConnection,
  requestID: RuntimeMessageID,
  generation: RuntimeStreamGeneration,
  entries: [RuntimeConversationEntryV2] = []
) async {
  do {
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .catalog(subscriptionRequestID: requestID),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .typedReply(.subscription(.subscribed(streamGeneration: generation)))
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .catalog(subscriptionRequestID: requestID),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .catalogSnapshot(
            try catalogSnapshot(base: .beforeFirst, entries: entries)
          )
        )
      )
    )
    await connection.send(
      .delivery(
        VerifiedRuntimeDelivery(
          fixtureMachineID: "machine-1",
          target: .catalog(subscriptionRequestID: requestID),
          streamGeneration: generation,
          outerCursor: .at(10),
          payload: .syncComplete(
            try makeCatalogSyncComplete(
              generation: generation,
              outerCursor: .at(10),
              innerCursor: .beforeFirst
            )
          )
        )
      )
    )
  } catch {
    XCTFail("catalog bootstrap fixture 构造失败: \(error)")
  }
}

private func eventually(_ condition: () async -> Bool) async -> Bool {
  for _ in 0..<10_000 {
    if await condition() { return true }
    await Task.yield()
  }
  return false
}

private func payloadKind(_ payload: VerifiedRuntimePayload) -> String {
  switch payload {
  case .catalogSnapshot: "catalogSnapshot"
  case .catalogBackfill: "catalogBackfill"
  case .catalogDelta: "catalogDelta"
  case .conversationSnapshot: "conversationSnapshot"
  case .conversationBackfill: "conversationBackfill"
  case .conversationEvent: "conversationEvent"
  case .commandState: "commandState"
  case .syncComplete: "syncComplete"
  case .typedReply: "typedReply"
  }
}

private func catalogSnapshot(
  base: RuntimeStreamCursorV1,
  entries: [RuntimeConversationEntryV2] = []
) throws -> RuntimeCatalogSnapshotV2 {
  try RuntimeCatalogSnapshotV2(
    baseCatalogCursor: base,
    entries: entries,
    nextPageCursor: nil
  )
}

private func conversationEntry(
  id: String,
  title: String,
  entryRevision: UInt64
) -> RuntimeConversationEntryV2 {
  RuntimeConversationEntryV2(
    conversationID: RuntimeConversationID(rawValue: id),
    agentKind: .codex,
    title: title,
    cwd: "/tmp/project",
    lastActiveMs: 42,
    archived: false,
    entryRevision: entryRevision
  )
}

private func conversationSnapshot(
  conversationID: RuntimeConversationID,
  base: RuntimeStreamCursorV1
) throws -> ConversationSnapshotV2 {
  try ConversationSnapshotV2(
    conversationID: conversationID,
    baseEventCursor: base,
    configurationState: RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    ),
    items: [.capabilities(try capabilities())]
  )
}

private func runtimeEvent(
  conversationID: RuntimeConversationID,
  sequence: UInt64,
  eventID: String,
  commandID: RuntimeCommandID? = nil,
  body: RuntimeEventBodyV2
) throws -> RuntimeEventV2 {
  try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: eventID),
    eventSeq: sequence,
    commandID: commandID,
    itemID: nil,
    entityID: nil,
    body: body
  )
}

private func capabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try decode(
    RuntimeSessionCapabilitiesV1.self,
    [
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
  )
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

private func makeSyncComplete(
  conversationID: RuntimeConversationID,
  outerCursor: RuntimeStreamCursorV1 = .at(0),
  generation: RuntimeStreamGeneration = RuntimeStreamGeneration(rawValue: "generation-1"),
  innerCursor: RuntimeStreamCursorV1 = .at(0)
) throws -> RuntimeSyncCompleteV1 {
  try decode(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": generation.rawValue,
      "streamCursor": cursorJSONObject(outerCursor),
      "innerCursor": [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": cursorJSONObject(innerCursor),
      ],
      "keyDirectoryRevision": 1,
    ]
  )
}

private func makeCatalogSyncComplete(
  generation: RuntimeStreamGeneration,
  outerCursor: RuntimeStreamCursorV1,
  innerCursor: RuntimeStreamCursorV1
) throws -> RuntimeSyncCompleteV1 {
  try decode(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": generation.rawValue,
      "streamCursor": cursorJSONObject(outerCursor),
      "innerCursor": [
        "scope": "catalog",
        "cursor": cursorJSONObject(innerCursor),
      ],
      "keyDirectoryRevision": 1,
    ]
  )
}

private func cursorJSONObject(_ cursor: RuntimeStreamCursorV1) -> Any {
  switch cursor {
  case .beforeFirst: "beforeFirst"
  case .at(let value): ["at": value]
  }
}

private func decode<Value: Decodable>(_ type: Value.Type, _ object: Any) throws -> Value {
  let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  return try JSONDecoder().decode(type, from: data)
}

private actor AssemblySpyProvider: RelayMachineConnectionAssemblyProvider {
  private let machines: [PairedMachine]
  private let connections: [String: AssemblySpyConnection]
  private var opened: [String] = []

  init(machines: [PairedMachine], connections: [String: AssemblySpyConnection]) {
    self.machines = machines
    self.connections = connections
  }

  func listMachines() async throws -> [PairedMachine] { machines }

  func openStartedConnection(
    machineID: String
  ) async throws -> any RelayMachineConnectionOwner {
    guard let connection = connections[machineID] else { throw AssemblySpyError.unavailable }
    opened.append(machineID)
    return connection
  }

  func openedMachineIDs() -> [String] { opened }
}

private actor RecoveryGenerationInterlock {
  private var invalidated = false
  private var released = false
  private var invalidationWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func blockAfterInvalidation() async {
    invalidated = true
    let waiters = invalidationWaiters
    invalidationWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
    guard !released else { return }
    await withCheckedContinuation { continuation in
      releaseWaiters.append(continuation)
    }
  }

  func waitUntilInvalidated() async {
    guard !invalidated else { return }
    await withCheckedContinuation { continuation in
      invalidationWaiters.append(continuation)
    }
  }

  func release() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }
}

private actor AssemblySpyConnection: RelayMachineConnectionOwner {
  nonisolated let machineID: String
  private var claims = 0
  private var continuation: AsyncStream<MachineConnectionUpdate>.Continuation?
  private let failPreparedCommit: Bool
  private let blockPreparedCommit: Bool
  private let blockShutdown: Bool
  private let startsBusinessReady: Bool
  private let initialScope: TransferAssemblyScope
  private var committedPrepared = 0
  private var discardedPrepared = 0
  private var startedPreparedCommits = 0
  private var preparedCommitWaiters: [CheckedContinuation<Void, Never>] = []
  private var shutdowns = 0
  private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

  init(
    machineID: String = "machine-1",
    failPreparedCommit: Bool = false,
    blockPreparedCommit: Bool = false,
    blockShutdown: Bool = false,
    startsBusinessReady: Bool = true
  ) {
    self.machineID = machineID
    self.failPreparedCommit = failPreparedCommit
    self.blockPreparedCommit = blockPreparedCommit
    self.blockShutdown = blockShutdown
    self.startsBusinessReady = startsBusinessReady
    initialScope = TransferAssemblyScope(
      connectionID: UUID(),
      generation: RelayTransportGeneration(rawValue: 1)
    )
  }

  func updates() async -> AsyncStream<MachineConnectionUpdate> {
    claims += 1
    let pair = AsyncStream<MachineConnectionUpdate>.makeStream(
      bufferingPolicy: .bufferingNewest(512)
    )
    continuation = pair.continuation
    if startsBusinessReady {
      pair.continuation.yield(.connectionScope(initialScope))
      pair.continuation.yield(.businessReady(initialScope))
    }
    return pair.stream
  }

  func claimCount() -> Int { claims }

  func readinessSnapshot() -> MachineConnectionReadinessSnapshot {
    MachineConnectionReadinessSnapshot(
      connectionScope: startsBusinessReady ? initialScope : nil,
      readyScope: startsBusinessReady ? initialScope : nil
    )
  }

  func expectedGrantSerial() async throws -> UInt64 { 1 }

  func beginSubscription(
    target _: RuntimeSubscriptionTargetV1,
    after _: RuntimeStreamCursorV1,
    requestID _: RuntimeMessageID
  ) async throws {}

  func endSubscription(
    target _: RuntimeSubscriptionTargetV1,
    requestID _: RuntimeMessageID
  ) async throws {}

  func sendDirectedRequest(
    _: RuntimeEnvelopeV2,
    contract _: MachineDirectedReplyContract
  ) async throws -> RuntimeReplyV2 {
    throw SessionSourceFailure(code: .commandRejected)
  }

  func commit(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard delivery.ingressPermit != nil else { return }
    startedPreparedCommits += 1
    if blockPreparedCommit {
      await withCheckedContinuation { continuation in
        preparedCommitWaiters.append(continuation)
      }
    }
    if failPreparedCommit { throw AssemblySpyError.unavailable }
    committedPrepared += 1
  }

  func discard(_ delivery: VerifiedRuntimeDelivery) async {
    if delivery.ingressPermit != nil { discardedPrepared += 1 }
  }

  func committedPreparedCount() -> Int { committedPrepared }
  func discardedPreparedCount() -> Int { discardedPrepared }
  func startedPreparedCommitCount() -> Int { startedPreparedCommits }

  func releasePreparedCommits() {
    let waiters = preparedCommitWaiters
    preparedCommitWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func shutdown() async {
    shutdowns += 1
    releasePreparedCommits()
    if blockShutdown {
      await withCheckedContinuation { continuation in
        shutdownWaiters.append(continuation)
      }
    }
    continuation?.finish()
  }

  func shutdownCount() -> Int { shutdowns }

  func releaseShutdowns() {
    let waiters = shutdownWaiters
    shutdownWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func send(_ update: MachineConnectionUpdate) {
    continuation?.yield(update)
  }

  func readyScope() -> TransferAssemblyScope { initialScope }
}

private actor AssemblySpyCommandClient: RelaySessionSourceCommandClient {
  private struct SubscriptionRequest: Sendable {
    let machineID: String
    let target: RuntimeSubscriptionTargetV1
    let requestID: RuntimeMessageID
  }

  private var subscribed: [String] = []
  private var subscriptionRequests: [SubscriptionRequest] = []
  private var unsubscriptionTargets: [RuntimeSubscriptionTargetV1] = []
  private var conversationSubscriptionFailure: SessionSourceFailureCode?
  private var blockConversationUnsubscribe: Bool
  private var conversationUnsubscribeWaiters: [CheckedContinuation<Void, Never>] = []
  private var blockShutdown: Bool
  private var shutdowns = 0
  private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

  init(
    conversationSubscriptionFailure: SessionSourceFailureCode? = nil,
    blockConversationUnsubscribe: Bool = false,
    blockShutdown: Bool = false
  ) {
    self.conversationSubscriptionFailure = conversationSubscriptionFailure
    self.blockConversationUnsubscribe = blockConversationUnsubscribe
    self.blockShutdown = blockShutdown
  }

  func shutdown() async {
    shutdowns += 1
    guard blockShutdown else { return }
    await withCheckedContinuation { continuation in
      shutdownWaiters.append(continuation)
    }
  }

  func shutdownCount() -> Int { shutdowns }

  func releaseShutdowns() {
    blockShutdown = false
    let waiters = shutdownWaiters
    shutdownWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func subscribe(
    machineID: String,
    target: RuntimeSubscriptionTargetV1,
    after _: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) async throws {
    if case .conversation = target, let conversationSubscriptionFailure {
      throw SessionSourceFailure(code: conversationSubscriptionFailure)
    }
    subscribed.append(machineID)
    subscriptionRequests.append(
      SubscriptionRequest(machineID: machineID, target: target, requestID: requestID)
    )
  }

  func unsubscribe(
    machineID _: String,
    target: RuntimeSubscriptionTargetV1
  ) async throws {
    unsubscriptionTargets.append(target)
    guard case .conversation = target, blockConversationUnsubscribe else { return }
    await withCheckedContinuation { continuation in
      conversationUnsubscribeWaiters.append(continuation)
    }
  }

  func subscribedMachineIDs() -> [String] { subscribed }

  func setConversationSubscriptionFailure(_ failure: SessionSourceFailureCode?) {
    conversationSubscriptionFailure = failure
  }

  func latestConversationSubscriptionRequestID(
    _ conversationID: String
  ) -> RuntimeMessageID? {
    subscriptionRequests.reversed().compactMap { request -> RuntimeMessageID? in
      guard case .conversation(let candidate) = request.target,
        candidate.rawValue == conversationID
      else {
        return nil
      }
      return request.requestID
    }.first
  }

  func latestCatalogSubscriptionRequestID() -> RuntimeMessageID? {
    subscriptionRequests.reversed().first { request in
      if case .catalog = request.target { return true }
      return false
    }?.requestID
  }

  func conversationSubscriptionCount(_ conversationID: String) -> Int {
    subscriptionRequests.reduce(into: 0) { count, request in
      guard case .conversation(let candidate) = request.target,
        candidate.rawValue == conversationID
      else {
        return
      }
      count += 1
    }
  }

  func catalogSubscriptionCount() -> Int {
    subscriptionRequests.reduce(into: 0) { count, request in
      if case .catalog = request.target { count += 1 }
    }
  }

  func conversationUnsubscriptionCount() -> Int {
    unsubscriptionTargets.reduce(into: 0) { count, target in
      if case .conversation = target { count += 1 }
    }
  }

  func conversationUnsubscriptionIDs() -> [String] {
    unsubscriptionTargets.compactMap { target in
      guard case .conversation(let conversationID) = target else { return nil }
      return conversationID.rawValue
    }
  }

  func releaseConversationUnsubscribes() {
    blockConversationUnsubscribe = false
    let waiters = conversationUnsubscribeWaiters
    conversationUnsubscribeWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func inspectPairInvite(_: String) async throws -> PairingPreview {
    throw AssemblySpyError.unavailable
  }

  func pair(_: String) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    throw AssemblySpyError.unavailable
  }

  func revokeSelf(machineID _: String) async throws -> RevocationReceipt {
    throw AssemblySpyError.unavailable
  }

  func sendPrompt(
    machineID _: String,
    conversationID _: String,
    text _: String,
    idempotencyKey _: UUID,
    expectedConfigurationRevision _: UInt64
  ) async throws -> CommandReceipt {
    throw AssemblySpyError.unavailable
  }

  func resolveApproval(
    machineID _: String,
    conversationID _: String,
    turnID _: String,
    approvalID _: String,
    requestID _: String,
    decision _: ActionDecisionKind,
    idempotencyKey _: UUID
  ) async throws -> ApprovalReceipt {
    throw AssemblySpyError.unavailable
  }

  func retryApprovalDelivery(
    machineID _: String,
    conversationID _: String,
    approvalID _: String
  ) async throws -> ApprovalReceipt {
    throw AssemblySpyError.unavailable
  }
}

private enum AssemblySpyError: Error {
  case unavailable
}

private actor AssemblyCompletionProbe {
  private var completed = false

  func markCompleted() {
    completed = true
  }

  func completedValue() -> Bool {
    completed
  }
}
