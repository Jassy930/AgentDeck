import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class WorkbenchRuntimeV2Tests: XCTestCase {
  func testCatalogBuildsTypedRegistryAndSelectionRejectsUnknownConversation() throws {
    let firstID = conversationID("conversation-1")
    let secondID = conversationID("conversation-2")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try catalogPage(
          cursor: .beforeFirst,
          entries: [
            catalogEntry(id: firstID, title: "First", lastActiveMs: 2_000),
            catalogEntry(id: secondID, title: "Second", lastActiveMs: 1_000),
          ]
        )
      ]
    )

    XCTAssertEqual(Set(workbench.runtimes.keys), [firstID, secondID])
    XCTAssertNil(workbench.selectedConversationID)
    try workbench.selectConversation(secondID)
    XCTAssertEqual(workbench.selectedConversationID, secondID)
    XCTAssertEqual(workbench.selectedRuntime?.conversationID, secondID)
    XCTAssertEqual(workbench.selectedRuntime?.unreadEventCount, 0)

    let unknown = conversationID("conversation-unknown")
    XCTAssertThrowsError(try workbench.selectConversation(unknown)) { error in
      XCTAssertEqual(error as? WorkbenchModelError, .unknownConversation(unknown))
    }
    XCTAssertEqual(workbench.selectedConversationID, secondID)

    workbench.clearSelection()
    XCTAssertNil(workbench.selectedConversationID)
    XCTAssertNil(workbench.selectedRuntime)
    XCTAssertEqual(workbench.catalogEntries.map(\.conversationID), [firstID, secondID])
    XCTAssertEqual(workbench.catalogEntry(conversationID: firstID)?.title, "First")
    XCTAssertEqual(workbench.catalogCursor, .beforeFirst)
  }

  func testCatalogReconcilePrevalidatesEveryExistingRuntimeBeforeMutatingPresentation() throws {
    let firstID = conversationID("conversation-1")
    let secondID = conversationID("conversation-2")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try catalogPage(
          cursor: .beforeFirst,
          entries: [
            catalogEntry(id: firstID, title: "First", lastActiveMs: 2_000),
            catalogEntry(id: secondID, title: "Second", lastActiveMs: 1_000),
          ]
        )
      ]
    )

    let replacement = try catalogPage(
      cursor: .at(4),
      entries: [
        catalogEntry(
          id: firstID,
          title: "Must roll back",
          lastActiveMs: 4_000,
          entryRevision: 2
        ),
        catalogEntry(
          id: secondID,
          agentKind: .claudeCode,
          title: "Invalid agent",
          lastActiveMs: 3_000,
          entryRevision: 2
        ),
      ]
    )

    XCTAssertThrowsError(try workbench.installCatalog(snapshotPages: [replacement])) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .catalogAgentMismatch(expected: .codex, actual: .claudeCode)
      )
    }
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.title, "First")
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.entryRevision, 1)
    XCTAssertEqual(workbench.runtime(conversationID: secondID)?.title, "Second")
    XCTAssertEqual(workbench.catalogEntry(conversationID: firstID)?.title, "First")
    XCTAssertEqual(workbench.catalogCursor, .beforeFirst)
  }

  func testSynchronizedCatalogSnapshotAndBackfillReplaceBaselineOnlyAtTerminal() throws {
    let oldID = conversationID("conversation-old")
    let nextID = conversationID("conversation-next")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try catalogPage(
          cursor: .beforeFirst,
          entries: [catalogEntry(id: oldID, title: "Old")]
        )
      ]
    )
    let snapshot = try catalogPage(
      cursor: .at(4),
      entries: [catalogEntry(id: nextID, title: "Snapshot", entryRevision: 1)]
    )
    let updated = catalogEntry(
      id: nextID,
      title: "Backfilled",
      lastActiveMs: 2_000,
      entryRevision: 2
    )
    let backfill = RuntimeBackfillChunkV2.catalog(
      range: try RuntimeBackfillRangeV1(after: .at(4), through: .at(5)),
      deltas: [
        RuntimeCatalogDeltaV2(
          catalogRevision: 5,
          changes: [.upserted(entry: updated)]
        )
      ]
    )

    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(
          .subscription(.subscribed(streamGeneration: generation("generation-1")))
        )
      )
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.catalog(snapshot))))
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.backfill(backfill))))
    XCTAssertEqual(workbench.catalogEntries.map(\.conversationID), [oldID])
    XCTAssertEqual(workbench.catalogCursor, .beforeFirst)

    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(.syncComplete(try catalogSyncComplete(cursor: .at(5))))
      )
    )
    XCTAssertEqual(workbench.catalogEntries.map(\.conversationID), [nextID])
    XCTAssertEqual(workbench.catalogEntries.first?.title, "Backfilled")
    XCTAssertEqual(workbench.catalogCursor, .at(5))
    XCTAssertNil(workbench.runtime(conversationID: oldID))
    XCTAssertEqual(workbench.runtime(conversationID: nextID)?.title, "Backfilled")
  }

  func testMalformedSynchronizedCatalogPagesLeaveExistingBaselineUntouched() throws {
    let oldID = conversationID("conversation-old")
    let nextID = conversationID("conversation-next")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try catalogPage(
          cursor: .beforeFirst,
          entries: [catalogEntry(id: oldID, title: "Old")]
        )
      ]
    )
    let unterminated = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(4),
      entries: [catalogEntry(id: nextID, title: "Uncommitted")],
      currentPageCursor: nil,
      nextPageCursor: RuntimeCatalogPageCursor(rawValue: "catalog-page-2")
    )

    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(
          .subscription(.subscribed(streamGeneration: generation("generation-1")))
        )
      )
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.catalog(unterminated))))
    XCTAssertThrowsError(
      try workbench.ingest(
        .synchronizedReply(.syncComplete(try catalogSyncComplete(cursor: .at(4))))
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCatalogModelError, .snapshotDidNotTerminate)
    }
    XCTAssertEqual(workbench.catalogEntries.map(\.conversationID), [oldID])
    XCTAssertEqual(workbench.catalogCursor, .beforeFirst)
    XCTAssertEqual(workbench.runtime(conversationID: oldID)?.title, "Old")
    XCTAssertNil(workbench.runtime(conversationID: nextID))
  }

  func testSynchronizedConversationRepliesStageUntilTerminalAndRollbackAsOneUnit() throws {
    let id = conversationID("conversation-1")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [try catalogPage(cursor: .beforeFirst, entries: [catalogEntry(id: id)])]
    )
    let snapshot = try conversationSnapshot(
      conversationID: id,
      baseCursor: .at(0),
      items: [item("item-1", entityID: "entity-1", text: "snapshot")]
    )

    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(
          .subscription(.subscribed(streamGeneration: generation("generation-1")))
        )
      )
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.snapshot(snapshot))))
    XCTAssertEqual(workbench.runtime(conversationID: id)?.cursor, .beforeFirst)
    XCTAssertTrue(workbench.runtime(conversationID: id)?.items.isEmpty ?? false)

    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(
          .syncComplete(try syncComplete(conversationID: id, cursor: .at(0)))
        )
      )
    )
    XCTAssertEqual(workbench.runtime(conversationID: id)?.cursor, .at(0))
    XCTAssertEqual(workbench.runtime(conversationID: id)?.items.map(\.text), ["snapshot"])
    XCTAssertEqual(workbench.runtime(conversationID: id)?.unreadEventCount, 0)

    let valid = try itemEvent(
      conversationID: id,
      sequence: 1,
      eventID: "event-1",
      itemID: "item-1",
      entityID: "entity-1",
      text: "must roll back"
    )
    let gap = try itemEvent(
      conversationID: id,
      sequence: 3,
      eventID: "event-3",
      itemID: "item-3",
      entityID: "entity-3",
      text: "gap"
    )
    let invalid = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .at(0), through: .at(2)),
      events: [valid, gap]
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.backfill(invalid))))
    XCTAssertEqual(workbench.runtime(conversationID: id)?.items.map(\.text), ["snapshot"])

    XCTAssertThrowsError(
      try workbench.ingest(
        .synchronizedReply(
          .syncComplete(try syncComplete(conversationID: id, cursor: .at(2)))
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 2, actual: 3)
      )
    }
    XCTAssertEqual(workbench.runtime(conversationID: id)?.cursor, .at(0))
    XCTAssertEqual(workbench.runtime(conversationID: id)?.items.map(\.text), ["snapshot"])
  }

  func testLiveStreamRoutesExactConversationUnreadPhaseQueueAndCatalogDelta() throws {
    let firstID = conversationID("conversation-1")
    let secondID = conversationID("conversation-2")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try catalogPage(
          cursor: .beforeFirst,
          entries: [catalogEntry(id: firstID), catalogEntry(id: secondID)]
        )
      ]
    )
    try synchronizeEmptyConversation(firstID, in: workbench)
    try synchronizeEmptyConversation(secondID, in: workbench)
    try workbench.selectConversation(firstID)

    let selectedItem = try itemEvent(
      conversationID: firstID,
      sequence: 0,
      eventID: "event-selected",
      itemID: "item-selected",
      entityID: "entity-selected",
      text: "selected"
    )
    XCTAssertNil(try workbench.ingest(.stream(frame(.event(selectedItem), suffix: "selected"))))
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.unreadEventCount, 0)
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.items.map(\.text), ["selected"])

    let backgroundItem = try itemEvent(
      conversationID: secondID,
      sequence: 0,
      eventID: "event-background",
      itemID: "item-background",
      entityID: "entity-background",
      text: "background"
    )
    XCTAssertNil(try workbench.ingest(.stream(frame(.event(backgroundItem), suffix: "background"))))
    XCTAssertEqual(workbench.runtime(conversationID: secondID)?.unreadEventCount, 1)
    XCTAssertEqual(workbench.selectedConversationID, firstID)

    let command = commandID("command-1")
    let turn = turnID("turn-1")
    XCTAssertNil(
      try workbench.ingest(
        .stream(
          frame(
            .event(
              try event(
                conversationID: firstID,
                sequence: 1,
                eventID: "event-start",
                commandID: command,
                body: .turnStarted(turnID: turn)
              )
            ),
            suffix: "start"
          )
        )
      )
    )
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.phase, .running)
    let queuedKey = RuntimeIdempotencyKey(rawValue: "prompt:live-queue")
    XCTAssertEqual(
      workbench.runtime(conversationID: firstID)?.enqueuePrompt(
        "next prompt",
        idempotencyKey: queuedKey
      ),
      .drainNextPrompt(prompt: "next prompt", idempotencyKey: queuedKey)
    )
    let action = try workbench.ingest(
      .stream(
        frame(
          .event(
            try event(
              conversationID: firstID,
              sequence: 2,
              eventID: "event-complete",
              commandID: command,
              body: .turnCompleted(turnID: turn, summary: try turnSummary())
            )
          ),
          suffix: "complete"
        )
      )
    )
    XCTAssertNil(action)
    XCTAssertEqual(
      workbench.runtime(conversationID: firstID)?.pendingPromptAdmissions,
      ["next prompt"]
    )
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.phase, .ready)

    let updatedEntry = catalogEntry(
      id: firstID,
      title: "Renamed",
      lastActiveMs: 3_000,
      entryRevision: 2
    )
    let delta = RuntimeCatalogDeltaV2(
      catalogRevision: 0,
      changes: [.upserted(entry: updatedEntry)]
    )
    XCTAssertNil(try workbench.ingest(.stream(frame(.catalogDelta(delta), suffix: "catalog"))))
    XCTAssertEqual(workbench.catalog?.cursor, .at(0))
    XCTAssertEqual(workbench.runtime(conversationID: firstID)?.title, "Renamed")

    let removed = RuntimeCatalogDeltaV2(
      catalogRevision: 1,
      changes: [.removed(conversationID: firstID)]
    )
    XCTAssertNil(try workbench.ingest(.stream(frame(.catalogDelta(removed), suffix: "removed"))))
    XCTAssertEqual(workbench.catalogCursor, .at(1))
    XCTAssertEqual(workbench.catalogEntries.map(\.conversationID), [secondID])
    XCTAssertNil(workbench.runtime(conversationID: firstID))
    XCTAssertNil(workbench.selectedConversationID)

    let removedConversationEvent = try itemEvent(
      conversationID: firstID,
      sequence: 3,
      eventID: "event-after-removal",
      itemID: "item-after-removal",
      entityID: "entity-after-removal",
      text: "must be rejected"
    )
    XCTAssertThrowsError(
      try workbench.ingest(
        .stream(frame(.event(removedConversationEvent), suffix: "after-removal"))
      )
    ) { error in
      XCTAssertEqual(error as? WorkbenchModelError, .unknownConversation(firstID))
    }

    let unknownEvent = try itemEvent(
      conversationID: conversationID("conversation-unknown"),
      sequence: 0,
      eventID: "event-unknown",
      itemID: "item-unknown",
      entityID: "entity-unknown",
      text: "unknown"
    )
    XCTAssertThrowsError(
      try workbench.ingest(.stream(frame(.event(unknownEvent), suffix: "unknown")))
    ) { error in
      XCTAssertEqual(
        error as? WorkbenchModelError,
        .unknownConversation(conversationID("conversation-unknown"))
      )
    }
  }

  func testSynchronizationTerminalReturnsExactQueuedPromptDrainAction() throws {
    let id = conversationID("conversation-1")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [try catalogPage(cursor: .beforeFirst, entries: [catalogEntry(id: id)])]
    )
    try synchronizeEmptyConversation(id, in: workbench)

    let command = commandID("command-1")
    let turn = turnID("turn-1")
    XCTAssertNil(
      try workbench.ingest(
        .stream(
          frame(
            .event(
              try event(
                conversationID: id,
                sequence: 0,
                eventID: "event-start",
                commandID: command,
                body: .turnStarted(turnID: turn)
              )
            ),
            suffix: "start"
          )
        )
      )
    )
    let queuedKey = RuntimeIdempotencyKey(rawValue: "prompt:reconnect-queue")
    XCTAssertEqual(
      workbench.runtime(conversationID: id)?.enqueuePrompt(
        "queued after reconnect",
        idempotencyKey: queuedKey
      ),
      .drainNextPrompt(prompt: "queued after reconnect", idempotencyKey: queuedKey)
    )

    let completed = try event(
      conversationID: id,
      sequence: 1,
      eventID: "event-complete",
      commandID: command,
      body: .turnCompleted(turnID: turn, summary: try turnSummary())
    )
    let backfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(),
      range: try RuntimeBackfillRangeV1(after: .at(0), through: .at(1)),
      events: [completed]
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.backfill(backfill))))
    XCTAssertEqual(workbench.runtime(conversationID: id)?.phase, .running)

    let action = try workbench.ingest(
      .synchronizedReply(
        .syncComplete(try syncComplete(conversationID: id, cursor: .at(1)))
      )
    )
    XCTAssertNil(action)
    XCTAssertEqual(workbench.runtime(conversationID: id)?.phase, .ready)
    XCTAssertEqual(
      workbench.runtime(conversationID: id)?.pendingPromptAdmissions,
      ["queued after reconnect"]
    )

    let nextLiveEvent = try itemEvent(
      conversationID: id,
      sequence: 2,
      eventID: "event-after-sync",
      itemID: "item-after-sync",
      entityID: "entity-after-sync",
      text: "live after terminal"
    )
    XCTAssertNil(
      try workbench.ingest(
        .stream(frame(.event(nextLiveEvent), suffix: "after-sync"))
      )
    )
    XCTAssertEqual(workbench.runtime(conversationID: id)?.cursor, .at(2))
  }

  func testInFlightDraftSuppliesContextBeforeStartResultWithoutProvisionalIdentity() throws {
    let id = conversationID("conversation-daemon")
    let workbench = WorkbenchModel()
    let draft = try conversationDraft(prompt: "hello")
    try workbench.beginConversationStart(
      draft,
      createdAt: Date(timeIntervalSince1970: 10)
    )

    XCTAssertNotNil(workbench.inFlightDraftContext)
    XCTAssertTrue(workbench.runtimes.isEmpty)
    let snapshot = try conversationSnapshot(
      conversationID: id,
      baseCursor: .beforeFirst,
      configurationState: try configuredState(revision: 1),
      items: []
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.snapshot(snapshot))))
    XCTAssertNil(
      try workbench.ingest(
        .synchronizedReply(
          .syncComplete(try syncComplete(conversationID: id, cursor: .beforeFirst))
        )
      )
    )

    let runtime = try XCTUnwrap(workbench.runtime(conversationID: id))
    XCTAssertEqual(runtime.conversationID, id)
    XCTAssertEqual(runtime.agentKind, .codex)
    XCTAssertEqual(runtime.cwd?.path, "/tmp/project")
    XCTAssertEqual(runtime.createdAt, Date(timeIntervalSince1970: 10))
    XCTAssertNil(workbench.selectedConversationID)
    XCTAssertEqual(workbench.runtimes.keys.map(\.rawValue), ["conversation-daemon"])

    let terminal = try syncComplete(conversationID: id, cursor: .beforeFirst)
    try workbench.completeConversationStart(
      AppRuntimeConversationStartResult(
        conversationID: id,
        configurationReceipt: .applied(
          conversationID: id,
          configurationRevision: 1
        ),
        synchronization: AppRuntimeSynchronizationResult(
          replies: [],
          terminal: terminal
        ),
        promptReceipt: nil
      )
    )
    XCTAssertNil(workbench.inFlightDraftContext)
    XCTAssertEqual(workbench.selectedConversationID, id)
    XCTAssertEqual(workbench.selectedRuntime?.phase, .ready)

    try workbench.installCatalog(
      snapshotPages: [try catalogPage(cursor: .beforeFirst, entries: [])]
    )
    XCTAssertNotNil(workbench.runtime(conversationID: id))
    XCTAssertEqual(workbench.selectedConversationID, id)
  }

  func testConversationStartAcceptsLiveCursorAdvancedPastSynchronizationTerminal() throws {
    let id = conversationID("conversation-live-before-start-result")
    let workbench = WorkbenchModel()
    try workbench.beginConversationStart(try conversationDraft(prompt: "hello"))
    let snapshot = try conversationSnapshot(
      conversationID: id,
      baseCursor: .beforeFirst,
      configurationState: try configuredState(revision: 1),
      items: []
    )
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.snapshot(snapshot))))
    let terminal = try syncComplete(conversationID: id, cursor: .beforeFirst)
    XCTAssertNil(try workbench.ingest(.synchronizedReply(.syncComplete(terminal))))

    let command = commandID("command-live")
    XCTAssertNil(
      try workbench.ingest(
        .stream(
          frame(
            .event(
              try event(
                conversationID: id,
                sequence: 0,
                eventID: "event-live",
                commandID: command,
                body: .turnStarted(turnID: turnID("turn-live"))
              )
            ),
            suffix: "live-before-start-result"
          )
        )
      )
    )
    XCTAssertEqual(workbench.runtime(conversationID: id)?.cursor, .at(0))

    try workbench.completeConversationStart(
      AppRuntimeConversationStartResult(
        conversationID: id,
        configurationReceipt: .applied(
          conversationID: id,
          configurationRevision: 1
        ),
        synchronization: AppRuntimeSynchronizationResult(
          replies: [],
          terminal: terminal
        ),
        promptReceipt: .accepted(
          commandID: command,
          queuePosition: 0,
          configurationRevision: 1
        )
      )
    )

    XCTAssertEqual(workbench.selectedConversationID, id)
    XCTAssertEqual(workbench.selectedRuntime?.phase, .running)
  }

  func testApprovalIntentKeepsExactCapturedBindingAcrossSelectionChanges() throws {
    let id = conversationID("conversation-1")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [try catalogPage(cursor: .beforeFirst, entries: [catalogEntry(id: id)])]
    )
    try synchronizeEmptyConversation(id, in: workbench)
    try workbench.selectConversation(id)
    let command = commandID("command-1")
    let turn = turnID("turn-1")
    _ = try workbench.ingest(
      .stream(
        frame(
          .event(
            try event(
              conversationID: id,
              sequence: 0,
              eventID: "event-start",
              commandID: command,
              body: .turnStarted(turnID: turn)
            )
          ),
          suffix: "start"
        )
      )
    )
    _ = try workbench.ingest(
      .stream(
        frame(
          .event(
            try event(
              conversationID: id,
              sequence: 1,
              eventID: "event-approval",
              commandID: command,
              body: .actionRequest(
                turnID: turn,
                approvalID: approvalID("approval-1"),
                request: try actionRequest(requestID: "request-1")
              )
            )
          ),
          suffix: "approval"
        )
      )
    )
    let pending = try XCTUnwrap(workbench.selectedRuntime?.pendingActionRequest)
    workbench.clearSelection()

    let intent = try workbench.approvalDecisionIntent(
      for: pending,
      decision: .approve,
      persist: true
    )
    XCTAssertEqual(intent.conversationID, id)
    XCTAssertEqual(intent.turnID, turn)
    XCTAssertEqual(intent.commandID, command)
    XCTAssertEqual(intent.approvalID, approvalID("approval-1"))
    XCTAssertEqual(intent.decision.requestID, "request-1")
    XCTAssertEqual(intent.decision.decision, .approve)
    XCTAssertTrue(intent.decision.persist)
    XCTAssertEqual(workbench.runtime(conversationID: id)?.pendingActionRequests.count, 1)
  }

  func testProductionAppModelContainsNoLegacyIdentityOrDriverShim() throws {
    let productionModelPaths = [
      "Sources/AgentDeck/SessionModel.swift",
      "Sources/AgentDeck/ThreadRuntimeModel.swift",
      "Sources/AgentDeck/WorkbenchModel.swift",
      "Sources/AgentDeck/OSAccountRuntimeWireSession.swift",
      "Sources/AgentDeck/AppDelegate.swift",
      "Sources/AgentDeck/SessionViewController.swift",
      "Sources/AgentDeck/session/AgentControlBar.swift",
      "Sources/AgentDeck/session/NewSessionDialog.swift",
    ]
    let forbidden = [
      "RuntimeTurnStarting", "RuntimeActionDeciding", "ServerEvent",
      "SessionStart", "SessionContinue", "sessionId", "threadId",
      "adoptRuntimeIdentityIfNeeded", "adoptSessionId", "selectedSessionId",
      "live-", "ai-", "client ?? DaemonClient()", "ProcessDaemonTransport",
    ]

    for path in productionModelPaths {
      let source = try String(
        contentsOf: repositoryRoot.appendingPathComponent(path),
        encoding: .utf8
      )
      for token in forbidden {
        XCTAssertFalse(source.contains(token), "\(path) leaked legacy token \(token)")
      }
    }
  }

  private func synchronizeEmptyConversation(
    _ id: RuntimeConversationID,
    in workbench: WorkbenchModel
  ) throws {
    let snapshot = try conversationSnapshot(
      conversationID: id,
      baseCursor: .beforeFirst,
      items: []
    )
    _ = try workbench.ingest(.synchronizedReply(.snapshot(snapshot)))
    _ = try workbench.ingest(
      .synchronizedReply(
        .syncComplete(try syncComplete(conversationID: id, cursor: .beforeFirst))
      )
    )
  }

  private func conversationSnapshot(
    conversationID: RuntimeConversationID,
    baseCursor: RuntimeStreamCursorV1,
    configurationState: RuntimeConversationConfigurationStateV2? = nil,
    items: [SnapshotItemV1]
  ) throws -> ConversationSnapshotV2 {
    try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: baseCursor,
      configurationState: try (configurationState ?? unconfiguredState()),
      items: [.capabilities(try capabilities())] + items
    )
  }

  private func item(
    _ itemIDValue: String,
    entityID entityIDValue: String,
    text: String
  ) -> SnapshotItemV1 {
    .item(
      itemID: itemID(itemIDValue),
      entityID: entityID(entityIDValue),
      commandID: nil,
      item: .assistantMessage(text: text, meta: RuntimeAgentItemMetaV1())
    )
  }

  private func itemEvent(
    conversationID: RuntimeConversationID,
    sequence: UInt64,
    eventID eventIDValue: String,
    itemID itemIDValue: String,
    entityID entityIDValue: String,
    text: String
  ) throws -> RuntimeEventV2 {
    try event(
      conversationID: conversationID,
      sequence: sequence,
      eventID: eventIDValue,
      itemID: itemID(itemIDValue),
      entityID: entityID(entityIDValue),
      body: .item(.assistantMessage(text: text, meta: RuntimeAgentItemMetaV1()))
    )
  }

  private func event(
    conversationID: RuntimeConversationID,
    sequence: UInt64,
    eventID eventIDValue: String,
    commandID: RuntimeCommandID? = nil,
    itemID: RuntimeItemID? = nil,
    entityID: RuntimeEntityID? = nil,
    body: RuntimeEventBodyV2
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: conversationID,
      eventID: RuntimeEventID(rawValue: eventIDValue),
      eventSeq: sequence,
      commandID: commandID,
      itemID: itemID,
      entityID: entityID,
      body: body
    )
  }

  private func catalogPage(
    cursor: RuntimeStreamCursorV1,
    entries: [RuntimeConversationEntryV2]
  ) throws -> RuntimeCatalogSnapshotV2 {
    try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: cursor,
      entries: entries,
      nextPageCursor: nil
    )
  }

  private func catalogEntry(
    id: RuntimeConversationID,
    agentKind: AgentKind = .codex,
    title: String? = nil,
    cwd: String? = "/tmp/project",
    lastActiveMs: UInt64 = 1_000,
    entryRevision: UInt64 = 1
  ) -> RuntimeConversationEntryV2 {
    RuntimeConversationEntryV2(
      conversationID: id,
      agentKind: agentKind,
      title: title,
      cwd: cwd,
      lastActiveMs: lastActiveMs,
      archived: false,
      entryRevision: entryRevision
    )
  }

  private func capabilities() throws -> RuntimeSessionCapabilitiesV1 {
    try decode(
      RuntimeSessionCapabilitiesV1.self,
      [
        "agentKind": "codex",
        "agentVersion": "test",
        "features": ["approval"],
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
        "elapsedMs": 1,
        "totalInputTokens": NSNull(),
        "totalOutputTokens": NSNull(),
      ]
    )
  }

  private func syncComplete(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1
  ) throws -> RuntimeSyncCompleteV1 {
    try decode(
      RuntimeSyncCompleteV1.self,
      [
        "streamGeneration": "generation-1",
        "streamCursor": "beforeFirst",
        "innerCursor": [
          "scope": "conversation",
          "conversationId": conversationID.rawValue,
          "cursor": cursorObject(cursor),
        ],
        "keyDirectoryRevision": 0,
      ]
    )
  }

  private func catalogSyncComplete(
    cursor: RuntimeStreamCursorV1
  ) throws -> RuntimeSyncCompleteV1 {
    try decode(
      RuntimeSyncCompleteV1.self,
      [
        "streamGeneration": "generation-1",
        "streamCursor": "beforeFirst",
        "innerCursor": [
          "scope": "catalog",
          "cursor": cursorObject(cursor),
        ],
        "keyDirectoryRevision": 0,
      ]
    )
  }

  private func conversationDraft(prompt: String) throws -> RuntimeConversationDraft {
    try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/project",
      prompt: prompt,
      vendorOptions: .codex(
        CodexSessionOptions(
          approvalPolicy: .onRequest,
          sandbox: .workspaceWrite,
          persistApproval: false,
          reasoningEffort: .medium
        )
      ),
      idempotencyKeys: RuntimeConversationIdempotencyKeys(
        start: RuntimeIdempotencyKey(rawValue: "start:fixed"),
        configure: RuntimeIdempotencyKey(rawValue: "configure:fixed"),
        prompt: RuntimeIdempotencyKey(rawValue: "prompt:fixed")
      )
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

  private func unconfiguredState() throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    )
  }

  private func frame(
    _ item: RuntimeStreamItemV2,
    suffix: String
  ) -> LocalRuntimeStreamFrame {
    LocalRuntimeStreamFrame(
      messageID: RuntimeMessageID(rawValue: "message-\(suffix)"),
      item: item
    )
  }

  private func cursorObject(_ cursor: RuntimeStreamCursorV1) -> Any {
    switch cursor {
    case .beforeFirst: "beforeFirst"
    case .at(let value): ["at": value]
    }
  }

  private func decode<Value: Decodable>(_ type: Value.Type, _ object: Any) throws -> Value {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(type, from: data)
  }

  private func conversationID(_ value: String) -> RuntimeConversationID {
    RuntimeConversationID(rawValue: value)
  }

  private func itemID(_ value: String) -> RuntimeItemID {
    RuntimeItemID(rawValue: value)
  }

  private func entityID(_ value: String) -> RuntimeEntityID {
    RuntimeEntityID(rawValue: value)
  }

  private func commandID(_ value: String) -> RuntimeCommandID {
    RuntimeCommandID(rawValue: value)
  }

  private func turnID(_ value: String) -> RuntimeTurnID {
    RuntimeTurnID(rawValue: value)
  }

  private func approvalID(_ value: String) -> RuntimeApprovalID {
    RuntimeApprovalID(rawValue: value)
  }

  private func generation(_ value: String) -> RuntimeStreamGeneration {
    RuntimeStreamGeneration(rawValue: value)
  }

  private var repositoryRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }
}
