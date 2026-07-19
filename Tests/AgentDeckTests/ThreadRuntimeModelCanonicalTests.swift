import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class ThreadRuntimeModelCanonicalTests: XCTestCase {
  func testCatalogPresentationUsesTypedConversationIdentityAndOptionalCWD() throws {
    let entry = catalogEntry(
      conversationID: "conversation-1",
      title: "Catalog title",
      cwd: nil,
      lastActiveMs: 2_000,
      entryRevision: 3
    )
    let model = try ThreadRuntimeModel(catalogEntry: entry)

    XCTAssertEqual(model.conversationID, conversationID("conversation-1"))
    XCTAssertEqual(model.agentKind, .codex)
    XCTAssertEqual(model.title, "Catalog title")
    XCTAssertNil(model.cwd)
    XCTAssertEqual(model.displayTitle, "Catalog title")
    XCTAssertEqual(model.entryRevision, 3)
    XCTAssertEqual(model.updatedAt, Date(timeIntervalSince1970: 2))

    XCTAssertThrowsError(
      try model.applyCatalogEntry(
        catalogEntry(
          conversationID: "conversation-other",
          title: nil,
          cwd: "/tmp/other",
          lastActiveMs: 3_000,
          entryRevision: 4
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .catalogConversationMismatch(
          expected: conversationID("conversation-1"),
          actual: conversationID("conversation-other")
        )
      )
    }

    XCTAssertThrowsError(
      try model.applyCatalogEntry(
        catalogEntry(
          conversationID: "conversation-1",
          title: "rollback",
          cwd: nil,
          lastActiveMs: 1_000,
          entryRevision: 2
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .catalogEntryRevisionRegressed(current: 3, actual: 2)
      )
    }
    XCTAssertEqual(model.title, "Catalog title")
    XCTAssertNil(model.cwd)
  }

  func testCatalogValidationIsPureBeforeAtomicReconcileCommit() throws {
    let model = try ThreadRuntimeModel(
      catalogEntry: catalogEntry(
        conversationID: "conversation-1",
        title: "before",
        cwd: "/tmp/before",
        lastActiveMs: 2_000,
        entryRevision: 3
      )
    )
    let candidate = catalogEntry(
      conversationID: "conversation-1",
      title: "after",
      cwd: nil,
      lastActiveMs: 4_000,
      entryRevision: 4
    )

    try model.validateCatalogEntry(candidate)

    XCTAssertEqual(model.title, "before")
    XCTAssertEqual(model.cwd?.path, "/tmp/before")
    XCTAssertEqual(model.entryRevision, 3)
    XCTAssertEqual(model.updatedAt, Date(timeIntervalSince1970: 2))

    try model.applyCatalogEntry(candidate)
    XCTAssertEqual(model.title, "after")
    XCTAssertNil(model.cwd)
    XCTAssertEqual(model.entryRevision, 4)
    XCTAssertEqual(model.updatedAt, Date(timeIntervalSince1970: 4))
  }

  func testSnapshotProjectsCanonicalUIItemAndCapabilityIdentity() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: URL(fileURLWithPath: "/tmp/project"),
      initialPhase: .ready
    )
    let snapshot = try ConversationSnapshotV2(
      conversationID: id,
      baseEventCursor: .at(4),
      configurationState: try unconfiguredState(),
      items: [
        .capabilities(try capabilities(agentKind: .codex)),
        .item(
          itemID: itemID("item-user"),
          entityID: entityID("entity-user"),
          commandID: commandID("command-user"),
          item: .userMessage(text: "hello", meta: RuntimeAgentItemMetaV1())
        ),
        .item(
          itemID: itemID("item-answer"),
          entityID: entityID("entity-answer"),
          commandID: commandID("command-user"),
          item: .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1())
        ),
      ]
    )

    try model.apply(snapshot)

    XCTAssertEqual(model.cursor, .at(4))
    XCTAssertEqual(model.items.map(\.id), ["item-user", "item-answer"])
    XCTAssertFalse(model.items.contains { $0.id.hasPrefix("ai-") || $0.id.hasPrefix("user-") })
    XCTAssertEqual(model.runtimeCapabilities?.agentKind, .codex)
    XCTAssertEqual(model.capabilities?.agentKind, .codex)
    XCTAssertEqual(model.capabilities?.features, [.shell, .approval])
    let identity = try XCTUnwrap(model.canonicalIdentity(for: itemID("item-answer")))
    XCTAssertEqual(identity.entityID, entityID("entity-answer"))
    XCTAssertEqual(identity.commandID, commandID("command-user"))
  }

  func testLiveItemApplyIsCumulativeAndFailureIsPresentationAtomic() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(
      snapshot(
        conversationID: id,
        baseCursor: .beforeFirst,
        items: [item("item-1", entityID: "entity-1", text: "partial")]
      )
    )
    try model.apply(
      itemEvent(
        conversationID: id,
        sequence: 0,
        eventID: "event-0",
        itemID: "item-1",
        entityID: "entity-1",
        text: "complete"
      )
    )

    XCTAssertEqual(model.items.count, 1)
    XCTAssertEqual(model.items.first?.id, "item-1")
    XCTAssertEqual(model.items.first?.text, "complete")
    XCTAssertEqual(model.items.first?.textBuffer.text, "complete")
    XCTAssertEqual(model.unreadEventCount, 1)

    let beforeUpdatedAt = model.updatedAt
    let conflict = try itemEvent(
      conversationID: id,
      sequence: 1,
      eventID: "event-conflict",
      itemID: "item-1",
      entityID: "entity-other",
      text: "tampered"
    )
    XCTAssertThrowsError(try model.apply(conflict)) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .itemIdentityConflict)
    }
    XCTAssertEqual(model.cursor, .at(0))
    XCTAssertEqual(model.items.map(\.text), ["complete"])
    XCTAssertEqual(model.unreadEventCount, 1)
    XCTAssertEqual(model.updatedAt, beforeUpdatedAt)
  }

  func testMultipleApprovalsBuildExactIntentWithoutEagerRemoval() throws {
    let id = conversationID("conversation-1")
    let turn = turnID("turn-1")
    let command = commandID("command-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(snapshot(conversationID: id, baseCursor: .beforeFirst, items: []))
    try model.apply(
      event(
        conversationID: id,
        sequence: 0,
        eventID: "event-start",
        commandID: command,
        body: .turnStarted(turnID: turn)
      )
    )
    try model.apply(
      event(
        conversationID: id,
        sequence: 1,
        eventID: "event-approval-1",
        commandID: command,
        body: .actionRequest(
          turnID: turn,
          approvalID: approvalID("approval-1"),
          request: try actionRequest(requestID: "request-1")
        )
      )
    )
    try model.apply(
      event(
        conversationID: id,
        sequence: 2,
        eventID: "event-approval-2",
        commandID: command,
        body: .actionRequest(
          turnID: turn,
          approvalID: approvalID("approval-2"),
          request: try actionRequest(requestID: "request-2")
        )
      )
    )

    XCTAssertEqual(model.pendingActionRequests.count, 2)
    XCTAssertEqual(model.phase, .waitingApproval)
    let second = model.pendingActionRequests[1]
    XCTAssertEqual(second.conversationID, id)
    XCTAssertEqual(second.turnID, turn)
    XCTAssertEqual(second.commandID, command)
    XCTAssertEqual(second.approvalID, approvalID("approval-2"))
    XCTAssertEqual(second.requestID, "request-2")

    let intent = try model.approvalDecisionIntent(
      for: second,
      decision: .deny,
      persist: false
    )
    XCTAssertEqual(intent.conversationID, id)
    XCTAssertEqual(intent.turnID, turn)
    XCTAssertEqual(intent.commandID, command)
    XCTAssertEqual(intent.approvalID, approvalID("approval-2"))
    XCTAssertEqual(intent.decision.requestID, "request-2")
    XCTAssertEqual(intent.decision.decision, .deny)
    XCTAssertEqual(model.pendingActionRequests.count, 2)

    let tampered = PendingActionRequest(
      conversationID: second.conversationID,
      turnID: second.turnID,
      commandID: commandID("command-other"),
      approvalID: second.approvalID,
      requestID: second.requestID,
      actionKind: second.actionKind,
      summary: second.summary,
      vendor: second.vendor
    )
    XCTAssertThrowsError(
      try model.approvalDecisionIntent(for: tampered, decision: .deny, persist: false)
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .approvalBindingMismatch(approvalID("approval-2"))
      )
    }
    XCTAssertEqual(model.pendingActionRequests.count, 2)

    let staleVendor = PendingActionRequest(
      conversationID: second.conversationID,
      turnID: second.turnID,
      commandID: second.commandID,
      approvalID: second.approvalID,
      requestID: second.requestID,
      actionKind: second.actionKind,
      summary: second.summary,
      vendor: .codex(
        approvalPolicyAtDecision: .onRequest,
        sandboxAtDecision: .workspaceWrite,
        canPersist: true
      )
    )
    XCTAssertThrowsError(
      try model.approvalDecisionIntent(for: staleVendor, decision: .deny, persist: false)
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .approvalBindingMismatch(approvalID("approval-2"))
      )
    }
    XCTAssertEqual(model.pendingActionRequests.count, 2)

    try model.apply(
      event(
        conversationID: id,
        sequence: 3,
        eventID: "event-resolved-2",
        commandID: command,
        body: .approvalResolved(
          turnID: turn,
          approvalID: approvalID("approval-2"),
          decision: .deny,
          state: .applied
        )
      )
    )
    XCTAssertEqual(model.pendingActionRequests.map(\.approvalID), [approvalID("approval-1")])
    XCTAssertEqual(model.phase, .waitingApproval)
    XCTAssertThrowsError(
      try model.approvalDecisionIntent(for: second, decision: .deny, persist: false)
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .approvalNoLongerPending(approvalID("approval-2"))
      )
    }

    try model.apply(
      event(
        conversationID: id,
        sequence: 4,
        eventID: "event-resolved-1",
        commandID: command,
        body: .approvalResolved(
          turnID: turn,
          approvalID: approvalID("approval-1"),
          decision: .approve,
          state: .applied
        )
      )
    )
    XCTAssertEqual(model.phase, .running)
    let queuedKey = RuntimeIdempotencyKey(rawValue: "prompt:approval-queue")
    XCTAssertEqual(
      model.enqueuePrompt("queued", idempotencyKey: queuedKey),
      .drainNextPrompt(prompt: "queued", idempotencyKey: queuedKey)
    )
    let action = try model.apply(
      event(
        conversationID: id,
        sequence: 5,
        eventID: "event-complete",
        commandID: command,
        body: .turnCompleted(turnID: turn, summary: try turnSummary())
      )
    )
    XCTAssertNil(action)
    XCTAssertEqual(model.pendingPromptAdmissions, ["queued"])
    let queuedCommand = commandID("command-queued-next")
    XCTAssertNil(
      model.acknowledgeQueuedPrompt(
        "queued",
        idempotencyKey: queuedKey,
        receipt: .accepted(
          commandID: queuedCommand,
          queuePosition: 1,
          configurationRevision: 1
        )
      )
    )
    XCTAssertTrue(model.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(model.queuedPrompts, ["queued"])
    XCTAssertEqual(model.phase, .ready)

    try model.apply(
      event(
        conversationID: id,
        sequence: 6,
        eventID: "event-queued-start",
        commandID: queuedCommand,
        body: .turnStarted(turnID: turnID("turn-queued-next"))
      )
    )
    XCTAssertTrue(model.queuedPrompts.isEmpty)
  }

  func testClaudeConfigurationDrivesUIBridgeAndAgentMismatchIsAtomic() throws {
    let id = conversationID("conversation-cc")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .claudeCode,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(
      try ConversationSnapshotV2(
        conversationID: id,
        baseEventCursor: .beforeFirst,
        configurationState: try RuntimeConversationConfigurationStateV2(
          configurationRevision: 1,
          configuration: RuntimeConversationConfigurationV2(
            vendorControl: .claudeCode(
              try RuntimeClaudeCodeConversationConfigurationV2(
                permissionMode: .plan,
                model: nil,
                effort: nil,
                outputStyle: nil
              )
            )
          )
        ),
        items: [.capabilities(try capabilities(agentKind: .claudeCode))]
      )
    )

    XCTAssertEqual(model.claudeCurrentPermissionMode, .plan)
    XCTAssertEqual(model.capabilities?.agentKind, .claudeCode)
    guard case .claudeCode(let vendor)? = model.capabilities?.vendor else {
      return XCTFail("expected Claude Code UI capabilities")
    }
    XCTAssertEqual(vendor.permissionModes, [.default, .plan])
    XCTAssertEqual(vendor.outputStyles, ["concise"])

    let mismatch = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-mismatch"),
      agentKind: .claudeCode,
      cwd: nil,
      initialPhase: .ready
    )
    XCTAssertThrowsError(
      try mismatch.apply(
        snapshot(
          conversationID: mismatch.conversationID,
          baseCursor: .at(0),
          items: []
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .stateAgentMismatch(expected: .claudeCode, actual: .codex)
      )
    }
    XCTAssertEqual(mismatch.cursor, .beforeFirst)
    XCTAssertNil(mismatch.runtimeCapabilities)
    XCTAssertEqual(model.capabilities?.agentKind, .claudeCode)
  }

  func testClaudeLiveConfigurationRevisionUpdatesPresentationAtomically() throws {
    let id = conversationID("conversation-cc")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .claudeCode,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(
      try ConversationSnapshotV2(
        conversationID: id,
        baseEventCursor: .beforeFirst,
        configurationState: claudeConfigurationState(revision: 1, permissionMode: .plan),
        items: [.capabilities(try capabilities(agentKind: .claudeCode))]
      )
    )
    try model.apply(
      event(
        conversationID: id,
        sequence: 0,
        eventID: "event-config-2",
        body: .configurationChanged(
          try claudeConfigurationState(revision: 2, permissionMode: .acceptEdits)
        )
      )
    )

    XCTAssertEqual(model.cursor, .at(0))
    XCTAssertEqual(model.configurationState?.configurationRevision, 2)
    XCTAssertEqual(model.claudeCurrentPermissionMode, .acceptEdits)
    XCTAssertEqual(model.unreadEventCount, 1)

    let beforeUpdatedAt = model.updatedAt
    let skippedRevision = try event(
      conversationID: id,
      sequence: 1,
      eventID: "event-config-4",
      body: .configurationChanged(
        try claudeConfigurationState(revision: 4, permissionMode: .auto)
      )
    )
    XCTAssertThrowsError(try model.apply(skippedRevision)) { error in
      XCTAssertEqual(
        error as? RuntimeConversationStateError,
        .configurationRevisionMismatch(expected: 3, actual: 4)
      )
    }
    XCTAssertEqual(model.cursor, .at(0))
    XCTAssertEqual(model.configurationState?.configurationRevision, 2)
    XCTAssertEqual(model.claudeCurrentPermissionMode, .acceptEdits)
    XCTAssertEqual(model.unreadEventCount, 1)
    XCTAssertEqual(model.updatedAt, beforeUpdatedAt)
  }

  func testSnapshotPresentationBuffersAreDetachedFromCanonicalState() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(
      snapshot(
        conversationID: id,
        baseCursor: .beforeFirst,
        items: [item("item-1", entityID: "entity-1", text: "canonical")]
      )
    )

    model.items[0].textBuffer.replace(with: "presentation-only")
    XCTAssertEqual(model.items[0].textBuffer.text, "presentation-only")
    XCTAssertEqual(model.items[0].text, "canonical")

    try model.applySynchronization([], terminalCursor: .beforeFirst)

    XCTAssertEqual(model.items[0].text, "canonical")
    XCTAssertEqual(model.items[0].textBuffer.text, "canonical")
    XCTAssertEqual(model.unreadEventCount, 0)
  }

  func testSnapshotLargeDiffKeepsDeferredContentDetachedAndMaterializable() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let patch = String(repeating: "+large\n", count: 3_000)
    let diffItem = try decode(
      RuntimeAgentItemV1.self,
      [
        "kind": "diff",
        "files": [["path": "large.swift", "status": "modified", "patch": patch]],
        "meta": ["vendorExtensions": [:]],
      ]
    )
    try model.apply(
      try ConversationSnapshotV2(
        conversationID: id,
        baseEventCursor: .beforeFirst,
        configurationState: try unconfiguredState(),
        items: [
          .capabilities(try capabilities(agentKind: .codex)),
          .item(
            itemID: itemID("item-diff"),
            entityID: entityID("entity-diff"),
            commandID: nil,
            item: diffItem
          ),
        ]
      )
    )

    XCTAssertEqual(model.items.first?.id, "item-diff")
    XCTAssertEqual(model.items.first?.diff, patch)
    XCTAssertTrue(model.items.first?.hasDeferredDiffBuffer ?? false)
    XCTAssertEqual(model.items.first?.diffBuffer.text, "")
    XCTAssertTrue(model.materializeDeferredContent(itemId: "item-diff", content: .diff))
    XCTAssertFalse(model.items.first?.hasDeferredDiffBuffer ?? true)
    XCTAssertEqual(model.items.first?.diffBuffer.text, patch)
    XCTAssertFalse(model.materializeDeferredContent(itemId: "unknown", content: .diff))
  }

  func testBackfillFailureDoesNotReplaceThreadPresentation() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(
      snapshot(
        conversationID: id,
        baseCursor: .beforeFirst,
        items: [item("item-0", entityID: "entity-0", text: "before")]
      )
    )
    let valid = try itemEvent(
      conversationID: id,
      sequence: 0,
      eventID: "event-0",
      itemID: "item-0",
      entityID: "entity-0",
      text: "must roll back"
    )
    let gap = try itemEvent(
      conversationID: id,
      sequence: 2,
      eventID: "event-2",
      itemID: "item-2",
      entityID: "entity-2",
      text: "gap"
    )
    let backfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(agentKind: .codex),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(1)),
      events: [valid, gap]
    )

    XCTAssertThrowsError(try model.apply(backfill)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 1, actual: 2)
      )
    }
    XCTAssertEqual(model.cursor, .beforeFirst)
    XCTAssertEqual(model.items.map(\.text), ["before"])
    XCTAssertEqual(model.unreadEventCount, 0)
  }

  func testSynchronizationPayloadsAndTerminalCommitAsOneAtomicBarrier() throws {
    let id = conversationID("conversation-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let baseline = try snapshot(
      conversationID: id,
      baseCursor: .at(0),
      items: [item("item-0", entityID: "entity-0", text: "snapshot")]
    )
    try model.apply(baseline)
    let update = try itemEvent(
      conversationID: id,
      sequence: 1,
      eventID: "event-1",
      itemID: "item-0",
      entityID: "entity-0",
      text: "updated"
    )
    let secondUpdate = try itemEvent(
      conversationID: id,
      sequence: 2,
      eventID: "event-2",
      itemID: "item-0",
      entityID: "entity-0",
      text: "updated twice"
    )
    let gap = try itemEvent(
      conversationID: id,
      sequence: 3,
      eventID: "event-3",
      itemID: "item-3",
      entityID: "entity-3",
      text: "gap"
    )
    let firstBackfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(agentKind: .codex),
      range: try RuntimeBackfillRangeV1(after: .at(0), through: .at(1)),
      events: [update]
    )
    let invalidSecondBackfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(agentKind: .codex),
      range: try RuntimeBackfillRangeV1(after: .at(1), through: .at(2)),
      events: [gap]
    )
    let secondBackfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(agentKind: .codex),
      range: try RuntimeBackfillRangeV1(after: .at(1), through: .at(2)),
      events: [secondUpdate]
    )

    XCTAssertThrowsError(
      try model.applySynchronization(
        [.backfill(firstBackfill), .backfill(invalidSecondBackfill)],
        terminalCursor: .at(2)
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 2, actual: 3)
      )
    }
    XCTAssertEqual(model.cursor, .at(0))
    XCTAssertEqual(model.items.map(\.text), ["snapshot"])
    XCTAssertEqual(model.unreadEventCount, 0)

    try model.applySynchronization(
      [.backfill(firstBackfill)],
      terminalCursor: .at(1)
    )
    XCTAssertEqual(model.cursor, .at(1))
    XCTAssertEqual(model.items.map(\.text), ["updated"])
    XCTAssertEqual(model.unreadEventCount, 0)

    try model.applySynchronization(
      [.snapshot(baseline), .backfill(firstBackfill), .backfill(secondBackfill)],
      terminalCursor: .at(2)
    )
    XCTAssertEqual(model.cursor, .at(2))
    XCTAssertEqual(model.items.map(\.text), ["updated twice"])
    XCTAssertEqual(model.unreadEventCount, 0)

    XCTAssertThrowsError(
      try model.applySynchronization(
        [.backfill(firstBackfill), .snapshot(baseline)],
        terminalCursor: .at(1)
      )
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .invalidSynchronizationPayloadSequence
      )
    }
    XCTAssertThrowsError(
      try model.applySynchronization(
        [.snapshot(baseline), .snapshot(baseline)],
        terminalCursor: .at(0)
      )
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .invalidSynchronizationPayloadSequence
      )
    }

    XCTAssertThrowsError(
      try model.applySynchronization([], terminalCursor: .at(3))
    ) { error in
      XCTAssertEqual(
        error as? ThreadRuntimeModelError,
        .synchronizationCursorMismatch(expected: .at(3), actual: .at(2))
      )
    }
    XCTAssertEqual(model.cursor, .at(2))
    XCTAssertEqual(model.items.map(\.text), ["updated twice"])
  }

  func testSynchronizationBackfillTerminalDrainsQueuedPromptAfterCommit() throws {
    let id = conversationID("conversation-1")
    let turn = turnID("turn-1")
    let command = commandID("command-1")
    let model = try ThreadRuntimeModel(
      conversationID: id,
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    try model.apply(snapshot(conversationID: id, baseCursor: .beforeFirst, items: []))
    try model.apply(
      event(
        conversationID: id,
        sequence: 0,
        eventID: "event-start",
        commandID: command,
        body: .turnStarted(turnID: turn)
      )
    )
    let queuedKey = RuntimeIdempotencyKey(rawValue: "prompt:sync-queue")
    XCTAssertEqual(
      model.enqueuePrompt("queued", idempotencyKey: queuedKey),
      .drainNextPrompt(prompt: "queued", idempotencyKey: queuedKey)
    )
    let terminal = try event(
      conversationID: id,
      sequence: 1,
      eventID: "event-complete",
      commandID: command,
      body: .turnCompleted(turnID: turn, summary: turnSummary())
    )
    let backfill = RuntimeBackfillChunkV2.conversation(
      conversationID: id,
      capabilitiesPreamble: try capabilities(agentKind: .codex),
      range: try RuntimeBackfillRangeV1(after: .at(0), through: .at(1)),
      events: [terminal]
    )

    let action = try model.applySynchronization(
      [.backfill(backfill)],
      terminalCursor: .at(1)
    )

    XCTAssertNil(action)
    XCTAssertEqual(model.pendingPromptAdmissions, ["queued"])
    XCTAssertNil(
      model.acknowledgeQueuedPrompt(
        "queued",
        idempotencyKey: queuedKey,
        receipt: .accepted(
          commandID: commandID("command-sync-queued"),
          queuePosition: 1,
          configurationRevision: 1
        )
      )
    )
    XCTAssertTrue(model.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(model.queuedPrompts, ["queued"])
    XCTAssertEqual(model.phase, .ready)
    XCTAssertEqual(model.cursor, .at(1))
    XCTAssertEqual(model.unreadEventCount, 1)
  }

  func testRunningPromptAdmissionIsImmediateAndLocallyBounded() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-prompt-admission"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .running
    )

    let firstAction = model.enqueuePrompt(
      "first",
      idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bounded:0")
    )
    XCTAssertEqual(
      firstAction,
      .drainNextPrompt(
        prompt: "first",
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bounded:0")
      ),
      "running prompt 必须立即进入 daemon admission，不能等待 turn terminal"
    )

    XCTAssertNil(
      model.enqueuePrompt(
        "must-be-rejected",
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bounded:overflow")
      )
    )
    XCTAssertEqual(model.pendingPromptAdmissions, ["first"])
    XCTAssertNotNil(model.warningMessage)
  }

  func testReplayedAdmissionProjectsQueuedUntilCanonicalEvidenceArrives() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-replayed-admission"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let key = RuntimeIdempotencyKey(rawValue: "prompt:replayed-admission")
    let command = commandID("command-replayed-admission")
    try model.apply(
      snapshot(
        conversationID: model.conversationID,
        baseCursor: .beforeFirst,
        items: []
      )
    )
    XCTAssertEqual(
      model.enqueuePrompt("replayed prompt", idempotencyKey: key),
      .drainNextPrompt(prompt: "replayed prompt", idempotencyKey: key)
    )

    XCTAssertNil(
      model.acknowledgeQueuedPrompt(
        "replayed prompt",
        idempotencyKey: key,
        receipt: .replayed(commandID: command, configurationRevision: 1)
      )
    )

    XCTAssertTrue(model.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(model.queuedPrompts, ["replayed prompt"])

    try model.apply(
      event(
        conversationID: model.conversationID,
        sequence: 0,
        eventID: "event-replayed-start",
        commandID: command,
        body: .turnStarted(turnID: turnID("turn-replayed-admission"))
      )
    )
    XCTAssertTrue(model.queuedPrompts.isEmpty)
  }

  func testReplayedReceiptUsesCanonicalSnapshotEvidenceAfterTerminalMarkerChanges() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-replayed-snapshot"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let command = commandID("command-old-canonical")
    let key = RuntimeIdempotencyKey(rawValue: "prompt:replayed-snapshot")
    try model.apply(
      ConversationSnapshotV2(
        conversationID: model.conversationID,
        baseEventCursor: .at(4),
        configurationState: try unconfiguredState(),
        items: [
          .capabilities(try capabilities(agentKind: .codex)),
          .item(
            itemID: itemID("item-old-canonical"),
            entityID: entityID("entity-old-canonical"),
            commandID: command,
            item: .userMessage(text: "already canonical", meta: RuntimeAgentItemMetaV1())
          ),
        ]
      )
    )
    XCTAssertEqual(
      model.enqueuePrompt("already canonical", idempotencyKey: key),
      .drainNextPrompt(prompt: "already canonical", idempotencyKey: key)
    )
    model.phase = .starting

    XCTAssertNil(
      model.acknowledgeQueuedPrompt(
        "already canonical",
        idempotencyKey: key,
        receipt: .replayed(commandID: command, configurationRevision: 1)
      )
    )

    XCTAssertEqual(model.phase, .ready)
    XCTAssertTrue(model.pendingPromptAdmissions.isEmpty)
    XCTAssertTrue(model.queuedPrompts.isEmpty)
  }

  func testFailedAdmissionStopsSendingAndRequiresExplicitIntent() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-failed-admission"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let originalKey = RuntimeIdempotencyKey(rawValue: "prompt:failed:original")
    XCTAssertEqual(
      model.enqueuePrompt("retry me", idempotencyKey: originalKey),
      .drainNextPrompt(prompt: "retry me", idempotencyKey: originalKey)
    )

    XCTAssertTrue(
      model.failQueuedPromptDispatch("retry me", idempotencyKey: originalKey)
    )

    XCTAssertTrue(
      model.pendingPromptAdmissions.isEmpty,
      "失败 admission 必须退出 sending，不得继续留在 pending FIFO"
    )
    XCTAssertEqual(model.retryRequiredPrompt, "retry me")

    let ignoredFreshKey = RuntimeIdempotencyKey(rawValue: "prompt:failed:fresh-same")
    XCTAssertEqual(
      model.enqueuePrompt("retry me", idempotencyKey: ignoredFreshKey),
      .drainNextPrompt(prompt: "retry me", idempotencyKey: originalKey),
      "明确重提相同文本必须复用原 idempotency key"
    )
    XCTAssertNil(model.retryRequiredPrompt)
    XCTAssertTrue(
      model.failQueuedPromptDispatch("retry me", idempotencyKey: originalKey)
    )

    let newIntentKey = RuntimeIdempotencyKey(rawValue: "prompt:failed:new-intent")
    XCTAssertEqual(
      model.enqueuePrompt("new intent", idempotencyKey: newIntentKey),
      .drainNextPrompt(prompt: "new intent", idempotencyKey: newIntentKey)
    )
    XCTAssertNil(model.retryRequiredPrompt)
    XCTAssertEqual(model.pendingPromptAdmissions, ["new intent"])
  }

  func testDefinitiveFailureRetainsDraftButUsesFreshRetryKey() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-definitive-failure"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .ready
    )
    let originalKey = RuntimeIdempotencyKey(rawValue: "prompt:definitive:original")
    let freshKey = RuntimeIdempotencyKey(rawValue: "prompt:definitive:fresh")
    XCTAssertEqual(
      model.enqueuePrompt("retry with fresh key", idempotencyKey: originalKey),
      .drainNextPrompt(prompt: "retry with fresh key", idempotencyKey: originalKey)
    )
    XCTAssertTrue(
      model.failQueuedPromptDispatch(
        "retry with fresh key",
        idempotencyKey: originalKey,
        reuseIdempotencyKey: false
      )
    )
    XCTAssertEqual(model.retryRequiredPrompt, "retry with fresh key")

    XCTAssertEqual(
      model.enqueuePrompt("retry with fresh key", idempotencyKey: freshKey),
      .drainNextPrompt(prompt: "retry with fresh key", idempotencyKey: freshKey)
    )
  }

  func testPromptAdmissionProtocolAndCombinedCountByteLimits() throws {
    let model = try ThreadRuntimeModel(
      conversationID: conversationID("conversation-prompt-bytes"),
      agentKind: .codex,
      cwd: nil,
      initialPhase: .running
    )
    let maxPrompt = String(
      repeating: "x",
      count: RuntimePromptPayloadV1.maxUTF8Bytes
    )
    let oversizedPrompt = maxPrompt + "x"

    XCTAssertNil(
      model.enqueuePrompt(
        oversizedPrompt,
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bytes:oversized")
      )
    )
    XCTAssertTrue(model.pendingPromptAdmissions.isEmpty)
    XCTAssertNotNil(model.warningMessage)

    XCTAssertEqual(
      model.enqueuePrompt(
        maxPrompt,
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bytes:0")
      ),
      .drainNextPrompt(
        prompt: maxPrompt,
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bytes:0")
      )
    )
    XCTAssertEqual(model.pendingPromptAdmissions.count, 1)

    XCTAssertNil(
      model.enqueuePrompt(
        "one-byte-over-local-budget",
        idempotencyKey: RuntimeIdempotencyKey(rawValue: "prompt:bytes:overflow")
      )
    )
    XCTAssertEqual(model.pendingPromptAdmissions.count, 1)
    XCTAssertNotNil(model.warningMessage)
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
      items: [.capabilities(try capabilities(agentKind: .codex))] + items
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
      body: .item(
        .assistantMessage(text: text, meta: RuntimeAgentItemMetaV1())
      )
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

  private func catalogEntry(
    conversationID conversationIDValue: String,
    title: String?,
    cwd: String?,
    lastActiveMs: UInt64,
    entryRevision: UInt64
  ) -> RuntimeConversationEntryV2 {
    RuntimeConversationEntryV2(
      conversationID: conversationID(conversationIDValue),
      agentKind: .codex,
      title: title,
      cwd: cwd,
      lastActiveMs: lastActiveMs,
      archived: false,
      entryRevision: entryRevision
    )
  }

  private func capabilities(agentKind: AgentKind) throws -> RuntimeSessionCapabilitiesV1 {
    switch agentKind {
    case .codex:
      return try decode(
        RuntimeSessionCapabilitiesV1.self,
        [
          "agentKind": "codex",
          "agentVersion": "test",
          "features": ["shell", "approval"],
          "vendor": [
            "agentKind": "codex",
            "sandboxModes": ["workspace-write"],
            "persistenceSupported": true,
            "reasoningEffortLevels": ["medium"],
          ],
        ]
      )
    case .claudeCode:
      return try decode(
        RuntimeSessionCapabilitiesV1.self,
        [
          "agentKind": "claude_code",
          "agentVersion": "test",
          "features": ["claudeCodePlanMode"],
          "vendor": [
            "agentKind": "claude_code",
            "permissionModes": ["default", "plan"],
            "outputStyles": ["concise"],
            "hooksSupported": [],
            "cliVersion": "test",
          ],
        ]
      )
    }
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

  private func unconfiguredState() throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    )
  }

  private func claudeConfigurationState(
    revision: UInt64,
    permissionMode: ClaudeCodePermissionMode
  ) throws -> RuntimeConversationConfigurationStateV2 {
    try RuntimeConversationConfigurationStateV2(
      configurationRevision: revision,
      configuration: RuntimeConversationConfigurationV2(
        vendorControl: .claudeCode(
          try RuntimeClaudeCodeConversationConfigurationV2(
            permissionMode: permissionMode,
            model: nil,
            effort: nil,
            outputStyle: nil
          )
        )
      )
    )
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
}
