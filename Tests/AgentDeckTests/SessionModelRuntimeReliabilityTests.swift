import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class SessionModelRuntimeReliabilityTests: XCTestCase {
  func testDescribeFailureRetriesWithoutStartingCoordinatorTwice() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      describeFailuresRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-bootstrap-retry")

    XCTAssertTrue(model.submit("bootstrap retry"))
    XCTAssertEqual(model.sendingPrompts, ["bootstrap retry"])
    try await wire.waitForDescribeRequestCount(1)
    try await waitUntil { model.errorMessage != nil }
    XCTAssertTrue(model.sendingPrompts.isEmpty)
    XCTAssertEqual(model.retryRequiredPrompt, "bootstrap retry")

    XCTAssertTrue(model.submit("bootstrap retry"))
    XCTAssertEqual(model.sendingPrompts, ["bootstrap retry"])
    try await wire.waitForDescribeRequestCount(2)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }

    let counts = await wire.bootstrapCounts()
    XCTAssertEqual(counts.start, 1)
    XCTAssertEqual(counts.describe, 2)
    XCTAssertTrue(model.sendingPrompts.isEmpty)
    XCTAssertEqual(model.queuedPrompts, ["bootstrap retry"])
    XCTAssertNil(model.retryRequiredPrompt)
  }

  func testBootstrapAdmissionRejectsSecondPromptUntilReceiptAndKeepsFirstVisible() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-bootstrap-single-flight")

    XCTAssertTrue(model.submit("first bootstrap prompt"))
    try await wire.waitForPromptRequestCount(1)
    XCTAssertEqual(model.sendingPrompts, ["first bootstrap prompt"])

    XCTAssertFalse(model.submit("must stay in composer"))
    XCTAssertEqual(model.sendingPrompts, ["first bootstrap prompt"])
    XCTAssertNotNil(model.warningMessage)
    let promptRequestsBeforeReceipt = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequestsBeforeReceipt, 1)

    await wire.releaseGatedPromptSuccess()
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertTrue(model.sendingPrompts.isEmpty)
    XCTAssertEqual(model.queuedPrompts, ["first bootstrap prompt"])
  }

  func testInitialPromptOutcomeUnknownCompletesStartAndRetriesExactPromptRequest() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .success]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let original = try reliabilityDraft(prompt: "retry exact draft", keySuffix: "original")

    model.startConversation(original)
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
        && model.retryRequiredPrompt == "retry exact draft"
    }
    XCTAssertNil(model.retryableConversationDraft)

    XCTAssertTrue(model.submit("retry exact draft"))
    try await wire.waitForPromptRequestCount(2)

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.start, [original.idempotencyKeys.start])
    XCTAssertEqual(keys.configure, [original.idempotencyKeys.configure])
    XCTAssertEqual(keys.prompt, [original.idempotencyKeys.prompt, original.idempotencyKeys.prompt])
    XCTAssertEqual(keys.promptExpectedRevisions, [1, 1])
  }

  func testStoreUnavailableRetriesStartConfigureAndPromptWithExactIdentityAndBytes()
    async throws
  {
    let prompt = "  修改配置  "

    do {
      let wire = try SessionReliabilityWire(
        promptOutcomes: [.success],
        startStoreUnavailableFailuresRemaining: 1
      )
      let model = SessionModel(runtimeWire: wire)
      defer { model.teardown() }
      let draft = try reliabilityDraft(prompt: prompt, keySuffix: "store-start")

      XCTAssertTrue(model.startConversation(draft))
      try await waitUntil { model.retryableConversationDraft != nil }
      model.retryConversationStart()
      try await wire.waitForPromptRequestCount(1)

      let capture = await wire.recordedIdempotencyKeys()
      XCTAssertEqual(capture.start, [draft.idempotencyKeys.start, draft.idempotencyKeys.start])
      XCTAssertEqual(capture.prompt, [draft.idempotencyKeys.prompt])
      XCTAssertEqual(capture.promptPayloads, [prompt])
    }

    do {
      let wire = try SessionReliabilityWire(
        promptOutcomes: [.success],
        configureStoreUnavailableFailuresRemaining: 1
      )
      let model = SessionModel(runtimeWire: wire)
      defer { model.teardown() }
      let draft = try reliabilityDraft(prompt: prompt, keySuffix: "store-configure")

      XCTAssertTrue(model.startConversation(draft))
      try await waitUntil { model.retryableConversationDraft != nil }
      model.retryConversationStart()
      try await wire.waitForPromptRequestCount(1)

      let capture = await wire.recordedIdempotencyKeys()
      XCTAssertEqual(capture.start, [draft.idempotencyKeys.start, draft.idempotencyKeys.start])
      XCTAssertEqual(
        capture.configure,
        [draft.idempotencyKeys.configure, draft.idempotencyKeys.configure]
      )
      XCTAssertEqual(capture.prompt, [draft.idempotencyKeys.prompt])
      XCTAssertEqual(capture.promptPayloads, [prompt])
    }

    do {
      let wire = try SessionReliabilityWire(
        promptOutcomes: [.storeUnavailable, .success]
      )
      let model = SessionModel(runtimeWire: wire)
      defer { model.teardown() }
      let draft = try reliabilityDraft(prompt: prompt, keySuffix: "store-prompt")

      XCTAssertTrue(model.startConversation(draft))
      try await waitUntil { model.retryRequiredPrompt == prompt }
      XCTAssertTrue(model.submit(prompt))
      try await wire.waitForPromptRequestCount(2)

      let capture = await wire.recordedIdempotencyKeys()
      XCTAssertEqual(
        capture.prompt,
        [draft.idempotencyKeys.prompt, draft.idempotencyKeys.prompt]
      )
      XCTAssertEqual(capture.promptExpectedRevisions, [1, 1])
      XCTAssertEqual(capture.promptPayloads, [prompt, prompt])
    }
  }

  func testProductionFactoryReconnectsAndResynchronizesBeforeExactPromptRetry() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure],
      latchTransportFailures: true
    )
    let secondWire = try SessionReliabilityWire(promptOutcomes: [.success])
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    let original = try reliabilityDraft(prompt: nil, keySuffix: "factory-prompt")
    XCTAssertEqual(factory.constructionCount, 0)

    XCTAssertTrue(model.startConversation(original))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertEqual(factory.constructionCount, 1)

    XCTAssertTrue(model.submit("factory exact prompt"))
    try await firstWire.waitForPromptRequestCount(1)
    try await waitUntil { model.retryRequiredPrompt == "factory exact prompt" }
    try await firstWire.waitForClose()
    XCTAssertEqual(factory.constructionCount, 1)

    XCTAssertTrue(model.submit("factory exact prompt"))
    try await secondWire.waitForPromptRequestCount(1)
    let firstCapture = await firstWire.recordedIdempotencyKeys()
    let secondCapture = await secondWire.recordedIdempotencyKeys()
    XCTAssertEqual(secondCapture.start.count, 0)
    XCTAssertEqual(secondCapture.configure.count, 0)
    XCTAssertEqual(secondCapture.prompt, firstCapture.prompt)
    XCTAssertEqual(secondCapture.promptExpectedRevisions, firstCapture.promptExpectedRevisions)
    XCTAssertEqual(secondCapture.promptPayloads, firstCapture.promptPayloads)
    XCTAssertEqual(factory.constructionCount, 2)

    let secondOperations = await secondWire.recordedOperations()
    let conversationSynchronization =
      "synchronize:\(SessionReliabilityWire.conversationID.rawValue)"
    let synchronizeIndex = try XCTUnwrap(
      secondOperations.firstIndex(of: conversationSynchronization)
    )
    let promptIndex = try XCTUnwrap(secondOperations.firstIndex(of: "prompt"))
    XCTAssertLessThan(synchronizeIndex, promptIndex)
    let firstPromptCount = await firstWire.currentPromptRequestCount()
    XCTAssertEqual(firstPromptCount, 1)

    model.teardown()
    try await secondWire.waitForClose()
    let firstCloseCount = await firstWire.currentCloseCount()
    let secondCloseCount = await secondWire.currentCloseCount()
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertEqual(secondCloseCount, 1)
  }

  func testProductionFactoryReconnectsBeforeExactStartReplay() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      startTransportFailuresRemaining: 1,
      latchTransportFailures: true
    )
    let secondWire = try SessionReliabilityWire(promptOutcomes: [.success])
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    let original = try reliabilityDraft(
      prompt: "factory bootstrap exact",
      keySuffix: "factory-bootstrap"
    )

    XCTAssertTrue(model.startConversation(original))
    try await waitUntil { model.retryableConversationDraft != nil }
    try await firstWire.waitForClose()
    XCTAssertEqual(factory.constructionCount, 1)

    model.retryConversationStart()
    try await secondWire.waitForPromptRequestCount(1)
    let firstCapture = await firstWire.recordedIdempotencyKeys()
    let secondCapture = await secondWire.recordedIdempotencyKeys()
    XCTAssertEqual(firstCapture.start, [original.idempotencyKeys.start])
    XCTAssertEqual(secondCapture.start, [original.idempotencyKeys.start])
    XCTAssertEqual(secondCapture.configure, [original.idempotencyKeys.configure])
    XCTAssertEqual(secondCapture.prompt, [original.idempotencyKeys.prompt])
    XCTAssertEqual(secondCapture.promptPayloads, ["factory bootstrap exact"])
    XCTAssertEqual(factory.constructionCount, 2)

    model.teardown()
    try await secondWire.waitForClose()
    let firstCloseCount = await firstWire.currentCloseCount()
    let secondCloseCount = await secondWire.currentCloseCount()
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertEqual(secondCloseCount, 1)
  }

  func testProductionFactoryRestoresDesiredCatalogBeforeConversationAndPrompt() async throws {
    let historyEntry = reliabilityHistoryEntry("factory-catalog")
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure],
      historyEntries: [historyEntry],
      latchTransportFailures: true
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      historyEntries: [historyEntry]
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })

    model.loadHistory()
    try await waitUntil {
      model.historyThreads.contains { $0.id == historyEntry.conversationID.rawValue }
    }
    XCTAssertTrue(model.startConversation(try reliabilityDraft(prompt: nil)))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertTrue(model.submit("catalog reconnect prompt"))
    try await waitUntil { model.retryRequiredPrompt == "catalog reconnect prompt" }

    XCTAssertTrue(model.submit("catalog reconnect prompt"))
    try await secondWire.waitForPromptRequestCount(1)
    let operations = await secondWire.recordedOperations()
    let catalogIndex = try XCTUnwrap(operations.firstIndex(of: "synchronize:catalog"))
    let conversationIndex = try XCTUnwrap(
      operations.firstIndex(of: "synchronize:\(SessionReliabilityWire.conversationID.rawValue)")
    )
    let promptIndex = try XCTUnwrap(operations.firstIndex(of: "prompt"))
    XCTAssertLessThan(catalogIndex, conversationIndex)
    XCTAssertLessThan(conversationIndex, promptIndex)

    model.teardown()
    try await secondWire.waitForClose()
  }

  func testIdleStreamFailureWaitsForCloseThenUsesFreshWireOnFirstUserRetry() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      gateClose: true
    )
    let secondWire = try SessionReliabilityWire(promptOutcomes: [.success])
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    defer { model.teardown() }

    XCTAssertTrue(model.startConversation(try reliabilityDraft(prompt: nil)))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    await firstWire.failStreamUnexpectedly()
    try await firstWire.waitForClose()

    XCTAssertTrue(model.submit("first action after idle stream failure"))
    try await Task.sleep(for: .milliseconds(20))
    XCTAssertEqual(factory.constructionCount, 1)
    let firstPromptCountBeforeClose = await firstWire.currentPromptRequestCount()
    XCTAssertEqual(firstPromptCountBeforeClose, 0)

    await firstWire.releaseClose()
    try await secondWire.waitForPromptRequestCount(1)
    XCTAssertEqual(factory.constructionCount, 2)
    let firstPromptCount = await firstWire.currentPromptRequestCount()
    XCTAssertEqual(firstPromptCount, 0)
    try await waitUntil {
      model.queuedPrompts == ["first action after idle stream failure"]
    }
    XCTAssertNil(model.retryRequiredPrompt)
  }

  func testReconnectRestoresSelectedAndDifferentRequiredConversation() async throws {
    let selectedEntry = reliabilityHistoryEntry("history-restore-selected")
    let requiredEntry = reliabilityHistoryEntry("history-restore-required")
    let entries = [selectedEntry, requiredEntry]
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    defer { model.teardown() }
    let threads = try await loadHistoryAndOpenPrefix(entries, count: 1, in: model)

    await firstWire.failStreamUnexpectedly()
    try await firstWire.waitForClose()
    try await waitUntil { model.selectedWarningMessage != nil }
    model.openHistoryThread(threads[1])

    try await waitUntil { model.workbench.selectedConversationID == requiredEntry.conversationID }
    let synchronizationOperations = await secondWire.recordedOperations().filter {
      $0.hasPrefix("synchronize:")
    }
    XCTAssertEqual(
      synchronizationOperations,
      [
        "synchronize:catalog",
        "synchronize:\(selectedEntry.conversationID.rawValue)",
        "synchronize:\(requiredEntry.conversationID.rawValue)",
      ]
    )
  }

  func testHistoryRefreshAsFirstReconnectActionStillRestoresSelectedConversation()
    async throws
  {
    let selectedEntry = reliabilityHistoryEntry("history-refresh-restores-selected")
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [selectedEntry]
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [selectedEntry]
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    defer { model.teardown() }
    _ = try await loadHistoryAndOpenPrefix([selectedEntry], count: 1, in: model)

    await firstWire.failStreamUnexpectedly()
    try await firstWire.waitForClose()
    try await waitUntil { model.selectedWarningMessage != nil }
    model.loadHistory()

    try await secondWire.waitForSynchronizationRequest(selectedEntry.conversationID)
    try await waitUntil { !model.isLoadingHistory }
    let operations = await secondWire.recordedOperations()
    XCTAssertTrue(operations.contains("synchronize:catalog"))
    XCTAssertTrue(operations.contains("synchronize:\(selectedEntry.conversationID.rawValue)"))
    XCTAssertTrue(operations.contains("backfill:catalog"))
    XCTAssertNil(model.historyErrorMessage)
  }

  func testOldGenerationHalfSynchronizationAndLateInboundCannotPolluteFreshWorkbench()
    async throws
  {
    let conversationID = RuntimeConversationID(rawValue: "generation-gated")
    let workbench = WorkbenchModel()
    try workbench.installCatalog(
      snapshotPages: [
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: [reliabilityHistoryEntry(conversationID.rawValue)],
          nextPageCursor: nil
        )
      ]
    )
    let bridge = SessionRuntimeInboundBridge(workbench: workbench)
    let subscription = RuntimeReplyV2.subscription(
      .subscribed(
        streamGeneration: RuntimeStreamGeneration(rawValue: "generation-reliability")
      )
    )
    let snapshot = RuntimeReplyV2.snapshot(
      try reliabilitySnapshot(conversationID: conversationID, agentKind: .codex)
    )
    let terminal = RuntimeReplyV2.syncComplete(
      try reliabilitySyncComplete(conversationID: conversationID)
    )

    bridge.activate(connectionGeneration: 1)
    try await bridge.ingest(.synchronizedReply(subscription), connectionGeneration: 1)
    workbench.cancelPendingSynchronization()
    bridge.activate(connectionGeneration: 2)
    try await bridge.ingest(.synchronizedReply(snapshot), connectionGeneration: 1)
    try await bridge.ingest(.synchronizedReply(terminal), connectionGeneration: 1)
    XCTAssertNil(workbench.runtime(conversationID: conversationID)?.runtimeCapabilities)

    try await bridge.ingest(.synchronizedReply(subscription), connectionGeneration: 2)
    try await bridge.ingest(.synchronizedReply(snapshot), connectionGeneration: 2)
    try await bridge.ingest(.synchronizedReply(terminal), connectionGeneration: 2)
    XCTAssertNotNil(workbench.runtime(conversationID: conversationID)?.runtimeCapabilities)
  }

  func testTeardownDuringFreshResubscribeDoesNotReviveOrConstructThirdWire() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure],
      latchTransportFailures: true
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      gatedHistoryConversationIDs: [SessionReliabilityWire.conversationID]
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })

    XCTAssertTrue(model.startConversation(try reliabilityDraft(prompt: nil)))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertTrue(model.submit("teardown reconnect prompt"))
    try await waitUntil { model.retryRequiredPrompt == "teardown reconnect prompt" }

    XCTAssertTrue(model.submit("teardown reconnect prompt"))
    try await secondWire.waitForSynchronizationRequest(SessionReliabilityWire.conversationID)
    XCTAssertEqual(factory.constructionCount, 2)
    model.teardown()
    try await secondWire.waitForClose()
    try await Task.sleep(for: .milliseconds(20))

    XCTAssertEqual(model.phase, .closed)
    XCTAssertEqual(factory.constructionCount, 2)
    let secondPromptCount = await secondWire.currentPromptRequestCount()
    let firstCloseCount = await firstWire.currentCloseCount()
    let secondCloseCount = await secondWire.currentCloseCount()
    XCTAssertEqual(secondPromptCount, 0)
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertEqual(secondCloseCount, 1)
  }

  func testOldGenerationStartFailureClearsPendingBootstrapForExactRetry() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      catalogTransportFailuresRemaining: 1,
      gatedHistoryConversationIDs: [SessionReliabilityWire.conversationID],
      latchTransportFailures: true
    )
    let secondWire = try SessionReliabilityWire(promptOutcomes: [.success])
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    let original = try reliabilityDraft(
      prompt: "stale bootstrap cleanup",
      keySuffix: "stale-bootstrap"
    )

    XCTAssertTrue(model.startConversation(original))
    try await firstWire.waitForSynchronizationRequest(SessionReliabilityWire.conversationID)
    model.loadHistory()
    try await firstWire.waitForClose()
    try await waitUntil { model.retryableConversationDraft != nil }

    XCTAssertEqual(model.retryableConversationDraft?.idempotencyKeys, original.idempotencyKeys)
    XCTAssertEqual(model.retryRequiredPrompt, "stale bootstrap cleanup")
    XCTAssertTrue(model.sendingPrompts.isEmpty)
    XCTAssertEqual(factory.constructionCount, 1)
    model.teardown()
  }

  func testReplacementCloseGenerationBlocksThirdWireUntilCurrentCloseCompletes() async throws {
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure],
      latchTransportFailures: true,
      gateClose: true
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [],
      describeFailuresRemaining: 1,
      latchTransportFailures: true,
      gateClose: true
    )
    let thirdWire = try SessionReliabilityWire(promptOutcomes: [.success])
    let factory = SessionReliabilityWireFactory([firstWire, secondWire, thirdWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })

    XCTAssertTrue(model.startConversation(try reliabilityDraft(prompt: nil)))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertTrue(model.submit("close generation exact"))
    try await firstWire.waitForClose()
    model.loadHistory()
    await firstWire.releaseClose()
    try await waitUntil { factory.constructionCount == 2 }
    try await secondWire.waitForClose()
    try await waitUntil { model.retryRequiredPrompt == "close generation exact" }

    XCTAssertTrue(model.submit("close generation exact"))
    try await Task.sleep(for: .milliseconds(20))
    XCTAssertEqual(factory.constructionCount, 2)
    await secondWire.releaseClose()
    try await thirdWire.waitForPromptRequestCount(1)
    XCTAssertEqual(factory.constructionCount, 3)

    model.teardown()
    try await thirdWire.waitForClose()
    let firstCloseCount = await firstWire.currentCloseCount()
    let secondCloseCount = await secondWire.currentCloseCount()
    let thirdCloseCount = await thirdWire.currentCloseCount()
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertEqual(secondCloseCount, 1)
    XCTAssertEqual(thirdCloseCount, 1)
  }

  func testDifferentIntentAfterInitialPromptUncertaintyUsesFreshKeyOnCanonicalConversation()
    async throws
  {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .gatedSuccess]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let original = try reliabilityDraft(prompt: "original intent", keySuffix: "original")

    model.startConversation(original)
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil { model.retryRequiredPrompt == "original intent" }

    XCTAssertTrue(model.submit("different intent"))
    try await wire.waitForPromptRequestCount(2)

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.start, [original.idempotencyKeys.start])
    XCTAssertEqual(keys.prompt.count, 2)
    XCTAssertNotEqual(keys.prompt[0], keys.prompt[1])
  }

  func testDefinitiveStartFailureAllowsEditedDraftAndUsesFreshStartKey() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      startFailuresRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-start-rejection")

    XCTAssertTrue(model.submit("rejected start prompt"))
    try await waitUntil { model.errorMessage != nil }
    XCTAssertEqual(model.retryRequiredPrompt, "rejected start prompt")

    XCTAssertTrue(model.submit("edited after rejection"))
    try await wire.waitForPromptRequestCount(1)
    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.start.count, 2)
    XCTAssertNotEqual(keys.start[0], keys.start[1])
  }

  func testDefinitiveConfigureFailurePreservesStartIdentityButAllowsEditedPrompt()
    async throws
  {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      configureFailuresRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let originalCwd = "/tmp/agentdeck-configure-rejection"
    model.cwd = URL(fileURLWithPath: originalCwd)

    XCTAssertTrue(model.submit("rejected configure prompt"))
    try await waitUntil { model.errorMessage != nil }

    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-configure-other-project")
    XCTAssertFalse(model.submit("must keep original cwd"))
    XCTAssertFalse(model.submit("must keep original agent", agentKind: .claudeCode))
    let requestsBeforeValidRetry = await wire.startRequests()
    XCTAssertEqual(requestsBeforeValidRetry, 1)

    model.cwd = URL(fileURLWithPath: originalCwd)
    XCTAssertTrue(model.submit("edited after configure rejection"))
    try await wire.waitForPromptRequestCount(1)

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.start.count, 2)
    XCTAssertEqual(keys.start[0], keys.start[1])
    XCTAssertEqual(keys.startAgentKinds, [.codex, .codex])
    XCTAssertEqual(keys.startCwds, [originalCwd, originalCwd])
    XCTAssertEqual(keys.configure.count, 2)
    XCTAssertNotEqual(keys.configure[0], keys.configure[1])
  }

  func testClaudeCodeOutcomeUnknownStartRetryKeepsAgentAndExactIdentity() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      startTransportFailuresRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let cwd = "/tmp/agentdeck-cc-exact"
    let original = try reliabilityDraft(
      prompt: "cc exact prompt",
      keySuffix: "cc-exact",
      agentKind: .claudeCode,
      cwd: cwd
    )
    model.cwd = URL(fileURLWithPath: cwd)

    XCTAssertTrue(model.startConversation(original))
    try await waitUntil { model.retryableConversationDraft != nil }
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .claudeCode)

    XCTAssertTrue(model.submit("cc exact prompt"))
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }

    let capture = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(capture.startAgentKinds, [.claudeCode, .claudeCode])
    XCTAssertEqual(capture.startCwds, [cwd, cwd])
    XCTAssertEqual(capture.start, [original.idempotencyKeys.start, original.idempotencyKeys.start])
    XCTAssertEqual(model.workbench.selectedRuntime?.agentKind, .claudeCode)
  }

  func testClaudeCodeDefinitiveStartRetryDefaultsToRetainedAgentAndFreshIdentity() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      startFailuresRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let cwd = "/tmp/agentdeck-cc-definitive"
    let original = try reliabilityDraft(
      prompt: "cc rejected prompt",
      keySuffix: "cc-definitive",
      agentKind: .claudeCode,
      cwd: cwd
    )
    model.cwd = URL(fileURLWithPath: cwd)

    XCTAssertTrue(model.startConversation(original))
    try await waitUntil { model.retryableConversationDraft != nil }
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .claudeCode)

    XCTAssertTrue(model.submit("cc edited prompt"))
    try await wire.waitForPromptRequestCount(1)
    let capture = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(capture.startAgentKinds, [.claudeCode, .claudeCode])
    XCTAssertEqual(capture.startCwds, [cwd, cwd])
    XCTAssertNotEqual(capture.start[0], capture.start[1])
    XCTAssertEqual(capture.promptPayloads, ["cc edited prompt"])
    XCTAssertEqual(model.workbench.selectedRuntime?.agentKind, .claudeCode)
  }

  func testCoordinatorClosedPromptRetryReusesOriginalKeyConservatively() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.coordinatorClosed, .success]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let original = try reliabilityDraft(
      prompt: "closed exact prompt",
      keySuffix: "closed-exact"
    )

    XCTAssertTrue(model.startConversation(original))
    try await waitUntil { model.retryRequiredPrompt == "closed exact prompt" }
    XCTAssertTrue(model.submit("closed exact prompt"))
    try await wire.waitForPromptRequestCount(2)

    let capture = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(
      capture.prompt, [original.idempotencyKeys.prompt, original.idempotencyKeys.prompt])
    XCTAssertEqual(capture.promptExpectedRevisions, [1, 1])
  }

  func testPendingBootstrapRejectsHistorySelectionAndKeepsVisibleOwnerAligned() async throws {
    let historyEntry = reliabilityHistoryEntry("history-pending")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.gatedSuccess],
      historyEntries: [historyEntry]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let historyThread = try installHistory([historyEntry], in: model)[0]
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-bootstrap-pending-history")

    XCTAssertTrue(model.submit("pending bootstrap"))
    try await wire.waitForPromptRequestCount(1)
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .codex)

    model.openHistoryThread(historyThread)

    XCTAssertNil(model.openingHistoryConversationID)
    XCTAssertNil(model.workbench.selectedConversationID)
    XCTAssertNil(model.selectedSidebarConversationID)
    XCTAssertNotNil(model.historyErrorMessage)
    let pendingHistoryRequests = await wire.historySyncRequests(for: historyEntry.conversationID)
    XCTAssertEqual(pendingHistoryRequests, 0)
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .codex)
    await wire.releaseGatedPromptSuccess()
  }

  func testFailedBootstrapRetryRejectsHistorySelectionFailClosed() async throws {
    let historyEntry = reliabilityHistoryEntry("history-retry")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      startFailuresRemaining: 1,
      historyEntries: [historyEntry]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let historyThread = try installHistory([historyEntry], in: model)[0]
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-bootstrap-retry-history")

    XCTAssertTrue(model.submit("retry blocks history"))
    try await waitUntil { model.retryableConversationDraft != nil }
    model.openHistoryThread(historyThread)

    XCTAssertNil(model.openingHistoryConversationID)
    XCTAssertNil(model.workbench.selectedConversationID)
    XCTAssertNil(model.selectedSidebarConversationID)
    XCTAssertNotNil(model.historyErrorMessage)
    let retryHistoryRequests = await wire.historySyncRequests(for: historyEntry.conversationID)
    XCTAssertEqual(retryHistoryRequests, 0)
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .codex)
  }

  func testStartNewSessionInvalidatesSlowHistoryCompletion() async throws {
    let historyEntry = reliabilityHistoryEntry("history-slow-new-session")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [historyEntry],
      gatedHistoryConversationIDs: [historyEntry.conversationID]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let historyThread = try installHistory([historyEntry], in: model)[0]
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-visible-project")

    model.openHistoryThread(historyThread)
    try await wire.waitForHistorySyncRequest(historyEntry.conversationID)
    model.startNewSessionFromCurrentProject()
    await wire.releaseHistorySync(historyEntry.conversationID)
    try await waitUntil {
      model.workbench.runtime(conversationID: historyEntry.conversationID)?.runtimeCapabilities
        != nil
    }
    await Task.yield()

    XCTAssertNil(model.workbench.selectedConversationID)
    XCTAssertNil(model.selectedSidebarConversationID)
    XCTAssertEqual(
      model.promptComposerOwner,
      .newConversation(cwd: "/tmp/agentdeck-visible-project")
    )
    XCTAssertTrue(model.selectedItems.isEmpty)
  }

  func testLatestHistoryIntentWinsWhenEarlierSlowOpenCompletesLate() async throws {
    let slowEntry = reliabilityHistoryEntry("history-slow-first", cwd: "/tmp/history-slow")
    let latestEntry = reliabilityHistoryEntry("history-latest", cwd: "/tmp/history-latest")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [slowEntry, latestEntry],
      gatedHistoryConversationIDs: [slowEntry.conversationID]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try installHistory([slowEntry, latestEntry], in: model)

    model.openHistoryThread(threads[0])
    try await wire.waitForHistorySyncRequest(slowEntry.conversationID)
    model.openHistoryThread(threads[1])
    try await Task.sleep(for: .milliseconds(20))

    XCTAssertNil(model.workbench.selectedConversationID)
    let latestRequestsBeforeRelease = await wire.historySyncRequests(
      for: latestEntry.conversationID
    )
    XCTAssertEqual(latestRequestsBeforeRelease, 0)

    await wire.releaseHistorySync(slowEntry.conversationID)
    try await wire.waitForHistorySyncRequest(latestEntry.conversationID)
    try await waitUntil { model.workbench.selectedConversationID == latestEntry.conversationID }

    XCTAssertEqual(model.workbench.selectedConversationID, latestEntry.conversationID)
    XCTAssertEqual(model.selectedHistoryConversationID, latestEntry.conversationID)
    XCTAssertEqual(model.selectedSidebarConversationID, latestEntry.conversationID.rawValue)
    XCTAssertEqual(model.promptComposerOwner, .conversation(latestEntry.conversationID))
    XCTAssertEqual(model.cwd?.path, "/tmp/history-latest")
    let slowRequests = await wire.historySyncRequests(for: slowEntry.conversationID)
    let latestRequests = await wire.historySyncRequests(for: latestEntry.conversationID)
    XCTAssertEqual(slowRequests, 1)
    XCTAssertEqual(latestRequests, 1)
  }

  func testHistoryDrainCoalescesAtoBtoCIntoAThenC() async throws {
    let firstEntry = reliabilityHistoryEntry("history-drain-a")
    let skippedEntry = reliabilityHistoryEntry("history-drain-b")
    let latestEntry = reliabilityHistoryEntry("history-drain-c")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [firstEntry, skippedEntry, latestEntry],
      gatedHistoryConversationIDs: [firstEntry.conversationID]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try installHistory([firstEntry, skippedEntry, latestEntry], in: model)

    model.openHistoryThread(threads[0])
    try await wire.waitForHistorySyncRequest(firstEntry.conversationID)
    model.openHistoryThread(threads[1])
    model.openHistoryThread(threads[2])
    await wire.releaseHistorySync(firstEntry.conversationID)

    try await wire.waitForHistorySyncRequest(latestEntry.conversationID)
    try await waitUntil { model.workbench.selectedConversationID == latestEntry.conversationID }
    let firstRequests = await wire.historySyncRequests(for: firstEntry.conversationID)
    let skippedRequests = await wire.historySyncRequests(for: skippedEntry.conversationID)
    let latestRequests = await wire.historySyncRequests(for: latestEntry.conversationID)
    XCTAssertEqual(firstRequests, 1)
    XCTAssertEqual(skippedRequests, 0)
    XCTAssertEqual(latestRequests, 1)
  }

  func testInvalidLatestHistoryIntentClearsPreviouslyPendingOpen() async throws {
    let activeEntry = reliabilityHistoryEntry("history-invalid-active")
    let pendingEntry = reliabilityHistoryEntry("history-invalid-pending")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: [activeEntry, pendingEntry],
      gatedHistoryConversationIDs: [activeEntry.conversationID]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try installHistory([activeEntry, pendingEntry], in: model)
    let staleThread = HistoryThreadSummary(
      id: "history-no-longer-authoritative",
      name: "stale",
      preview: "stale",
      cwd: "/tmp/agentdeck-history",
      createdAt: 1,
      updatedAt: 1,
      status: "ready",
      modelProvider: "openai",
      source: "codex",
      agentKind: .codex
    )

    model.openHistoryThread(threads[0])
    try await wire.waitForHistorySyncRequest(activeEntry.conversationID)
    model.openHistoryThread(threads[1])
    model.openHistoryThread(staleThread)
    XCTAssertNotNil(model.historyErrorMessage)

    await wire.releaseHistorySync(activeEntry.conversationID)
    try await Task.sleep(for: .milliseconds(40))
    let pendingRequests = await wire.historySyncRequests(for: pendingEntry.conversationID)
    XCTAssertEqual(pendingRequests, 0)
    XCTAssertNil(model.workbench.selectedConversationID)
  }

  func testStaleHistoryFailureReconnectsBeforeDrainingLatestIntent() async throws {
    let staleEntry = reliabilityHistoryEntry("history-stale-wire-a")
    let latestEntry = reliabilityHistoryEntry("history-fresh-wire-b")
    let entries = [staleEntry, latestEntry]
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries,
      gatedHistoryConversationIDs: [staleEntry.conversationID],
      historyTransportFailureConversationIDs: [staleEntry.conversationID]
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    defer { model.teardown() }
    let threads = try installHistory(entries, in: model)

    model.openHistoryThread(threads[0])
    try await firstWire.waitForHistorySyncRequest(staleEntry.conversationID)
    model.openHistoryThread(threads[1])
    await firstWire.releaseHistorySync(staleEntry.conversationID)

    try await firstWire.waitForClose()
    try await secondWire.waitForHistorySyncRequest(latestEntry.conversationID)
    try await waitUntil { model.workbench.selectedConversationID == latestEntry.conversationID }
    XCTAssertEqual(factory.constructionCount, 2)
    let firstLatestRequests = await firstWire.historySyncRequests(for: latestEntry.conversationID)
    let secondLatestRequests = await secondWire.historySyncRequests(for: latestEntry.conversationID)
    XCTAssertEqual(firstLatestRequests, 0)
    XCTAssertEqual(secondLatestRequests, 1)
  }

  func testCatalogPlus63ConversationsEvictsLeastRecentlyUsedBeforeNextOpen()
    async throws
  {
    let entries = (0..<64).map { reliabilityHistoryEntry("history-cap-\($0)") }
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try await loadHistoryAndOpenPrefix(
      entries,
      count: 63,
      in: model
    )

    model.openHistoryThread(threads[63])
    try await waitUntil { model.workbench.selectedConversationID == entries[63].conversationID }

    let unsubscribed = await wire.recordedUnsubscribeConversationIDs()
    XCTAssertEqual(unsubscribed, [entries[0].conversationID])
    let operations = await wire.recordedOperations()
    let unsubscribeIndex = try XCTUnwrap(
      operations.firstIndex(of: "unsubscribe:\(entries[0].conversationID.rawValue)")
    )
    let subscribeIndex = try XCTUnwrap(
      operations.firstIndex(of: "synchronize:\(entries[63].conversationID.rawValue)")
    )
    XCTAssertLessThan(unsubscribeIndex, subscribeIndex)
  }

  func testFailedUnsubscribeKeepsLedgerAndRetriesSameLeastRecentlyUsedVictim()
    async throws
  {
    let entries = (0..<64).map { reliabilityHistoryEntry("history-unsubscribe-retry-\($0)") }
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      unsubscribeFailuresRemaining: 1,
      historyEntries: entries
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try await loadHistoryAndOpenPrefix(
      entries,
      count: 63,
      in: model
    )

    model.openHistoryThread(threads[63])
    try await wire.waitForUnsubscribeRequestCount(1)
    try await waitUntil { model.historyErrorMessage != nil }
    XCTAssertEqual(model.workbench.selectedConversationID, entries[62].conversationID)
    let failedOpenSyncs = await wire.historySyncRequests(for: entries[63].conversationID)
    XCTAssertEqual(failedOpenSyncs, 0)

    model.openHistoryThread(threads[63])
    try await wire.waitForUnsubscribeRequestCount(2)
    try await waitUntil { model.workbench.selectedConversationID == entries[63].conversationID }
    let unsubscribed = await wire.recordedUnsubscribeConversationIDs()
    XCTAssertEqual(unsubscribed, [entries[0].conversationID, entries[0].conversationID])
  }

  func testNewConversationEvictsBeforeAnyStartSideEffectAtSubscriptionCapacity()
    async throws
  {
    let entries = (0..<63).map { reliabilityHistoryEntry("history-start-cap-\($0)") }
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    _ = try await loadHistoryAndOpenPrefix(entries, count: entries.count, in: model)
    model.startNewSessionFromCurrentProject()

    XCTAssertTrue(
      model.startConversation(
        try reliabilityDraft(prompt: nil, keySuffix: "start-at-subscription-cap")
      )
    )
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }

    let operations = await wire.recordedOperations()
    let unsubscribeIndex = try XCTUnwrap(
      operations.firstIndex(of: "unsubscribe:\(entries[0].conversationID.rawValue)")
    )
    let startIndex = try XCTUnwrap(operations.firstIndex(of: "start-conversation"))
    XCTAssertLessThan(unsubscribeIndex, startIndex)
  }

  func testNewConversationWithAllSubscriptionsPinnedFailsBeforeStartSideEffect()
    async throws
  {
    let entries = (0..<63).map { reliabilityHistoryEntry("history-start-pinned-\($0)") }
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    _ = try await loadHistoryAndOpenPrefix(entries, count: entries.count, in: model)
    for entry in entries {
      model.workbench.runtime(conversationID: entry.conversationID)?.phase = .running
    }
    model.startNewSessionFromCurrentProject()

    XCTAssertTrue(
      model.startConversation(
        try reliabilityDraft(prompt: nil, keySuffix: "start-with-pinned-subscriptions")
      )
    )
    try await waitUntil { model.retryableConversationDraft != nil }

    let startRequests = await wire.startRequests()
    let unsubscribeRequests = await wire.recordedUnsubscribeConversationIDs()
    XCTAssertEqual(startRequests, 0)
    XCTAssertTrue(unsubscribeRequests.isEmpty)
    XCTAssertTrue(
      model.errorMessage?.contains("subscription slots") == true,
      "expected a typed local capacity failure"
    )
  }

  func testConcurrentSlotConsumersSerializeEvictionThroughSubscribeAdmission()
    async throws
  {
    let entries = (0..<64).map { reliabilityHistoryEntry("history-admission-race-\($0)") }
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries,
      gateFirstUnsubscribe: true
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let threads = try await loadHistoryAndOpenPrefix(
      entries,
      count: 63,
      in: model
    )

    model.openHistoryThread(threads[63])
    try await wire.waitForUnsubscribeRequestCount(1)
    XCTAssertTrue(
      model.startConversation(
        try reliabilityDraft(prompt: nil, keySuffix: "concurrent-subscription-admission")
      )
    )
    try await Task.sleep(for: .milliseconds(40))

    let requestsBeforeFirstAck = await wire.startRequests()
    let evictionsBeforeFirstAck = await wire.recordedUnsubscribeConversationIDs()
    XCTAssertEqual(requestsBeforeFirstAck, 0)
    XCTAssertEqual(evictionsBeforeFirstAck, [entries[0].conversationID])

    await wire.releaseFirstUnsubscribe()
    try await wire.waitForUnsubscribeRequestCount(2)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let evictions = await wire.recordedUnsubscribeConversationIDs()
    XCTAssertEqual(evictions, [entries[0].conversationID, entries[1].conversationID])
    let operations = await wire.recordedOperations()
    let secondEvictionIndex = try XCTUnwrap(
      operations.firstIndex(of: "unsubscribe:\(entries[1].conversationID.rawValue)")
    )
    let startIndex = try XCTUnwrap(operations.firstIndex(of: "start-conversation"))
    XCTAssertLessThan(secondEvictionIndex, startIndex)
  }

  func testReconnectAfterOpening100RestoresOnlyCatalogAndSelectedConversation()
    async throws
  {
    let entries = (0..<100).map { reliabilityHistoryEntry("history-reconnect-\($0)") }
    let firstWire = try SessionReliabilityWire(
      promptOutcomes: [],
      historyEntries: entries
    )
    let secondWire = try SessionReliabilityWire(
      promptOutcomes: [.success],
      historyEntries: entries
    )
    let factory = SessionReliabilityWireFactory([firstWire, secondWire])
    let model = SessionModel(runtimeWireFactory: { factory.make() })
    defer { model.teardown() }
    _ = try await loadHistoryAndOpenPrefix(entries, count: entries.count, in: model)

    await firstWire.failStreamUnexpectedly()
    try await firstWire.waitForClose()
    try await waitUntil { model.selectedWarningMessage != nil }
    XCTAssertTrue(model.submit("bounded reconnect restore"))
    try await secondWire.waitForPromptRequestCount(1)

    let synchronizationOperations = await secondWire.recordedOperations().filter {
      $0.hasPrefix("synchronize:")
    }
    XCTAssertEqual(
      synchronizationOperations,
      [
        "synchronize:catalog",
        "synchronize:\(entries[99].conversationID.rawValue)",
      ]
    )
    XCTAssertEqual(factory.constructionCount, 2)
  }

  func testBootstrapInvalidatesSlowHistoryCompletion() async throws {
    let historyEntry = reliabilityHistoryEntry("history-slow-bootstrap")
    let wire = try SessionReliabilityWire(
      promptOutcomes: [],
      startFailuresRemaining: 1,
      historyEntries: [historyEntry],
      gatedHistoryConversationIDs: [historyEntry.conversationID]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let historyThread = try installHistory([historyEntry], in: model)[0]
    let bootstrapCwd = "/tmp/agentdeck-bootstrap-invalidates-history"
    model.cwd = URL(fileURLWithPath: bootstrapCwd)

    model.openHistoryThread(historyThread)
    try await wire.waitForHistorySyncRequest(historyEntry.conversationID)
    XCTAssertTrue(model.submit("new bootstrap intent"))
    try await Task.sleep(for: .milliseconds(20))
    XCTAssertNil(model.workbench.selectedConversationID)

    await wire.releaseHistorySync(historyEntry.conversationID)
    try await waitUntil { model.retryableConversationDraft != nil }
    try await waitUntil {
      model.workbench.runtime(conversationID: historyEntry.conversationID)?.runtimeCapabilities
        != nil
    }
    await Task.yield()

    XCTAssertNil(model.workbench.selectedConversationID)
    XCTAssertNil(model.selectedSidebarConversationID)
    assertBootstrapOwner(model.promptComposerOwner, agentKind: .codex)
    XCTAssertEqual(model.retryableConversationDraft?.cwd, bootstrapCwd)
  }

  func testConfigureConflictSynchronizesCurrentStateAndRestoresPromptForExplicitRetry()
    async throws
  {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.gatedSuccess],
      configureConflictsRemaining: 1
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-configure-conflict")

    XCTAssertTrue(model.submit("prompt after conflict"))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertEqual(model.retryRequiredPrompt, "prompt after conflict")
    XCTAssertNotNil(model.selectedWarningMessage)
    let promptRequestCount = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequestCount, 0)

    XCTAssertTrue(model.submit("prompt after conflict"))
    try await wire.waitForPromptRequestCount(1)
    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.promptExpectedRevisions, [1])
  }

  func testDuplicateStartWarnsWithoutOverwritingActiveStartPhase() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let draft = try reliabilityDraft(prompt: "single active start", keySuffix: "active")

    model.startConversation(draft)
    try await wire.waitForPromptRequestCount(1)
    model.startConversation(
      try reliabilityDraft(prompt: "single active start", keySuffix: "duplicate")
    )

    XCTAssertEqual(model.phase, .starting)
    XCTAssertNil(model.errorMessage)
    XCTAssertNotNil(model.warningMessage)

    await wire.releaseGatedPromptSuccess()
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    XCTAssertNil(model.errorMessage)
    XCTAssertNil(model.warningMessage)
  }

  func testPromptAdmissionBecomesQueuedOnlyAfterCommandReceiptSucceeds() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }

    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)

    XCTAssertEqual(runtime.pendingPromptAdmissions, ["queued prompt"])
    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
    XCTAssertEqual(model.queuedPrompts, ["queued prompt"])
  }

  func testReadyComposerPromptIsSendingUntilDaemonReceiptThenQueued() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(
      model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
    )
    XCTAssertEqual(runtime.phase, .ready)

    model.submit("ready composer prompt")
    try await wire.waitForPromptRequestCount(1)
    XCTAssertEqual(runtime.pendingPromptAdmissions, ["ready composer prompt"])

    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
    XCTAssertEqual(model.queuedPrompts, ["ready composer prompt"])
  }

  func testActivePhasePromptsEnterDaemonAdmissionBeforeTurnTerminal() async throws {
    for activePhase in [
      SessionModel.Phase.running,
      .waitingApproval,
      .draining,
    ] {
      let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
      let model = SessionModel(runtimeWire: wire)
      model.startConversation(try reliabilityDraft(prompt: nil))
      try await waitUntil {
        model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
      }
      let runtime = try XCTUnwrap(
        model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
      )
      runtime.phase = activePhase

      model.submit("prompt while \(activePhase.rawValue)")

      try await wire.waitForPromptRequestCount(1)
      XCTAssertEqual(runtime.phase, activePhase)
      XCTAssertTrue(
        model.queuedPrompts.isEmpty,
        "daemon receipt 前的本地 admission 不得冒充 Accepted queued"
      )

      await wire.releaseGatedPromptSuccess()
      try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
      XCTAssertEqual(model.queuedPrompts, ["prompt while \(activePhase.rawValue)"])
      model.teardown()
      try await wire.waitForClose()
    }
  }

  func testOversizedComposerPromptNeverPoisonsRuntimeQueue() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.success])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(
      model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
    )
    let oversized = String(repeating: "x", count: RuntimePromptPayloadV1.maxUTF8Bytes + 1)

    model.submit(oversized)
    await Task.yield()

    XCTAssertTrue(runtime.pendingPromptAdmissions.isEmpty)
    XCTAssertNotNil(runtime.errorMessage)
    let promptRequests = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequests, 0)

    model.submit("valid after oversized")
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
  }

  func testAdmissionFailuresExitSendingAndRetainRetryDraft() async throws {
    let failures: [SessionReliabilityPromptOutcome] = [
      .operationInProgress,
      .transportFailure,
      .daemonFailure,
    ]

    for failure in failures {
      let wire = try SessionReliabilityWire(promptOutcomes: [failure])
      let model = SessionModel(runtimeWire: wire)
      let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)

      try await waitUntil { runtime.errorMessage != nil }
      XCTAssertTrue(runtime.pendingPromptAdmissions.isEmpty)
      XCTAssertEqual(runtime.retryRequiredPrompt, "queued prompt")
      XCTAssertTrue(model.sendingPrompts.isEmpty)
      model.teardown()
    }
  }

  func testOutcomeUnknownRetryReusesOriginalIdempotencyKey() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .gatedSuccess]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    try await waitUntil { runtime.errorMessage != nil }

    XCTAssertTrue(model.submit("queued prompt"))
    try await wire.waitForPromptRequestCount(2)
    XCTAssertEqual(runtime.pendingPromptAdmissions, ["queued prompt"])
    XCTAssertNil(runtime.retryRequiredPrompt)

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.prompt.count, 2)
    XCTAssertEqual(keys.prompt[0], keys.prompt[1])
    XCTAssertNil(runtime.errorMessage)
  }

  func testOutcomeUnknownRetryKeepsFrozenRevisionAfterConfigurationAdvance() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .gatedSuccess]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(model.workbench.selectedRuntime)

    XCTAssertTrue(model.submit("frozen revision prompt"))
    try await waitUntil { runtime.retryRequiredPrompt == "frozen revision prompt" }
    try await wire.emitConfigurationChanged(sequence: 0, revision: 2)
    try await waitUntil { runtime.configurationState?.configurationRevision == 2 }

    XCTAssertTrue(model.submit("frozen revision prompt"))
    try await wire.waitForPromptRequestCount(2)
    let capture = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(capture.prompt.count, 2)
    XCTAssertEqual(capture.prompt[0], capture.prompt[1])
    XCTAssertEqual(capture.promptExpectedRevisions, [1, 1])
  }

  func testCanonicalEquivalentDifferentBytesNeverReuseOutcomeUnknownKey() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .gatedSuccess]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let precomposed = "caf\u{00E9}"
    let decomposed = "cafe\u{0301}"
    XCTAssertEqual(precomposed, decomposed)

    XCTAssertTrue(model.submit(precomposed))
    try await waitUntil { model.retryRequiredPrompt == precomposed }
    XCTAssertTrue(model.submit(decomposed))
    try await wire.waitForPromptRequestCount(2)

    let capture = await wire.recordedIdempotencyKeys()
    XCTAssertNotEqual(capture.prompt[0], capture.prompt[1])
    XCTAssertEqual(Array(capture.promptPayloads[0].utf8), Array(precomposed.utf8))
    XCTAssertEqual(Array(capture.promptPayloads[1].utf8), Array(decomposed.utf8))
  }

  func testDefinitiveAdmissionFailuresRetryWithFreshIdempotencyKey() async throws {
    for definitiveFailure in [
      SessionReliabilityPromptOutcome.operationInProgress,
      .daemonFailure,
    ] {
      let wire = try SessionReliabilityWire(
        promptOutcomes: [definitiveFailure, .gatedSuccess]
      )
      let model = SessionModel(runtimeWire: wire)
      let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
      try await waitUntil { runtime.retryRequiredPrompt == "queued prompt" }

      XCTAssertTrue(model.submit("queued prompt"))
      try await wire.waitForPromptRequestCount(2)
      let keys = await wire.recordedIdempotencyKeys()
      XCTAssertEqual(keys.prompt.count, 2)
      XCTAssertNotEqual(
        keys.prompt[0],
        keys.prompt[1],
        "明确未接受的 \(definitiveFailure) 不得复用会稳定重放失败的旧 key"
      )
      await wire.releaseGatedPromptSuccess()
      model.teardown()
    }
  }

  func testDifferentPromptReplacesRetryDraftWithoutImplicitOldRetry() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .gatedSuccess]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    try await waitUntil { runtime.retryRequiredPrompt == "queued prompt" }

    XCTAssertTrue(model.submit("new intent"))
    try await wire.waitForPromptRequestCount(2)

    XCTAssertEqual(runtime.pendingPromptAdmissions, ["new intent"])
    XCTAssertNil(runtime.retryRequiredPrompt)
    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.prompt.count, 2)
    XCTAssertNotEqual(keys.prompt[0], keys.prompt[1])
  }

  func testOutcomeUnknownFailureDoesNotOverwriteLiveRunningPhase() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedTransportFailure])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)

    await wire.releaseGatedPromptTransportFailure()
    try await waitUntil { runtime.errorMessage != nil }

    XCTAssertEqual(runtime.phase, .running)
    XCTAssertTrue(runtime.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(runtime.retryRequiredPrompt, "queued prompt")
  }

  func testSingleFlightRejectsSecondPromptUntilFirstReceipt() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess, .success])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    XCTAssertFalse(model.submit("second queued prompt"))
    XCTAssertEqual(runtime.pendingPromptAdmissions, ["queued prompt"])

    try await wire.emitTurnCompleted(
      sequence: 1,
      commandID: "command-active",
      turnID: "turn-active"
    )
    try await waitUntil { runtime.phase == .ready }
    let promptRequestsBeforeReceipt = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequestsBeforeReceipt, 1)

    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
    XCTAssertTrue(model.submit("second queued prompt"))
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
  }

  func testLaterAdmissionFailureCannotRestoreEarlierAcceptedCommandToReady() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.gatedSuccess, .transportFailure]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(
      model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
    )

    model.submit("first accepted prompt")
    try await wire.waitForPromptRequestCount(1)
    XCTAssertEqual(runtime.phase, .starting)

    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
    XCTAssertTrue(model.submit("later failed prompt"))
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil { runtime.errorMessage != nil }

    XCTAssertEqual(
      runtime.phase,
      .starting,
      "后续 admission 失败不得把前一条已 Accepted、尚待 canonical event 的 command 冒充 ready"
    )
    XCTAssertTrue(runtime.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(runtime.retryRequiredPrompt, "later failed prompt")
  }

  func testReplayedTerminalReceiptRestoresReadyAndDispatchesNextQueuedPrompt() async throws {
    let replayedCommandID = "command-replayed-terminal"
    let wire = try SessionReliabilityWire(
      promptOutcomes: [
        .gatedTransportFailure,
        .replayed(commandID: replayedCommandID),
        .success,
      ]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    model.startConversation(try reliabilityDraft(prompt: nil))
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(
      model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
    )

    model.submit("outcome unknown prompt")
    try await wire.waitForPromptRequestCount(1)
    try await wire.emitTurnStarted(
      commandID: replayedCommandID,
      turnID: "turn-replayed-terminal"
    )
    try await wire.emitTurnCompleted(
      commandID: replayedCommandID,
      turnID: "turn-replayed-terminal"
    )
    try await waitUntil { runtime.phase == .ready }
    await wire.releaseGatedPromptTransportFailure()
    try await waitUntil { runtime.errorMessage != nil }
    XCTAssertTrue(runtime.pendingPromptAdmissions.isEmpty)
    XCTAssertEqual(runtime.retryRequiredPrompt, "outcome unknown prompt")

    XCTAssertTrue(model.submit("outcome unknown prompt"))
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }
    XCTAssertTrue(model.submit("next accepted prompt"))
    try await wire.waitForPromptRequestCount(3)
    try await waitUntil { runtime.pendingPromptAdmissions.isEmpty }

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.prompt.count, 3)
    XCTAssertEqual(keys.prompt[0], keys.prompt[1])
    XCTAssertNotEqual(keys.prompt[1], keys.prompt[2])
    XCTAssertEqual(
      runtime.phase,
      .starting,
      "真实 accepted command 仍须等待 canonical turn event，不能被 replay 恢复逻辑误判为 ready"
    )
  }

  func testTeardownPreventsLatePromptFailureFromMutatingClosedModel() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    XCTAssertEqual(runtime.phase, .running)

    model.teardown()
    try await wire.waitForClose()
    try await Task.sleep(for: .milliseconds(10))

    XCTAssertEqual(model.phase, .closed)
    XCTAssertEqual(runtime.phase, .running)
    XCTAssertNil(runtime.errorMessage)
    XCTAssertEqual(runtime.pendingPromptAdmissions, ["queued prompt"])
  }

  private func prepareQueuedPromptDispatch(
    model: SessionModel,
    wire: SessionReliabilityWire
  ) async throws -> ThreadRuntimeModel {
    let draft = try reliabilityDraft(prompt: nil)
    model.startConversation(draft)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }
    let runtime = try XCTUnwrap(
      model.workbench.runtime(conversationID: SessionReliabilityWire.conversationID)
    )

    try await wire.emitTurnStarted()
    try await waitUntil { runtime.phase == .running }
    XCTAssertTrue(model.submit("queued prompt"))

    try await wire.waitForPromptRequestCount(1)
    return runtime
  }

  private func installHistory(
    _ entries: [RuntimeConversationEntryV2],
    in model: SessionModel
  ) throws -> [HistoryThreadSummary] {
    try model.workbench.installCatalog(
      snapshotPages: [
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: entries,
          nextPageCursor: nil
        )
      ]
    )
    let threads = entries.map { entry in
      HistoryThreadSummary(
        id: entry.conversationID.rawValue,
        name: entry.title,
        preview: entry.title ?? entry.conversationID.rawValue,
        cwd: entry.cwd ?? "",
        createdAt: Int(entry.lastActiveMs / 1_000),
        updatedAt: Int(entry.lastActiveMs / 1_000),
        status: "ready",
        modelProvider: entry.agentKind == .codex ? "openai" : "anthropic",
        source: entry.agentKind == .codex ? "codex" : "claude_code",
        agentKind: entry.agentKind
      )
    }
    model.setHistoryThreads(threads)
    return threads
  }

  private func loadHistoryAndOpenPrefix(
    _ entries: [RuntimeConversationEntryV2],
    count: Int,
    in model: SessionModel
  ) async throws -> [HistoryThreadSummary] {
    precondition((0...entries.count).contains(count))
    model.loadHistory()
    try await waitUntil { model.historyThreads.count == entries.count }
    let threads = try entries.map { entry in
      try XCTUnwrap(
        model.historyThreads.first { $0.id == entry.conversationID.rawValue }
      )
    }
    for index in 0..<count {
      model.openHistoryThread(threads[index])
      try await waitUntil {
        model.workbench.selectedConversationID == entries[index].conversationID
      }
    }
    return threads
  }

  private func waitUntil(
    _ predicate: @MainActor () -> Bool
  ) async throws {
    for _ in 0..<400 {
      if predicate() { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }
}

private enum SessionReliabilityPromptOutcome: CustomStringConvertible, Sendable {
  case success
  case gatedSuccess
  case gatedTransportFailure
  case replayed(commandID: String)
  case operationInProgress
  case coordinatorClosed
  case transportFailure
  case daemonFailure
  case storeUnavailable

  var description: String {
    switch self {
    case .success: "success"
    case .gatedSuccess: "gatedSuccess"
    case .gatedTransportFailure: "gatedTransportFailure"
    case .replayed(let commandID): "replayed(\(commandID))"
    case .operationInProgress: "operationInProgress"
    case .coordinatorClosed: "coordinatorClosed"
    case .transportFailure: "transportFailure"
    case .daemonFailure: "daemonFailure"
    case .storeUnavailable: "storeUnavailable"
    }
  }
}

private enum SessionReliabilityWireError: Error {
  case closed
  case timeout
  case unexpectedRequest
}

private actor SessionReliabilityWire: AppRuntimeWireSession {
  static let conversationID = RuntimeConversationID(rawValue: "conversation-reliability")

  private let descriptions: RuntimeAgentDescriptionsV2
  private let catalogEntries: [RuntimeConversationEntryV2]
  private let historySnapshots: [RuntimeConversationID: ConversationSnapshotV2]
  private let gatedHistoryConversationIDs: Set<RuntimeConversationID>
  private let historyTransportFailureConversationIDs: Set<RuntimeConversationID>
  private let latchTransportFailures: Bool
  private let gateClose: Bool
  private let gateFirstUnsubscribe: Bool
  private var promptOutcomes: [SessionReliabilityPromptOutcome]
  private var latchedTransportFailure: RuntimeEnvelopeClientFailure?
  private var operationLog: [String] = []
  private var describeFailuresRemaining: Int
  private var catalogTransportFailuresRemaining: Int
  private var startTransportFailuresRemaining: Int
  private var promptRequestCount = 0
  private var startCallCount = 0
  private var describeRequestCount = 0
  private var startRequestCount = 0
  private var configureRequestCount = 0
  private var startIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var startAgentKinds: [AgentKind] = []
  private var startCwds: [String] = []
  private var configureIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var promptIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var promptExpectedRevisions: [UInt64] = []
  private var promptPayloads: [String] = []
  private var startFailuresRemaining: Int
  private var startStoreUnavailableFailuresRemaining: Int
  private var configureFailuresRemaining: Int
  private var configureStoreUnavailableFailuresRemaining: Int
  private var configureConflictsRemaining: Int
  private var unsubscribeFailuresRemaining: Int
  private var unsubscribeConversationIDs: [RuntimeConversationID] = []
  private var firstUnsubscribeGateReleased = false
  private var firstUnsubscribeContinuation: CheckedContinuation<Void, Never>?
  private var activeConversationAgentKind: AgentKind = .codex
  private var historySyncRequestCounts: [RuntimeConversationID: Int] = [:]
  private var synchronizationRequestCounts: [RuntimeConversationID: Int] = [:]
  private var gatedHistorySequences: [RuntimeConversationID: SessionReliabilityReplySequence] = [:]
  private var streamFrames: [LocalRuntimeStreamFrame] = []
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var pendingStreamFailure: RuntimeEnvelopeClientFailure?
  private var gatedPromptContinuation: CheckedContinuation<RuntimeReplyV2, Error>?
  private var gatedPromptRevision: UInt64?
  private var gatedPromptWillSucceed = false
  private var isClosed = false
  private var closeCount = 0
  private var closeGateReleased = false
  private var closeGateContinuation: CheckedContinuation<Void, Never>?

  init(
    promptOutcomes: [SessionReliabilityPromptOutcome],
    describeFailuresRemaining: Int = 0,
    catalogTransportFailuresRemaining: Int = 0,
    startTransportFailuresRemaining: Int = 0,
    startFailuresRemaining: Int = 0,
    startStoreUnavailableFailuresRemaining: Int = 0,
    configureFailuresRemaining: Int = 0,
    configureStoreUnavailableFailuresRemaining: Int = 0,
    configureConflictsRemaining: Int = 0,
    unsubscribeFailuresRemaining: Int = 0,
    historyEntries: [RuntimeConversationEntryV2] = [],
    gatedHistoryConversationIDs: Set<RuntimeConversationID> = [],
    historyTransportFailureConversationIDs: Set<RuntimeConversationID> = [],
    latchTransportFailures: Bool = false,
    gateClose: Bool = false,
    gateFirstUnsubscribe: Bool = false
  ) throws {
    self.promptOutcomes = promptOutcomes
    self.describeFailuresRemaining = describeFailuresRemaining
    self.catalogTransportFailuresRemaining = catalogTransportFailuresRemaining
    self.startTransportFailuresRemaining = startTransportFailuresRemaining
    self.startFailuresRemaining = startFailuresRemaining
    self.startStoreUnavailableFailuresRemaining = startStoreUnavailableFailuresRemaining
    self.configureFailuresRemaining = configureFailuresRemaining
    self.configureStoreUnavailableFailuresRemaining =
      configureStoreUnavailableFailuresRemaining
    self.configureConflictsRemaining = configureConflictsRemaining
    self.unsubscribeFailuresRemaining = unsubscribeFailuresRemaining
    self.gatedHistoryConversationIDs = gatedHistoryConversationIDs
    self.historyTransportFailureConversationIDs = historyTransportFailureConversationIDs
    self.latchTransportFailures = latchTransportFailures
    self.gateClose = gateClose
    self.gateFirstUnsubscribe = gateFirstUnsubscribe
    catalogEntries = historyEntries
    let codexCapabilities = try reliabilityCodexCapabilities()
    let claudeCodeCapabilities = try reliabilityClaudeCodeCapabilities()
    descriptions = try RuntimeAgentDescriptionsV2(
      agents: [
        try RuntimeAgentDescriptionV2(
          agentKind: .codex,
          capabilities: codexCapabilities,
          defaultConfiguration: reliabilityCodexConfiguration()
        ),
        try RuntimeAgentDescriptionV2(
          agentKind: .claudeCode,
          capabilities: claudeCodeCapabilities,
          defaultConfiguration: try reliabilityClaudeCodeConfiguration()
        ),
      ]
    )
    historySnapshots = try Dictionary(
      uniqueKeysWithValues: historyEntries.map { entry in
        (
          entry.conversationID,
          try reliabilitySnapshot(
            conversationID: entry.conversationID,
            agentKind: entry.agentKind
          )
        )
      }
    )
  }

  func start() async throws {
    if let latchedTransportFailure { throw latchedTransportFailure }
    startCallCount += 1
    operationLog.append("start-wire")
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    if let latchedTransportFailure { throw latchedTransportFailure }
    switch request {
    case .describeAgents:
      describeRequestCount += 1
      operationLog.append("describe")
      if describeFailuresRemaining > 0 {
        describeFailuresRemaining -= 1
        throw latchIfRequested(
          RuntimeEnvelopeClientFailure(
            code: "test.describe.failed",
            message: "DescribeAgents unavailable"
          )
        )
      }
      return .agents(descriptions)
    case .catalog:
      operationLog.append("catalog-page")
      if catalogTransportFailuresRemaining > 0 {
        catalogTransportFailuresRemaining -= 1
        throw latchIfRequested(
          RuntimeEnvelopeClientFailure(
            code: "test.catalog.transport",
            message: "Catalog outcome unknown"
          )
        )
      }
      return .catalog(
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: catalogEntries,
          nextPageCursor: nil
        )
      )
    case .start(let agentKind, let idempotencyKey, let cwd, _):
      startRequestCount += 1
      startIdempotencyKeys.append(idempotencyKey)
      startAgentKinds.append(agentKind)
      startCwds.append(cwd)
      activeConversationAgentKind = agentKind
      operationLog.append("start-conversation")
      if startTransportFailuresRemaining > 0 {
        startTransportFailuresRemaining -= 1
        throw latchIfRequested(
          RuntimeEnvelopeClientFailure(
            code: "test.start.transport",
            message: "Start outcome unknown"
          )
        )
      }
      if startFailuresRemaining > 0 {
        startFailuresRemaining -= 1
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.invalid_request",
            message: "Start rejected before commit"
          )
        )
      }
      if startStoreUnavailableFailuresRemaining > 0 {
        startStoreUnavailableFailuresRemaining -= 1
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.store_unavailable",
            message: "Start commit outcome is unknown"
          )
        )
      }
      return .conversationStart(
        ConversationStartReceiptV2(
          conversationID: Self.conversationID,
          replayed: startRequestCount > 1
        )
      )
    case .configureConversation(let configuration):
      configureRequestCount += 1
      configureIdempotencyKeys.append(configuration.idempotencyKey)
      operationLog.append("configure")
      if configureFailuresRemaining > 0 {
        configureFailuresRemaining -= 1
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.invalid_request",
            message: "Configure rejected before commit"
          )
        )
      }
      if configureStoreUnavailableFailuresRemaining > 0 {
        configureStoreUnavailableFailuresRemaining -= 1
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.store_unavailable",
            message: "Configure commit outcome is unknown"
          )
        )
      }
      if configureConflictsRemaining > 0 {
        configureConflictsRemaining -= 1
        return .configuration(
          .conflict(
            conversationID: Self.conversationID,
            currentConfigurationRevision: 1
          )
        )
      }
      return .configuration(
        configureRequestCount > 1
          ? .replayed(conversationID: Self.conversationID, configurationRevision: 1)
          : .applied(conversationID: Self.conversationID, configurationRevision: 1)
      )
    case .sendPrompt(_, let idempotencyKey, let revision, let prompt):
      promptRequestCount += 1
      promptIdempotencyKeys.append(idempotencyKey)
      promptExpectedRevisions.append(revision)
      promptPayloads.append(prompt.rawValue)
      operationLog.append("prompt")
      guard !promptOutcomes.isEmpty else {
        throw SessionReliabilityWireError.unexpectedRequest
      }
      switch promptOutcomes.removeFirst() {
      case .success:
        return commandReceipt(revision: revision)
      case .gatedSuccess:
        gatedPromptRevision = revision
        gatedPromptWillSucceed = true
        return try await withCheckedThrowingContinuation { continuation in
          precondition(gatedPromptContinuation == nil)
          gatedPromptContinuation = continuation
        }
      case .gatedTransportFailure:
        gatedPromptRevision = revision
        gatedPromptWillSucceed = false
        return try await withCheckedThrowingContinuation { continuation in
          precondition(gatedPromptContinuation == nil)
          gatedPromptContinuation = continuation
        }
      case .replayed(let commandID):
        return .command(
          .replayed(
            commandID: RuntimeCommandID(rawValue: commandID),
            configurationRevision: revision
          )
        )
      case .operationInProgress:
        throw AppRuntimeCoordinatorError.operationInProgress
      case .coordinatorClosed:
        throw AppRuntimeCoordinatorError.closed
      case .transportFailure:
        throw latchIfRequested(
          RuntimeEnvelopeClientFailure(
            code: "test.transport",
            message: "transport unavailable"
          )
        )
      case .daemonFailure:
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.invalid_request",
            message: "daemon rejected prompt before commit"
          )
        )
      case .storeUnavailable:
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.store_unavailable",
            message: "Prompt commit outcome is unknown"
          )
        )
      }
    case .unsubscribe(.conversation(let conversationID)):
      unsubscribeConversationIDs.append(conversationID)
      operationLog.append("unsubscribe:\(conversationID.rawValue)")
      if gateFirstUnsubscribe,
        unsubscribeConversationIDs.count == 1,
        !firstUnsubscribeGateReleased
      {
        await withCheckedContinuation { continuation in
          if firstUnsubscribeGateReleased {
            continuation.resume()
          } else {
            precondition(firstUnsubscribeContinuation == nil)
            firstUnsubscribeContinuation = continuation
          }
        }
      }
      if unsubscribeFailuresRemaining > 0 {
        unsubscribeFailuresRemaining -= 1
        return .failure(
          RuntimeFailureV1(
            code: "daemon.runtime.store_unavailable",
            message: "Unsubscribe outcome is unavailable"
          )
        )
      }
      return .subscription(.unsubscribed)
    default:
      throw SessionReliabilityWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    if let latchedTransportFailure { throw latchedTransportFailure }
    if case .backfill(.catalog(let cursor)) = request {
      operationLog.append("backfill:catalog")
      return SessionReliabilityReplySequence(
        replies: [.syncComplete(try reliabilityCatalogSyncComplete(cursor: cursor))]
      )
    }
    guard case .subscribe(let cursor) = request else {
      throw SessionReliabilityWireError.unexpectedRequest
    }
    if case .catalog(let catalogCursor) = cursor {
      operationLog.append("synchronize:catalog")
      return SessionReliabilityReplySequence(
        replies: [
          .subscription(
            .subscribed(
              streamGeneration: RuntimeStreamGeneration(rawValue: "generation-reliability")
            )
          ),
          .syncComplete(try reliabilityCatalogSyncComplete(cursor: catalogCursor)),
        ]
      )
    }
    guard case .conversation(let conversationID, let conversationCursor) = cursor else {
      throw SessionReliabilityWireError.unexpectedRequest
    }
    operationLog.append("synchronize:\(conversationID.rawValue)")
    synchronizationRequestCounts[conversationID, default: 0] += 1
    var replies: [RuntimeReplyV2] = [
      .subscription(
        .subscribed(
          streamGeneration: RuntimeStreamGeneration(rawValue: "generation-reliability")
        )
      )
    ]
    if conversationID == Self.conversationID {
      if conversationCursor == .beforeFirst {
        replies.append(
          .snapshot(
            try reliabilitySnapshot(
              conversationID: conversationID,
              agentKind: activeConversationAgentKind
            )
          )
        )
      }
    } else if let historySnapshot = historySnapshots[conversationID] {
      if conversationCursor == .beforeFirst { replies.append(.snapshot(historySnapshot)) }
      historySyncRequestCounts[conversationID, default: 0] += 1
    } else {
      throw SessionReliabilityWireError.unexpectedRequest
    }
    replies.append(
      .syncComplete(
        try reliabilitySyncComplete(
          conversationID: conversationID,
          cursor: conversationCursor
        )
      )
    )
    let sequence = SessionReliabilityReplySequence(
      replies: replies,
      gateAfterFirstReply: gatedHistoryConversationIDs.contains(conversationID),
      failureAfterFirstReply: historyTransportFailureConversationIDs.contains(conversationID)
        ? RuntimeEnvelopeClientFailure(
          code: "test.history.transport",
          message: "History synchronization outcome is unknown"
        )
        : nil
    )
    if gatedHistoryConversationIDs.contains(conversationID) {
      gatedHistorySequences[conversationID] = sequence
    }
    return sequence
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !isClosed else { throw SessionReliabilityWireError.closed }
    if let pendingStreamFailure {
      self.pendingStreamFailure = nil
      throw pendingStreamFailure
    }
    if !streamFrames.isEmpty { return streamFrames.removeFirst() }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamContinuation == nil)
      streamContinuation = continuation
    }
  }

  func close() async {
    guard !isClosed else { return }
    isClosed = true
    closeCount += 1
    operationLog.append("close")
    streamContinuation?.resume(throwing: SessionReliabilityWireError.closed)
    streamContinuation = nil
    gatedPromptContinuation?.resume(throwing: SessionReliabilityWireError.closed)
    gatedPromptContinuation = nil
    releaseFirstUnsubscribe()
    for sequence in gatedHistorySequences.values { await sequence.cancel() }
    gatedHistorySequences.removeAll()
    if gateClose, !closeGateReleased {
      await withCheckedContinuation { continuation in
        if closeGateReleased {
          continuation.resume()
        } else {
          closeGateContinuation = continuation
        }
      }
    }
  }

  func emitTurnStarted(
    sequence: UInt64 = 0,
    commandID: String = "command-active",
    turnID: String = "turn-active"
  ) throws {
    try enqueue(
      RuntimeEventV2(
        conversationID: Self.conversationID,
        eventID: RuntimeEventID(rawValue: "event-turn-started-\(sequence)"),
        eventSeq: sequence,
        commandID: RuntimeCommandID(rawValue: commandID),
        itemID: nil,
        entityID: nil,
        body: .turnStarted(turnID: RuntimeTurnID(rawValue: turnID))
      )
    )
  }

  func emitTurnCompleted(
    sequence: UInt64 = 1,
    commandID: String = "command-active",
    turnID: String = "turn-active"
  ) throws {
    try enqueue(
      RuntimeEventV2(
        conversationID: Self.conversationID,
        eventID: RuntimeEventID(rawValue: "event-turn-completed-\(sequence)"),
        eventSeq: sequence,
        commandID: RuntimeCommandID(rawValue: commandID),
        itemID: nil,
        entityID: nil,
        body: .turnCompleted(
          turnID: RuntimeTurnID(rawValue: turnID),
          summary: try reliabilityTurnSummary()
        )
      )
    )
  }

  func emitConfigurationChanged(sequence: UInt64, revision: UInt64) throws {
    try enqueue(
      RuntimeEventV2(
        conversationID: Self.conversationID,
        eventID: RuntimeEventID(rawValue: "event-configuration-\(sequence)"),
        eventSeq: sequence,
        commandID: nil,
        itemID: nil,
        entityID: nil,
        body: .configurationChanged(
          try RuntimeConversationConfigurationStateV2(
            configurationRevision: revision,
            configuration: reliabilityCodexConfiguration()
          )
        )
      )
    )
  }

  func waitForPromptRequestCount(_ expected: Int) async throws {
    for _ in 0..<400 {
      if promptRequestCount >= expected { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func waitForDescribeRequestCount(_ expected: Int) async throws {
    for _ in 0..<400 {
      if describeRequestCount >= expected { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func waitForClose() async throws {
    for _ in 0..<400 {
      if closeCount > 0 { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func waitForUnsubscribeRequestCount(_ expected: Int) async throws {
    for _ in 0..<400 {
      if unsubscribeConversationIDs.count >= expected { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func bootstrapCounts() -> (start: Int, describe: Int) {
    (startCallCount, describeRequestCount)
  }

  func startRequests() -> Int {
    startRequestCount
  }

  func historySyncRequests(for conversationID: RuntimeConversationID) -> Int {
    historySyncRequestCounts[conversationID, default: 0]
  }

  func waitForSynchronizationRequest(_ conversationID: RuntimeConversationID) async throws {
    for _ in 0..<400 {
      if synchronizationRequestCounts[conversationID, default: 0] > 0 { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func waitForHistorySyncRequest(_ conversationID: RuntimeConversationID) async throws {
    for _ in 0..<400 {
      if historySyncRequestCounts[conversationID, default: 0] > 0 { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw SessionReliabilityWireError.timeout
  }

  func releaseHistorySync(_ conversationID: RuntimeConversationID) async {
    await gatedHistorySequences[conversationID]?.releaseGate()
  }

  func currentPromptRequestCount() -> Int {
    promptRequestCount
  }

  func currentCloseCount() -> Int {
    closeCount
  }

  func releaseClose() {
    closeGateReleased = true
    closeGateContinuation?.resume()
    closeGateContinuation = nil
  }

  func recordedIdempotencyKeys() -> SessionReliabilityIdempotencyCapture {
    SessionReliabilityIdempotencyCapture(
      start: startIdempotencyKeys,
      startAgentKinds: startAgentKinds,
      startCwds: startCwds,
      configure: configureIdempotencyKeys,
      prompt: promptIdempotencyKeys,
      promptExpectedRevisions: promptExpectedRevisions,
      promptPayloads: promptPayloads
    )
  }

  func recordedOperations() -> [String] {
    operationLog
  }

  func recordedUnsubscribeConversationIDs() -> [RuntimeConversationID] {
    unsubscribeConversationIDs
  }

  func releaseFirstUnsubscribe() {
    firstUnsubscribeGateReleased = true
    firstUnsubscribeContinuation?.resume()
    firstUnsubscribeContinuation = nil
  }

  func failStreamUnexpectedly() {
    let failure = RuntimeEnvelopeClientFailure(
      code: "test.stream.closed",
      message: "Runtime stream terminated unexpectedly"
    )
    if let streamContinuation {
      self.streamContinuation = nil
      streamContinuation.resume(throwing: failure)
    } else {
      pendingStreamFailure = failure
    }
  }

  func releaseGatedPromptSuccess() {
    guard gatedPromptWillSucceed, let revision = gatedPromptRevision else { return }
    gatedPromptRevision = nil
    gatedPromptContinuation?.resume(returning: commandReceipt(revision: revision))
    gatedPromptContinuation = nil
  }

  func releaseGatedPromptTransportFailure() {
    guard !gatedPromptWillSucceed, gatedPromptRevision != nil else { return }
    gatedPromptRevision = nil
    gatedPromptContinuation?.resume(
      throwing: RuntimeEnvelopeClientFailure(
        code: "test.transport",
        message: "transport unavailable after live event"
      )
    )
    gatedPromptContinuation = nil
  }

  private func enqueue(_ event: RuntimeEventV2) {
    let frame = LocalRuntimeStreamFrame(
      messageID: RuntimeMessageID(rawValue: "message-\(event.eventSeq)"),
      item: .event(event)
    )
    if let continuation = streamContinuation {
      streamContinuation = nil
      continuation.resume(returning: frame)
    } else {
      streamFrames.append(frame)
    }
  }

  private func commandReceipt(revision: UInt64) -> RuntimeReplyV2 {
    .command(
      .accepted(
        commandID: RuntimeCommandID(rawValue: "command-\(promptRequestCount)"),
        queuePosition: 0,
        configurationRevision: revision
      )
    )
  }

  private func latchIfRequested(
    _ failure: RuntimeEnvelopeClientFailure
  ) -> RuntimeEnvelopeClientFailure {
    if latchTransportFailures, latchedTransportFailure == nil {
      latchedTransportFailure = failure
    }
    return failure
  }
}

private struct SessionReliabilityIdempotencyCapture: Sendable {
  let start: [RuntimeIdempotencyKey]
  let startAgentKinds: [AgentKind]
  let startCwds: [String]
  let configure: [RuntimeIdempotencyKey]
  let prompt: [RuntimeIdempotencyKey]
  let promptExpectedRevisions: [UInt64]
  let promptPayloads: [String]
}

@MainActor
private final class SessionReliabilityWireFactory {
  private let wires: [SessionReliabilityWire]
  private(set) var constructionCount = 0

  init(_ wires: [SessionReliabilityWire]) {
    self.wires = wires
  }

  func make() -> any AppRuntimeWireSession {
    precondition(constructionCount < wires.count)
    defer { constructionCount += 1 }
    return wires[constructionCount]
  }
}

private func assertBootstrapOwner(
  _ owner: PromptComposerOwner,
  agentKind expectedAgentKind: AgentKind,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  guard case .bootstrap(let actualAgentKind, _) = owner else {
    return XCTFail("expected bootstrap composer owner, got \(owner)", file: file, line: line)
  }
  XCTAssertEqual(actualAgentKind, expectedAgentKind, file: file, line: line)
}

private actor SessionReliabilityReplySequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]
  private let gateAfterFirstReply: Bool
  private var failureAfterFirstReply: RuntimeEnvelopeClientFailure?
  private var didReturnFirstReply = false
  private var gateReleased = false
  private var gateContinuation: CheckedContinuation<Void, Never>?

  init(
    replies: [RuntimeReplyV2],
    gateAfterFirstReply: Bool = false,
    failureAfterFirstReply: RuntimeEnvelopeClientFailure? = nil
  ) {
    self.replies = replies
    self.gateAfterFirstReply = gateAfterFirstReply
    self.failureAfterFirstReply = failureAfterFirstReply
  }

  func next() async throws -> RuntimeReplyV2? {
    if gateAfterFirstReply, didReturnFirstReply, !gateReleased {
      await withCheckedContinuation { continuation in
        if gateReleased {
          continuation.resume()
        } else {
          precondition(gateContinuation == nil)
          gateContinuation = continuation
        }
      }
    }
    if didReturnFirstReply, let failureAfterFirstReply {
      self.failureAfterFirstReply = nil
      throw failureAfterFirstReply
    }
    guard !replies.isEmpty else { return nil }
    let reply = replies.removeFirst()
    didReturnFirstReply = true
    return reply
  }

  func cancel() async {
    replies.removeAll()
    failureAfterFirstReply = nil
    releaseGate()
  }

  func releaseGate() {
    gateReleased = true
    gateContinuation?.resume()
    gateContinuation = nil
  }
}

private func reliabilityDraft(
  prompt: String?,
  keySuffix: String = "reliability",
  agentKind: AgentKind = .codex,
  cwd: String = "/tmp/agentdeck-reliability"
) throws -> RuntimeConversationDraft {
  let vendorOptions: VendorSessionOptions =
    switch agentKind {
    case .codex:
      .codex(
        CodexSessionOptions(
          approvalPolicy: .onRequest,
          sandbox: .workspaceWrite,
          persistApproval: false,
          reasoningEffort: .medium
        )
      )
    case .claudeCode:
      .claudeCode(
        ClaudeCodeSessionOptions(
          permissionMode: .default,
          model: "claude-fixture",
          effort: "medium",
          outputStyle: "concise"
        )
      )
    }
  return try RuntimeConversationDraft(
    agentKind: agentKind,
    cwd: cwd,
    prompt: prompt,
    vendorOptions: vendorOptions,
    idempotencyKeys: RuntimeConversationIdempotencyKeys(
      start: RuntimeIdempotencyKey(rawValue: "start:\(keySuffix)"),
      configure: RuntimeIdempotencyKey(rawValue: "configure:\(keySuffix)"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt:\(keySuffix)")
    )
  )
}

private func reliabilityCodexCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
}

private func reliabilityCodexConfiguration() -> RuntimeConversationConfigurationV2 {
  RuntimeConversationConfigurationV2(
    vendorControl: .codex(
      RuntimeCodexConversationConfigurationV2(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        reasoningEffort: .medium
      )
    )
  )
}

private func reliabilityClaudeCodeCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"claude_code","agentVersion":"fixture","features":[],"vendor":{"agentKind":"claude_code","permissionModes":["default","plan"],"outputStyles":["concise"],"hooksSupported":[],"cliVersion":"fixture"}}"#
        .utf8
    )
  )
}

private func reliabilityClaudeCodeConfiguration() throws -> RuntimeConversationConfigurationV2 {
  RuntimeConversationConfigurationV2(
    vendorControl: .claudeCode(
      try RuntimeClaudeCodeConversationConfigurationV2(
        permissionMode: .default,
        model: "claude-fixture",
        effort: "medium",
        outputStyle: "concise"
      )
    )
  )
}

private func reliabilitySnapshot(
  conversationID: RuntimeConversationID,
  agentKind: AgentKind
) throws -> ConversationSnapshotV2 {
  let capabilities: RuntimeSessionCapabilitiesV1
  let configuration: RuntimeConversationConfigurationV2
  switch agentKind {
  case .codex:
    capabilities = try reliabilityCodexCapabilities()
    configuration = reliabilityCodexConfiguration()
  case .claudeCode:
    capabilities = try reliabilityClaudeCodeCapabilities()
    configuration = try reliabilityClaudeCodeConfiguration()
  }
  return try ConversationSnapshotV2(
    conversationID: conversationID,
    baseEventCursor: .beforeFirst,
    configurationState: RuntimeConversationConfigurationStateV2(
      configurationRevision: 1,
      configuration: configuration
    ),
    items: [.capabilities(capabilities)]
  )
}

private func reliabilityHistoryEntry(
  _ rawID: String,
  agentKind: AgentKind = .codex,
  cwd: String = "/tmp/agentdeck-history"
) -> RuntimeConversationEntryV2 {
  RuntimeConversationEntryV2(
    conversationID: RuntimeConversationID(rawValue: rawID),
    agentKind: agentKind,
    title: rawID,
    cwd: cwd,
    lastActiveMs: 1_000,
    archived: false,
    entryRevision: 1
  )
}

private func reliabilitySyncComplete(
  conversationID: RuntimeConversationID,
  cursor: RuntimeStreamCursorV1 = .beforeFirst
) throws -> RuntimeSyncCompleteV1 {
  let cursorObject: Any =
    switch cursor {
    case .beforeFirst: "beforeFirst"
    case .at(let sequence): ["at": sequence]
    }
  return try decodeReliabilityFixture(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": "generation-reliability",
      "streamCursor": cursorObject,
      "innerCursor": [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": cursorObject,
      ],
      "keyDirectoryRevision": 0,
    ]
  )
}

private func reliabilityCatalogSyncComplete(
  cursor: RuntimeStreamCursorV1
) throws -> RuntimeSyncCompleteV1 {
  let cursorObject: Any =
    switch cursor {
    case .beforeFirst: "beforeFirst"
    case .at(let sequence): ["at": sequence]
    }
  return try decodeReliabilityFixture(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": "generation-reliability",
      "streamCursor": cursorObject,
      "innerCursor": [
        "scope": "catalog",
        "cursor": cursorObject,
      ],
      "keyDirectoryRevision": 0,
    ]
  )
}

private func reliabilityTurnSummary() throws -> RuntimeTurnSummaryV1 {
  try decodeReliabilityFixture(
    RuntimeTurnSummaryV1.self,
    [
      "elapsedMs": 1,
      "totalInputTokens": NSNull(),
      "totalOutputTokens": NSNull(),
    ]
  )
}

private func decodeReliabilityFixture<Value: Decodable>(
  _ type: Value.Type,
  _ object: Any
) throws -> Value {
  try JSONDecoder().decode(
    type,
    from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  )
}
