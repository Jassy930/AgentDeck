import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

final class AppRuntimeCoordinatorTests: XCTestCase {
  func testNewConversationRunsStartConfigureSubscribeSyncBeforePrompt() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-new")
    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/project",
      prompt: "hello",
      vendorOptions: codexVendorOptions(),
      idempotencyKeys: RuntimeConversationIdempotencyKeys(
        start: RuntimeIdempotencyKey(rawValue: "start-key"),
        configure: RuntimeIdempotencyKey(rawValue: "configure-key"),
        prompt: RuntimeIdempotencyKey(rawValue: "prompt-key")
      )
    )
    let timeline = AppRuntimeTestTimeline()
    let wire = AppRuntimeFakeWire(
      unaryReplies: [
        .conversationStart(
          ConversationStartReceiptV2(conversationID: conversationID, replayed: false)
        ),
        .configuration(
          .applied(conversationID: conversationID, configurationRevision: 1)
        ),
        .command(
          .accepted(
            commandID: RuntimeCommandID(rawValue: "command-1"),
            queuePosition: 0,
            configurationRevision: 1
          )
        ),
      ],
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try conversationSnapshot(conversationID: conversationID)),
          .backfill(
            try conversationBackfill(conversationID: conversationID, eventSequence: 1)
          ),
          .syncComplete(try syncComplete(conversationID: conversationID)),
        ]
      ],
      timeline: timeline
    )
    let coordinator = AppRuntimeCoordinator(wire: wire) { inbound in
      switch inbound {
      case .synchronizedReply(let reply):
        await timeline.append("handled.\(reply.testKind)")
      case .stream:
        await timeline.append("handled.stream")
      }
    }

    try await coordinator.start()
    let result = try await coordinator.startConversation(draft)

    XCTAssertEqual(result.conversationID, conversationID)
    XCTAssertEqual(result.synchronization.replies.count, 4)
    XCTAssertNotNil(result.promptReceipt)
    let timelineValues = await timeline.values()
    XCTAssertEqual(
      timelineValues,
      [
        "wire.start",
        "request.start",
        "request.configureConversation",
        "sequence.subscribe",
        "handled.subscription",
        "handled.snapshot",
        "handled.backfill",
        "handled.syncComplete",
        "request.sendPrompt",
      ]
    )

    await coordinator.close()
  }

  func testStartOwnsExactlyOneStreamPumpAndHandlerIsSequential() async throws {
    let timeline = AppRuntimeTestTimeline()
    let wire = AppRuntimeFakeWire(timeline: timeline)
    let handlerProbe = AppRuntimeMainActorHandlerProbe()
    let coordinator = AppRuntimeCoordinator(wire: wire) { inbound in
      guard case .stream = inbound else { return }
      await handlerProbe.consume()
    }

    try await coordinator.start()
    try await wire.waitForStreamReads(1)
    do {
      try await coordinator.start()
      XCTFail("duplicate start unexpectedly succeeded")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(error, .alreadyStarted)
    }

    await wire.emitStream(messageID: "stream-1")
    try await wire.waitForStreamReads(2)
    await wire.emitStream(messageID: "stream-2")
    try await wire.waitForStreamReads(3)

    let maximumStreamReads = await wire.maximumConcurrentStreamReads()
    let maximumHandlerCalls = await handlerProbe.maximumConcurrentCalls
    let handlerCallCount = await handlerProbe.callCount
    XCTAssertEqual(maximumStreamReads, 1)
    XCTAssertEqual(maximumHandlerCalls, 1)
    XCTAssertEqual(handlerCallCount, 2)
    await coordinator.close()
  }

  func testReceiptConversationMismatchFailsTypedAndSkipsSubscribe() async throws {
    let expected = RuntimeConversationID(rawValue: "conversation-expected")
    let actual = RuntimeConversationID(rawValue: "conversation-other")
    let draft = try RuntimeConversationDraft(
      agentKind: .codex,
      cwd: "/tmp/project",
      prompt: nil,
      vendorOptions: codexVendorOptions(),
      idempotencyKeys: RuntimeConversationIdempotencyKeys(
        start: RuntimeIdempotencyKey(rawValue: "start-key"),
        configure: RuntimeIdempotencyKey(rawValue: "configure-key"),
        prompt: RuntimeIdempotencyKey(rawValue: "prompt-key")
      )
    )
    let wire = AppRuntimeFakeWire(unaryReplies: [
      .conversationStart(
        ConversationStartReceiptV2(conversationID: expected, replayed: false)
      ),
      .configuration(.applied(conversationID: actual, configurationRevision: 1)),
    ])
    let coordinator = AppRuntimeCoordinator(wire: wire) { _ in }
    try await coordinator.start()

    do {
      _ = try await coordinator.startConversation(draft)
      XCTFail("mismatched Configure receipt unexpectedly succeeded")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(
        error,
        .receiptConversationMismatch(
          operation: .configureConversation,
          expected: expected,
          actual: actual
        )
      )
    }
    let synchronizedRequestCount = await wire.synchronizedRequestCount()
    XCTAssertEqual(synchronizedRequestCount, 0)
    await coordinator.close()
  }

  func testTargetMismatchPublishesNoPartiallyValidatedSynchronization() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-expected")
    let otherID = RuntimeConversationID(rawValue: "conversation-other")
    let published = AppRuntimePublishedReplyProbe()
    let wire = AppRuntimeFakeWire(
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try conversationSnapshot(conversationID: conversationID)),
          .backfill(try conversationBackfill(conversationID: otherID, eventSequence: 1)),
        ]
      ]
    )
    let coordinator = AppRuntimeCoordinator(wire: wire) { inbound in
      guard case .synchronizedReply = inbound else { return }
      await published.record()
    }
    try await coordinator.start()

    do {
      _ = try await coordinator.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("mismatched synchronization target unexpectedly succeeded")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(error, .synchronizationTargetMismatch)
    }

    let publishedCount = await published.count()
    let closeCount = await wire.closeCount()
    XCTAssertEqual(publishedCount, 0)
    XCTAssertEqual(closeCount, 1)
  }

  func testMissingTerminalPublishesNoPartiallyValidatedSynchronization() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-missing-terminal")
    let published = AppRuntimePublishedReplyProbe()
    let wire = AppRuntimeFakeWire(
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try conversationSnapshot(conversationID: conversationID)),
        ]
      ]
    )
    let coordinator = AppRuntimeCoordinator(wire: wire) { inbound in
      guard case .synchronizedReply = inbound else { return }
      await published.record()
    }
    try await coordinator.start()

    do {
      _ = try await coordinator.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("unterminated synchronization unexpectedly succeeded")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(error, .missingSynchronizationTerminal)
    }

    let publishedCount = await published.count()
    let closeCount = await wire.closeCount()
    XCTAssertEqual(publishedCount, 0)
    XCTAssertEqual(closeCount, 1)
  }

  func testHandlerFailureClosesWireBeforeStreamGateCanResume() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-handler-failure")
    let handler = AppRuntimeFailingHandlerProbe(failOnSynchronizedReply: 2)
    let wire = AppRuntimeFakeWire(
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-1"))
          ),
          .snapshot(try conversationSnapshot(conversationID: conversationID)),
          .syncComplete(try syncComplete(conversationID: conversationID)),
        ]
      ]
    )
    let coordinator = AppRuntimeCoordinator(wire: wire) { inbound in
      try await handler.consume(inbound)
    }
    try await coordinator.start()

    do {
      _ = try await coordinator.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("throwing handler unexpectedly completed synchronization")
    } catch AppRuntimeTestError.handlerFailure {
      // Expected: coordinator closes this wire before its deferred gate release.
    }

    let counts = await handler.counts()
    let closeCount = await wire.closeCount()
    XCTAssertEqual(counts.synchronizedReplies, 2)
    XCTAssertEqual(counts.streams, 0)
    XCTAssertEqual(closeCount, 1)
  }

  func testOuterAndNestedFailuresPreserveDaemonCode() async throws {
    let outer = AppRuntimeFakeWire(unaryReplies: [
      .failure(
        RuntimeFailureV1(
          code: "daemon.catalog.denied",
          message: "catalog denied",
          diagnosticRef: "diag-catalog"
        )
      )
    ])
    let outerCoordinator = AppRuntimeCoordinator(wire: outer) { _ in }
    try await outerCoordinator.start()
    await assertDaemonFailure(
      code: "daemon.catalog.denied",
      diagnosticRef: "diag-catalog"
    ) {
      _ = try await outerCoordinator.loadCatalog()
    }
    await outerCoordinator.close()

    let nested = AppRuntimeFakeWire(unaryReplies: [
      .configuration(
        .failed(
          RuntimeFailureV1(
            code: "daemon.configuration.rejected",
            message: "configuration rejected",
            diagnosticRef: nil
          )
        )
      )
    ])
    let nestedCoordinator = AppRuntimeCoordinator(wire: nested) { _ in }
    try await nestedCoordinator.start()
    await assertDaemonFailure(code: "daemon.configuration.rejected", diagnosticRef: nil) {
      _ = try await nestedCoordinator.configureConversation(
        RuntimeConfigureConversationRequestV2(
          conversationID: RuntimeConversationID(rawValue: "conversation-1"),
          idempotencyKey: RuntimeIdempotencyKey(rawValue: "configuration-key"),
          expectedConfigurationRevision: 0,
          configuration: try codexConfiguration()
        )
      )
    }
    await nestedCoordinator.close()
  }

  func testCatalogPaginationDescribeAgentsAndCloseAreExact() async throws {
    let next = RuntimeCatalogPageCursor(rawValue: "page-2")
    let agents = try RuntimeAgentDescriptionsV2(agents: [])
    let first = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(4),
      entries: [],
      nextPageCursor: next
    )
    let second = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(4),
      entries: [],
      nextPageCursor: nil
    )
    let wire = AppRuntimeFakeWire(unaryReplies: [
      .agents(agents), .catalog(first), .catalog(second),
    ])
    let coordinator = AppRuntimeCoordinator(wire: wire) { _ in }

    try await coordinator.start()
    let descriptions = try await coordinator.describeAgents()
    let pages = try await coordinator.loadCatalog()
    XCTAssertEqual(descriptions.agents.count, 0)
    XCTAssertEqual(pages.count, 2)
    await coordinator.close()
    await coordinator.close()

    let closeCount = await wire.closeCount()
    let requestKinds = await wire.controlRequestKinds()
    XCTAssertEqual(closeCount, 1)
    XCTAssertEqual(
      requestKinds,
      ["describeAgents", "catalog.nil", "catalog.page-2"]
    )
  }

  func testCloseDuringCoordinatorStartCannotPublishRunningState() async throws {
    let wire = AppRuntimeStartBarrierWire()
    let coordinator = AppRuntimeCoordinator(wire: wire) { _ in }
    let startTask = Task { try await coordinator.start() }
    try await wire.waitUntilStartBlocked()

    await coordinator.close()
    await wire.releaseStart()

    do {
      try await startTask.value
      XCTFail("start completed after coordinator close")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(error, .closed)
    }
    do {
      _ = try await coordinator.describeAgents()
      XCTFail("closed coordinator was revived to running")
    } catch let error as AppRuntimeCoordinatorError {
      XCTAssertEqual(error, .closed)
    }
    let closeCount = await wire.closeCount()
    let requestCount = await wire.requestCount()
    XCTAssertEqual(closeCount, 1)
    XCTAssertEqual(requestCount, 0)
  }

  func testOSAccountWireCloseDuringCandidateStartNeverPublishesCandidate() async throws {
    let candidate = AppRuntimeStartBarrierWire()
    let wire = OSAccountRuntimeWireSession(sessionFactory: { candidate })
    let startTask = Task { try await wire.start() }
    try await candidate.waitUntilStartBlocked()

    await wire.close()
    await candidate.releaseStart()

    do {
      try await startTask.value
      XCTFail("candidate published after OS-account wire close")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.connection_closed")
    }
    do {
      _ = try await wire.request(.describeAgents)
      XCTFail("closed OS-account wire retained a published candidate")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.not_started")
    }
    let closeCount = await candidate.closeCount()
    let requestCount = await candidate.requestCount()
    XCTAssertEqual(closeCount, 1)
    XCTAssertEqual(requestCount, 0)
  }

  private func assertDaemonFailure(
    code: String,
    diagnosticRef: String?,
    operation: () async throws -> Void
  ) async {
    do {
      try await operation()
      XCTFail("daemon failure unexpectedly succeeded")
    } catch let error as AppRuntimeCoordinatorError {
      guard case .daemonFailure(let actualCode, _, let actualDiagnosticRef) = error else {
        return XCTFail("unexpected coordinator error: \(error)")
      }
      XCTAssertEqual(actualCode, code)
      XCTAssertEqual(actualDiagnosticRef, diagnosticRef)
    } catch {
      XCTFail("unexpected error type: \(error)")
    }
  }
}

private actor AppRuntimeFakeWire: AppRuntimeWireSession {
  private var unaryReplies: [RuntimeReplyV2]
  private var synchronizedReplies: [[RuntimeReplyV2]]
  private let timeline: AppRuntimeTestTimeline?
  private var requestKinds: [String] = []
  private var synchronizedRequests = 0
  private var closes = 0
  private var streamReads = 0
  private var concurrentStreamReads = 0
  private var maximumStreamReads = 0
  private var streamWaiter: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var closed = false

  init(
    unaryReplies: [RuntimeReplyV2] = [],
    synchronizedReplies: [[RuntimeReplyV2]] = [],
    timeline: AppRuntimeTestTimeline? = nil
  ) {
    self.unaryReplies = unaryReplies
    self.synchronizedReplies = synchronizedReplies
    self.timeline = timeline
  }

  func start() async throws {
    await timeline?.append("wire.start")
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    let kind = request.testKind
    requestKinds.append(kind)
    await timeline?.append("request.\(kind)")
    guard !unaryReplies.isEmpty else {
      throw RuntimeEnvelopeClientFailure(
        code: "test.reply.missing",
        message: "fake unary reply missing"
      )
    }
    return unaryReplies.removeFirst()
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    synchronizedRequests += 1
    await timeline?.append("sequence.\(request.testKind)")
    guard !synchronizedReplies.isEmpty else {
      throw RuntimeEnvelopeClientFailure(
        code: "test.sequence.missing",
        message: "fake synchronized reply missing"
      )
    }
    return AppRuntimeFakeReplySequence(replies: synchronizedReplies.removeFirst())
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    if closed {
      throw RuntimeEnvelopeClientFailure(
        code: "test.closed",
        message: "fake wire closed"
      )
    }
    streamReads += 1
    concurrentStreamReads += 1
    maximumStreamReads = max(maximumStreamReads, concurrentStreamReads)
    defer { concurrentStreamReads -= 1 }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamWaiter == nil)
      streamWaiter = continuation
    }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    closes += 1
    streamWaiter?.resume(
      throwing: RuntimeEnvelopeClientFailure(
        code: "test.closed",
        message: "fake wire closed"
      )
    )
    streamWaiter = nil
  }

  func emitStream(messageID: String) {
    streamWaiter?.resume(
      returning: LocalRuntimeStreamFrame(
        messageID: RuntimeMessageID(rawValue: messageID),
        item: .catalogDelta(RuntimeCatalogDeltaV2(catalogRevision: 0, changes: []))
      )
    )
    streamWaiter = nil
  }

  func waitForStreamReads(_ expected: Int) async throws {
    for _ in 0..<1_000 {
      if streamReads >= expected { return }
      await Task.yield()
    }
    throw AppRuntimeTestError.timeout
  }

  func synchronizedRequestCount() -> Int { synchronizedRequests }
  func closeCount() -> Int { closes }
  func controlRequestKinds() -> [String] { requestKinds }
  func maximumConcurrentStreamReads() -> Int { maximumStreamReads }
}

private actor AppRuntimeFakeReplySequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]

  init(replies: [RuntimeReplyV2]) {
    self.replies = replies
  }

  func next() async throws -> RuntimeReplyV2? {
    guard !replies.isEmpty else { return nil }
    return replies.removeFirst()
  }

  func cancel() async {}
}

private actor AppRuntimeStartBarrierWire: AppRuntimeWireSession {
  private var startBlocked = false
  private var startReleased = false
  private var startContinuation: CheckedContinuation<Void, Never>?
  private var closes = 0
  private var requests = 0
  private var closed = false

  func start() async throws {
    startBlocked = true
    guard !startReleased else { return }
    await withCheckedContinuation { continuation in
      startContinuation = continuation
    }
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    requests += 1
    return .agents(try RuntimeAgentDescriptionsV2(agents: []))
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    AppRuntimeFakeReplySequence(replies: [])
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    try await Task.sleep(for: .seconds(60))
    throw AppRuntimeTestError.timeout
  }

  func close() async {
    guard !closed else { return }
    closed = true
    closes += 1
  }

  func waitUntilStartBlocked() async throws {
    for _ in 0..<1_000 {
      if startBlocked { return }
      await Task.yield()
    }
    throw AppRuntimeTestError.timeout
  }

  func releaseStart() {
    startReleased = true
    startContinuation?.resume()
    startContinuation = nil
  }

  func closeCount() -> Int { closes }
  func requestCount() -> Int { requests }
}

private actor AppRuntimeTestTimeline {
  private var entries: [String] = []

  func append(_ entry: String) {
    entries.append(entry)
  }

  func values() -> [String] { entries }
}

private actor AppRuntimePublishedReplyProbe {
  private var publishedCount = 0

  func record() {
    publishedCount += 1
  }

  func count() -> Int { publishedCount }
}

private actor AppRuntimeFailingHandlerProbe {
  private let failOnSynchronizedReply: Int
  private var synchronizedReplies = 0
  private var streams = 0

  init(failOnSynchronizedReply: Int) {
    self.failOnSynchronizedReply = failOnSynchronizedReply
  }

  func consume(_ inbound: AppRuntimeInbound) throws {
    switch inbound {
    case .synchronizedReply:
      synchronizedReplies += 1
      if synchronizedReplies == failOnSynchronizedReply {
        throw AppRuntimeTestError.handlerFailure
      }
    case .stream:
      streams += 1
    }
  }

  func counts() -> (synchronizedReplies: Int, streams: Int) {
    (synchronizedReplies, streams)
  }
}

@MainActor
private final class AppRuntimeMainActorHandlerProbe {
  private(set) var callCount = 0
  private(set) var maximumConcurrentCalls = 0
  private var concurrentCalls = 0

  func consume() async {
    concurrentCalls += 1
    maximumConcurrentCalls = max(maximumConcurrentCalls, concurrentCalls)
    await Task.yield()
    callCount += 1
    concurrentCalls -= 1
  }
}

private enum AppRuntimeTestError: Error {
  case handlerFailure
  case timeout
}

extension RuntimeRequestV2 {
  fileprivate var testKind: String {
    switch self {
    case .describeAgents: "describeAgents"
    case .catalog(let cursor): "catalog.\(cursor?.rawValue ?? "nil")"
    case .subscribe: "subscribe"
    case .backfill: "backfill"
    case .start: "start"
    case .configureConversation: "configureConversation"
    case .updateConversationMetadata: "updateConversationMetadata"
    case .sendPrompt: "sendPrompt"
    case .resolveApproval: "resolveApproval"
    default: "other"
    }
  }
}

extension RuntimeReplyV2 {
  fileprivate var testKind: String {
    switch self {
    case .subscription: "subscription"
    case .snapshot: "snapshot"
    case .backfill: "backfill"
    case .syncComplete: "syncComplete"
    default: "other"
    }
  }
}

private func codexConfiguration() throws -> RuntimeConversationConfigurationV2 {
  try JSONDecoder().decode(
    RuntimeConversationConfigurationV2.self,
    from: Data(
      #"{"vendorControl":{"agentKind":"codex","configuration":{"approvalPolicy":"on-request","sandbox":"workspace-write","reasoningEffort":"high"}}}"#
        .utf8
    )
  )
}

private func codexVendorOptions() -> VendorSessionOptions {
  .codex(
    CodexSessionOptions(
      approvalPolicy: .onRequest,
      sandbox: .workspaceWrite,
      persistApproval: false,
      reasoningEffort: .high
    )
  )
}

private func syncComplete(
  conversationID: RuntimeConversationID
) throws -> RuntimeSyncCompleteV1 {
  let object: [String: Any] = [
    "streamGeneration": "generation-1",
    "streamCursor": ["at": 3],
    "innerCursor": [
      "scope": "conversation",
      "conversationId": conversationID.rawValue,
      "cursor": ["at": 1],
    ],
    "keyDirectoryRevision": 2,
  ]
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: JSONSerialization.data(withJSONObject: object)
  )
}

private func conversationSnapshot(
  conversationID: RuntimeConversationID
) throws -> ConversationSnapshotV2 {
  let capabilities = try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
  let configurationState = try RuntimeConversationConfigurationStateV2(
    configurationRevision: 1,
    configuration: try codexConfiguration()
  )
  return try ConversationSnapshotV2(
    conversationID: conversationID,
    baseEventCursor: .at(0),
    configurationState: configurationState,
    items: [.capabilities(capabilities)]
  )
}

private func conversationBackfill(
  conversationID: RuntimeConversationID,
  eventSequence: UInt64
) throws -> RuntimeBackfillChunkV2 {
  let capabilities = try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
  let event = try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: "event-\(eventSequence)"),
    eventSeq: eventSequence,
    commandID: RuntimeCommandID(rawValue: "command-1"),
    itemID: nil,
    entityID: nil,
    body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-1"))
  )
  return .conversation(
    conversationID: conversationID,
    capabilitiesPreamble: capabilities,
    range: try RuntimeBackfillRangeV1(
      after: .at(eventSequence - 1),
      through: .at(eventSequence)
    ),
    events: [event]
  )
}
