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

    model.submit("bootstrap retry")
    try await wire.waitForDescribeRequestCount(1)
    try await waitUntil { model.errorMessage != nil }

    model.submit("bootstrap retry")
    try await wire.waitForDescribeRequestCount(2)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }

    let counts = await wire.bootstrapCounts()
    XCTAssertEqual(counts.start, 1)
    XCTAssertEqual(counts.describe, 2)
  }

  func testEquivalentStartRetriesOutcomeUnknownWithOriginalDraftKeys() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .success]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let original = try reliabilityDraft(prompt: "retry exact draft", keySuffix: "original")

    model.startConversation(original)
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil { model.retryableConversationDraft != nil }
    XCTAssertEqual(model.retryableConversationDraft?.idempotencyKeys, original.idempotencyKeys)

    model.startConversation(
      try reliabilityDraft(prompt: "retry exact draft", keySuffix: "new-attempt")
    )
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil {
      model.workbench.selectedConversationID == SessionReliabilityWire.conversationID
    }

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.start, [original.idempotencyKeys.start, original.idempotencyKeys.start])
    XCTAssertEqual(
      keys.configure,
      [original.idempotencyKeys.configure, original.idempotencyKeys.configure]
    )
    XCTAssertEqual(keys.prompt, [original.idempotencyKeys.prompt, original.idempotencyKeys.prompt])
    XCTAssertNil(model.retryableConversationDraft)
  }

  func testDifferentIntentCannotReplaceOutcomeUnknownDraft() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.transportFailure])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let original = try reliabilityDraft(prompt: "original intent", keySuffix: "original")

    model.startConversation(original)
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil { model.retryableConversationDraft != nil }

    model.startConversation(
      try reliabilityDraft(prompt: "different intent", keySuffix: "different")
    )
    await Task.yield()

    let startRequests = await wire.startRequests()
    XCTAssertEqual(startRequests, 1)
    XCTAssertEqual(model.retryableConversationDraft?.idempotencyKeys, original.idempotencyKeys)
    XCTAssertNotNil(model.warningMessage)
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

  func testQueuedPromptStaysQueuedUntilCommandReceiptSucceeds() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }

    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)

    XCTAssertEqual(runtime.queuedPrompts, ["queued prompt"])
    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.queuedPrompts.isEmpty }
  }

  func testReadyComposerPromptIsDurablyQueuedBeforeDispatchReceipt() async throws {
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
    XCTAssertEqual(runtime.queuedPrompts, ["ready composer prompt"])

    await wire.releaseGatedPromptSuccess()
    try await waitUntil { runtime.queuedPrompts.isEmpty }
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

    XCTAssertTrue(runtime.queuedPrompts.isEmpty)
    XCTAssertNotNil(runtime.errorMessage)
    let promptRequests = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequests, 0)

    model.submit("valid after oversized")
    try await wire.waitForPromptRequestCount(1)
    try await waitUntil { runtime.queuedPrompts.isEmpty }
  }

  func testQueuedPromptSurvivesOperationTransportAndDaemonReceiptFailures() async throws {
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
      XCTAssertEqual(
        runtime.queuedPrompts,
        ["queued prompt"],
        "\(failure) 不得永久丢弃未收到成功 receipt 的 prompt"
      )
      model.teardown()
    }
  }

  func testQueuedPromptRetryReusesOriginalIdempotencyKey() async throws {
    let wire = try SessionReliabilityWire(
      promptOutcomes: [.transportFailure, .success]
    )
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    try await waitUntil { runtime.errorMessage != nil }

    model.submit("later prompt")
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil { runtime.queuedPrompts == ["later prompt"] }

    let keys = await wire.recordedIdempotencyKeys()
    XCTAssertEqual(keys.prompt.count, 2)
    XCTAssertEqual(keys.prompt[0], keys.prompt[1])
    XCTAssertNil(runtime.errorMessage)
  }

  func testQueuedPromptFailureDoesNotOverwriteLiveRunningPhase() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedTransportFailure])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)

    try await wire.emitTurnStarted(
      sequence: 2,
      commandID: "command-queued",
      turnID: "turn-queued"
    )
    try await waitUntil { runtime.phase == .running }
    await wire.releaseGatedPromptTransportFailure()
    try await waitUntil { runtime.errorMessage != nil }

    XCTAssertEqual(runtime.phase, .running)
    XCTAssertEqual(runtime.queuedPrompts, ["queued prompt"])
  }

  func testReceiptAfterTerminalImmediatelyDispatchesNextQueuedPrompt() async throws {
    let wire = try SessionReliabilityWire(promptOutcomes: [.gatedSuccess, .success])
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }
    let runtime = try await prepareQueuedPromptDispatch(model: model, wire: wire)
    model.submit("second queued prompt")

    try await wire.emitTurnStarted(
      sequence: 2,
      commandID: "command-queued",
      turnID: "turn-queued"
    )
    try await wire.emitTurnCompleted(
      sequence: 3,
      commandID: "command-queued",
      turnID: "turn-queued"
    )
    try await waitUntil { runtime.phase == .ready }
    let promptRequestsBeforeReceipt = await wire.currentPromptRequestCount()
    XCTAssertEqual(promptRequestsBeforeReceipt, 1)

    await wire.releaseGatedPromptSuccess()
    try await wire.waitForPromptRequestCount(2)
    try await waitUntil { runtime.queuedPrompts.isEmpty }
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
    XCTAssertEqual(runtime.queuedPrompts, ["outcome unknown prompt"])

    model.submit("next accepted prompt")
    try await wire.waitForPromptRequestCount(3)
    try await waitUntil { runtime.queuedPrompts.isEmpty }

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
    XCTAssertEqual(runtime.phase, .starting)

    model.teardown()
    try await wire.waitForClose()
    try await Task.sleep(for: .milliseconds(10))

    XCTAssertEqual(model.phase, .closed)
    XCTAssertEqual(runtime.phase, .starting)
    XCTAssertNil(runtime.errorMessage)
    XCTAssertEqual(runtime.queuedPrompts, ["queued prompt"])
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
    model.submit("queued prompt")
    XCTAssertEqual(runtime.queuedPrompts, ["queued prompt"])

    try await wire.emitTurnCompleted()
    try await wire.waitForPromptRequestCount(1)
    return runtime
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
  case transportFailure
  case daemonFailure

  var description: String {
    switch self {
    case .success: "success"
    case .gatedSuccess: "gatedSuccess"
    case .gatedTransportFailure: "gatedTransportFailure"
    case .replayed(let commandID): "replayed(\(commandID))"
    case .operationInProgress: "operationInProgress"
    case .transportFailure: "transportFailure"
    case .daemonFailure: "daemonFailure"
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
  private let snapshot: ConversationSnapshotV2
  private let terminal: RuntimeSyncCompleteV1
  private var promptOutcomes: [SessionReliabilityPromptOutcome]
  private var describeFailuresRemaining: Int
  private var promptRequestCount = 0
  private var startCallCount = 0
  private var describeRequestCount = 0
  private var startRequestCount = 0
  private var configureRequestCount = 0
  private var startIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var configureIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var promptIdempotencyKeys: [RuntimeIdempotencyKey] = []
  private var streamFrames: [LocalRuntimeStreamFrame] = []
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var gatedPromptContinuation: CheckedContinuation<RuntimeReplyV2, Error>?
  private var gatedPromptRevision: UInt64?
  private var gatedPromptWillSucceed = false
  private var isClosed = false
  private var closeCount = 0

  init(
    promptOutcomes: [SessionReliabilityPromptOutcome],
    describeFailuresRemaining: Int = 0
  ) throws {
    self.promptOutcomes = promptOutcomes
    self.describeFailuresRemaining = describeFailuresRemaining
    let capabilities = try reliabilityCodexCapabilities()
    let configuration = reliabilityCodexConfiguration()
    descriptions = try RuntimeAgentDescriptionsV2(
      agents: [
        try RuntimeAgentDescriptionV2(
          agentKind: .codex,
          capabilities: capabilities,
          defaultConfiguration: configuration
        )
      ]
    )
    snapshot = try ConversationSnapshotV2(
      conversationID: Self.conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: try RuntimeConversationConfigurationStateV2(
        configurationRevision: 1,
        configuration: configuration
      ),
      items: [.capabilities(capabilities)]
    )
    terminal = try reliabilitySyncComplete(conversationID: Self.conversationID)
  }

  func start() async throws {
    startCallCount += 1
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    switch request {
    case .describeAgents:
      describeRequestCount += 1
      if describeFailuresRemaining > 0 {
        describeFailuresRemaining -= 1
        throw RuntimeEnvelopeClientFailure(
          code: "test.describe.failed",
          message: "DescribeAgents unavailable"
        )
      }
      return .agents(descriptions)
    case .start(_, let idempotencyKey, _, _):
      startRequestCount += 1
      startIdempotencyKeys.append(idempotencyKey)
      return .conversationStart(
        ConversationStartReceiptV2(
          conversationID: Self.conversationID,
          replayed: startRequestCount > 1
        )
      )
    case .configureConversation(let configuration):
      configureRequestCount += 1
      configureIdempotencyKeys.append(configuration.idempotencyKey)
      return .configuration(
        configureRequestCount > 1
          ? .replayed(conversationID: Self.conversationID, configurationRevision: 1)
          : .applied(conversationID: Self.conversationID, configurationRevision: 1)
      )
    case .sendPrompt(_, let idempotencyKey, let revision, _):
      promptRequestCount += 1
      promptIdempotencyKeys.append(idempotencyKey)
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
      case .transportFailure:
        throw RuntimeEnvelopeClientFailure(
          code: "test.transport",
          message: "transport unavailable"
        )
      case .daemonFailure:
        return .failure(
          RuntimeFailureV1(
            code: "test.receipt.failed",
            message: "daemon rejected prompt"
          )
        )
      }
    default:
      throw SessionReliabilityWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    guard case .subscribe(let cursor) = request,
      case .conversation(let conversationID, .beforeFirst) = cursor,
      conversationID == Self.conversationID
    else {
      throw SessionReliabilityWireError.unexpectedRequest
    }
    return SessionReliabilityReplySequence(
      replies: [
        .subscription(
          .subscribed(
            streamGeneration: RuntimeStreamGeneration(rawValue: "generation-reliability")
          )
        ),
        .snapshot(snapshot),
        .syncComplete(terminal),
      ]
    )
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !isClosed else { throw SessionReliabilityWireError.closed }
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
    streamContinuation?.resume(throwing: SessionReliabilityWireError.closed)
    streamContinuation = nil
    gatedPromptContinuation?.resume(throwing: SessionReliabilityWireError.closed)
    gatedPromptContinuation = nil
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

  func bootstrapCounts() -> (start: Int, describe: Int) {
    (startCallCount, describeRequestCount)
  }

  func startRequests() -> Int {
    startRequestCount
  }

  func currentPromptRequestCount() -> Int {
    promptRequestCount
  }

  func recordedIdempotencyKeys() -> SessionReliabilityIdempotencyCapture {
    SessionReliabilityIdempotencyCapture(
      start: startIdempotencyKeys,
      configure: configureIdempotencyKeys,
      prompt: promptIdempotencyKeys
    )
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
        commandID: RuntimeCommandID(rawValue: "command-queued"),
        queuePosition: 0,
        configurationRevision: revision
      )
    )
  }
}

private struct SessionReliabilityIdempotencyCapture: Sendable {
  let start: [RuntimeIdempotencyKey]
  let configure: [RuntimeIdempotencyKey]
  let prompt: [RuntimeIdempotencyKey]
}

private actor SessionReliabilityReplySequence: AppRuntimeWireReplySequence {
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

private func reliabilityDraft(
  prompt: String?,
  keySuffix: String = "reliability"
) throws -> RuntimeConversationDraft {
  try RuntimeConversationDraft(
    agentKind: .codex,
    cwd: "/tmp/agentdeck-reliability",
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

private func reliabilitySyncComplete(
  conversationID: RuntimeConversationID
) throws -> RuntimeSyncCompleteV1 {
  try decodeReliabilityFixture(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": "generation-reliability",
      "streamCursor": "beforeFirst",
      "innerCursor": [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": "beforeFirst",
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
