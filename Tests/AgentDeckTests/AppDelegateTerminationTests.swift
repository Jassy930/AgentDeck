import AgentDeckCore
import AgentDeckSessionSource
import AppKit
import XCTest

@testable import AgentDeck

@MainActor
final class AppDelegateTerminationTests: XCTestCase {
  func testTerminationIsSingleFlightAndRepliesOnlyAfterCompositionShutdown() async {
    let gate = AppDelegateTerminationGate()
    let composition = AppDelegateCompositionSpy(gate: gate)
    var replies: [Bool] = []
    let delegate = AppDelegate(
      profile: .dev,
      composition: composition,
      terminationReply: { replies.append($0) }
    )

    let first = delegate.applicationShouldTerminate(NSApplication.shared)
    let second = delegate.applicationShouldTerminate(NSApplication.shared)
    XCTAssertEqual(first, .terminateLater)
    XCTAssertEqual(second, .terminateLater)

    for _ in 0..<100 where composition.shutdownCount == 0 {
      await Task.yield()
    }
    XCTAssertEqual(composition.shutdownCount, 1)
    XCTAssertEqual(composition.events, ["shutdown-started"])
    XCTAssertTrue(replies.isEmpty)

    await gate.release()
    for _ in 0..<100 where replies.isEmpty {
      await Task.yield()
    }

    XCTAssertEqual(composition.shutdownCount, 1)
    XCTAssertEqual(composition.events, ["shutdown-started", "shutdown-finished"])
    XCTAssertEqual(replies, [true])
    XCTAssertEqual(
      delegate.applicationShouldTerminate(NSApplication.shared),
      .terminateNow
    )
    XCTAssertEqual(composition.shutdownCount, 1)
    XCTAssertEqual(replies, [true])
  }

  func testTerminationReplyWaitsForSessionModelOperationJoinBarrier() async throws {
    let wire = AppDelegateBlockingHistoryWire()
    let model = SessionModel(runtimeWire: wire)
    let composition = AppDelegateSessionModelComposition(model: model)
    var replies: [Bool] = []
    let delegate = AppDelegate(
      profile: .dev,
      composition: composition,
      terminationReply: { replies.append($0) }
    )

    model.loadHistory()
    try await wire.waitForCatalogRequest()

    XCTAssertEqual(
      delegate.applicationShouldTerminate(NSApplication.shared),
      .terminateLater
    )
    try await wire.waitForClose()
    for _ in 0..<10 { await Task.yield() }

    XCTAssertTrue(replies.isEmpty)
    XCTAssertEqual(model.phase, .closed)

    await wire.releaseCatalogRequest()
    for _ in 0..<100 where replies.isEmpty { await Task.yield() }

    XCTAssertEqual(replies, [true])
    XCTAssertEqual(model.phase, .closed)
    XCTAssertTrue(model.historyThreads.isEmpty)
    XCTAssertNil(model.historyErrorMessage)
  }

  func testPreviewTerminationReplyWaitsForSessionModelOperationJoinBarrier() async throws {
    let wire = AppDelegateBlockingHistoryWire()
    let binding = SessionModel.makeFixtureBinding(
      runtimeWire: wire,
      machineID: "preview-termination-fixture"
    )
    let localPlaceholder = LocalDaemonSessionSource(
      runtimeWire: PreviewRuntimeWireSession(),
      machineID: "preview-termination-placeholder"
    )
    let registry = try SessionSourceRegistry(
      local: SessionSourceRegistration(
        scope: .local,
        source: localPlaceholder,
        capabilities: SessionSourceCapabilities(
          localPairingAdministration: localPlaceholder,
          localConversationAdministration: localPlaceholder
        ),
        lifecycle: localPlaceholder
      ),
      remoteFactory: { _ in throw PreviewCompositionError.remoteScopeUnavailable }
    )
    try await registry.registerFixture(
      SessionSourceRegistration(
        scope: .fixture(id: "preview-termination"),
        source: binding.source,
        capabilities: SessionSourceCapabilities(),
        lifecycle: binding.source
      )
    )
    let selectedMachineScope = SelectedMachineScopeGenerationOwner(registry: registry)
    _ = try await selectedMachineScope.select(.fixture(id: "preview-termination"))
    let composition = PreviewAppSessionSourceComposition(
      model: binding.model,
      registry: registry,
      selectedMachineScope: selectedMachineScope
    )
    var replies: [Bool] = []
    let delegate = AppDelegate(
      profile: .dev,
      composition: composition,
      preview: true,
      terminationReply: { replies.append($0) }
    )

    binding.model.loadHistory()
    try await wire.waitForCatalogRequest()
    XCTAssertEqual(
      delegate.applicationShouldTerminate(NSApplication.shared),
      .terminateLater
    )
    try await wire.waitForClose()
    for _ in 0..<10 { await Task.yield() }

    XCTAssertTrue(replies.isEmpty)
    await wire.releaseCatalogRequest()
    for _ in 0..<100 where replies.isEmpty { await Task.yield() }

    XCTAssertEqual(replies, [true])
    XCTAssertEqual(binding.model.phase, .closed)
    XCTAssertTrue(binding.model.historyThreads.isEmpty)
    XCTAssertNil(binding.model.historyErrorMessage)
  }

  func testTerminationCancelsAndJoinsPreviewBootstrapConsumerTask() async {
    let compositionGate = AppDelegateTerminationGate()
    await compositionGate.release()
    let composition = AppDelegateCompositionSpy(gate: compositionGate)
    let previewGate = AppDelegateTerminationGate()
    var replies: [Bool] = []
    let delegate = AppDelegate(
      profile: .dev,
      composition: composition,
      preview: true,
      previewBootstrapOperation: { _ in
        await previewGate.wait()
        XCTAssertTrue(Task.isCancelled)
      },
      terminationReply: { replies.append($0) }
    )

    delegate.startPreviewBootstrapIfNeeded()
    for _ in 0..<100 where await previewGate.pendingWaiterCount() == 0 {
      await Task.yield()
    }
    let previewWaiterCount = await previewGate.pendingWaiterCount()
    XCTAssertEqual(previewWaiterCount, 1)

    XCTAssertEqual(
      delegate.applicationShouldTerminate(NSApplication.shared),
      .terminateLater
    )
    for _ in 0..<100 where composition.events.last != "shutdown-finished" {
      await Task.yield()
    }

    XCTAssertEqual(composition.events.last, "shutdown-finished")
    XCTAssertTrue(replies.isEmpty)

    await previewGate.release()
    for _ in 0..<100 where replies.isEmpty { await Task.yield() }

    XCTAssertEqual(replies, [true])
  }
}

@MainActor
private final class AppDelegateSessionModelComposition: AppSessionSourceCompositionOwner {
  let model: SessionModel

  init(model: SessionModel) {
    self.model = model
  }

  func shutdown() async {
    await model.shutdown()
  }
}

@MainActor
private final class AppDelegateCompositionSpy: AppSessionSourceCompositionOwner {
  let model = SessionModel()
  private let gate: AppDelegateTerminationGate
  private(set) var shutdownCount = 0
  private(set) var events: [String] = []

  init(gate: AppDelegateTerminationGate) {
    self.gate = gate
  }

  func shutdown() async {
    shutdownCount += 1
    events.append("shutdown-started")
    await gate.wait()
    await model.shutdown()
    events.append("shutdown-finished")
  }
}

private enum AppDelegateBlockingHistoryWireError: Error {
  case closed
  case timeout
  case unexpectedRequest
}

private actor AppDelegateBlockingHistoryWire: AppRuntimeWireSession {
  private let catalogGate = AppDelegateTerminationGate()
  private var catalogRequestStarted = false
  private var isClosed = false
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?

  func start() async throws {}

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    switch request {
    case .describeAgents:
      return .agents(try RuntimeAgentDescriptionsV2(agents: []))
    case .catalog:
      catalogRequestStarted = true
      await catalogGate.wait()
      return .catalog(
        try RuntimeCatalogSnapshotV2(
          baseCatalogCursor: .beforeFirst,
          entries: [],
          nextPageCursor: nil
        )
      )
    default:
      throw AppDelegateBlockingHistoryWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    throw AppDelegateBlockingHistoryWireError.unexpectedRequest
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    if isClosed { throw AppDelegateBlockingHistoryWireError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      streamContinuation = continuation
    }
  }

  func close() async {
    guard !isClosed else { return }
    isClosed = true
    streamContinuation?.resume(throwing: AppDelegateBlockingHistoryWireError.closed)
    streamContinuation = nil
  }

  func waitForCatalogRequest() async throws {
    for _ in 0..<400 {
      if catalogRequestStarted { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw AppDelegateBlockingHistoryWireError.timeout
  }

  func waitForClose() async throws {
    for _ in 0..<400 {
      if isClosed { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw AppDelegateBlockingHistoryWireError.timeout
  }

  func releaseCatalogRequest() async {
    await catalogGate.release()
  }
}

private actor AppDelegateTerminationGate {
  private var isReleased = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    guard !isReleased else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !isReleased else { return }
    isReleased = true
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for waiter in pending { waiter.resume() }
  }

  func pendingWaiterCount() -> Int {
    waiters.count
  }
}
