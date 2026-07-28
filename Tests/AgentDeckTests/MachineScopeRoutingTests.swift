import AgentDeckCore
import AgentDeckRelayClient
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeck

final class MachineScopeRoutingTests: XCTestCase {
  @MainActor
  func testProductionCompositionIsLazyAndSharesRemoteStoreAcrossPerMachineSources()
    async throws
  {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-composition-\(UUID().uuidString.lowercased())",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: home) }

    let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)
    let factory = RoutingRemoteLifecycleFactorySpy()
    let composition = try AppSessionSourceComposition.production(
      installation: installation,
      remoteLifecycleFactory: { machineID, store in
        await factory.make(machineID: machineID, store: store)
      }
    )

    XCTAssertFalse(FileManager.default.fileExists(atPath: installation.recordPath.path))
    let local = try await composition.selectedMachineScope.select(.local)
    XCTAssertEqual(local.context.scope, .local)
    XCTAssertNotNil(local.handle.localPairingAdministration)
    XCTAssertNotNil(local.handle.localConversationAdministration)
    XCTAssertFalse(FileManager.default.fileExists(atPath: installation.recordPath.path))
    let initialRemoteFactoryCallCount = await factory.callCount()
    XCTAssertEqual(initialRemoteFactoryCallCount, 0)

    let remoteA = try await composition.selectedMachineScope.select(
      .remote(machineID: "remote-a")
    )
    let remoteB = try await composition.selectedMachineScope.select(
      .remote(machineID: "remote-b")
    )
    XCTAssertEqual(remoteA.context.scope, .remote(machineID: "remote-a"))
    XCTAssertEqual(remoteB.context.scope, .remote(machineID: "remote-b"))
    XCTAssertNil(remoteA.handle.localPairingAdministration)
    XCTAssertNil(remoteA.handle.localConversationAdministration)
    XCTAssertNil(remoteB.handle.localPairingAdministration)
    XCTAssertNil(remoteB.handle.localConversationAdministration)
    XCTAssertTrue(FileManager.default.fileExists(atPath: installation.recordPath.path))
    let remoteMachineIDs = await factory.machineIDs()
    let uniqueRemoteSourceCount = await factory.uniqueSourceCount()
    let uniqueRemoteStoreCount = await factory.uniqueStoreCount()
    XCTAssertEqual(remoteMachineIDs, ["remote-a", "remote-b"])
    XCTAssertEqual(uniqueRemoteSourceCount, 2)
    XCTAssertEqual(uniqueRemoteStoreCount, 1)

    await composition.shutdown()
    let remoteShutdownCount = await factory.totalShutdownCount()
    let remoteJoinCount = await factory.totalJoinCount()
    XCTAssertEqual(remoteShutdownCount, 2)
    XCTAssertEqual(remoteJoinCount, 2)
  }

  func testScopeSwitchCancelsAndJoinsAllOldObservationsBeforeOpeningRemote()
    async throws
  {
    let localSource = RoutingSessionSourceSpy(name: "local")
    let remoteSource = RoutingSessionSourceSpy(name: "remote")
    let localCapabilities = RoutingLocalCapabilitiesSpy()
    let remoteFactory = RoutingRemoteFactoryProbe(source: remoteSource)
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: localCapabilities
      ),
      remoteFactory: { machineID in
        try await remoteFactory.make(machineID: machineID)
      }
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)
    let recorder = RoutingEventRecorder()
    let catalogHandlerGate = RoutingAsyncGate()

    let localSelection = try await owner.select(.local)
    try await owner.observeCatalog(machineID: "local-machine") { context, state in
      await recorder.record(resource: state, channel: "catalog", context: context)
      await catalogHandlerGate.arriveAndWait()
    }
    try await owner.observeConversation(conversationID: "conversation-local") {
      context,
      update in
      await recorder.record(update: update, channel: "conversation", context: context)
    }
    try await owner.observeInbox { context, state in
      await recorder.record(resource: state, channel: "inbox", context: context)
    }
    let localObservationsStarted = await routingEventually {
      await localSource.activeObservationCount() == 3
    }
    XCTAssertTrue(localObservationsStarted)

    await localSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "local-machine", title: "local-before")],
        revision: 1
      )
    )
    await localSource.emitConversation(.connectionState(.connected))
    await localSource.emitInbox(
      .ready(value: [routingInbox(machineID: "local-machine", title: "local-inbox")], revision: 1)
    )
    await catalogHandlerGate.waitForArrival()

    let switchTask = Task {
      try await owner.select(.remote(machineID: "remote-machine"))
    }
    let oldSelectionInvalidated = await routingEventually {
      await owner.selection() == nil
    }
    XCTAssertTrue(oldSelectionInvalidated)
    let remoteFactoryCallCountWhileOldHandlerIsRunning = await remoteFactory.callCount()
    XCTAssertEqual(remoteFactoryCallCountWhileOldHandlerIsRunning, 0)

    await catalogHandlerGate.release()
    let remoteSelection = try await switchTask.value
    XCTAssertEqual(remoteSelection.context.scope, .remote(machineID: "remote-machine"))
    XCTAssertGreaterThan(remoteSelection.context.generation, localSelection.context.generation)
    let remoteFactoryCallCountAfterSwitch = await remoteFactory.callCount()
    XCTAssertEqual(remoteFactoryCallCountAfterSwitch, 1)
    let oldObservationsTerminated = await routingEventually {
      await localSource.terminationCount() == 3
    }
    XCTAssertTrue(oldObservationsTerminated)

    try await owner.observeCatalog(machineID: "remote-machine") { context, state in
      await recorder.record(resource: state, channel: "catalog", context: context)
    }
    try await owner.observeConversation(conversationID: "conversation-remote") {
      context,
      update in
      await recorder.record(update: update, channel: "conversation", context: context)
    }
    try await owner.observeInbox { context, state in
      await recorder.record(resource: state, channel: "inbox", context: context)
    }
    let remoteObservationsStarted = await routingEventually {
      await remoteSource.activeObservationCount() == 3
    }
    XCTAssertTrue(remoteObservationsStarted)

    // 旧 source 在 scope 已切换后迟到的值不得再次发布。
    await localSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "local-machine", title: "local-late")],
        revision: 2
      )
    )
    await localSource.emitConversation(.connectionState(.securityError))
    await localSource.emitInbox(
      .ready(value: [routingInbox(machineID: "local-machine", title: "local-late")], revision: 2)
    )
    await remoteSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "remote-machine", title: "remote-after")],
        revision: 1
      )
    )
    await remoteSource.emitConversation(.connectionState(.connected))
    await remoteSource.emitInbox(
      .ready(value: [routingInbox(machineID: "remote-machine", title: "remote-inbox")], revision: 1)
    )
    let remoteEventsPublished = await routingEventually {
      let catalogPublished = await recorder.contains(
        channel: "catalog",
        scope: .remote(machineID: "remote-machine")
      )
      let conversationPublished = await recorder.contains(
        channel: "conversation",
        scope: .remote(machineID: "remote-machine")
      )
      let inboxPublished = await recorder.contains(
        channel: "inbox",
        scope: .remote(machineID: "remote-machine")
      )
      return catalogPublished && conversationPublished && inboxPublished
    }
    XCTAssertTrue(remoteEventsPublished)
    let containsLateLocalPayload = await recorder.containsPayload("local-late")
    XCTAssertFalse(containsLateLocalPayload)

    await owner.shutdown()
    await registry.shutdown()
  }

  func testCatalogHandlerCanReenterSelectWithoutJoiningItsOwnObservation() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local-reentrant-select")
    let remoteSource = RoutingSessionSourceSpy(name: "remote-reentrant-select")
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: RoutingLocalCapabilitiesSpy()
      ),
      remoteFactory: { machineID in
        try SessionSourceRegistration(
          scope: .remote(machineID: machineID),
          source: remoteSource,
          capabilities: SessionSourceCapabilities(),
          lifecycle: remoteSource
        )
      }
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)
    let recorder = RoutingEventRecorder()
    let reentryFinished = RoutingCompletionProbe()
    let reentrySucceeded = RoutingCompletionProbe()
    let oldHandlerTailGate = RoutingAsyncGate()

    let localSelection = try await owner.select(.local)
    try await owner.observeCatalog(machineID: "local-machine") { context, state in
      await recorder.record(resource: state, channel: "catalog", context: context)
      do {
        let remoteSelection = try await owner.select(
          .remote(machineID: "remote-machine")
        )
        if remoteSelection.context.scope == .remote(machineID: "remote-machine") {
          await reentrySucceeded.complete()
        }
      } catch {
        // Assertions below retain the deterministic failure instead of trapping this task.
      }
      await reentryFinished.complete()
      await oldHandlerTailGate.arriveAndWait()
    }
    let localObservationStarted = await routingEventually {
      await localSource.activeObservationCount() == 1
    }
    XCTAssertTrue(localObservationStarted)

    await localSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "local-machine", title: "local-trigger")],
        revision: 1
      )
    )
    let reentryReturned = await routingEventuallyAllowingChildTasks {
      await reentryFinished.isComplete()
    }
    guard reentryReturned else {
      await registry.shutdown()
      return XCTFail("catalog handler reentrant select self-joined its observation task")
    }

    let reentryDidSucceed = await reentrySucceeded.isComplete()
    XCTAssertTrue(reentryDidSucceed)
    await oldHandlerTailGate.waitForArrival()
    let remoteSelection = await owner.selection()
    XCTAssertEqual(remoteSelection?.context.scope, .remote(machineID: "remote-machine"))
    XCTAssertGreaterThan(
      remoteSelection?.context.generation ?? 0,
      localSelection.context.generation
    )

    // 旧 callback 尚未返回时，新 generation 已可建立自己的 observation；旧 task
    // 只能留在 retired 集合，不能占用或清理新 generation 的 active slot。
    try await owner.observeCatalog(machineID: "remote-machine") { context, state in
      await recorder.record(resource: state, channel: "catalog", context: context)
    }
    let remoteObservationStarted = await routingEventually {
      await remoteSource.activeObservationCount() == 1
    }
    XCTAssertTrue(remoteObservationStarted)
    await remoteSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "remote-machine", title: "remote-first")],
        revision: 1
      )
    )
    let remoteFirstPublished = await routingEventually {
      await recorder.containsPayload("remote-first")
    }
    XCTAssertTrue(remoteFirstPublished)

    await localSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "local-machine", title: "local-late")],
        revision: 2
      )
    )
    await oldHandlerTailGate.release()
    let oldObservationTerminated = await routingEventually {
      await localSource.terminationCount() == 1
    }
    XCTAssertTrue(oldObservationTerminated)
    let containsLateLocalPayload = await recorder.containsPayload("local-late")
    XCTAssertFalse(containsLateLocalPayload)

    // 旧 task 的 finish 回调也不得误清理新 generation 的同类 observation。
    await remoteSource.emitCatalog(
      .ready(
        value: [routingConversation(machineID: "remote-machine", title: "remote-second")],
        revision: 2
      )
    )
    let remoteSecondPublished = await routingEventually {
      await recorder.containsPayload("remote-second")
    }
    XCTAssertTrue(remoteSecondPublished)

    await owner.shutdown()
    await registry.shutdown()
  }

  func testInboxHandlerCanReenterShutdownWithoutJoiningItsOwnObservation() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local-reentrant-shutdown")
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: RoutingLocalCapabilitiesSpy()
      ),
      remoteFactory: { _ in throw RoutingTestFailure.unsupported }
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)
    let recorder = RoutingEventRecorder()
    let shutdownReturned = RoutingCompletionProbe()
    let oldHandlerTailGate = RoutingAsyncGate()

    _ = try await owner.select(.local)
    try await owner.observeInbox { context, state in
      await recorder.record(resource: state, channel: "inbox", context: context)
      await owner.shutdown()
      await shutdownReturned.complete()
      await oldHandlerTailGate.arriveAndWait()
    }
    let localObservationStarted = await routingEventually {
      await localSource.activeObservationCount() == 1
    }
    XCTAssertTrue(localObservationStarted)

    await localSource.emitInbox(
      .ready(
        value: [routingInbox(machineID: "local-machine", title: "shutdown-trigger")],
        revision: 1
      )
    )
    let reentryReturned = await routingEventuallyAllowingChildTasks {
      await shutdownReturned.isComplete()
    }
    guard reentryReturned else {
      await registry.shutdown()
      return XCTFail("inbox handler reentrant shutdown self-joined its observation task")
    }

    await oldHandlerTailGate.waitForArrival()
    let selectionAfterShutdown = await owner.selection()
    XCTAssertNil(selectionAfterShutdown)
    do {
      _ = try await owner.select(.local)
      XCTFail("reentrant shutdown 后 selection unexpectedly succeeded")
    } catch let error as SelectedMachineScopeError {
      XCTAssertEqual(error, .shutDown)
    } catch {
      XCTFail("expected SelectedMachineScopeError.shutDown, got \(error)")
    }

    await localSource.emitInbox(
      .ready(
        value: [routingInbox(machineID: "local-machine", title: "shutdown-late")],
        revision: 2
      )
    )
    await oldHandlerTailGate.release()
    // 外部 caller 仍能取得完整 barrier；它会 join 刚刚获准 unwind 的 callback task。
    await owner.shutdown()
    let oldObservationTerminated = await routingEventually {
      await localSource.terminationCount() == 1
    }
    XCTAssertTrue(oldObservationTerminated)
    let containsLateShutdownPayload = await recorder.containsPayload("shutdown-late")
    XCTAssertFalse(containsLateShutdownPayload)

    await registry.shutdown()
  }

  func testShutdownPreemptsScopeSwitchBlockedInRemoteFactory() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local")
    let factoryGate = RoutingCancellationFactoryGate()
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: RoutingLocalCapabilitiesSpy()
      ),
      remoteFactory: { _ in
        try await factoryGate.arriveAndWaitForCancellation()
        throw RoutingTestFailure.unsupported
      }
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)
    _ = try await owner.select(.local)

    let blockedSelection = Task {
      try await owner.select(.remote(machineID: "remote-blocked"))
    }
    await factoryGate.waitForArrival()

    let ownerShutdownFinished = RoutingCompletionProbe()
    let ownerShutdown = Task {
      await owner.shutdown()
      await ownerShutdownFinished.complete()
    }
    let preempted = await routingEventually {
      await ownerShutdownFinished.isComplete()
    }

    guard preempted else {
      let forcedRegistryShutdown = Task { await registry.shutdown() }
      await factoryGate.waitForCancellation()
      await forcedRegistryShutdown.value
      await ownerShutdown.value
      _ = await blockedSelection.result
      return XCTFail("scope owner shutdown did not preempt blocked registry.open")
    }

    // 即使 factory generation 仍由 registry 持有且 gate 未释放，scope owner 也必须
    // 已取消自己的 waiter 并完成；composition 随后才能进入 registry.shutdown。
    let factoryWasPrematurelyCancelled = await factoryGate.wasCancelled()
    XCTAssertFalse(factoryWasPrematurelyCancelled)
    do {
      _ = try await blockedSelection.value
      XCTFail("shutdown 后 blocked selection unexpectedly succeeded")
    } catch is CancellationError {
      // expected
    } catch {
      XCTFail("expected CancellationError, got \(error)")
    }

    let registryShutdown = Task { await registry.shutdown() }
    await factoryGate.waitForCancellation()
    await registryShutdown.value
    await ownerShutdown.value

    let factoryWasCancelled = await factoryGate.wasCancelled()
    let localShutdowns = await localSource.shutdownCount()
    let localJoins = await localSource.joinCount()
    XCTAssertTrue(factoryWasCancelled)
    XCTAssertEqual(localShutdowns, 1)
    XCTAssertEqual(localJoins, 1)
  }

  func testShutdownRejectsLateSuccessfulSelectionBeforeOuterReturn() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local")
    let remoteSource = RoutingSessionSourceSpy(name: "remote-late-success")
    let postOperationGate = RoutingAsyncGate()
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: RoutingLocalCapabilitiesSpy()
      ),
      remoteFactory: { machineID in
        try SessionSourceRegistration(
          scope: .remote(machineID: machineID),
          source: remoteSource,
          capabilities: SessionSourceCapabilities(),
          lifecycle: remoteSource
        )
      }
    )
    let owner = SelectedMachineScopeGenerationOwner(
      registry: registry,
      selectionPostOperationHook: {
        await postOperationGate.arriveAndWait()
      }
    )

    let lateSelection = Task {
      try await owner.select(.remote(machineID: "remote-late-success"))
    }
    await postOperationGate.waitForArrival()

    let installedBeforeShutdown = await owner.selection()
    XCTAssertEqual(
      installedBeforeShutdown?.context.scope,
      .remote(machineID: "remote-late-success")
    )

    await owner.shutdown()
    let selectionAfterShutdown = await owner.selection()
    XCTAssertNil(selectionAfterShutdown)
    await postOperationGate.release()

    do {
      _ = try await lateSelection.value
      XCTFail("shutdown 后 late-success selection unexpectedly escaped")
    } catch let error as SelectedMachineScopeError {
      XCTAssertEqual(error, .shutDown)
    } catch {
      XCTFail("expected SelectedMachineScopeError.shutDown, got \(error)")
    }

    await registry.shutdown()
    let remoteShutdowns = await remoteSource.shutdownCount()
    let remoteJoins = await remoteSource.joinCount()
    XCTAssertEqual(remoteShutdowns, 1)
    XCTAssertEqual(remoteJoins, 1)
  }

  func testExplicitFixtureSelectionHasNoLocalCapabilities() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local")
    let fixtureSource = RoutingSessionSourceSpy(name: "preview-fixture")
    let capabilities = RoutingLocalCapabilitiesSpy()
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(source: localSource, capabilities: capabilities),
      remoteFactory: { _ in throw RoutingTestFailure.unsupported }
    )
    try await registry.registerFixture(
      SessionSourceRegistration(
        scope: .fixture(id: "preview"),
        source: fixtureSource,
        capabilities: SessionSourceCapabilities(),
        lifecycle: fixtureSource
      )
    )
    let owner = SelectedMachineScopeGenerationOwner(registry: registry)

    let fixture = try await owner.select(.fixture(id: "preview"))
    XCTAssertEqual(fixture.context.scope, .fixture(id: "preview"))
    XCTAssertNil(fixture.handle.localPairingAdministration)
    XCTAssertNil(fixture.handle.localConversationAdministration)

    await owner.shutdown()
    await registry.shutdown()
  }

  func testRemotePairingOperationDoesNotTouchOrReplaceLocalSource() async throws {
    let localSource = RoutingSessionSourceSpy(name: "local")
    let remoteSource = RoutingSessionSourceSpy(name: "remote")
    let registry = try SessionSourceRegistry(
      local: try routingLocalRegistration(
        source: localSource,
        capabilities: RoutingLocalCapabilitiesSpy()
      ),
      remoteFactory: { machineID in
        try SessionSourceRegistration(
          scope: .remote(machineID: machineID),
          source: remoteSource,
          capabilities: SessionSourceCapabilities(),
          lifecycle: remoteSource
        )
      }
    )

    let localBefore = try await registry.open(.local)
    let remote = try await registry.open(.remote(machineID: "remote-machine"))
    let progress = try await remote.source.pair("fixture-invite")
    var iterator = progress.makeAsyncIterator()
    let terminalProgress = try await iterator.next()
    XCTAssertNil(terminalProgress)

    let localAfter = try await registry.open(.local)
    let localPairCalls = await localSource.pairCallCount()
    let remotePairCalls = await remoteSource.pairCallCount()
    let localShutdowns = await localSource.shutdownCount()
    let localJoins = await localSource.joinCount()
    XCTAssertTrue(sameRoutingSource(localBefore.source, localSource))
    XCTAssertTrue(sameRoutingSource(localAfter.source, localSource))
    XCTAssertEqual(localPairCalls, 0)
    XCTAssertEqual(remotePairCalls, 1)
    XCTAssertEqual(localShutdowns, 0)
    XCTAssertEqual(localJoins, 0)

    await registry.shutdown()
  }

  func testProductionCompositionDoesNotReferencePreviewRuntimeWire() throws {
    let repositoryRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let compositionURL =
      repositoryRoot
      .appendingPathComponent("Sources/AgentDeck/SessionSources/AppSessionSourceComposition.swift")
    let source = try String(contentsOf: compositionURL, encoding: .utf8)

    XCTAssertFalse(source.contains("PreviewRuntimeWireSession"))
    XCTAssertFalse(source.contains("PreviewBootstrap"))
    XCTAssertTrue(source.contains("SessionModel.makeProductionLocalBinding"))
    XCTAssertTrue(source.contains("RelaySessionSource.open"))
    XCTAssertTrue(source.contains("scope: .machine(machineID)"))
  }
}

private enum RoutingTestFailure: Error, Sendable {
  case unsupported
}

private actor RoutingRemoteLifecycleFactorySpy {
  private var calls: [(machineID: String, storeID: ObjectIdentifier)] = []
  private var sources: [String: RoutingSessionSourceSpy] = [:]

  func make(
    machineID: String,
    store: PairedMachineStore
  ) -> any SessionSourceLifecycle {
    let source = RoutingSessionSourceSpy(name: machineID)
    calls.append((machineID: machineID, storeID: ObjectIdentifier(store)))
    sources[machineID] = source
    return source
  }

  func callCount() -> Int { calls.count }

  func machineIDs() -> [String] { calls.map(\.machineID) }

  func uniqueSourceCount() -> Int {
    Set(sources.values.map(ObjectIdentifier.init)).count
  }

  func uniqueStoreCount() -> Int {
    Set(calls.map(\.storeID)).count
  }

  func totalShutdownCount() async -> Int {
    var total = 0
    for source in sources.values { total += await source.shutdownCount() }
    return total
  }

  func totalJoinCount() async -> Int {
    var total = 0
    for source in sources.values { total += await source.joinCount() }
    return total
  }
}

private actor RoutingRemoteFactoryProbe {
  private let source: RoutingSessionSourceSpy
  private var calls = 0

  init(source: RoutingSessionSourceSpy) {
    self.source = source
  }

  func make(machineID: String) throws -> SessionSourceRegistration {
    calls += 1
    return try SessionSourceRegistration(
      scope: .remote(machineID: machineID),
      source: source,
      capabilities: SessionSourceCapabilities(),
      lifecycle: source
    )
  }

  func callCount() -> Int { calls }
}

private actor RoutingSessionSourceSpy: SessionSourceLifecycle {
  private enum Channel {
    case catalog
    case conversation
    case inbox
  }

  private let name: String
  private var catalogContinuations:
    [UUID: AsyncStream<ResourceState<[ConversationSummary]>>.Continuation] = [:]
  private var conversationContinuations: [UUID: AsyncStream<ConversationUpdate>.Continuation] = [:]
  private var inboxContinuations: [UUID: AsyncStream<ResourceState<[InboxItem]>>.Continuation] = [:]
  private var terminations = 0
  private var shutdowns = 0
  private var joins = 0
  private var pairCalls = 0

  init(name: String) {
    self.name = name
  }

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    AsyncStream { continuation in continuation.finish() }
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    let id = UUID()
    let pair = AsyncStream<ResourceState<[ConversationSummary]>>.makeStream()
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.remove(.catalog, id: id) }
    }
    catalogContinuations[id] = pair.continuation
    return pair.stream
  }

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
    let id = UUID()
    let pair = AsyncStream<ConversationUpdate>.makeStream()
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.remove(.conversation, id: id) }
    }
    conversationContinuations[id] = pair.continuation
    return pair.stream
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    let id = UUID()
    let pair = AsyncStream<ResourceState<[InboxItem]>>.makeStream()
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.remove(.inbox, id: id) }
    }
    inboxContinuations[id] = pair.continuation
    return pair.stream
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    throw RoutingTestFailure.unsupported
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    _ = encodedInvite
    pairCalls += 1
    return AsyncThrowingStream { continuation in continuation.finish() }
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    throw RoutingTestFailure.unsupported
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    throw RoutingTestFailure.unsupported
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    throw RoutingTestFailure.unsupported
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    throw RoutingTestFailure.unsupported
  }

  func shutdown() async {
    shutdowns += 1
    finishAll()
  }

  func join() async {
    joins += 1
  }

  func emitCatalog(_ state: ResourceState<[ConversationSummary]>) {
    for continuation in catalogContinuations.values { continuation.yield(state) }
  }

  func emitConversation(_ update: ConversationUpdate) {
    for continuation in conversationContinuations.values { continuation.yield(update) }
  }

  func emitInbox(_ state: ResourceState<[InboxItem]>) {
    for continuation in inboxContinuations.values { continuation.yield(state) }
  }

  func activeObservationCount() -> Int {
    catalogContinuations.count + conversationContinuations.count + inboxContinuations.count
  }

  func terminationCount() -> Int { terminations }

  func shutdownCount() -> Int { shutdowns }

  func joinCount() -> Int { joins }

  func pairCallCount() -> Int { pairCalls }

  private func remove(_ channel: Channel, id: UUID) {
    switch channel {
    case .catalog:
      guard catalogContinuations.removeValue(forKey: id) != nil else { return }
    case .conversation:
      guard conversationContinuations.removeValue(forKey: id) != nil else { return }
    case .inbox:
      guard inboxContinuations.removeValue(forKey: id) != nil else { return }
    }
    terminations += 1
  }

  private func finishAll() {
    for continuation in catalogContinuations.values { continuation.finish() }
    for continuation in conversationContinuations.values { continuation.finish() }
    for continuation in inboxContinuations.values { continuation.finish() }
  }
}

private actor RoutingLocalCapabilitiesSpy:
  LocalPairingAdministration,
  LocalConversationAdministration
{
  func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>> {
    AsyncStream { continuation in continuation.finish() }
  }

  func confirmPairing(id: String) async throws -> PairingAdministrationReceipt {
    throw RoutingTestFailure.unsupported
  }

  func cancelPairing(id: String) async throws -> PairingAdministrationReceipt {
    throw RoutingTestFailure.unsupported
  }

  func connectionLease() async throws -> LocalConversationConnectionLease {
    throw RoutingTestFailure.unsupported
  }

  func requireCurrentConnection(_ lease: LocalConversationConnectionLease) async throws {
    throw RoutingTestFailure.unsupported
  }

  func requiresFreshConnection(_ lease: LocalConversationConnectionLease) async -> Bool {
    true
  }

  func invalidateConnection(
    _ lease: LocalConversationConnectionLease,
    reason: LocalConversationConnectionInvalidationReason
  ) async -> Bool {
    false
  }

  func describeAgents(
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeAgentDescriptionsV2 {
    throw RoutingTestFailure.unsupported
  }

  func startConversation(
    _ draft: RuntimeConversationDraft,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeConversationStartResult {
    throw RoutingTestFailure.unsupported
  }

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConfigurationReceiptV2 {
    throw RoutingTestFailure.unsupported
  }

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConversationMetadataReceiptV2 {
    throw RoutingTestFailure.unsupported
  }

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> ApprovalReceiptV1 {
    throw RoutingTestFailure.unsupported
  }

  func loadCatalog(
    using lease: LocalConversationConnectionLease
  ) async throws -> [RuntimeCatalogSnapshotV2] {
    throw RoutingTestFailure.unsupported
  }

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    throw RoutingTestFailure.unsupported
  }

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    throw RoutingTestFailure.unsupported
  }

  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    throw RoutingTestFailure.unsupported
  }

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    throw RoutingTestFailure.unsupported
  }

  func unsubscribeConversation(
    _ conversationID: RuntimeConversationID,
    using lease: LocalConversationConnectionLease
  ) async throws {
    throw RoutingTestFailure.unsupported
  }

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> CommandReceiptV2 {
    throw RoutingTestFailure.unsupported
  }
}

private actor RoutingEventRecorder {
  private struct Event: Sendable {
    let channel: String
    let scope: MachineScope
    let payload: String
  }

  private var events: [Event] = []

  func record<Value>(
    resource: ResourceState<[Value]>,
    channel: String,
    context: MachineScopeObservationContext
  ) where Value: Sendable {
    let payload: String
    switch resource {
    case .loading:
      payload = "loading"
    case .ready(let values, let revision):
      payload = "ready:\(values):\(revision)"
    case .stale(let values, let reason):
      payload = "stale:\(values):\(reason)"
    case .failed(let error, let retryable):
      payload = "failed:\(error.code.rawValue):\(retryable)"
    }
    events.append(Event(channel: channel, scope: context.scope, payload: payload))
  }

  func record(
    update: ConversationUpdate,
    channel: String,
    context: MachineScopeObservationContext
  ) {
    events.append(Event(channel: channel, scope: context.scope, payload: "\(update)"))
  }

  func contains(channel: String, scope: MachineScope) -> Bool {
    events.contains { $0.channel == channel && $0.scope == scope }
  }

  func containsPayload(_ fragment: String) -> Bool {
    events.contains { $0.payload.contains(fragment) }
  }
}

private actor RoutingAsyncGate {
  private var arrivals = 0
  private var released = false
  private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func arriveAndWait() async {
    arrivals += 1
    let waiters = arrivalWaiters
    arrivalWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
    guard !released else { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func waitForArrival() async {
    guard arrivals == 0 else { return }
    await withCheckedContinuation { arrivalWaiters.append($0) }
  }

  func release() {
    guard !released else { return }
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
  }
}

private actor RoutingCancellationFactoryGate {
  private var arrived = false
  private var cancelled = false
  private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []
  private var cancellationWaiters: [CheckedContinuation<Void, Never>] = []

  func arriveAndWaitForCancellation() async throws {
    arrived = true
    let arrivals = arrivalWaiters
    arrivalWaiters.removeAll(keepingCapacity: false)
    for waiter in arrivals { waiter.resume() }

    do {
      try await Task.sleep(for: .seconds(60))
    } catch is CancellationError {
      cancelled = true
      let pending = cancellationWaiters
      cancellationWaiters.removeAll(keepingCapacity: false)
      for waiter in pending { waiter.resume() }
      throw CancellationError()
    }
    throw RoutingTestFailure.unsupported
  }

  func waitForArrival() async {
    guard !arrived else { return }
    await withCheckedContinuation { arrivalWaiters.append($0) }
  }

  func waitForCancellation() async {
    guard !cancelled else { return }
    await withCheckedContinuation { cancellationWaiters.append($0) }
  }

  func wasCancelled() -> Bool { cancelled }
}

private actor RoutingCompletionProbe {
  private var completed = false

  func complete() { completed = true }

  func isComplete() -> Bool { completed }
}

private func routingLocalRegistration(
  source: RoutingSessionSourceSpy,
  capabilities: RoutingLocalCapabilitiesSpy
) throws -> SessionSourceRegistration {
  try SessionSourceRegistration(
    scope: .local,
    source: source,
    capabilities: SessionSourceCapabilities(
      localPairingAdministration: capabilities,
      localConversationAdministration: capabilities
    ),
    lifecycle: source
  )
}

private func sameRoutingSource(
  _ source: any SessionSource,
  _ expected: RoutingSessionSourceSpy
) -> Bool {
  (source as AnyObject) === expected
}

private func routingConversation(machineID: String, title: String) -> ConversationSummary {
  ConversationSummary(
    id: "conversation-\(title)",
    machineID: machineID,
    title: title,
    cwd: "/tmp",
    agentKind: .codex,
    group: .recent,
    lastActiveMs: 1,
    archived: false,
    revision: 1
  )
}

private func routingInbox(machineID: String, title: String) -> InboxItem {
  InboxItem(
    id: "inbox-\(title)",
    conversationID: "conversation-\(title)",
    machineID: machineID,
    kind: .turnCompleted,
    title: title
  )
}

private func routingEventually(
  attempts: Int = 500,
  condition: @escaping @Sendable () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await condition() { return true }
    await Task.yield()
  }
  return false
}

private func routingEventuallyAllowingChildTasks(
  attempts: Int = 1_000,
  condition: @escaping @Sendable () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await condition() { return true }
    try? await Task.sleep(for: .milliseconds(1))
  }
  return false
}
