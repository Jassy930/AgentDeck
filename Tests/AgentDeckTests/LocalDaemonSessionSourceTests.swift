import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeck

final class LocalDaemonSessionSourceTests: XCTestCase {
  func testAsyncWireOpeningAndActivationAreSingleFlightBeforeCoordinatorStart() async throws {
    let wire = try LocalDaemonSourceFakeWire()
    let factoryGate = LocalDaemonSourceGate()
    let activationGate = LocalDaemonSourceGate()
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: {
        await factoryGate.arriveAndWait()
        return wire
      },
      machineID: "installation-activation",
      connectionActivation: { generation in
        XCTAssertEqual(generation, 1)
        await activationGate.arriveAndWait()
      }
    )

    let first = Task { try await source.describeAgents() }
    let second = Task { try await source.describeAgents() }
    let factoryIsWaiting = await localSourceEventually {
      await factoryGate.arrivalCount() == 1
    }
    XCTAssertTrue(
      factoryIsWaiting,
      "concurrent opens did not share the same async factory reservation"
    )
    let startsBeforeFactory = await wire.startCount()
    XCTAssertEqual(startsBeforeFactory, 0)

    await factoryGate.releaseAll()
    let activationIsWaiting = await localSourceEventually {
      await activationGate.arrivalCount() == 1
    }
    XCTAssertTrue(
      activationIsWaiting,
      "connection generation was not offered to the activation barrier"
    )
    let startsBeforeActivation = await wire.startCount()
    XCTAssertEqual(
      startsBeforeActivation,
      0,
      "coordinator started before activation completed"
    )

    await activationGate.releaseAll()
    _ = try await (first.value, second.value)
    let finalStartCount = await wire.startCount()
    let describeCount = await wire.requestKinds().filter { $0 == "describeAgents" }.count
    XCTAssertEqual(finalStartCount, 1)
    XCTAssertEqual(describeCount, 1)
    await source.shutdown()
  }

  func testConstructionIsLazyAndConcurrentObserversSingleFlightOneWire() async throws {
    let wire = try LocalDaemonSourceFakeWire()
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      machineName: "This Mac"
    )

    let initialStartCount = await wire.startCount()
    XCTAssertEqual(initialStartCount, 0)
    async let firstStream = source.machines()
    async let secondStream = source.machines()
    var first = await firstStream.makeAsyncIterator()
    var second = await secondStream.makeAsyncIterator()

    guard case .loading = await first.next() else {
      return XCTFail("first observer did not receive loading")
    }
    guard case .loading = await second.next() else {
      return XCTFail("second observer did not receive loading")
    }
    guard case .ready(let firstMachines, _) = await first.next() else {
      return XCTFail("first observer did not become ready")
    }
    guard case .ready(let secondMachines, _) = await second.next() else {
      return XCTFail("second observer did not become ready")
    }

    XCTAssertEqual(firstMachines.map(\.id), ["installation-local"])
    XCTAssertEqual(secondMachines.map(\.id), ["installation-local"])
    XCTAssertEqual(firstMachines.first?.connectionState, .connected)
    let finalStartCount = await wire.startCount()
    XCTAssertEqual(finalStartCount, 1)
    await source.shutdown()
    let closeCount = await wire.closeCount()
    let requestKinds = await wire.requestKinds()
    XCTAssertEqual(closeCount, 1)
    XCTAssertEqual(requestKinds.filter { $0 == "shutdown" }.count, 0)
  }

  func testOfflineUDSIsTransportUnavailableInsteadOfRemoteMachineOffline() async throws {
    let wire = try LocalDaemonSourceFakeWire(
      startFailure: RuntimeEnvelopeClientFailure(
        code: "daemon.client.socket_unavailable",
        message: "local UDS unavailable"
      )
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-offline",
      machineName: "Offline Mac"
    )
    var machines = await source.machines().makeAsyncIterator()
    _ = await machines.next()

    guard case .failed(let failure, let retryable) = await machines.next() else {
      return XCTFail("offline local source did not publish typed failure")
    }
    XCTAssertEqual(failure.code, .transportUnavailable)
    XCTAssertTrue(retryable)
    await source.shutdown()
  }

  func testCatalogAndConversationUseCanonicalSnapshotAndLiveEvent() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-local")
    let wire = try LocalDaemonSourceFakeWire(conversationID: conversationID)
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      machineName: "This Mac"
    )

    var catalog = await source.conversations(machineID: "installation-local").makeAsyncIterator()
    guard case .loading = await catalog.next() else {
      return XCTFail("catalog did not start in loading")
    }
    guard case .ready(let summaries, _) = await catalog.next() else {
      return XCTFail("catalog did not publish ready")
    }
    XCTAssertEqual(summaries.map(\.id), [conversationID.rawValue])

    let conversationStream = await source.conversation(
      conversationID: conversationID.rawValue
    )
    var conversation = conversationStream.makeAsyncIterator()
    guard case .connectionState(.connecting) = await conversation.next() else {
      return XCTFail("conversation did not publish connecting")
    }
    guard case .snapshot(let snapshot) = await conversation.next() else {
      return XCTFail("conversation did not publish canonical snapshot")
    }
    XCTAssertEqual(snapshot.conversationID, conversationID)
    guard case .connectionState(.connected) = await conversation.next() else {
      return XCTFail("conversation did not publish connected")
    }

    let event = try localSourceTurnStartedEvent(
      conversationID: conversationID,
      eventSequence: 0
    )
    await wire.emit(.event(event))
    guard case .event(let delivered) = await conversation.next() else {
      return XCTFail("conversation did not publish live canonical event")
    }
    XCTAssertEqual(delivered.eventID, event.eventID)
    _ = conversationStream
    await source.shutdown()
  }

  func testLocalPairingAdministrationUsesSameCoordinatorOwner() async throws {
    let pairingID = RuntimePairingID(rawValue: "pairing-local")
    let pending = try RuntimePendingPairingV4(
      pairingID: pairingID,
      requestHash: Data(repeating: 0x41, count: 32),
      deviceSignFingerprint: Data(repeating: 0x42, count: 32),
      requestedAtMs: 1,
      expiresAtMs: 2
    )
    let wire = try LocalDaemonSourceFakeWire(
      additionalUnaryReplies: [
        .pendingPairings([pending]),
        .pairing(.confirmed(pairingID)),
        .pendingPairings([]),
      ]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      machineName: "This Mac"
    )

    var stream = await source.pendingPairings().makeAsyncIterator()
    guard case .loading = await stream.next() else {
      return XCTFail("pending pairing stream did not start in loading")
    }
    guard case .ready(let pairings, _) = await stream.next() else {
      return XCTFail("pending pairing stream did not publish initial list")
    }
    XCTAssertEqual(pairings.map(\.pairingID), [pairingID])
    _ = try await source.confirmPairing(id: pairingID.rawValue)
    guard case .ready(let remaining, _) = await stream.next() else {
      return XCTFail("pending pairing stream did not refresh after confirm")
    }
    XCTAssertTrue(remaining.isEmpty)
    let startCount = await wire.startCount()
    XCTAssertEqual(startCount, 1)
    await source.shutdown()
  }

  func testCatalogAndConversationSynchronizationAreFIFOWithoutOperationInProgress() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-fifo")
    let catalogGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationID)
      ],
      requestHook: { request in
        if case .catalog = request { await catalogGate.arriveAndWait() }
      }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    let catalog = Task { try await source.loadCatalog() }
    let catalogStarted = await localSourceEventually { await catalogGate.arrivalCount() == 1 }
    XCTAssertTrue(catalogStarted)
    let conversation = Task {
      try await source.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
    }
    let queued = await localSourceEventually { await source.debugSynchronizationWaiterCount() == 1 }
    XCTAssertTrue(queued)
    let requestsBeforeRelease = await wire.requestKinds()
    XCTAssertEqual(requestsBeforeRelease.filter { $0 == "subscribeConversation" }.count, 0)

    await catalogGate.releaseAll()
    _ = try await catalog.value
    _ = try await conversation.value
    let requestsAfterRelease = await wire.requestKinds()
    XCTAssertEqual(requestsAfterRelease.filter { $0 == "subscribeConversation" }.count, 1)
    await source.shutdown()
  }

  func testUnaryCatalogBaselineSupportsSubsequentSubscriptionOnSharedIngress() async throws {
    let wire = try LocalDaemonSourceFakeWire()
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    let pages = try await source.loadCatalog()
    let cursor = try XCTUnwrap(pages.first?.baseCatalogCursor)
    _ = try await source.synchronizeCatalog(cursor: cursor)

    let fatalFailure = await source.debugFatalFailure()
    XCTAssertNil(fatalFailure)
    var catalog = await source.conversations(
      machineID: "installation-local"
    ).makeAsyncIterator()
    guard case .ready(let summaries, _) = await catalog.next() else {
      return XCTFail("shared unary/stream ingress did not publish the subscribed catalog")
    }
    XCTAssertEqual(summaries.map(\.id), ["conversation-local"])
    let requestKinds = await wire.requestKinds()
    XCTAssertEqual(requestKinds.filter { $0 == "catalog" }.count, 1)
    XCTAssertEqual(requestKinds.filter { $0 == "subscribeCatalog" }.count, 1)

    await source.shutdown()
  }

  func testCatalogSubscriptionSnapshotAtomicallyReplacesUnaryBaseline() async throws {
    let unaryConversationID = RuntimeConversationID(rawValue: "conversation-unary-baseline")
    let synchronizedConversationID = RuntimeConversationID(
      rawValue: "conversation-subscription-snapshot"
    )
    let synchronizedEntry = RuntimeConversationEntryV2(
      conversationID: synchronizedConversationID,
      agentKind: .codex,
      title: "Subscription snapshot",
      cwd: "/tmp/subscription-snapshot",
      lastActiveMs: 20,
      archived: false,
      entryRevision: 1
    )
    let synchronizedPage = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .beforeFirst,
      entries: [synchronizedEntry],
      currentPageCursor: nil,
      nextPageCursor: nil
    )
    let wire = try LocalDaemonSourceFakeWire(
      conversationID: unaryConversationID,
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(
              streamGeneration: RuntimeStreamGeneration(rawValue: "catalog-generation")
            )
          ),
          .catalog(synchronizedPage),
          .syncComplete(try localSourceCatalogSyncComplete()),
        ]
      ]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    var catalog = await source.conversations(
      machineID: "installation-local"
    ).makeAsyncIterator()
    guard case .loading = await catalog.next() else {
      return XCTFail("catalog did not start in loading")
    }
    guard case .ready(let summaries, _) = await catalog.next() else {
      return XCTFail("Catalog subscription snapshot did not publish a ready baseline")
    }
    XCTAssertEqual(summaries.map(\.id), [synchronizedConversationID.rawValue])
    XCTAssertEqual(summaries.first?.cwd, "/tmp/subscription-snapshot")
    let fatalFailure = await source.debugFatalFailure()
    XCTAssertNil(fatalFailure)

    await source.shutdown()
  }

  @MainActor
  func testFixtureBindingProjectsCatalogSnapshotAndBackfillIntoModelAndSource() async throws {
    let machineID = "installation-binding"
    let unaryConversationID = RuntimeConversationID(rawValue: "conversation-binding-unary")
    let firstConversationID = RuntimeConversationID(rawValue: "conversation-binding-first")
    let secondConversationID = RuntimeConversationID(rawValue: "conversation-binding-second")
    let secondPageCursor = RuntimeCatalogPageCursor(rawValue: "binding-catalog-page-2")

    let firstSnapshotEntry = RuntimeConversationEntryV2(
      conversationID: firstConversationID,
      agentKind: .codex,
      title: "Snapshot first",
      cwd: "/tmp/binding-snapshot-first",
      lastActiveMs: 100,
      archived: false,
      entryRevision: 1
    )
    let secondSnapshotEntry = RuntimeConversationEntryV2(
      conversationID: secondConversationID,
      agentKind: .claudeCode,
      title: "Stable second",
      cwd: "/tmp/binding-stable-second",
      lastActiveMs: 200,
      archived: false,
      entryRevision: 3
    )
    let firstPage = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(4),
      entries: [firstSnapshotEntry],
      currentPageCursor: nil,
      nextPageCursor: secondPageCursor
    )
    let secondPage = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .at(4),
      entries: [secondSnapshotEntry],
      currentPageCursor: secondPageCursor,
      nextPageCursor: nil
    )
    let backfilledFirstEntry = RuntimeConversationEntryV2(
      conversationID: firstConversationID,
      agentKind: .codex,
      title: "Backfilled first",
      cwd: "/tmp/binding-backfilled-first",
      lastActiveMs: 300,
      archived: false,
      entryRevision: 2
    )
    let backfill = RuntimeBackfillChunkV2.catalog(
      range: try RuntimeBackfillRangeV1(after: .at(4), through: .at(5)),
      deltas: [
        RuntimeCatalogDeltaV2(
          catalogRevision: 5,
          changes: [.upserted(entry: backfilledFirstEntry)]
        )
      ]
    )
    let wire = try LocalDaemonSourceFakeWire(
      conversationID: unaryConversationID,
      synchronizedReplies: [
        [
          .subscription(
            .subscribed(
              streamGeneration: RuntimeStreamGeneration(rawValue: "catalog-generation")
            )
          ),
          .catalog(firstPage),
          .catalog(secondPage),
          .backfill(backfill),
          .syncComplete(try localSourceCatalogSyncComplete(cursor: .at(5))),
        ]
      ]
    )
    let binding = SessionModel.makeFixtureBinding(runtimeWire: wire, machineID: machineID)
    let model = binding.model
    let source = binding.source
    defer { model.teardown() }

    model.loadHistory()
    XCTAssertTrue(model.isLoadingHistory)
    let historyLoaded = await localSourceEventually {
      await MainActor.run { !model.isLoadingHistory }
    }
    XCTAssertTrue(historyLoaded, "fixture binding did not finish the production history load")

    var sourceCatalog = await source.conversations(machineID: machineID).makeAsyncIterator()
    var sourceSummaries: [ConversationSummary] = []
    if let state = await sourceCatalog.next() {
      switch state {
      case .ready(let summaries, _):
        sourceSummaries = summaries
      case .loading:
        XCTFail("LocalDaemonSessionSource did not retain the subscribed Catalog projection")
      case .stale(let summaries, let reason):
        sourceSummaries = summaries
        XCTFail("LocalDaemonSessionSource unexpectedly published stale Catalog: \(reason)")
      case .failed(let failure, _):
        XCTFail("LocalDaemonSessionSource published an unexpected failure: \(failure)")
      }
    } else {
      XCTFail("LocalDaemonSessionSource Catalog stream ended before its ready projection")
    }

    let workbenchEntries = model.workbench.catalogEntries
    XCTAssertEqual(model.workbench.catalogCursor, .at(5))
    XCTAssertEqual(
      workbenchEntries.map(\.conversationID.rawValue),
      [firstConversationID.rawValue, secondConversationID.rawValue]
    )
    // source 只有在认证 terminal cursor 后才会发布 ready；这里再与 Workbench 的 .at(5)
    // projection 逐字段对齐，覆盖 production binding 两侧的同一 canonical barrier。
    XCTAssertEqual(
      sourceSummaries.map(\.id),
      workbenchEntries.map(\.conversationID.rawValue)
    )
    XCTAssertEqual(
      sourceSummaries.map(\.title),
      workbenchEntries.map { $0.title ?? $0.conversationID.rawValue }
    )
    XCTAssertEqual(sourceSummaries.map(\.cwd), workbenchEntries.map { $0.cwd ?? "" })
    XCTAssertEqual(sourceSummaries.map(\.revision), workbenchEntries.map(\.entryRevision))
    XCTAssertEqual(model.historyThreads.map(\.id), sourceSummaries.map(\.id))
    XCTAssertEqual(model.historyThreads.map(\.name), workbenchEntries.map(\.title))
    XCTAssertEqual(model.historyThreads.map(\.cwd), sourceSummaries.map(\.cwd))

    XCTAssertEqual(
      model.workbench.runtime(conversationID: firstConversationID)?.title,
      backfilledFirstEntry.title
    )
    XCTAssertEqual(
      model.workbench.runtime(conversationID: firstConversationID)?.cwd?.path,
      backfilledFirstEntry.cwd
    )
    XCTAssertEqual(
      model.workbench.runtime(conversationID: firstConversationID)?.entryRevision,
      backfilledFirstEntry.entryRevision
    )
    XCTAssertNil(model.workbench.catalogEntry(conversationID: unaryConversationID))
    XCTAssertNil(model.workbench.runtime(conversationID: unaryConversationID))
    XCTAssertFalse(model.historyThreads.contains { $0.id == unaryConversationID.rawValue })
    XCTAssertFalse(sourceSummaries.contains { $0.id == unaryConversationID.rawValue })
    XCTAssertNil(model.historyErrorMessage)
    XCTAssertNil(model.errorMessage)
    let fatalFailure = await source.debugFatalFailure()
    XCTAssertNil(fatalFailure)

    let requestKinds = await wire.requestKinds()
    XCTAssertEqual(requestKinds.filter { $0 == "describeAgents" }.count, 1)
    XCTAssertEqual(requestKinds.filter { $0 == "catalog" }.count, 1)
    XCTAssertEqual(requestKinds.filter { $0 == "subscribeCatalog" }.count, 1)
    XCTAssertEqual(requestKinds.filter { $0 == "other" }.count, 0)
    XCTAssertEqual(requestKinds.count, 3)
    let startCount = await wire.startCount()
    XCTAssertEqual(startCount, 1)
    let streamPumpIsWaiting = await localSourceEventually { await wire.streamWaiterActive() }
    XCTAssertTrue(streamPumpIsWaiting)
    let closeCountBeforeTeardown = await wire.closeCount()
    XCTAssertEqual(
      closeCountBeforeTeardown,
      0,
      "fixture wire closed before production teardown"
    )

    model.teardown()
    await source.shutdown()
    await source.join()
    let finalCloseCount = await wire.closeCount()
    let finalRequestKinds = await wire.requestKinds()
    XCTAssertEqual(finalCloseCount, 1)
    XCTAssertEqual(finalRequestKinds, requestKinds)
  }

  func testCancelledQueuedStartNeverReachesDaemon() async throws {
    let catalogGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      requestHook: { request in
        if case .catalog = request { await catalogGate.arriveAndWait() }
      }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )
    let catalog = Task { try await source.loadCatalog() }
    let catalogStarted = await localSourceEventually { await catalogGate.arrivalCount() == 1 }
    XCTAssertTrue(catalogStarted)

    let start = Task { try await source.startConversation(try localSourceConversationDraft()) }
    let queued = await localSourceEventually { await source.debugSynchronizationWaiterCount() == 1 }
    XCTAssertTrue(queued)
    start.cancel()
    let cancelledWaiterRemoved = await localSourceEventually {
      await source.debugSynchronizationWaiterCount() == 0
    }
    XCTAssertTrue(cancelledWaiterRemoved)

    await catalogGate.releaseAll()
    _ = try await catalog.value
    switch await start.result {
    case .success:
      XCTFail("cancelled queued Start reached the daemon")
    case .failure(let error):
      XCTAssertTrue(error is CancellationError)
    }
    let requestKinds = await wire.requestKinds()
    XCTAssertEqual(requestKinds.filter { $0 == "startConversation" }.count, 0)
    await source.shutdown()
  }

  func testCancellationAfterFIFOGrantReleasesNextWaiterWithoutDaemonRequest() async throws {
    let conversationB = RuntimeConversationID(rawValue: "conversation-granted-cancel")
    let conversationC = RuntimeConversationID(rawValue: "conversation-next-waiter")
    let catalogGate = LocalDaemonSourceGate()
    let postGrantGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationC)
      ],
      requestHook: { request in
        if case .catalog = request { await catalogGate.arriveAndWait() }
      }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      synchronizationPostGrantHook: { await postGrantGate.arriveAndWait() }
    )
    let catalog = Task { try await source.loadCatalog() }
    let catalogStarted = await localSourceEventually { await catalogGate.arrivalCount() == 1 }
    XCTAssertTrue(catalogStarted)
    let cancelled = Task {
      try await source.synchronizeConversation(
        conversationID: conversationB,
        cursor: .beforeFirst
      )
    }
    let next = Task {
      try await source.synchronizeConversation(
        conversationID: conversationC,
        cursor: .beforeFirst
      )
    }
    let bothQueued = await localSourceEventually {
      await source.debugSynchronizationWaiterCount() == 2
    }
    XCTAssertTrue(bothQueued)

    await catalogGate.releaseAll()
    _ = try await catalog.value
    let cancelledWasGranted = await localSourceEventually {
      await postGrantGate.arrivalCount() == 1
    }
    XCTAssertTrue(cancelledWasGranted)
    cancelled.cancel()
    await postGrantGate.releaseAll()

    switch await cancelled.result {
    case .success:
      XCTFail("cancelled granted waiter reached the daemon")
    case .failure(let error):
      XCTAssertTrue(error is CancellationError)
    }
    _ = try await next.value
    let requestKinds = await wire.requestKinds()
    XCTAssertEqual(requestKinds.filter { $0 == "subscribeConversation" }.count, 1)
    let gateActive = await source.debugSynchronizationTurnActive()
    let waiterCount = await source.debugSynchronizationWaiterCount()
    XCTAssertFalse(gateActive)
    XCTAssertEqual(waiterCount, 0)
    await source.shutdown()
  }

  func testRejectsBackfillThenSnapshotEvenWhenTerminalCursorMatches() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-backfill-before-snapshot")
    let replies: [RuntimeReplyV2] = [
      .subscription(
        .subscribed(
          streamGeneration: RuntimeStreamGeneration(rawValue: "conversation-generation")
        )
      ),
      .backfill(try localSourceConversationBackfill(conversationID: conversationID)),
      .snapshot(try localSourceSnapshot(conversationID: conversationID)),
      .syncComplete(
        try localSourceConversationSyncComplete(
          conversationID: conversationID,
          cursor: .at(0)
        )
      ),
    ]
    let wire = try LocalDaemonSourceFakeWire(synchronizedReplies: [replies])
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    do {
      _ = try await source.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("Backfill → Snapshot must fail closed")
    } catch let failure as SessionSourceFailure {
      XCTAssertEqual(failure.code, .securityError)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
    await source.shutdown()
  }

  func testFreshSubscribeBeforeFirstRequiresCapabilitiesSnapshot() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-missing-baseline")
    let replies: [RuntimeReplyV2] = [
      .subscription(
        .subscribed(
          streamGeneration: RuntimeStreamGeneration(rawValue: "conversation-generation")
        )
      ),
      .syncComplete(try localSourceConversationSyncComplete(conversationID: conversationID)),
    ]
    let wire = try LocalDaemonSourceFakeWire(synchronizedReplies: [replies])
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    do {
      _ = try await source.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("fresh Subscribe(BeforeFirst) must carry a capabilities snapshot")
    } catch let failure as SessionSourceFailure {
      XCTAssertEqual(failure.code, .securityError)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
    await source.shutdown()
  }

  func testConversationAdmissionReservesSameIDBeforeCrossActorAwait() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-admission")
    let admissionGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationID)
      ]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      conversationAdmissionHook: { await admissionGate.arriveAndWait() }
    )

    let firstOpen = Task { await source.conversation(conversationID: conversationID.rawValue) }
    let firstAdmissionArrived = await localSourceEventually {
      await admissionGate.arrivalCount() == 1
    }
    XCTAssertTrue(firstAdmissionArrived)

    var duplicate = await source.conversation(
      conversationID: conversationID.rawValue
    ).makeAsyncIterator()
    guard case .connectionState(.lagged(reason: .snapshotRequired)) = await duplicate.next() else {
      return XCTFail("same-ID concurrent open bypassed the admission reservation")
    }
    let duplicateTerminal = await duplicate.next()
    XCTAssertNil(duplicateTerminal)
    let ownerCount = await source.debugConversationOwnerCount()
    XCTAssertEqual(ownerCount, 1)

    await admissionGate.releaseAll()
    _ = await firstOpen.value
    await source.shutdown()
  }

  func testConversationAdmissionCapIncludesAllProvisionalOwnersAndShutdownInvalidatesThem()
    async throws
  {
    let admissionGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire()
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      conversationAdmissionHook: { await admissionGate.arriveAndWait() }
    )
    let opens = (0..<LocalDaemonSessionSource.maximumConversationObservations).map { index in
      Task { await source.conversation(conversationID: "admission-\(index)") }
    }
    let allAdmissionsArrived = await localSourceEventually {
      await admissionGate.arrivalCount()
        == LocalDaemonSessionSource.maximumConversationObservations
    }
    XCTAssertTrue(allAdmissionsArrived)
    let ownerCountAtCapacity = await source.debugConversationOwnerCount()
    XCTAssertEqual(
      ownerCountAtCapacity,
      LocalDaemonSessionSource.maximumConversationObservations
    )

    var overflow = await source.conversation(
      conversationID: "admission-overflow"
    ).makeAsyncIterator()
    guard case .connectionState(.lagged(reason: .snapshotRequired)) = await overflow.next() else {
      return XCTFail("65th provisional owner bypassed the global cap")
    }
    await source.shutdown()
    let ownerCountAfterShutdown = await source.debugConversationOwnerCount()
    XCTAssertEqual(ownerCountAfterShutdown, 0)

    await admissionGate.releaseAll()
    for open in opens {
      var stream = await open.value.makeAsyncIterator()
      guard case .connectionState(.machineOffline) = await stream.next() else {
        return XCTFail("admission resumed after shutdown")
      }
      let terminal = await stream.next()
      XCTAssertNil(terminal)
    }
    let finalOwnerCount = await source.debugConversationOwnerCount()
    XCTAssertEqual(finalOwnerCount, 0)
  }

  func testSameConversationReopenWaitsForExactRetirementWhileSiblingCanOpen() async throws {
    let conversationA = RuntimeConversationID(rawValue: "conversation-retirement-a")
    let conversationB = RuntimeConversationID(rawValue: "conversation-retirement-b")
    let unsubscribeGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      additionalUnaryReplies: [.subscription(.unsubscribed)],
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationA),
        try localSourceConversationSynchronizationReplies(conversationID: conversationB),
        try localSourceConversationSynchronizationReplies(conversationID: conversationA),
      ],
      requestHook: { request in
        if case .unsubscribe(.conversation) = request {
          await unsubscribeGate.arriveAndWait()
        }
      }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    let firstA = await source.conversation(conversationID: conversationA.rawValue)
    var firstAIterator = firstA.makeAsyncIterator()
    _ = await firstAIterator.next()
    _ = await firstAIterator.next()
    _ = await firstAIterator.next()
    let stalledRead = Task { await firstAIterator.next() }
    stalledRead.cancel()
    _ = await stalledRead.value
    let unsubscribeStarted = await localSourceEventually {
      await unsubscribeGate.arrivalCount() == 1
    }
    XCTAssertTrue(unsubscribeStarted)
    let retirementCount = await source.debugConversationRetirementCount()
    XCTAssertEqual(retirementCount, 1)

    let reopenedA = Task { await source.conversation(conversationID: conversationA.rawValue) }
    let reopenIsWaiting = await localSourceEventually {
      await source.debugConversationRetirementWaiterCount() == 1
    }
    XCTAssertTrue(reopenIsWaiting)

    let siblingB = await source.conversation(conversationID: conversationB.rawValue)
    var siblingBIterator = siblingB.makeAsyncIterator()
    _ = await siblingBIterator.next()
    _ = await siblingBIterator.next()
    _ = await siblingBIterator.next()
    let beforeACK = await wire.requestKinds()
    XCTAssertEqual(beforeACK.filter { $0 == "subscribeConversation" }.count, 2)

    await unsubscribeGate.releaseAll()
    let secondA = await reopenedA.value
    var secondAIterator = secondA.makeAsyncIterator()
    _ = await secondAIterator.next()
    _ = await secondAIterator.next()
    _ = await secondAIterator.next()
    let afterACK = await wire.requestKinds()
    XCTAssertEqual(afterACK.filter { $0 == "subscribeConversation" }.count, 3)
    let finalRetirementCount = await source.debugConversationRetirementCount()
    XCTAssertEqual(finalRetirementCount, 0)
    await source.shutdown()
  }

  func testConversationBackfillWithoutSubscribedEstablishesCapabilitiesBaseline() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-backfill-only")
    let wire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        [
          .backfill(try localSourceConversationBackfill(conversationID: conversationID)),
          .syncComplete(
            try localSourceConversationSyncComplete(
              conversationID: conversationID,
              cursor: .at(0)
            )
          ),
        ]
      ]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    _ = try await source.backfillConversation(
      conversationID: conversationID,
      after: .beforeFirst
    )
    let hasCapabilities = await source.debugConversationHasCapabilities(conversationID.rawValue)
    XCTAssertTrue(hasCapabilities)
    await source.shutdown()
  }

  func testConversationTerminalCursorMismatchFailsClosed() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-terminal-mismatch")
    let replies: [RuntimeReplyV2] = [
      .subscription(
        .subscribed(
          streamGeneration: RuntimeStreamGeneration(rawValue: "conversation-generation")
        )
      ),
      .snapshot(try localSourceSnapshot(conversationID: conversationID)),
      .syncComplete(
        try localSourceConversationSyncComplete(
          conversationID: conversationID,
          cursor: .at(0)
        )
      ),
    ]
    let wire = try LocalDaemonSourceFakeWire(synchronizedReplies: [replies])
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )

    do {
      _ = try await source.synchronizeConversation(
        conversationID: conversationID,
        cursor: .beforeFirst
      )
      XCTFail("terminal cursor mismatch must fail closed")
    } catch let failure as SessionSourceFailure {
      XCTAssertEqual(failure.code, .securityError)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
    await source.shutdown()
  }

  func testPairingListDoesNotOverwriteNewerLivePendingValue() async throws {
    let pairingID = RuntimePairingID(rawValue: "pairing-list-live-race")
    let listed = try RuntimePendingPairingV4(
      pairingID: pairingID,
      requestHash: Data(repeating: 0x31, count: 32),
      deviceSignFingerprint: Data(repeating: 0x41, count: 32),
      requestedAtMs: 1,
      expiresAtMs: 10
    )
    let live = try RuntimePendingPairingV4(
      pairingID: pairingID,
      requestHash: Data(repeating: 0x32, count: 32),
      deviceSignFingerprint: Data(repeating: 0x42, count: 32),
      requestedAtMs: 2,
      expiresAtMs: 11
    )
    let listGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      additionalUnaryReplies: [.pendingPairings([listed])],
      requestHook: { request in
        if case .listPendingPairings = request { await listGate.arriveAndWait() }
      }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )
    var pending = await source.pendingPairings().makeAsyncIterator()
    _ = await pending.next()
    let listStarted = await localSourceEventually { await listGate.arrivalCount() == 1 }
    XCTAssertTrue(listStarted)

    await wire.emit(.pairingPending(live))
    guard case .ready(let liveValues, _) = await pending.next() else {
      return XCTFail("live pairing update was not published while list was pending")
    }
    XCTAssertEqual(liveValues.first?.requestHash, live.requestHash)

    await listGate.releaseAll()
    guard case .ready(let mergedValues, _) = await pending.next() else {
      return XCTFail("pairing list merge did not publish")
    }
    XCTAssertEqual(mergedValues.count, 1)
    XCTAssertEqual(mergedValues.first?.requestHash, live.requestHash)
    await source.shutdown()
  }

  func testResolvedPairingTombstoneRejectsFrameReceivedBeforeReceiptButIngestedAfter()
    async throws
  {
    let pairingID = RuntimePairingID(rawValue: "pairing-late-after-receipt")
    let pendingValue = try RuntimePendingPairingV4(
      pairingID: pairingID,
      requestHash: Data(repeating: 0x51, count: 32),
      deviceSignFingerprint: Data(repeating: 0x61, count: 32),
      requestedAtMs: 10,
      expiresAtMs: 100
    )
    let inboundGate = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      additionalUnaryReplies: [
        .pendingPairings([pendingValue]),
        .pairing(.confirmed(pairingID)),
      ]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      inboundHandler: { inbound, _ in
        guard case .stream(let frame) = inbound,
          case .pairingPending = frame.item
        else { return }
        await inboundGate.arriveAndWait()
      }
    )

    var pending = await source.pendingPairings().makeAsyncIterator()
    _ = await pending.next()
    guard case .ready(let initial, _) = await pending.next() else {
      return XCTFail("pending pairing baseline was not published")
    }
    XCTAssertEqual(initial.map(\.pairingID), [pairingID])
    let pumpIsWaiting = await localSourceEventually { await wire.streamWaiterActive() }
    XCTAssertTrue(pumpIsWaiting)

    await wire.emit(.pairingPending(pendingValue))
    let frameReachedDownstream = await localSourceEventually {
      await inboundGate.arrivalCount() == 1
    }
    XCTAssertTrue(frameReachedDownstream)

    guard
      case .confirmed(let confirmedID) = try await source.confirmPairing(
        id: pairingID.rawValue
      )
    else {
      return XCTFail("confirm did not return the canonical terminal receipt")
    }
    XCTAssertEqual(confirmedID, pairingID)
    guard case .ready(let afterReceipt, _) = await pending.next() else {
      return XCTFail("terminal receipt did not remove the pending pairing")
    }
    XCTAssertTrue(afterReceipt.isEmpty)

    await inboundGate.releaseAll()
    let staleFrameWasConsumed = await localSourceEventually { await wire.streamWaiterActive() }
    XCTAssertTrue(staleFrameWasConsumed)
    let pendingCount = await source.debugPendingPairingCount()
    let tombstoneCount = await source.debugResolvedPairingTombstoneCount()
    XCTAssertEqual(pendingCount, 0)
    XCTAssertEqual(tombstoneCount, 1)
    await source.shutdown()
  }

  func testTransportFailureClearsAndFailsPendingPairingControlPlane() async throws {
    let pairingID = RuntimePairingID(rawValue: "pairing-transport-failure")
    let pendingValue = try RuntimePendingPairingV4(
      pairingID: pairingID,
      requestHash: Data(repeating: 0x71, count: 32),
      deviceSignFingerprint: Data(repeating: 0x72, count: 32),
      requestedAtMs: 10,
      expiresAtMs: 100
    )
    let wire = try LocalDaemonSourceFakeWire(
      additionalUnaryReplies: [.pendingPairings([pendingValue])]
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )
    var pending = await source.pendingPairings().makeAsyncIterator()
    _ = await pending.next()
    guard case .ready(let initial, _) = await pending.next() else {
      return XCTFail("pending pairing baseline was not published")
    }
    XCTAssertEqual(initial.map(\.pairingID), [pairingID])
    let pumpIsWaiting = await localSourceEventually { await wire.streamWaiterActive() }
    XCTAssertTrue(pumpIsWaiting)
    let failed = await wire.failStream()
    XCTAssertTrue(failed)

    guard case .failed(let failure, let retryable) = await pending.next() else {
      return XCTFail("transport failure left stale pending pairing controls visible")
    }
    XCTAssertEqual(failure.code, .transportUnavailable)
    XCTAssertTrue(retryable)
    let pendingCount = await source.debugPendingPairingCount()
    XCTAssertEqual(pendingCount, 0)
    await source.shutdown()
  }

  func testTransportFailureRetiresOldObservationAndColdOpensNewWire() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-reconnect")
    let firstWire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationID)
      ]
    )
    let secondWire = try LocalDaemonSourceFakeWire(
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationID)
      ]
    )
    let factory = LocalDaemonSourceWireFactory(wires: [firstWire, secondWire])
    let activations = LocalDaemonSourceGenerationRecorder()
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { try factory.make() },
      machineID: "installation-local",
      connectionActivation: { generation in
        await activations.append(generation)
      }
    )

    let first = await source.conversation(conversationID: conversationID.rawValue)
    var firstIterator = first.makeAsyncIterator()
    _ = await firstIterator.next()
    _ = await firstIterator.next()
    _ = await firstIterator.next()
    let firstLease = try await source.connectionLease()
    let pumpIsWaiting = await localSourceEventually { await firstWire.streamWaiterActive() }
    XCTAssertTrue(pumpIsWaiting)
    let failed = await firstWire.failStream()
    XCTAssertTrue(failed)
    guard case .connectionState(.reconnecting) = await firstIterator.next() else {
      return XCTFail("transport failure did not publish reconnecting")
    }
    let firstTerminal = await firstIterator.next()
    XCTAssertNil(firstTerminal)
    let oldOwnerRetired = await localSourceEventually {
      await source.debugConversationOwnerCount() == 0
    }
    XCTAssertTrue(oldOwnerRetired)

    let reopened = await source.conversation(conversationID: conversationID.rawValue)
    var reopenedIterator = reopened.makeAsyncIterator()
    guard case .connectionState(.connecting) = await reopenedIterator.next() else {
      return XCTFail("cold-open did not start connecting")
    }
    guard case .snapshot = await reopenedIterator.next() else {
      return XCTFail("cold-open did not publish a fresh snapshot")
    }
    guard case .connectionState(.connected) = await reopenedIterator.next() else {
      return XCTFail("cold-open did not reconnect")
    }
    let secondLease = try await source.connectionLease()
    XCTAssertNotEqual(firstLease, secondLease)
    let staleInvalidated = await source.invalidateConnection(
      firstLease,
      reason: .transportOrProtocolFault
    )
    XCTAssertFalse(
      staleInvalidated,
      "stale generation invalidated the replacement connection"
    )
    let replacementCloseCount = await secondWire.closeCount()
    let activationValues = await activations.values()
    XCTAssertEqual(replacementCloseCount, 0)
    XCTAssertEqual(factory.makeCount(), 2)
    XCTAssertEqual(activationValues, [1, 2])
    await source.shutdown()
  }

  func testLiveEventSequenceGapLatchesSecurityAndPreventsColdReconnect() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-event-gap")
    let wire = try LocalDaemonSourceFakeWire(
      conversationID: conversationID,
      synchronizedReplies: [
        try localSourceConversationSynchronizationReplies(conversationID: conversationID)
      ]
    )
    let replacement = try LocalDaemonSourceFakeWire(conversationID: conversationID)
    let factory = LocalDaemonSourceWireFactory(wires: [wire, replacement])
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { try factory.make() },
      machineID: "installation-local"
    )

    let stream = await source.conversation(conversationID: conversationID.rawValue)
    var conversation = stream.makeAsyncIterator()
    guard case .connectionState(.connecting) = await conversation.next() else {
      return XCTFail("conversation did not start connecting")
    }
    guard case .snapshot = await conversation.next() else {
      return XCTFail("conversation did not install its canonical snapshot")
    }
    guard case .connectionState(.connected) = await conversation.next() else {
      return XCTFail("conversation did not become connected")
    }
    let pumpIsWaiting = await localSourceEventually { await wire.streamWaiterActive() }
    XCTAssertTrue(pumpIsWaiting)

    await wire.emit(
      .event(
        try localSourceTurnStartedEvent(
          conversationID: conversationID,
          eventSequence: 1
        )
      )
    )
    guard case .connectionState(.securityError) = await conversation.next() else {
      return XCTFail("event-seq gap was downgraded to a reconnectable transport failure")
    }
    let terminal = await conversation.next()
    XCTAssertNil(terminal)
    let closed = await localSourceEventually { await wire.closeCount() == 1 }
    XCTAssertTrue(closed)

    do {
      _ = try await source.connectionLease()
      XCTFail("fatal security state cold-opened a replacement wire")
    } catch let failure as SessionSourceFailure {
      XCTAssertEqual(failure.code, .securityError)
    }
    let fatal = await source.debugFatalFailure()
    XCTAssertEqual(fatal?.code, .securityError)
    XCTAssertEqual(factory.makeCount(), 1)

    var machines = await source.machines().makeAsyncIterator()
    guard case .failed(let failure, let retryable) = await machines.next() else {
      return XCTFail("fatal security state was not durable for new observers")
    }
    XCTAssertEqual(failure.code, .securityError)
    XCTAssertFalse(retryable)
    _ = stream
    await source.shutdown()
  }

  func testConcurrentShutdownAndJoinWaitForExistingCloseBarrier() async throws {
    let closeGate = LocalDaemonSourceGate()
    let completion = LocalDaemonSourceGate()
    let wire = try LocalDaemonSourceFakeWire(
      closeHook: { await closeGate.arriveAndWait() }
    )
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local"
    )
    _ = try await source.describeAgents()
    let lease = try await source.connectionLease()
    let invalidation = Task { await source.invalidate(lease) }
    let closeStarted = await localSourceEventually { await closeGate.arrivalCount() == 1 }
    XCTAssertTrue(closeStarted)

    let shutdown = Task {
      await source.shutdown()
      await completion.arrive()
    }
    let join = Task {
      await source.join()
      await completion.arrive()
    }
    let bothAreWaiting = await localSourceEventually {
      let didShutdown = await source.debugDidShutdown()
      let waiterCount = await source.debugShutdownWaiterCount()
      return didShutdown && waiterCount == 1
    }
    XCTAssertTrue(bothAreWaiting)
    let completionBeforeRelease = await completion.arrivalCount()
    XCTAssertEqual(completionBeforeRelease, 0)

    await closeGate.releaseAll()
    await invalidation.value
    await shutdown.value
    await join.value
    let completionAfterRelease = await completion.arrivalCount()
    let closeCount = await wire.closeCount()
    XCTAssertEqual(completionAfterRelease, 2)
    XCTAssertEqual(closeCount, 1)
  }

  func testConversationOverflowClearsQueuedSuffixAndPublishesBufferDroppedFirst() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-overflow")
    let wire = try LocalDaemonSourceFakeWire(conversationID: conversationID)
    let source = LocalDaemonSessionSource(
      runtimeWireFactory: { wire },
      machineID: "installation-local",
      machineName: "This Mac"
    )

    var catalog = await source.conversations(machineID: "installation-local").makeAsyncIterator()
    _ = await catalog.next()
    _ = await catalog.next()
    let conversationStream = await source.conversation(
      conversationID: conversationID.rawValue
    )
    var conversation = conversationStream.makeAsyncIterator()
    _ = await conversation.next()
    _ = await conversation.next()
    _ = await conversation.next()

    for sequence in 0...LocalDaemonSessionSource.conversationBufferCapacity {
      await wire.emit(
        .event(
          try localSourceCapabilitiesEvent(
            conversationID: conversationID,
            eventSequence: UInt64(sequence)
          )
        )
      )
    }
    let retired = await localSourceEventually {
      await source.debugConversationObservationCount() == 0
    }
    XCTAssertTrue(retired, "overflowed observation did not retire")
    let overflowEvents = await source.debugConversationOverflowEvents()
    XCTAssertEqual(overflowEvents, 1, "observation retired before the bounded channel overflowed")

    let firstAfterOverflow = await conversation.next()
    guard case .connectionState(.lagged(reason: .bufferDropped)) = firstAfterOverflow else {
      switch firstAfterOverflow {
      case .event(let event):
        return XCTFail("overflow leaked queued event suffix at seq \(event.eventSeq)")
      case .connectionState(let state):
        return XCTFail("overflow published wrong connection state: \(state)")
      case .snapshot:
        return XCTFail("overflow leaked a stale snapshot")
      case .commandState:
        return XCTFail("overflow leaked a stale command state")
      case nil:
        return XCTFail("overflow finished before publishing bufferDropped")
      }
    }
    let terminal = await conversation.next()
    XCTAssertNil(terminal)
    _ = conversationStream
    await source.shutdown()
  }
}

private enum LocalDaemonSourceFakeError: Error {
  case unexpectedRequest
  case closed
}

private actor LocalDaemonSourceFakeWire: AppRuntimeWireSession {
  typealias RequestHook = @Sendable (RuntimeRequestV2) async -> Void
  typealias SynchronizedRequestHook = @Sendable (RuntimeRequestV2) async -> Void
  typealias CloseHook = @Sendable () async -> Void

  private let startFailure: RuntimeEnvelopeClientFailure?
  private let requestHook: RequestHook?
  private let synchronizedRequestHook: SynchronizedRequestHook?
  private let closeHook: CloseHook?
  private let catalogPage: RuntimeCatalogSnapshotV2
  private var unaryReplies: [RuntimeReplyV2]
  private var synchronizedReplies: [[RuntimeReplyV2]]
  private var starts = 0
  private var closes = 0
  private var requests: [String] = []
  private var streamFrames: [LocalRuntimeStreamFrame] = []
  private var streamWaiter: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var closed = false

  init(
    conversationID: RuntimeConversationID = RuntimeConversationID(
      rawValue: "conversation-local"
    ),
    startFailure: RuntimeEnvelopeClientFailure? = nil,
    additionalUnaryReplies: [RuntimeReplyV2] = [],
    synchronizedReplies customSynchronizedReplies: [[RuntimeReplyV2]]? = nil,
    requestHook: RequestHook? = nil,
    synchronizedRequestHook: SynchronizedRequestHook? = nil,
    closeHook: CloseHook? = nil
  ) throws {
    self.startFailure = startFailure
    self.requestHook = requestHook
    self.synchronizedRequestHook = synchronizedRequestHook
    self.closeHook = closeHook
    let entry = RuntimeConversationEntryV2(
      conversationID: conversationID,
      agentKind: .codex,
      title: "Local conversation",
      cwd: "/tmp/project",
      lastActiveMs: 10,
      archived: false,
      entryRevision: 1
    )
    unaryReplies = additionalUnaryReplies
    catalogPage = try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: .beforeFirst,
      entries: [entry],
      nextPageCursor: nil
    )
    let defaultSynchronizedReplies: [[RuntimeReplyV2]] = [
      [
        .subscription(
          .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "catalog-generation"))
        ),
        .syncComplete(try localSourceCatalogSyncComplete()),
      ],
      [
        .subscription(
          .subscribed(
            streamGeneration: RuntimeStreamGeneration(rawValue: "conversation-generation")
          )
        ),
        .snapshot(try localSourceSnapshot(conversationID: conversationID)),
        .syncComplete(try localSourceConversationSyncComplete(conversationID: conversationID)),
      ],
    ]
    synchronizedReplies = customSynchronizedReplies ?? defaultSynchronizedReplies
  }

  func start() async throws {
    starts += 1
    if let startFailure { throw startFailure }
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    requests.append(request.localSourceTestKind)
    await requestHook?(request)
    if case .describeAgents = request {
      return .agents(try RuntimeAgentDescriptionsV2(agents: []))
    }
    if case .catalog = request { return .catalog(catalogPage) }
    guard !unaryReplies.isEmpty else { throw LocalDaemonSourceFakeError.unexpectedRequest }
    return unaryReplies.removeFirst()
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    requests.append(request.localSourceTestKind)
    await synchronizedRequestHook?(request)
    guard !synchronizedReplies.isEmpty else {
      throw LocalDaemonSourceFakeError.unexpectedRequest
    }
    return LocalDaemonSourceFakeSequence(replies: synchronizedReplies.removeFirst())
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    if closed { throw LocalDaemonSourceFakeError.closed }
    if !streamFrames.isEmpty { return streamFrames.removeFirst() }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamWaiter == nil)
      streamWaiter = continuation
    }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    closes += 1
    streamWaiter?.resume(throwing: LocalDaemonSourceFakeError.closed)
    streamWaiter = nil
    await closeHook?()
  }

  func failStream() -> Bool {
    guard let streamWaiter else { return false }
    self.streamWaiter = nil
    streamWaiter.resume(
      throwing: RuntimeEnvelopeClientFailure(
        code: "daemon.client.connection_closed",
        message: "test local Runtime connection closed"
      )
    )
    return true
  }

  func emit(_ item: RuntimeStreamItemV2) {
    let frame = LocalRuntimeStreamFrame(
      messageID: RuntimeMessageID(rawValue: "stream-\(UUID().uuidString)"),
      item: item
    )
    if let streamWaiter {
      self.streamWaiter = nil
      streamWaiter.resume(returning: frame)
    } else {
      streamFrames.append(frame)
    }
  }

  func startCount() -> Int { starts }
  func closeCount() -> Int { closes }
  func requestKinds() -> [String] { requests }
  func streamWaiterActive() -> Bool { streamWaiter != nil }
}

private actor LocalDaemonSourceFakeSequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]

  init(replies: [RuntimeReplyV2]) {
    self.replies = replies
  }

  func next() async throws -> RuntimeReplyV2? {
    replies.isEmpty ? nil : replies.removeFirst()
  }

  func cancel() async {}
}

private actor LocalDaemonSourceGate {
  private var arrivals = 0
  private var released = false
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func arriveAndWait() async {
    arrivals += 1
    guard !released else { return }
    await withCheckedContinuation { continuation in
      releaseWaiters.append(continuation)
    }
  }

  func arrive() { arrivals += 1 }

  func arrivalCount() -> Int { arrivals }

  func releaseAll() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
  }
}

private actor LocalDaemonSourceGenerationRecorder {
  private var generations: [UInt64] = []

  func append(_ generation: UInt64) {
    generations.append(generation)
  }

  func values() -> [UInt64] { generations }
}

private final class LocalDaemonSourceWireFactory: @unchecked Sendable {
  private let lock = NSLock()
  private var wires: [any AppRuntimeWireSession]
  private var count = 0

  init(wires: [any AppRuntimeWireSession]) {
    self.wires = wires
  }

  func make() throws -> any AppRuntimeWireSession {
    lock.lock()
    defer { lock.unlock() }
    guard !wires.isEmpty else { throw LocalDaemonSourceFakeError.unexpectedRequest }
    count += 1
    return wires.removeFirst()
  }

  func makeCount() -> Int {
    lock.lock()
    defer { lock.unlock() }
    return count
  }
}

extension RuntimeRequestV2 {
  fileprivate var localSourceTestKind: String {
    switch self {
    case .describeAgents: "describeAgents"
    case .start: "startConversation"
    case .catalog: "catalog"
    case .subscribe(.catalog): "subscribeCatalog"
    case .subscribe(.conversation): "subscribeConversation"
    case .unsubscribe(.conversation): "unsubscribeConversation"
    case .listPendingPairings: "listPendingPairings"
    case .confirmPairing: "confirmPairing"
    default: "other"
    }
  }
}

private func localSourceCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  return try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
}

private func localSourceConversationDraft() throws -> RuntimeConversationDraft {
  try RuntimeConversationDraft(
    agentKind: .codex,
    cwd: "/tmp/project",
    prompt: nil,
    vendorOptions: .codex(
      CodexSessionOptions(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        persistApproval: false,
        reasoningEffort: .medium
      )
    ),
    idempotencyKeys: RuntimeConversationIdempotencyKeys(
      start: RuntimeIdempotencyKey(rawValue: "start:local-source"),
      configure: RuntimeIdempotencyKey(rawValue: "configure:local-source"),
      prompt: RuntimeIdempotencyKey(rawValue: "prompt:local-source")
    )
  )
}

private func localSourceSnapshot(
  conversationID: RuntimeConversationID
) throws -> ConversationSnapshotV2 {
  try ConversationSnapshotV2(
    conversationID: conversationID,
    baseEventCursor: .beforeFirst,
    configurationState: RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    ),
    items: [.capabilities(try localSourceCapabilities())]
  )
}

private func localSourceTurnStartedEvent(
  conversationID: RuntimeConversationID,
  eventSequence: UInt64
) throws -> RuntimeEventV2 {
  try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: "event-\(eventSequence)"),
    eventSeq: eventSequence,
    commandID: RuntimeCommandID(rawValue: "command-1"),
    itemID: nil,
    entityID: nil,
    body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-1"))
  )
}

private func localSourceConversationBackfill(
  conversationID: RuntimeConversationID
) throws -> RuntimeBackfillChunkV2 {
  .conversation(
    conversationID: conversationID,
    capabilitiesPreamble: try localSourceCapabilities(),
    range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
    events: [
      try localSourceTurnStartedEvent(conversationID: conversationID, eventSequence: 0)
    ]
  )
}

private func localSourceConversationSynchronizationReplies(
  conversationID: RuntimeConversationID
) throws -> [RuntimeReplyV2] {
  [
    .subscription(
      .subscribed(
        streamGeneration: RuntimeStreamGeneration(rawValue: "conversation-generation")
      )
    ),
    .snapshot(try localSourceSnapshot(conversationID: conversationID)),
    .syncComplete(try localSourceConversationSyncComplete(conversationID: conversationID)),
  ]
}

private func localSourceCapabilitiesEvent(
  conversationID: RuntimeConversationID,
  eventSequence: UInt64
) throws -> RuntimeEventV2 {
  try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: "capabilities-\(eventSequence)"),
    eventSeq: eventSequence,
    commandID: nil,
    itemID: nil,
    entityID: nil,
    body: .capabilities(try localSourceCapabilities())
  )
}

private func localSourceEventually(
  attempts: Int = 5_000,
  _ condition: @escaping @Sendable () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await condition() { return true }
    try? await Task.sleep(for: .milliseconds(1))
  }
  return false
}

private func localSourceCatalogSyncComplete(
  cursor: RuntimeStreamCursorV1 = .beforeFirst
) throws -> RuntimeSyncCompleteV1 {
  let cursorJSON: String
  switch cursor {
  case .beforeFirst:
    cursorJSON = #""beforeFirst""#
  case .at(let value):
    cursorJSON = #"{"at":\#(value)}"#
  }
  let payload =
    "{\"streamGeneration\":\"catalog-generation\",\"streamCursor\":{\"at\":0},"
    + "\"innerCursor\":{\"scope\":\"catalog\",\"cursor\":\(cursorJSON)},"
    + "\"keyDirectoryRevision\":0}"
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: Data(payload.utf8)
  )
}

private func localSourceConversationSyncComplete(
  conversationID: RuntimeConversationID,
  cursor: RuntimeStreamCursorV1 = .beforeFirst
) throws -> RuntimeSyncCompleteV1 {
  let cursorJSON: String
  switch cursor {
  case .beforeFirst:
    cursorJSON = #""beforeFirst""#
  case .at(let value):
    cursorJSON = #"{"at":\#(value)}"#
  }
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: Data(
      "{\"streamGeneration\":\"conversation-generation\",\"streamCursor\":{\"at\":0},\"innerCursor\":{\"scope\":\"conversation\",\"conversationId\":\"\(conversationID.rawValue)\",\"cursor\":\(cursorJSON)},\"keyDirectoryRevision\":0}"
        .utf8
    )
  )
}
