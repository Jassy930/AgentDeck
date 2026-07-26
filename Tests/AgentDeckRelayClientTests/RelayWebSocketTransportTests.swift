import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class RelayWebSocketTransportTests: XCTestCase {
  func testPublishedQueueLimitsDistinguishRegularReservesAndAggregateCaps() {
    XCTAssertEqual(RelayWebSocketTransport.maximumRegularIncomingFrames, 512)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumRegularIncomingBytes,
      16 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayWebSocketTransport.maximumUrgentIncomingFrames, 4)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumUrgentIncomingBytes,
      8 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayWebSocketTransport.maximumAggregateIncomingFrames, 516)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumAggregateIncomingBytes,
      24 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayWebSocketTransport.maximumApplicationWriterFrames, 512)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumApplicationWriterBytes,
      16 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayWebSocketTransport.maximumControlWriterFrames, 8)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumControlWriterBytes,
      1 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayWebSocketTransport.maximumAggregateWriterFrames, 520)
    XCTAssertEqual(
      RelayWebSocketTransport.maximumAggregateWriterBytes,
      17 * 1_024 * 1_024
    )
    XCTAssertEqual(RelayTransportLimits.production.incomingFrames, 512)
    XCTAssertEqual(RelayTransportLimits.production.urgentIncomingFrames, 4)
  }

  func testEndpointIsCanonicalWSSRootAndBuildsFixedRoute() throws {
    let principal = try RelayTransportEndpoint(
      origin: XCTUnwrap(URL(string: "wss://relay.example:8443/")),
      route: .principal
    )
    XCTAssertEqual(principal.webSocketURL.absoluteString, "wss://relay.example:8443/v2/connect")

    let pairing = try RelayTransportEndpoint(
      origin: XCTUnwrap(URL(string: "wss://relay.example")),
      route: .pairing
    )
    XCTAssertEqual(pairing.webSocketURL.absoluteString, "wss://relay.example/v2/pair")
    XCTAssertNoThrow(
      try RelayTransportEndpoint(
        origin: XCTUnwrap(URL(string: "wss://xn--xample-9ua.com/")),
        route: .principal
      )
    )
    XCTAssertNoThrow(
      try RelayTransportEndpoint(
        origin: XCTUnwrap(URL(string: "wss://[::1]/")),
        route: .principal
      )
    )

    for invalid in [
      "ws://relay.example",
      "https://relay.example",
      "wss://user@relay.example",
      "wss://relay.example/path",
      "wss://relay.example?query=1",
      "wss://relay.example#fragment",
      "wss://relay.example:0",
      "wss://relay.example:99999",
    ] {
      XCTAssertThrowsError(
        try RelayTransportEndpoint(
          origin: XCTUnwrap(URL(string: invalid)),
          route: .principal
        ),
        invalid
      )
    }
  }

  func testLifecycleSeparatesWebSocketCloseTaskCompletionAndSessionInvalidation() async {
    let lifecycle = RelayWebSocketLifecycle()
    await lifecycle.opened()
    await lifecycle.webSocketClosed()
    var readback = await lifecycle.debugReadback()
    XCTAssertTrue(readback.webSocketDidClose)
    XCTAssertNil(readback.taskCompleted)
    XCTAssertNil(readback.sessionInvalidated)

    await lifecycle.taskCompleted(openError: nil)
    let taskCompleted = await lifecycle.waitUntilTaskCompleted()
    XCTAssertTrue(taskCompleted)
    readback = await lifecycle.debugReadback()
    XCTAssertEqual(readback.taskCompleted, true)
    XCTAssertNil(readback.sessionInvalidated)

    await lifecycle.sessionBecameInvalid()
    let sessionInvalidated = await lifecycle.waitUntilSessionInvalidated()
    XCTAssertTrue(sessionInvalidated)
    readback = await lifecycle.debugReadback()
    XCTAssertEqual(readback.sessionInvalidated, true)

    let forced = RelayWebSocketLifecycle()
    await forced.opened()
    await forced.forceTerminated()
    let forcedTaskCompletion = await forced.waitUntilTaskCompleted()
    let forcedSessionInvalidation = await forced.waitUntilSessionInvalidated()
    XCTAssertFalse(forcedTaskCompletion)
    XCTAssertFalse(forcedSessionInvalidation)
    let confirmedInvalidation = Task {
      await forced.waitUntilSessionInvalidationConfirmed()
    }
    await forced.sessionBecameInvalid()
    await confirmedInvalidation.value
    let upgradedReadback = await forced.debugReadback()
    XCTAssertEqual(upgradedReadback.sessionInvalidated, true)
  }

  func testPinnedDelegatePublishesCloseCompletionAndInvalidationSeparately() throws {
    let recorder = DelegateCallbackRecorder()
    let delegate = PinnedURLSessionDelegate(
      expectedHost: "relay.example",
      policy: .publicCA,
      onClose: { code in recorder.record("close:\(code.rawValue)") },
      onComplete: { error in recorder.record(error == nil ? "complete" : "complete-error") },
      onInvalidation: { error in
        recorder.record(error == nil ? "invalidated" : "invalidated-error")
      }
    )
    let session = URLSession(configuration: .ephemeral)
    let task = session.webSocketTask(
      with: try XCTUnwrap(URL(string: "wss://relay.example/v2/connect"))
    )

    delegate.urlSession(
      session,
      webSocketTask: task,
      didCloseWith: .normalClosure,
      reason: nil
    )
    delegate.urlSession(session, task: task, didCompleteWithError: nil)
    delegate.urlSession(session, didBecomeInvalidWithError: nil)

    XCTAssertEqual(recorder.events, ["close:1000", "complete", "invalidated"])
    task.cancel()
    session.invalidateAndCancel()
  }

  func testConcurrentConnectSharesGenerationAndSendsFixedHelloFirst() async throws {
    let connection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(connections: [connection])
    let transport = try makeTransport(factory: factory)

    async let first = transport.connect()
    async let second = transport.connect()
    let generations = try await [first, second]

    XCTAssertEqual(generations[0], generations[1])
    let makeCount = await factory.makeCount
    XCTAssertEqual(makeCount, 1)
    let sent = await connection.sentFrames
    XCTAssertEqual(sent.count, 1)
    guard case .hello(let hello) = try RelayWireCodecV2.decode(sent[0]).body else {
      return XCTFail("transport must send Hello first")
    }
    XCTAssertEqual(hello.protocolVersion, relayProtocolVersionV2)

    do {
      try await transport.send(.hello(protocolVersion: 99), on: generations[0])
      XCTFail("callers cannot send a second or caller-selected Hello")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .handshakeFrameReserved)
    }
    await transport.shutdown()
  }

  func testCancelingEitherSharedConnectWaiterLeavesTheOtherOwnerAlive() async throws {
    for canceledIndex in 0..<2 {
      let connection = FakeRelayWebSocketConnection(blockStart: true)
      let factory = FakeRelayWebSocketConnectionFactory(connections: [connection])
      let transport = try makeTransport(factory: factory)
      let first = Task { try await transport.connect() }
      let startPending = await eventually { await connection.startIsPending }
      XCTAssertTrue(startPending, "canceled waiter \(canceledIndex)")
      let second = Task { try await transport.connect() }
      let bothRegistered = await eventually {
        await transport.debugConnectWaiterCount() == 2
      }
      XCTAssertTrue(bothRegistered, "canceled waiter \(canceledIndex)")

      let canceled = canceledIndex == 0 ? first : second
      let survivor = canceledIndex == 0 ? second : first
      canceled.cancel()
      do {
        _ = try await canceled.value
        XCTFail("canceled shared waiter must detach promptly")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .canceled)
      }
      let oneOwnerRemains = await transport.debugConnectWaiterCount()
      XCTAssertEqual(oneOwnerRemains, 1)
      let makeCount = await factory.makeCount
      XCTAssertEqual(makeCount, 1)
      let closesBeforeRelease = await connection.closeEvents
      XCTAssertTrue(closesBeforeRelease.isEmpty)

      await connection.releaseStart()
      let generation = try await survivor.value
      XCTAssertEqual(generation.rawValue, 1)
      let sentFrames = await connection.sentFrames
      XCTAssertEqual(sentFrames.count, 1)
      await transport.shutdown()
    }
  }

  func testConnectCancellationLatchWinsConcurrentLateStartAcrossRepeatedRuns() async throws {
    for iteration in 0..<64 {
      let connection = FakeRelayWebSocketConnection(blockStart: true)
      let transport = try makeTransport(
        factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
      )
      let connect = Task { try await transport.connect() }
      let readyToRace = await eventually {
        let startPending = await connection.startIsPending
        let waiterCount = await transport.debugConnectWaiterCount()
        return startPending && waiterCount == 1
      }
      XCTAssertTrue(readyToRace, "iteration \(iteration)")

      connect.cancel()
      await connection.releaseStart()
      do {
        _ = try await connect.value
        XCTFail("canceled waiter won a late success; iteration \(iteration)")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .canceled, "iteration \(iteration)")
      }
      await transport.shutdown()
      let noHello = await connection.sentFrames
      XCTAssertTrue(noHello.isEmpty, "iteration \(iteration)")
    }
  }

  func testFreshConnectNeverInheritsLastWaiterCancellation() async throws {
    let canceledConnection = FakeRelayWebSocketConnection(blockStart: true)
    let freshConnection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(
      connections: [canceledConnection, freshConnection]
    )
    let transport = try makeTransport(factory: factory)
    let canceled = Task { try await transport.connect() }
    let firstAttemptPending = await eventually { await canceledConnection.startIsPending }
    XCTAssertTrue(firstAttemptPending)

    canceled.cancel()
    let survivor = Task { try await transport.connect() }
    await canceledConnection.releaseStart()

    do {
      _ = try await canceled.value
      XCTFail("the canceled owner must detach")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .canceled)
    }
    let generation = try await survivor.value
    XCTAssertTrue(generation.rawValue == 1 || generation.rawValue == 2)
    await transport.shutdown()
  }

  func testHelloFailureWaitsForForcedInvalidationBeforeFreshGeneration() async throws {
    let failedConnection = HelloFailureForceConfirmationConnection()
    let freshConnection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(
      connections: [failedConnection, freshConnection]
    )
    let transport = try makeTransport(factory: factory)
    let first = Task { try await transport.connect() }
    let forceIsPending = await eventually { await failedConnection.forceCloseIsPending }
    XCTAssertTrue(forceIsPending)

    let joiningCaller = Task { try await transport.connect() }
    let bothWaitersRemainOnOneAttempt = await eventually {
      let waiterCount = await transport.debugConnectWaiterCount()
      let makeCount = await factory.makeCount
      return waiterCount == 2 && makeCount == 1
    }
    XCTAssertTrue(bothWaitersRemainOnOneAttempt)

    await failedConnection.confirmInvalidation()
    for waiter in [first, joiningCaller] {
      do {
        _ = try await waiter.value
        XCTFail("the failed Hello attempt must not install")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .connectionFailed)
      }
    }

    let freshGeneration = try await transport.connect()
    XCTAssertEqual(freshGeneration.rawValue, 2)
    let makeCount = await factory.makeCount
    XCTAssertEqual(makeCount, 2)
    await transport.shutdown()
  }

  func testIncomingPreservesGenerationDecodedFrameAndCanonicalBytesAndAutoPongs()
    async throws
  {
    let connection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    let ping = try RelayWireCodecV2.encode(.control(.ping(nonce: 42)))

    await connection.push(.data(ping))
    let pongArrived = await eventually { await connection.sentFrames.count == 2 }
    XCTAssertTrue(pongArrived)
    let delivered = try RelayWireCodecV2.encode(.control(.pong(nonce: 99)))
    await connection.push(.data(delivered))
    let nextReceived = try await iterator.next()
    let received = try XCTUnwrap(nextReceived)
    XCTAssertEqual(received.generation, generation)
    XCTAssertEqual(received.canonicalBytes, delivered)
    guard case .pong(let nonce) = received.frame.body else {
      return XCTFail("expected delivered Pong")
    }
    XCTAssertEqual(nonce, 99)

    let sent = await connection.sentFrames
    guard case .pong(let pongNonce) = try RelayWireCodecV2.decode(sent[1]).body else {
      return XCTFail("transport must prioritize Relay Pong")
    }
    XCTAssertEqual(pongNonce, 42)
    await transport.shutdown()
  }

  func testIncomingCanOnlyBeClaimedOncePerGeneration() async throws {
    let connection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    _ = await transport.incomingFrames(on: generation)
    let duplicate = await transport.incomingFrames(on: generation)
    var iterator = duplicate.makeAsyncIterator()

    do {
      _ = try await iterator.next()
      XCTFail("second consumer must fail")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .incomingAlreadyClaimed)
    }
    await transport.shutdown()
  }

  func testTextAndMalformedMessagesFailCurrentGenerationWithProtocolError()
    async throws
  {
    for message in [
      RelayWebSocketMessage.text("not-binary"),
      .data(Data("not-a-relay-frame".utf8)),
    ] {
      let connection = FakeRelayWebSocketConnection()
      let transport = try makeTransport(
        factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
      )
      let generation = try await transport.connect()
      let stream = await transport.incomingFrames(on: generation)
      var iterator = stream.makeAsyncIterator()

      await connection.push(message)
      let closed = await eventually { await connection.closeEvents.count == 1 }
      XCTAssertTrue(closed)
      do {
        _ = try await iterator.next()
        XCTFail("invalid WebSocket message must terminate the stream")
      } catch let error as RelayTransportError {
        if case .text = message {
          XCTAssertEqual(error, .textMessage)
        } else {
          XCTAssertEqual(error, .invalidFrame)
        }
      }
      let closeCode = await connection.closeEvents.last?.code
      XCTAssertEqual(closeCode, .protocolError)
    }
  }

  func testExactFourMiBFrameIsAcceptedAndPlusOneClosesWith1009() async throws {
    let exactConnection = FakeRelayWebSocketConnection()
    let exactTransport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [exactConnection])
    )
    let exactGeneration = try await exactTransport.connect()
    let exactStream = await exactTransport.incomingFrames(on: exactGeneration)
    var exactIterator = exactStream.makeAsyncIterator()
    let exact = try exactMaximumIncomingFrame()
    XCTAssertEqual(exact.count, RelayWireCodecV2.maxFrameBytes)

    await exactConnection.push(.data(exact))
    let exactReceived = try await exactIterator.next()
    XCTAssertEqual(exactReceived?.canonicalBytes.count, exact.count)
    await exactTransport.shutdown()

    let oversizedConnection = FakeRelayWebSocketConnection()
    let oversizedTransport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [oversizedConnection])
    )
    let oversizedGeneration = try await oversizedTransport.connect()
    let oversizedStream = await oversizedTransport.incomingFrames(on: oversizedGeneration)
    var oversizedIterator = oversizedStream.makeAsyncIterator()
    await oversizedConnection.push(
      .data(Data(repeating: 0, count: RelayWireCodecV2.maxFrameBytes + 1))
    )
    let oversizedClosed = await eventually {
      await oversizedConnection.closeEvents.count == 1
    }
    XCTAssertTrue(oversizedClosed)
    do {
      _ = try await oversizedIterator.next()
      XCTFail("4 MiB + 1 must fail before decode")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .frameTooLarge)
    }
    let oversizedCloseCode = await oversizedConnection.closeEvents.last?.code
    XCTAssertEqual(oversizedCloseCode, .messageTooBig)
  }

  func testIncomingFrameAndByteBudgetOverflowNeverSilentlyDrops() async throws {
    let connection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(connections: [connection])
    let limits = RelayTransportLimits(
      incomingFrames: 2,
      incomingBytes: 1_024,
      outgoingFrames: 8,
      outgoingBytes: 1_024,
      controlFrames: 2,
      controlBytes: 256,
      urgentIncomingFrames: 1,
      urgentIncomingBytes: 1_024
    )
    let transport = try makeTransport(factory: factory, limits: limits)
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    let frame = try RelayWireCodecV2.encode(.control(.pong(nonce: 1)))

    await connection.push(.data(frame))
    await connection.push(.data(frame))
    await connection.push(.data(frame))
    let closed = await eventually { await connection.closeEvents.count == 1 }
    XCTAssertTrue(closed)
    do {
      _ = try await iterator.next()
      XCTFail("overflow must discard queued frames and terminate")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .incomingBackpressure)
    }
    let closeCode = await connection.closeEvents.last?.code
    XCTAssertEqual(closeCode, .policyViolation)
  }

  func testWriterIsSerializedChargedUntilCompletionAndOverflowFailsGeneration()
    async throws
  {
    let connection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let limits = RelayTransportLimits(
      incomingFrames: 8,
      incomingBytes: 1_024,
      outgoingFrames: 2,
      outgoingBytes: 1_024,
      controlFrames: 2,
      controlBytes: 256,
      urgentIncomingFrames: 1,
      urgentIncomingBytes: 1_024
    )
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection]),
      limits: limits
    )
    let generation = try await transport.connect()

    let first = Task {
      try await transport.send(.control(.ping(nonce: 1)), on: generation)
    }
    let firstBlocked = await eventually { await connection.pendingSendCount == 1 }
    XCTAssertTrue(firstBlocked)
    let second = Task {
      try await transport.send(.control(.ping(nonce: 2)), on: generation)
    }
    let bothCharged = await eventually {
      let usage = await transport.debugOutgoingApplicationUsage()
      return usage.frames == 2
    }
    XCTAssertTrue(bothCharged)

    do {
      try await transport.send(.control(.ping(nonce: 3)), on: generation)
      XCTFail("third unflushed application frame must overflow")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .outgoingBackpressure)
    }
    let closed = await eventually { await connection.closeEvents.count == 1 }
    XCTAssertTrue(closed)
    let closeCode = await connection.closeEvents.last?.code
    XCTAssertEqual(closeCode, .policyViolation)

    await assertTaskFails(first, as: .outcomeUnknown)
    await assertTaskFails(second, as: .outgoingBackpressure)
    let usage = await transport.debugOutgoingApplicationUsage()
    XCTAssertEqual(usage.frames, 0)
    XCTAssertEqual(usage.bytes, 0)
  }

  func testBlockedWriterHitsAbsoluteDeadlineAndFailsCurrentGeneration() async throws {
    let sleeper = ManualRelayTransportSleeper()
    let connection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection]),
      sleeper: sleeper,
      deadlines: RelayTransportDeadlines(
        connectAttemptMilliseconds: 101,
        canceledAttemptCleanupMilliseconds: 5,
        outboundWriteMilliseconds: 7
      )
    )
    let generation = try await transport.connect()
    let send = Task {
      try await transport.send(.control(.ping(nonce: 1)), on: generation)
    }
    let writeIsBlocked = await eventually {
      let pendingSend = await connection.pendingSendCount == 1
      let deadlinePending = await sleeper.pendingMilliseconds.contains(7)
      return pendingSend && deadlinePending
    }
    XCTAssertTrue(writeIsBlocked)

    let fired = await sleeper.resumeFirst(milliseconds: 7)
    XCTAssertTrue(fired)
    await assertTaskFails(send, as: .outcomeUnknown)
    let closed = await eventually { await connection.closeEvents.count == 1 }
    XCTAssertTrue(closed)
    let usage = await transport.debugOutgoingApplicationUsage()
    XCTAssertEqual(usage.frames, 0)
    XCTAssertEqual(usage.bytes, 0)
  }

  func testLateWriterDeadlineCannotCloseFreshGenerationOrOutboundID() async throws {
    let sleeper = NonCooperativeRelayTransportSleeper()
    let firstConnection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let secondConnection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(
        connections: [firstConnection, secondConnection]
      ),
      sleeper: sleeper,
      deadlines: RelayTransportDeadlines(
        connectAttemptMilliseconds: 101,
        canceledAttemptCleanupMilliseconds: 5,
        outboundWriteMilliseconds: 7
      )
    )

    let firstGeneration = try await transport.connect()
    let firstSend = Task {
      try await transport.send(.control(.ping(nonce: 1)), on: firstGeneration)
    }
    let firstBlocked = await eventually {
      let pendingSend = await firstConnection.pendingSendCount == 1
      let deadlinePending = await sleeper.pendingMilliseconds.contains(7)
      return pendingSend && deadlinePending
    }
    XCTAssertTrue(firstBlocked)
    await firstConnection.releaseNextApplicationSend()
    try await firstSend.value
    try await transport.close(generation: firstGeneration)

    let secondGeneration = try await transport.connect()
    let secondSend = Task {
      try await transport.send(.control(.ping(nonce: 2)), on: secondGeneration)
    }
    let secondBlocked = await eventually {
      let pendingSend = await secondConnection.pendingSendCount == 1
      let pendingDeadlines = await sleeper.pendingMilliseconds.filter { $0 == 7 }.count
      return pendingSend && pendingDeadlines == 2
    }
    XCTAssertTrue(secondBlocked)

    let firedStaleDeadline = await sleeper.resumeFirst(milliseconds: 7)
    XCTAssertTrue(firedStaleDeadline)
    await Task.yield()
    let freshPendingCount = await secondConnection.pendingSendCount
    let freshCloseEvents = await secondConnection.closeEvents
    XCTAssertEqual(freshPendingCount, 1)
    XCTAssertTrue(freshCloseEvents.isEmpty)

    await secondConnection.releaseNextApplicationSend()
    try await secondSend.value
    await transport.shutdown()
    await sleeper.resumeAll()
  }

  func testControlReserveFrameAndByteBudgetsFailClosedIndependently() async throws {
    let autoPong = try RelayWireCodecV2.encode(.control(.pong(nonce: 1)))
    let scenarios: [(label: String, frames: Int, bytes: Int)] = [
      ("frame", 1, autoPong.count * 4),
      ("byte", 4, autoPong.count),
    ]

    for scenario in scenarios {
      let connection = FakeRelayWebSocketConnection(blockApplicationSends: true)
      let limits = RelayTransportLimits(
        incomingFrames: 8,
        incomingBytes: 1_024,
        outgoingFrames: 8,
        outgoingBytes: 1_024,
        controlFrames: scenario.frames,
        controlBytes: scenario.bytes,
        urgentIncomingFrames: 1,
        urgentIncomingBytes: 1_024
      )
      let transport = try makeTransport(
        factory: FakeRelayWebSocketConnectionFactory(connections: [connection]),
        limits: limits
      )
      let generation = try await transport.connect()
      let stream = await transport.incomingFrames(on: generation)
      var iterator = stream.makeAsyncIterator()
      let applicationInFlight = Task {
        try await transport.send(.control(.ping(nonce: 100)), on: generation)
      }
      let applicationBlocked = await eventually {
        await connection.pendingSendCount == 1
      }
      XCTAssertTrue(applicationBlocked, scenario.label)

      await connection.push(
        .data(try RelayWireCodecV2.encode(.control(.ping(nonce: 1))))
      )
      let controlReserved = await eventually {
        let usage = await transport.debugOutgoingControlUsage()
        return usage.frames == 1 && usage.bytes == autoPong.count
      }
      XCTAssertTrue(controlReserved, scenario.label)
      let applicationUsage = await transport.debugOutgoingApplicationUsage()
      XCTAssertEqual(applicationUsage.frames, 1, scenario.label)

      await connection.push(
        .data(try RelayWireCodecV2.encode(.control(.ping(nonce: 2))))
      )
      let closed = await eventually { await connection.closeEvents.count == 1 }
      XCTAssertTrue(closed, scenario.label)
      do {
        _ = try await iterator.next()
        XCTFail("\(scenario.label) control reserve overflow must terminate")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .outgoingBackpressure, scenario.label)
      }
      let closeCode = await connection.closeEvents.last?.code
      XCTAssertEqual(closeCode, .policyViolation, scenario.label)
      await assertTaskFails(applicationInFlight, as: .outcomeUnknown)
    }
  }

  func testServerRestartingIsDeliveredExactlyThenClosesGenerationWith1001()
    async throws
  {
    let connection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    let restarting = try RelayWireCodecV2.encode(
      .control(.serverRestarting(drainDeadlineMs: 50_000))
    )

    await connection.push(.data(restarting))
    let nextReceived = try await iterator.next()
    let received = try XCTUnwrap(nextReceived)
    XCTAssertEqual(received.canonicalBytes, restarting)
    guard case .serverRestarting(let deadline) = received.frame.body else {
      return XCTFail("expected ServerRestarting")
    }
    XCTAssertEqual(deadline, 50_000)
    do {
      _ = try await iterator.next()
      XCTFail("restart hint must terminate this authenticated generation")
    } catch let error as RelayTransportError {
      XCTAssertEqual(
        error,
        .serverRestarting(drainDeadlineMilliseconds: 50_000)
      )
    }
    let closeCode = await connection.closeEvents.last?.code
    XCTAssertEqual(closeCode, .goingAway)
  }

  func testTerminalFrameRemainsClaimableWhenPeerClosesBeforeConsumerStarts()
    async throws
  {
    let connection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    let restarting = try RelayWireCodecV2.encode(
      .control(.serverRestarting(drainDeadlineMs: 75_000))
    )

    await connection.push(.data(restarting))
    let closed = await eventually { await connection.closeEvents.count == 1 }
    XCTAssertTrue(closed)
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    let received = try await iterator.next()
    XCTAssertEqual(received?.canonicalBytes, restarting)
    do {
      _ = try await iterator.next()
      XCTFail("terminal queue must retain its typed close")
    } catch let error as RelayTransportError {
      XCTAssertEqual(
        error,
        .serverRestarting(drainDeadlineMilliseconds: 75_000)
      )
    }
  }

  func testGenerationScopedAPIsRejectStaleOwnerWithoutTouchingFreshSocket()
    async throws
  {
    let firstConnection = FakeRelayWebSocketConnection()
    let secondConnection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(
        connections: [firstConnection, secondConnection]
      )
    )
    let firstGeneration = try await transport.connect()
    try await transport.close(generation: firstGeneration)
    let secondGeneration = try await transport.connect()

    do {
      try await transport.send(
        .control(.ping(nonce: 1)),
        on: firstGeneration
      )
      XCTFail("stale owner must not send on a fresh generation")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .staleGeneration)
    }
    let staleStream = await transport.incomingFrames(on: firstGeneration)
    var staleIterator = staleStream.makeAsyncIterator()
    do {
      _ = try await staleIterator.next()
      XCTFail("stale owner must not claim the fresh incoming queue")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .staleGeneration)
    }
    do {
      try await transport.close(generation: firstGeneration)
      XCTFail("stale owner close must not report success")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .staleGeneration)
    }
    let untouchedSentFrames = await secondConnection.sentFrames
    let untouchedCloseEvents = await secondConnection.closeEvents
    XCTAssertEqual(untouchedSentFrames.count, 1)
    XCTAssertTrue(untouchedCloseEvents.isEmpty)

    try await transport.send(
      .control(.ping(nonce: 8)),
      on: secondGeneration
    )
    let freshSentFrames = await secondConnection.sentFrames
    XCTAssertEqual(freshSentFrames.count, 2)

    let freshStream = await transport.incomingFrames(on: secondGeneration)
    var freshIterator = freshStream.makeAsyncIterator()
    let frame = try RelayWireCodecV2.encode(.control(.pong(nonce: 9)))
    await secondConnection.push(.data(frame))
    let freshReceived = try await freshIterator.next()
    XCTAssertEqual(freshReceived?.canonicalBytes, frame)
    await transport.shutdown()
  }

  func testPeerCloseCodesArePreservedForSupervisorRetryClassification() async throws {
    let closeCodes: [UInt16] = [1_000, 1_001, 1_002, 1_008, 1_011, 1_012, 1_013]
    for code in closeCodes {
      let connection = FakeRelayWebSocketConnection()
      let transport = try makeTransport(
        factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
      )
      let generation = try await transport.connect()
      let stream = await transport.incomingFrames(on: generation)
      var iterator = stream.makeAsyncIterator()

      await connection.push(.close(code: code))
      do {
        _ = try await iterator.next()
        XCTFail("peer close \(code) must terminate the generation")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .peerClosed(code: code))
      }
      let closeReadBack = await eventually {
        await connection.closeEvents.count == 1
      }
      XCTAssertTrue(closeReadBack)
      let closeEvents = await connection.closeEvents
      XCTAssertEqual(closeEvents.count, 1)
      XCTAssertEqual(closeEvents.first?.code, .normalClosure)
    }
  }

  func testPeerClose1009MapsToFrameTooLarge() async throws {
    let connection = FakeRelayWebSocketConnection()
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()

    await connection.push(.close(code: 1_009))
    do {
      _ = try await iterator.next()
      XCTFail("1009 must use the local oversize classification")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .frameTooLarge)
    }
    let closeReadBack = await eventually {
      await connection.closeEvents.count == 1
    }
    XCTAssertTrue(closeReadBack)
    let closeEvents = await connection.closeEvents
    XCTAssertEqual(closeEvents.count, 1)
    XCTAssertEqual(closeEvents.first?.code, .normalClosure)
  }

  func testUrgentRestartSurvivesFullNormalQueueAndDiscardsOlderData() async throws {
    let connection = FakeRelayWebSocketConnection()
    let limits = RelayTransportLimits(
      incomingFrames: 1,
      incomingBytes: 256,
      outgoingFrames: 8,
      outgoingBytes: 1_024,
      controlFrames: 2,
      controlBytes: 256,
      urgentIncomingFrames: 1,
      urgentIncomingBytes: 1_024
    )
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection]),
      limits: limits
    )
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    await connection.push(
      .data(try RelayWireCodecV2.encode(.control(.pong(nonce: 1))))
    )
    let normalQueueIsFull = await eventually {
      await transport.debugIncomingQueueUsage(on: generation)?.regularFrames == 1
    }
    XCTAssertTrue(normalQueueIsFull)
    let restarting = try RelayWireCodecV2.encode(
      .control(.serverRestarting(drainDeadlineMs: 90_000))
    )
    await connection.push(.data(restarting))
    let restartWasProcessed = await eventually {
      await connection.closeEvents.count == 1
    }
    XCTAssertTrue(restartWasProcessed)

    let received = try await iterator.next()
    XCTAssertEqual(received?.canonicalBytes, restarting)
    do {
      _ = try await iterator.next()
      XCTFail("restart terminal must follow the urgent frame")
    } catch let error as RelayTransportError {
      XCTAssertEqual(
        error,
        .serverRestarting(drainDeadlineMilliseconds: 90_000)
      )
    }
  }

  func testUrgentIncomingFrameAndByteBudgetsFailClosedIndependently() async throws {
    let urgent = try RelayWireCodecV2.encode(
      .control(
        .pairRouteClosed(
          pairRoute: Data(repeating: 0x11, count: 16),
          outcome: .closed
        )
      )
    )
    let chargedBytes = urgent.count * 2
    let scenarios: [(label: String, frames: Int, bytes: Int)] = [
      ("frame", 1, chargedBytes * 4),
      ("byte", 4, chargedBytes),
    ]

    for scenario in scenarios {
      let connection = FakeRelayWebSocketConnection()
      let limits = RelayTransportLimits(
        incomingFrames: 8,
        incomingBytes: 1_024,
        outgoingFrames: 8,
        outgoingBytes: 1_024,
        controlFrames: 2,
        controlBytes: 256,
        urgentIncomingFrames: scenario.frames,
        urgentIncomingBytes: scenario.bytes
      )
      let transport = try makeTransport(
        factory: FakeRelayWebSocketConnectionFactory(connections: [connection]),
        limits: limits
      )
      let generation = try await transport.connect()
      let stream = await transport.incomingFrames(on: generation)
      var iterator = stream.makeAsyncIterator()

      await connection.push(.data(urgent))
      let firstUrgentReserved = await eventually {
        await transport.debugIncomingQueueUsage(on: generation)?.urgentFrames == 1
      }
      XCTAssertTrue(firstUrgentReserved, scenario.label)
      await connection.push(.data(urgent))

      let closed = await eventually { await connection.closeEvents.count == 1 }
      XCTAssertTrue(closed, scenario.label)
      do {
        _ = try await iterator.next()
        XCTFail("\(scenario.label) urgent reserve overflow must terminate")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .incomingBackpressure, scenario.label)
      }
      let closeCode = await connection.closeEvents.last?.code
      XCTAssertEqual(closeCode, .policyViolation, scenario.label)
    }
  }

  func testServerRestartingAbortsInFlightAndQueuedApplicationWrites() async throws {
    let connection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let transport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [connection])
    )
    let generation = try await transport.connect()
    let stream = await transport.incomingFrames(on: generation)
    var iterator = stream.makeAsyncIterator()
    let inFlight = Task {
      try await transport.send(.control(.ping(nonce: 1)), on: generation)
    }
    let blocked = await eventually { await connection.pendingSendCount == 1 }
    XCTAssertTrue(blocked)
    let queued = Task {
      try await transport.send(.control(.ping(nonce: 2)), on: generation)
    }
    let bothCharged = await eventually {
      await transport.debugOutgoingApplicationUsage().frames == 2
    }
    XCTAssertTrue(bothCharged)

    await connection.push(
      .data(
        try RelayWireCodecV2.encode(
          .control(.serverRestarting(drainDeadlineMs: 100_000))
        )
      )
    )
    _ = try await iterator.next()
    await assertTaskFails(inFlight, as: .outcomeUnknown)
    await assertTaskFails(
      queued,
      as: .serverRestarting(drainDeadlineMilliseconds: 100_000)
    )
  }

  func testByteBudgetsFailIndependentlyOfFrameBudgets() async throws {
    let inboundConnection = FakeRelayWebSocketConnection()
    let frame = try RelayWireCodecV2.encode(.control(.pong(nonce: 1)))
    let chargedFrameBytes = frame.count * 2
    let inboundLimits = RelayTransportLimits(
      incomingFrames: 10,
      incomingBytes: chargedFrameBytes * 2,
      outgoingFrames: 10,
      outgoingBytes: 1_024,
      controlFrames: 2,
      controlBytes: 256,
      urgentIncomingFrames: 1,
      urgentIncomingBytes: 1_024
    )
    let inboundTransport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [inboundConnection]),
      limits: inboundLimits
    )
    let inboundGeneration = try await inboundTransport.connect()
    let inboundStream = await inboundTransport.incomingFrames(on: inboundGeneration)
    var inboundIterator = inboundStream.makeAsyncIterator()
    await inboundConnection.push(.data(frame))
    await inboundConnection.push(.data(frame))
    await inboundConnection.push(.data(frame))
    let inboundClosed = await eventually { await inboundConnection.closeEvents.count == 1 }
    XCTAssertTrue(inboundClosed)
    do {
      _ = try await inboundIterator.next()
      XCTFail("incoming byte cap must fail below frame cap")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .incomingBackpressure)
    }

    let outboundConnection = FakeRelayWebSocketConnection(blockApplicationSends: true)
    let outgoingBytes = try RelayWireCodecV2.encode(.control(.ping(nonce: 1))).count
    let outboundLimits = RelayTransportLimits(
      incomingFrames: 10,
      incomingBytes: 1_024,
      outgoingFrames: 10,
      outgoingBytes: outgoingBytes * 2,
      controlFrames: 2,
      controlBytes: 256,
      urgentIncomingFrames: 1,
      urgentIncomingBytes: 1_024
    )
    let outboundTransport = try makeTransport(
      factory: FakeRelayWebSocketConnectionFactory(connections: [outboundConnection]),
      limits: outboundLimits
    )
    let outboundGeneration = try await outboundTransport.connect()
    let first = Task {
      try await outboundTransport.send(
        .control(.ping(nonce: 1)),
        on: outboundGeneration
      )
    }
    let firstBlocked = await eventually { await outboundConnection.pendingSendCount == 1 }
    XCTAssertTrue(firstBlocked)
    let second = Task {
      try await outboundTransport.send(
        .control(.ping(nonce: 2)),
        on: outboundGeneration
      )
    }
    let twoCharged = await eventually {
      await outboundTransport.debugOutgoingApplicationUsage().frames == 2
    }
    XCTAssertTrue(twoCharged)
    do {
      try await outboundTransport.send(
        .control(.ping(nonce: 3)),
        on: outboundGeneration
      )
      XCTFail("outgoing byte cap must fail below frame cap")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .outgoingBackpressure)
    }
    await assertTaskFails(first, as: .outcomeUnknown)
    await assertTaskFails(second, as: .outgoingBackpressure)
  }

  func testCloseIsIdempotentAndReconnectUsesFreshGenerationAndTask() async throws {
    let firstConnection = FakeRelayWebSocketConnection()
    let secondConnection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(
      connections: [firstConnection, secondConnection]
    )
    let transport = try makeTransport(factory: factory)

    let first = try await transport.connect()
    await transport.shutdown()
    await transport.shutdown()
    let second = try await transport.connect()

    XCTAssertNotEqual(first, second)
    let firstCloseCount = await firstConnection.closeEvents.count
    let secondSentCount = await secondConnection.sentFrames.count
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertEqual(secondSentCount, 1)
    await transport.shutdown()
  }

  func testCloseAndReconnectWaitForSocketTerminalReadback() async throws {
    let firstConnection = StagedCloseRelayWebSocketConnection()
    let secondConnection = FakeRelayWebSocketConnection()
    let factory = FakeRelayWebSocketConnectionFactory(
      connections: [firstConnection, secondConnection]
    )
    let transport = try makeTransport(factory: factory)
    let firstGeneration = try await transport.connect()

    let close = Task { try await transport.close(generation: firstGeneration) }
    let closeRequestIssued = await eventually {
      let requestIssued = await firstConnection.closeRequestCount == 1
      let isClosing = await transport.debugIsClosing()
      return requestIssued && isClosing
    }
    XCTAssertTrue(closeRequestIssued)
    let reconnect = Task { try await transport.connect() }
    await Task.yield()
    let makesBeforeReadback = await factory.makeCount
    XCTAssertEqual(makesBeforeReadback, 1)

    await firstConnection.reportWebSocketClose()
    await Task.yield()
    let makesAfterWebSocketClose = await factory.makeCount
    let invalidationBeforeTaskCompletion = await firstConnection.finishInvalidationRequestCount
    XCTAssertEqual(makesAfterWebSocketClose, 1)
    XCTAssertEqual(invalidationBeforeTaskCompletion, 0)

    await firstConnection.reportTaskCompletion()
    let invalidationRequested = await eventually {
      await firstConnection.finishInvalidationRequestCount == 1
    }
    XCTAssertTrue(invalidationRequested)
    let makesBeforeInvalidation = await factory.makeCount
    XCTAssertEqual(makesBeforeInvalidation, 1)

    await firstConnection.reportSessionInvalidation()
    try await close.value
    let secondGeneration = try await reconnect.value
    XCTAssertEqual(secondGeneration.rawValue, firstGeneration.rawValue + 1)
    let makesAfterReadback = await factory.makeCount
    XCTAssertEqual(makesAfterReadback, 2)
    await transport.shutdown()
  }

  func testCloseCleanupDeadlineForceClosesAndPoisonsTransport() async throws {
    let sleeper = ManualRelayTransportSleeper()
    let connection = FakeRelayWebSocketConnection(blockClose: true)
    let factory = FakeRelayWebSocketConnectionFactory(connections: [connection])
    let transport = try makeTransport(
      factory: factory,
      sleeper: sleeper,
      deadlines: RelayTransportDeadlines(
        connectAttemptMilliseconds: 101,
        canceledAttemptCleanupMilliseconds: 5,
        outboundWriteMilliseconds: 7
      )
    )
    let generation = try await transport.connect()
    let close = Task { try await transport.close(generation: generation) }
    let cleanupPending = await eventually {
      let requestIssued = await connection.closeEvents.count == 1
      let deadlinePending = await sleeper.pendingMilliseconds.contains(5)
      return requestIssued && deadlinePending
    }
    XCTAssertTrue(cleanupPending)
    let reconnect = Task { try await transport.connect() }

    let fired = await sleeper.resumeFirst(milliseconds: 5)
    XCTAssertTrue(fired)
    do {
      try await close.value
      XCTFail("close must report an unconfirmed terminal cleanup")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    do {
      _ = try await reconnect.value
      XCTFail("a stalled close must poison the transport")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    let forceCloseCount = await connection.forceCloseCount
    XCTAssertEqual(forceCloseCount, 1)
    let makeCount = await factory.makeCount
    XCTAssertEqual(makeCount, 1)
  }

  func testCanceledConnectCannotReuseGenerationOrInstallLateStaleSocket() async throws {
    for iteration in 0..<32 {
      let staleConnection = FakeRelayWebSocketConnection(blockStart: true)
      let freshConnection = FakeRelayWebSocketConnection()
      let factory = FakeRelayWebSocketConnectionFactory(
        connections: [staleConnection, freshConnection]
      )
      let transport = try makeTransport(factory: factory)

      let staleConnect = Task { try await transport.connect() }
      let staleStarted = await eventually { await staleConnection.startIsPending }
      XCTAssertTrue(staleStarted, "iteration \(iteration)")
      staleConnect.cancel()
      do {
        _ = try await staleConnect.value
        XCTFail("canceled stale connect must not install; iteration \(iteration)")
      } catch let error as RelayTransportError {
        XCTAssertEqual(error, .canceled, "iteration \(iteration)")
      }
      let freshConnect = Task { try await transport.connect() }
      await staleConnection.releaseStart()
      let freshGeneration = try await freshConnect.value
      XCTAssertEqual(freshGeneration.rawValue, 2, "iteration \(iteration)")
      let staleClosed = await eventually { await staleConnection.forceCloseCount == 1 }
      XCTAssertTrue(staleClosed, "iteration \(iteration)")
      let freshSentCount = await freshConnection.sentFrames.count
      XCTAssertEqual(freshSentCount, 1, "iteration \(iteration)")
      await transport.shutdown()
    }
  }

  func testConnectAttemptAndCleanupDeadlinesFailClosedWithoutLateInstall() async throws {
    let sleeper = ManualRelayTransportSleeper()
    let staleConnection = FakeRelayWebSocketConnection(blockStart: true)
    let factory = FakeRelayWebSocketConnectionFactory(connections: [staleConnection])
    let transport = try makeTransport(
      factory: factory,
      sleeper: sleeper,
      deadlines: RelayTransportDeadlines(
        connectAttemptMilliseconds: 100,
        canceledAttemptCleanupMilliseconds: 5
      )
    )
    let connect = Task { try await transport.connect() }
    let startPending = await eventually { await staleConnection.startIsPending }
    XCTAssertTrue(startPending)
    let attemptDeadlinePending = await eventually {
      await sleeper.pendingMilliseconds.contains(100)
    }
    XCTAssertTrue(attemptDeadlinePending)

    let firedAttemptDeadline = await sleeper.resumeFirst(milliseconds: 100)
    XCTAssertTrue(firedAttemptDeadline)
    do {
      _ = try await connect.value
      XCTFail("absolute connect deadline must fail the waiter")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionTimedOut)
    }
    let cleanupDeadlinePending = await eventually {
      await sleeper.pendingMilliseconds.contains(5)
    }
    XCTAssertTrue(cleanupDeadlinePending)

    let freshConnect = Task { try await transport.connect() }
    let firedCleanupDeadline = await sleeper.resumeFirst(milliseconds: 5)
    XCTAssertTrue(firedCleanupDeadline)
    do {
      _ = try await freshConnect.value
      XCTFail("stalled cleanup must poison this transport instance")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    await transport.shutdown()

    await staleConnection.releaseStart()
    let staleClosed = await eventually { await staleConnection.forceCloseCount == 1 }
    XCTAssertTrue(staleClosed)
    let staleSent = await staleConnection.sentFrames
    XCTAssertTrue(staleSent.isEmpty)
    do {
      _ = try await transport.connect()
      XCTFail("a poisoned transport must never create another attempt")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    let makeCount = await factory.makeCount
    XCTAssertEqual(makeCount, 1)
  }

  func testUnconfirmedForcedInvalidationPoisonsConnectCleanupWithoutNewSocket() async throws {
    let sleeper = ManualRelayTransportSleeper()
    let failedConnection = HelloFailureForceConfirmationConnection()
    let factory = FakeRelayWebSocketConnectionFactory(connections: [failedConnection])
    let transport = try makeTransport(
      factory: factory,
      sleeper: sleeper,
      deadlines: RelayTransportDeadlines(
        connectAttemptMilliseconds: 100,
        canceledAttemptCleanupMilliseconds: 5,
        outboundWriteMilliseconds: 7
      )
    )
    let first = Task { try await transport.connect() }
    let forceIsPending = await eventually { await failedConnection.forceCloseIsPending }
    XCTAssertTrue(forceIsPending)
    let attemptDeadlinePending = await eventually {
      await sleeper.pendingMilliseconds.contains(100)
    }
    XCTAssertTrue(attemptDeadlinePending)

    let firedAttemptDeadline = await sleeper.resumeFirst(milliseconds: 100)
    XCTAssertTrue(firedAttemptDeadline)
    do {
      _ = try await first.value
      XCTFail("the absolute connect deadline must win")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionTimedOut)
    }

    let reconnect = Task { try await transport.connect() }
    let cleanupDeadlinePending = await eventually {
      await sleeper.pendingMilliseconds.contains(5)
    }
    XCTAssertTrue(cleanupDeadlinePending)
    let firedCleanupDeadline = await sleeper.resumeFirst(milliseconds: 5)
    XCTAssertTrue(firedCleanupDeadline)
    do {
      _ = try await reconnect.value
      XCTFail("unconfirmed invalidation must poison the transport")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    let makeCountBeforeConfirmation = await factory.makeCount
    XCTAssertEqual(makeCountBeforeConfirmation, 1)

    await failedConnection.confirmInvalidation()
    let forceFinished = await eventually { !(await failedConnection.forceCloseIsPending) }
    XCTAssertTrue(forceFinished)
    do {
      _ = try await transport.connect()
      XCTFail("late invalidation confirmation must not unpoison the transport")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, .connectionCleanupStalled)
    }
    let finalMakeCount = await factory.makeCount
    XCTAssertEqual(finalMakeCount, 1)
  }

  func testReconnectPolicyIsDeterministicBoundedAndHonorsRestartDeadline() throws {
    let policy = RelayReconnectPolicy()
    XCTAssertEqual(policy.baseDelayMilliseconds(forAttempt: 0), 250)
    XCTAssertEqual(policy.baseDelayMilliseconds(forAttempt: 1), 500)
    XCTAssertEqual(policy.baseDelayMilliseconds(forAttempt: 20), 30_000)
    XCTAssertEqual(
      try policy.delayMilliseconds(
        forAttempt: 0,
        reason: .transportFailure,
        nowMilliseconds: 0,
        jitterUnitInterval: 0
      ),
      200
    )
    XCTAssertEqual(
      try policy.delayMilliseconds(
        forAttempt: 0,
        reason: .transportFailure,
        nowMilliseconds: 0,
        jitterUnitInterval: 1
      ),
      300
    )
    XCTAssertEqual(
      try policy.delayMilliseconds(
        forAttempt: 2,
        reason: .serverRestarting(drainDeadlineMilliseconds: 9_000),
        nowMilliseconds: 1_000,
        jitterUnitInterval: 0.5
      ),
      9_000
    )
    XCTAssertThrowsError(
      try policy.delayMilliseconds(
        forAttempt: 0,
        reason: .transportFailure,
        nowMilliseconds: 0,
        jitterUnitInterval: .nan
      )
    )
  }

  private func makeTransport(
    factory: FakeRelayWebSocketConnectionFactory,
    limits: RelayTransportLimits = .production,
    sleeper: any RelayTransportSleeper = ContinuousRelayTransportSleeper(),
    deadlines: RelayTransportDeadlines = .production
  ) throws -> RelayWebSocketTransport {
    let endpoint = try RelayTransportEndpoint(
      origin: XCTUnwrap(URL(string: "wss://relay.example")),
      route: .principal
    )
    return RelayWebSocketTransport(
      configuration: RelayTransportConfiguration(
        endpoint: endpoint,
        tlsPolicy: .publicCA
      ),
      factory: factory,
      limits: limits,
      sleeper: sleeper,
      deadlines: deadlines
    )
  }

  private func exactMaximumIncomingFrame() throws -> Data {
    let fixedBytes = 5 + 2 + 2 + 16 + 4
    return try RelayWireCodecV2.encodeFixture(
      RelayV2Frame(
        version: relayProtocolVersionV2,
        body: .pairData(
          pairRoute: Data(repeating: 0x11, count: 16),
          sealedBlob: Data(
            repeating: 0xA5,
            count: RelayWireCodecV2.maxFrameBytes - fixedBytes
          )
        )
      )
    )
  }

  private func assertTaskFails(
    _ task: Task<Void, any Error>,
    as expected: RelayTransportError
  ) async {
    do {
      try await task.value
      XCTFail("task should fail with \(expected)")
    } catch let error as RelayTransportError {
      XCTAssertEqual(error, expected)
    } catch {
      XCTFail("unexpected error: \(error)")
    }
  }
}

private actor FakeRelayWebSocketConnectionFactory: RelayWebSocketConnectionFactory {
  private var connections: [any RelayWebSocketConnection]
  private(set) var makeCount = 0

  init(connections: [any RelayWebSocketConnection]) {
    self.connections = connections
  }

  func makeConnection(
    endpoint: RelayTransportEndpoint,
    tlsPolicy: RelayTLSPolicy
  ) async throws -> any RelayWebSocketConnection {
    guard !connections.isEmpty else { throw RelayTransportError.connectionFailed }
    makeCount += 1
    return connections.removeFirst()
  }
}

private actor HelloFailureForceConfirmationConnection: RelayWebSocketConnection {
  private var invalidationConfirmed = false
  private var invalidationWaiter: CheckedContinuation<Void, Never>?
  private(set) var forceCloseIsPending = false

  func start() {}

  func send(data: Data) throws {
    throw RelayTransportError.connectionFailed
  }

  func receive() async throws -> RelayWebSocketMessage {
    throw RelayTransportError.connectionClosed
  }

  func close(code: URLSessionWebSocketTask.CloseCode, reason: Data?) async {}

  func forceClose() async {
    guard !invalidationConfirmed else { return }
    forceCloseIsPending = true
    await withCheckedContinuation { continuation in
      if invalidationConfirmed {
        forceCloseIsPending = false
        continuation.resume()
      } else {
        invalidationWaiter = continuation
      }
    }
  }

  func confirmInvalidation() {
    invalidationConfirmed = true
    forceCloseIsPending = false
    invalidationWaiter?.resume()
    invalidationWaiter = nil
  }
}

private actor StagedCloseRelayWebSocketConnection: RelayWebSocketConnection {
  private var started = false
  private var closed = false
  private var taskCompleted = false
  private var sessionInvalidated = false
  private var taskCompletionWaiters: [CheckedContinuation<Void, Never>] = []
  private var sessionInvalidationWaiters: [CheckedContinuation<Void, Never>] = []
  private var receiveWaiter: CheckedContinuation<RelayWebSocketMessage, any Error>?
  private(set) var closeRequestCount = 0
  private(set) var webSocketCloseReadbackCount = 0
  private(set) var finishInvalidationRequestCount = 0
  private(set) var sentFrames: [Data] = []

  func start() {
    started = true
  }

  func send(data: Data) throws {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    sentFrames.append(data)
  }

  func receive() async throws -> RelayWebSocketMessage {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    return try await withCheckedThrowingContinuation { continuation in
      receiveWaiter = continuation
    }
  }

  func close(code: URLSessionWebSocketTask.CloseCode, reason: Data?) async {
    if !closed {
      closed = true
      closeRequestCount += 1
      receiveWaiter?.resume(throwing: RelayTransportError.connectionClosed)
      receiveWaiter = nil
    }
    await waitForTaskCompletion()
    finishInvalidationRequestCount += 1
    await waitForSessionInvalidation()
  }

  func forceClose() {
    closed = true
    receiveWaiter?.resume(throwing: RelayTransportError.connectionClosed)
    receiveWaiter = nil
    reportTaskCompletion()
    reportSessionInvalidation()
  }

  func reportWebSocketClose() {
    webSocketCloseReadbackCount += 1
  }

  func reportTaskCompletion() {
    guard !taskCompleted else { return }
    taskCompleted = true
    let waiters = taskCompletionWaiters
    taskCompletionWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      continuation.resume()
    }
  }

  func reportSessionInvalidation() {
    guard !sessionInvalidated else { return }
    sessionInvalidated = true
    let waiters = sessionInvalidationWaiters
    sessionInvalidationWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      continuation.resume()
    }
  }

  private func waitForTaskCompletion() async {
    if taskCompleted { return }
    await withCheckedContinuation { continuation in
      if taskCompleted {
        continuation.resume()
      } else {
        taskCompletionWaiters.append(continuation)
      }
    }
  }

  private func waitForSessionInvalidation() async {
    if sessionInvalidated { return }
    await withCheckedContinuation { continuation in
      if sessionInvalidated {
        continuation.resume()
      } else {
        sessionInvalidationWaiters.append(continuation)
      }
    }
  }
}

private actor FakeRelayWebSocketConnection: RelayWebSocketConnection {
  struct CloseEvent: Sendable {
    let code: URLSessionWebSocketTask.CloseCode
    let reason: Data?
  }

  private struct SendWaiter {
    let continuation: CheckedContinuation<Void, any Error>
  }

  private let blockApplicationSends: Bool
  private let blockStart: Bool
  private let blockClose: Bool
  private var startWaiter: CheckedContinuation<Void, any Error>?
  private var closeWaiters: [CheckedContinuation<Void, Never>] = []
  private var closeReadbackReleased: Bool
  private var receiveBuffer: [RelayWebSocketMessage] = []
  private var receiveWaiter: CheckedContinuation<RelayWebSocketMessage, any Error>?
  private var sendWaiters: [SendWaiter] = []
  private(set) var sentFrames: [Data] = []
  private(set) var closeEvents: [CloseEvent] = []
  private(set) var forceCloseCount = 0
  private var started = false
  private var closed = false

  init(
    blockApplicationSends: Bool = false,
    blockStart: Bool = false,
    blockClose: Bool = false
  ) {
    self.blockApplicationSends = blockApplicationSends
    self.blockStart = blockStart
    self.blockClose = blockClose
    closeReadbackReleased = !blockClose
  }

  var pendingSendCount: Int { sendWaiters.count }
  var startIsPending: Bool { startWaiter != nil }

  func start() async throws {
    guard !closed else { throw RelayTransportError.connectionClosed }
    if blockStart {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        startWaiter = continuation
      }
    }
    started = true
  }

  func releaseStart() {
    startWaiter?.resume()
    startWaiter = nil
  }

  func send(data: Data) async throws {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    sentFrames.append(data)
    let decoded = try RelayWireCodecV2.decode(data)
    if case .hello = decoded.body { return }
    guard blockApplicationSends else { return }
    try await withCheckedThrowingContinuation { continuation in
      sendWaiters.append(SendWaiter(continuation: continuation))
    }
  }

  func releaseNextApplicationSend() {
    guard !sendWaiters.isEmpty else { return }
    let waiter = sendWaiters.removeFirst()
    waiter.continuation.resume()
  }

  func receive() async throws -> RelayWebSocketMessage {
    guard started, !closed else { throw RelayTransportError.connectionClosed }
    if !receiveBuffer.isEmpty { return receiveBuffer.removeFirst() }
    return try await withCheckedThrowingContinuation { continuation in
      receiveWaiter = continuation
    }
  }

  func close(code: URLSessionWebSocketTask.CloseCode, reason: Data?) async {
    if !closed {
      closed = true
      closeEvents.append(CloseEvent(code: code, reason: reason))
      terminatePendingIO()
    }
    guard blockClose, !closeReadbackReleased else { return }
    await withCheckedContinuation { continuation in
      if closeReadbackReleased {
        continuation.resume()
      } else {
        closeWaiters.append(continuation)
      }
    }
  }

  func forceClose() {
    forceCloseCount += 1
    if !closed {
      closed = true
      terminatePendingIO()
    }
    releaseCloseReadback()
  }

  func releaseCloseReadback() {
    guard !closeReadbackReleased else { return }
    closeReadbackReleased = true
    let waiters = closeWaiters
    closeWaiters.removeAll(keepingCapacity: false)
    for continuation in waiters {
      continuation.resume()
    }
  }

  func push(_ message: RelayWebSocketMessage) {
    if let receiveWaiter {
      self.receiveWaiter = nil
      receiveWaiter.resume(returning: message)
    } else {
      receiveBuffer.append(message)
    }
  }

  private func terminatePendingIO() {
    receiveWaiter?.resume(throwing: RelayTransportError.connectionClosed)
    receiveWaiter = nil
    for waiter in sendWaiters {
      waiter.continuation.resume(throwing: RelayTransportError.connectionClosed)
    }
    sendWaiters.removeAll()
  }
}

private actor ManualRelayTransportSleeper: RelayTransportSleeper {
  private struct Waiter {
    let id: UInt64
    let milliseconds: UInt64
    let continuation: CheckedContinuation<Void, any Error>
  }

  private var waiters: [Waiter] = []
  private var nextWaiterID: UInt64 = 1

  var pendingMilliseconds: [UInt64] {
    waiters.map(\.milliseconds)
  }

  func sleep(milliseconds: UInt64) async throws {
    let waiterID = nextWaiterID
    nextWaiterID = nextWaiterID == UInt64.max ? 1 : nextWaiterID + 1
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, any Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else {
          waiters.append(
            Waiter(
              id: waiterID,
              milliseconds: milliseconds,
              continuation: continuation
            )
          )
        }
      }
    } onCancel: {
      Task { await self.cancel(id: waiterID) }
    }
  }

  func resumeFirst(milliseconds: UInt64) -> Bool {
    guard let index = waiters.firstIndex(where: { $0.milliseconds == milliseconds }) else {
      return false
    }
    let waiter = waiters.remove(at: index)
    waiter.continuation.resume()
    return true
  }

  private func cancel(id: UInt64) {
    guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
    let waiter = waiters.remove(at: index)
    waiter.continuation.resume(throwing: CancellationError())
  }
}

/// 模拟底层 deadline wait 已经越过取消点：取消 Task 不会移除 waiter，迟到 callback
/// 仍会执行，用于确定性验证 generation + outbound ID fencing。
private actor NonCooperativeRelayTransportSleeper: RelayTransportSleeper {
  private struct Waiter {
    let milliseconds: UInt64
    let continuation: CheckedContinuation<Void, Never>
  }

  private var waiters: [Waiter] = []

  var pendingMilliseconds: [UInt64] {
    waiters.map(\.milliseconds)
  }

  func sleep(milliseconds: UInt64) async throws {
    await withCheckedContinuation { continuation in
      waiters.append(
        Waiter(
          milliseconds: milliseconds,
          continuation: continuation
        )
      )
    }
  }

  func resumeFirst(milliseconds: UInt64) -> Bool {
    guard let index = waiters.firstIndex(where: { $0.milliseconds == milliseconds }) else {
      return false
    }
    let waiter = waiters.remove(at: index)
    waiter.continuation.resume()
    return true
  }

  func resumeAll() {
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for waiter in pending {
      waiter.continuation.resume()
    }
  }
}

private final class DelegateCallbackRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [String] = []

  var events: [String] {
    lock.withLock { storage }
  }

  func record(_ event: String) {
    lock.withLock {
      storage.append(event)
    }
  }
}

private func eventually(
  attempts: Int = 10_000,
  _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await predicate() { return true }
    await Task.yield()
  }
  return false
}
