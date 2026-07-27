import AgentDeckCore
import AgentDeckSessionSource
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class MachineConnectionTests: XCTestCase {
  func testSupervisorIngressSurfaceOnlyReturnsVerifiedOrTypedOutcomes() {
    requireSendable(MachineConnectionVerifiedIngressOutcome.self)
    requireSendable(MachineConnectionSupervisorFailure.self)
  }

  func testSupervisorAuthenticatesFreshChallengeBeforeResumeAndVerifiedDelivery() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 1)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0x91, count: 16))
          )
        ),
      ]
    )
    let delivery = supervisorDelivery(machineID: "machine-supervisor")
    let resume = RelayV2OutboundFrame.control(
      .subscribe(
        streamRoute: Data(repeating: 0x81, count: 16),
        generation: Data(repeating: 0x82, count: 16),
        cursor: .beforeFirst
      )
    )
    let ingress = SupervisorIngress(
      resumeFrames: [resume],
      outcomes: [.delivery(delivery)]
    )
    let budget = TransferAssemblyBudgetCoordinator()
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    guard case .delivery(let received)? = await iterator.next() else {
      await connection.shutdown()
      return XCTFail("verified ingress delivery must reach Source channel")
    }
    XCTAssertEqual(received.machineID, "machine-supervisor")

    let sent = await transport.sentFrames
    XCTAssertEqual(sent.count, 2, "Authenticate must precede the single resume frame")
    guard case .authenticate(let proof, let signature) = sent[0].body else {
      await connection.shutdown()
      return XCTFail("first owner write must be Authenticate")
    }
    XCTAssertEqual(proof, .device(relayGrant: fixture.grant))
    let challenge = try RelayDeviceAuthenticationChallenge(
      relayServerID: fixture.relayServerID,
      connectionInstance: fixture.connectionInstance,
      challengeNonce: fixture.challengeNonce
    )
    XCTAssertTrue(
      fixture.deviceSigningKey.publicKey.isValidSignature(
        signature,
        for: try AuthenticationTranscriptV1.encode(
          challenge: challenge,
          grant: fixture.grant
        )
      ),
      "Authenticate must sign the complete Rust-compatible transcript"
    )
    guard case .subscribe = sent[1].body else {
      await connection.shutdown()
      return XCTFail("resume frame must be sent only after Authenticated")
    }
    let heartbeatIntervals = await ingress.heartbeatIntervals
    XCTAssertEqual(heartbeatIntervals, [17])

    await connection.shutdown()
    let endedScopeCount = await ingress.endedScopes.count
    XCTAssertEqual(endedScopeCount, 1)
    XCTAssertEqual(budget.usage, .zero)
  }

  func testRuntimeEndpointSendsOnExactGenerationAndAwaitsDirectedReply() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 301)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
      ]
    )
    let ingress = EndpointSupervisorIngress()
    let connection = MachineConnection(
      machineID: "machine-endpoint",
      grantSerial: 41,
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    let grantSerial = try await connection.expectedGrantSerial()
    XCTAssertEqual(grantSerial, 41)

    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "endpoint-directed"),
      body: .request(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
    )
    let request = Task {
      try await connection.sendDirectedRequest(
        envelope,
        contract: .command(expectedConfigurationRevision: 1)
      )
    }
    let requestWasSent = await eventuallyMachineConnectionTest {
      let sentCount = await transport.sentFrames.count
      let pendingCount = await ingress.pendingDirectedCount
      return sentCount == 2 && pendingCount == 1
    }
    XCTAssertTrue(requestWasSent)
    await ingress.completeDirected(
      .command(
        .replayed(
          commandID: RuntimeCommandID(rawValue: "endpoint-command"),
          configurationRevision: 1
        )
      )
    )
    guard case .command(.replayed(let commandID, let revision)) = try await request.value else {
      await connection.shutdown()
      return XCTFail("directed waiter must return the exact correlated reply")
    }
    XCTAssertEqual(commandID.rawValue, "endpoint-command")
    XCTAssertEqual(revision, 1)
    let cancelCount = await ingress.cancelCount
    XCTAssertEqual(cancelCount, 0)
    await connection.shutdown()
  }

  func testRuntimeEndpointSendFailureCancelsExactPreparedOwner() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 302)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
      ],
      failSendAtIndex: 1
    )
    let ingress = EndpointSupervisorIngress()
    let connection = MachineConnection(
      machineID: "machine-endpoint",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)

    do {
      _ = try await connection.sendDirectedRequest(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "endpoint-send-failure"),
          body: .request(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
        ),
        contract: .command(expectedConfigurationRevision: 1)
      )
      XCTFail("outcome-unknown send must fail typed")
    } catch let error as SessionSourceFailure {
      XCTAssertEqual(error.code, .transportUnavailable)
    }
    let cancelCount = await ingress.cancelCount
    let pendingCount = await ingress.pendingDirectedCount
    XCTAssertEqual(cancelCount, 1)
    XCTAssertEqual(pendingCount, 0)
    await connection.shutdown()
  }

  func testEndSubscriptionWaitsForRuntimeReceiptThenSendsExactOuterUnsubscribe() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 304)
    let streamRoute = Data(repeating: 0xC4, count: 16)
    let streamGeneration = Data(repeating: 0xC5, count: 16)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: generation
      )
    )
    let ingress = EndpointSupervisorIngress(
      retirement: MachineSubscriptionRetirement(
        outerUnsubscribe: .control(
          .unsubscribe(
            streamRoute: streamRoute,
            generation: streamGeneration
          )
        ),
        requiresGenerationRollover: false
      )
    )
    let connection = MachineConnection(
      machineID: "machine-unsubscribe",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)

    let target = RuntimeSubscriptionTargetV1.conversation(
      conversationID: RuntimeConversationID(rawValue: "conversation-unsubscribe")
    )
    let unsubscribe = Task {
      try await connection.endSubscription(
        target: target,
        requestID: RuntimeMessageID(rawValue: "unsubscribe-runtime-request")
      )
    }
    let runtimeRequestSent = await eventuallyMachineConnectionTest {
      let pendingCount = await ingress.pendingDirectedCount
      let sentCount = await transport.sentFrames.count
      return pendingCount == 1 && sentCount == 2
    }
    XCTAssertTrue(runtimeRequestSent)
    await ingress.completeDirected(.subscription(.unsubscribed))
    try await unsubscribe.value

    let sent = await transport.sentFrames
    XCTAssertEqual(sent.count, 3)
    guard case .unsubscribe(let sentRoute, let sentGeneration) = sent[2].body else {
      await connection.shutdown()
      return XCTFail("Runtime Unsubscribed 后必须发送 exact Relay outer Unsubscribe")
    }
    XCTAssertEqual(sentRoute, streamRoute)
    XCTAssertEqual(sentGeneration, streamGeneration)
    let contracts = await ingress.preparedContracts
    XCTAssertEqual(contracts, [.unsubscribe])
    let retiredTargets = await ingress.retiredTargetCount
    XCTAssertEqual(retiredTargets, 1)
    await connection.shutdown()
  }

  func testVerifiedIngressTransportActionsPreserveExactOrder() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 303)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0xA7, count: 16))
          )
        ),
      ]
    )
    let ingress = EndpointSupervisorIngress(
      outcomes: [
        .transportActions([
          .control(.ping(nonce: 701)),
          .control(.ping(nonce: 702)),
        ])
      ]
    )
    let connection = MachineConnection(
      machineID: "machine-actions",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    let actionsWereSent = await eventuallyMachineConnectionTest {
      let sentCount = await transport.sentFrames.count
      return sentCount == 3
    }
    XCTAssertTrue(actionsWereSent)
    let sent = await transport.sentFrames
    guard case .ping(let first) = sent[1].body,
      case .ping(let second) = sent[2].body
    else {
      await connection.shutdown()
      return XCTFail("verified actions must stay ordered on the active generation")
    }
    XCTAssertEqual([first, second], [701, 702])
    await connection.shutdown()
  }

  func testSupervisorWaitsForExactSourceCommitBeforeReadingNextFrame() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 2)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0x92, count: 16))
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0x93, count: 16))
          )
        ),
      ]
    )
    let first = supervisorPreparedDelivery(machineID: "machine-supervisor")
    let second = supervisorDelivery(machineID: "machine-supervisor")
    let ingress = SupervisorIngress(
      outcomes: [.delivery(first), .delivery(second)],
      blocksPreparedResolution: true
    )
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    guard case .delivery(let receivedFirst)? = await iterator.next() else {
      return XCTFail("first prepared delivery must reach Source")
    }

    let blocked = await eventuallyMachineConnectionTest {
      let pending = await ingress.pendingResolutionCount
      let received = await ingress.receivedFrameCount
      return pending == 1 && received == 1
    }
    XCTAssertTrue(blocked, "next frame must not pass unresolved durable cut")

    try await connection.commit(receivedFirst)
    guard case .delivery(let receivedSecond)? = await iterator.next() else {
      return XCTFail("exact commit 后 supervisor 才能读取下一帧")
    }
    XCTAssertNil(receivedSecond.ingressPermit)
    let processed = await ingress.receivedFrameCount
    XCTAssertEqual(processed, 2)
    await connection.shutdown()
  }

  func testShutdownEndsGenerationAndUnblocksUnresolvedDeliveryPermit() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 200)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        supervisorFrame(
          generation: generation,
          body: .authenticated(heartbeatIntervalSecs: 17)
        ),
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0xA2, count: 16))
          )
        ),
      ]
    )
    let ingress = SupervisorIngress(
      outcomes: [.delivery(supervisorPreparedDelivery(machineID: "machine-supervisor"))],
      blocksPreparedResolution: true
    )
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    guard case .delivery? = await iterator.next() else {
      return XCTFail("prepared delivery must reach Source before shutdown")
    }
    let waiterInstalled = await eventuallyMachineConnectionTest {
      await ingress.pendingResolutionCount == 1
    }
    XCTAssertTrue(waiterInstalled)

    let completion = ShutdownCompletionProbe()
    let shutdownTask = Task {
      await connection.shutdown()
      await completion.markCompleted()
    }
    let completed = await eventuallyMachineConnectionTest {
      await completion.isCompleted
    }
    if !completed { shutdownTask.cancel() }
    XCTAssertTrue(completed, "generationEnded 必须解除 awaitResolution，shutdown 不得永久 join")
    let pendingResolutionCount = await ingress.pendingResolutionCount
    let endedScopeCount = await ingress.endedScopes.count
    XCTAssertEqual(pendingResolutionCount, 0)
    XCTAssertEqual(endedScopeCount, 1)
  }

  func testShutdownClosesUpdateChannelBeforeJoiningBackpressuredSupervisor() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 202)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: generation
      )
    )
    let budget = TransferAssemblyBudgetCoordinator()
    let ingress = SupervisorIngress(
      reserveBudgetOnResume: true,
      budgetCoordinator: budget
    )
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    XCTAssertNotEqual(budget.usage, .zero)

    for _ in 0..<512 {
      await connection.handle(.relayUnavailable)
    }
    await transport.finishIncoming(throwing: .connectionClosed)
    let supervisorIsBackpressured = await eventuallyMachineConnectionTest {
      await connection.debugPendingUpdateSendCount() == 1
    }
    XCTAssertTrue(
      supervisorIsBackpressured,
      "the supervisor must own the single pending send behind the full 512-element queue"
    )

    let completion = ShutdownCompletionProbe()
    let shutdownTask = Task {
      await connection.shutdown()
      await completion.markCompleted()
    }
    let completedWithoutConsumerDrain = await eventuallyMachineConnectionTest {
      await completion.isCompleted
    }
    XCTAssertTrue(
      completedWithoutConsumerDrain,
      "shutdown must close the channel before joining a backpressured supervisor"
    )

    var drainedStates: [SessionConnectionState] = []
    if !completedWithoutConsumerDrain {
      if let state = await iterator.next()?.connectionState {
        drainedStates.append(state)
      }
      let cleanupCompleted = await eventuallyMachineConnectionTest {
        await completion.isCompleted
      }
      XCTAssertTrue(cleanupCompleted, "red-test cleanup must release the old ordering")
    }
    await shutdownTask.value

    let pendingSendCount = await connection.debugPendingUpdateSendCount()
    let endedScopeCount = await ingress.endedScopes.count
    XCTAssertEqual(pendingSendCount, 0)
    XCTAssertEqual(endedScopeCount, 1)
    XCTAssertEqual(budget.usage, .zero)

    while let update = await iterator.next() {
      guard let state = update.connectionState else {
        return XCTFail("the saturated queue must contain only connection states")
      }
      drainedStates.append(state)
    }
    XCTAssertEqual(drainedStates.count, 512, "finish must preserve the full queued prefix")
    XCTAssertTrue(
      drainedStates.allSatisfy { $0 == .relayUnavailable },
      "finish must not admit the pending supervisor update"
    )
  }

  func testDiscardBeforeAwaitResolutionIsATerminalTombstone() async throws {
    let generation = RelayTransportGeneration(rawValue: 201)
    let scope = TransferAssemblyScope(connectionID: UUID(), generation: generation)
    let ingress = SupervisorIngress(
      outcomes: [.delivery(supervisorPreparedDelivery(machineID: "machine-supervisor"))],
      blocksPreparedResolution: true
    )
    _ = try await ingress.resumeFrames(
      generation: generation,
      scope: scope,
      heartbeatIntervalSeconds: 17
    )
    let outcome = try await ingress.receive(
      supervisorFrame(
        generation: generation,
        body: .routeAccepted(
          accepted: .request(requestRoute: Data(repeating: 0xA3, count: 16))
        )
      ),
      scope: scope
    )
    guard case .delivery(let delivery) = outcome else {
      return XCTFail("fixture must return a prepared delivery")
    }

    await ingress.discard(delivery)
    do {
      try await ingress.awaitResolution(delivery)
      XCTFail("discard-before-wait 必须立即返回 terminal failure，不能丢唤醒")
    } catch {
      XCTAssertEqual(error as? MachineConnectionSupervisorFailure, .securityError)
    }
  }

  func testFreshScopeAfterGenerationEndCanResolveNewDelivery() async throws {
    let firstGeneration = RelayTransportGeneration(rawValue: 202)
    let secondGeneration = RelayTransportGeneration(rawValue: 203)
    let firstScope = TransferAssemblyScope(connectionID: UUID(), generation: firstGeneration)
    let secondScope = TransferAssemblyScope(connectionID: UUID(), generation: secondGeneration)
    let ingress = SupervisorIngress(
      outcomes: [
        .delivery(supervisorPreparedDelivery(machineID: "machine-supervisor")),
        .delivery(supervisorPreparedDelivery(machineID: "machine-supervisor")),
      ],
      blocksPreparedResolution: true
    )
    _ = try await ingress.resumeFrames(
      generation: firstGeneration,
      scope: firstScope,
      heartbeatIntervalSeconds: 17
    )
    _ = try await ingress.receive(
      supervisorFrame(
        generation: firstGeneration,
        body: .routeAccepted(
          accepted: .request(requestRoute: Data(repeating: 0xA4, count: 16))
        )
      ),
      scope: firstScope
    )
    await ingress.generationEnded(scope: firstScope)

    _ = try await ingress.resumeFrames(
      generation: secondGeneration,
      scope: secondScope,
      heartbeatIntervalSeconds: 17
    )
    let secondOutcome = try await ingress.receive(
      supervisorFrame(
        generation: secondGeneration,
        body: .routeAccepted(
          accepted: .request(requestRoute: Data(repeating: 0xA5, count: 16))
        )
      ),
      scope: secondScope
    )
    guard case .delivery(let secondDelivery) = secondOutcome else {
      return XCTFail("fresh generation must own a new delivery")
    }
    try await ingress.commit(secondDelivery)
    try await ingress.awaitResolution(secondDelivery)
  }

  func testChallengeRelayMismatchFailsClosedBeforePrivateAuthenticationWrite() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 3)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: Data(repeating: 0xFE, count: 16),
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        )
      ]
    )
    let ingress = SupervisorIngress()
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.securityError, iterator: &iterator)
    let terminal = await iterator.next()
    XCTAssertNil(terminal)
    let sentFrames = await transport.sentFrames
    let receivedFrames = await ingress.receivedFrames
    XCTAssertTrue(sentFrames.isEmpty)
    XCTAssertTrue(receivedFrames.isEmpty)
  }

  func testHandshakeUsesOneAbsoluteDeadlineAndTearsDownBeforeReconnectSleep() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 5)
    let transport = try SupervisorTransport(generation: generation)
    let budget = TransferAssemblyBudgetCoordinator()
    let ingress = SupervisorIngress(reserveBudgetOnResume: false)
    let sleeper = RecordingLongMachineConnectionSleeper()
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: sleeper,
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5),
      handshakeDeadlineMilliseconds: 20
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.reconnecting, iterator: &iterator)
    let closedGenerations = await transport.closedGenerations
    let endedScopeCount = await ingress.endedScopes.count
    XCTAssertEqual(closedGenerations, [generation])
    XCTAssertEqual(endedScopeCount, 1)
    XCTAssertEqual(budget.usage, .zero)
    await connection.shutdown()
    let delayCount = await sleeper.delays.count
    XCTAssertEqual(delayCount, 1)
  }

  func testReconnectUsesFreshChallengeResumeAndReleasesOnlyEndedGenerationScope() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let firstGeneration = RelayTransportGeneration(rawValue: 7)
    let secondGeneration = RelayTransportGeneration(rawValue: 1)
    let first = try SupervisorTransport(
      generation: firstGeneration,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: firstGeneration
      ),
      finishError: .connectionClosed
    )
    let second = try SupervisorTransport(
      generation: secondGeneration,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: secondGeneration,
        nonceByte: 0xA7
      )
    )
    let factory = SupervisorTransportFactory(transports: [first, second])
    let budget = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 1_024,
      maximumCompletedTombstones: 8
    )
    let ingress = SupervisorIngress(
      resumeFrames: [],
      reserveBudgetOnResume: true,
      budgetCoordinator: budget
    )
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { try await factory.next() },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    await assertNextConnectionState(.reconnecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)

    let makeCount = await factory.makeCount
    XCTAssertEqual(makeCount, 2)
    let resumedScopes = await ingress.resumedScopes
    let endedScopes = await ingress.endedScopes
    XCTAssertEqual(resumedScopes.count, 2)
    XCTAssertEqual(endedScopes, [resumedScopes[0]])
    XCTAssertNotEqual(resumedScopes[0], resumedScopes[1])
    XCTAssertEqual(
      budget.usage,
      TransferAssemblyBudgetUsage(
        reassemblyBytes: 8,
        completedTombstones: 1,
        reservationCount: 2
      ),
      "only the live generation may retain its assembler scope"
    )

    await connection.shutdown()
    let finalEndedScopes = await ingress.endedScopes
    XCTAssertEqual(finalEndedScopes, resumedScopes)
    XCTAssertEqual(budget.usage, .zero)
  }

  func testBackgroundShutdownThenForegroundRebuildUsesFreshAuthenticatedGeneration()
    async throws
  {
    let fixture = try makeSupervisorAuthenticationFixture()
    let backgroundGeneration = RelayTransportGeneration(rawValue: 71)
    let foregroundGeneration = RelayTransportGeneration(rawValue: 72)
    let backgroundTransport = try SupervisorTransport(
      generation: backgroundGeneration,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: backgroundGeneration,
        nonceByte: 0xB1
      )
    )
    let foregroundTransport = try SupervisorTransport(
      generation: foregroundGeneration,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: foregroundGeneration,
        nonceByte: 0xB2
      )
    )
    let budget = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 1_024,
      maximumCompletedTombstones: 8
    )
    let ingress = SupervisorIngress(
      reserveBudgetOnResume: true,
      budgetCoordinator: budget
    )

    let backgroundConnection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { backgroundTransport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    var backgroundUpdates = await backgroundConnection.updates().makeAsyncIterator()
    await backgroundConnection.start()
    await assertNextConnectionState(.connecting, iterator: &backgroundUpdates)
    await assertNextConnectionState(.connected, iterator: &backgroundUpdates)
    await backgroundConnection.shutdown()

    var endedScopes = await ingress.endedScopes
    XCTAssertEqual(endedScopes.count, 1)
    XCTAssertEqual(endedScopes[0].generation, backgroundGeneration)
    XCTAssertEqual(budget.usage, .zero, "background teardown must release the exact scope")

    let foregroundConnection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { foregroundTransport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: budget,
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 2_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    var foregroundUpdates = await foregroundConnection.updates().makeAsyncIterator()
    await foregroundConnection.start()
    await assertNextConnectionState(.connecting, iterator: &foregroundUpdates)
    await assertNextConnectionState(.connected, iterator: &foregroundUpdates)

    let resumedScopes = await ingress.resumedScopes
    XCTAssertEqual(resumedScopes.count, 2)
    XCTAssertEqual(
      resumedScopes.map(\.generation),
      [backgroundGeneration, foregroundGeneration]
    )
    XCTAssertNotEqual(resumedScopes[0].connectionID, resumedScopes[1].connectionID)
    let backgroundSentFrames = await backgroundTransport.sentFrames
    let foregroundSentFrames = await foregroundTransport.sentFrames
    XCTAssertEqual(backgroundSentFrames.count, 1)
    XCTAssertEqual(foregroundSentFrames.count, 1)

    await foregroundConnection.shutdown()
    endedScopes = await ingress.endedScopes
    XCTAssertEqual(endedScopes, resumedScopes)
    XCTAssertEqual(budget.usage, .zero)
  }

  func testHandshakeSignedTerminalUsesExactWireVerifierButUnsignedRevokedErrorDoesNot() async throws
  {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 9)
    let terminal = try supervisorFrame(
      generation: generation,
      body: .revocationCommitted(
        deviceRoute: fixture.grant.deviceRoute,
        grantSerial: fixture.grant.grantSerial,
        signedRevocation: RelayV2DeviceRevocation(
          machineRoute: fixture.grant.machineRoute,
          deviceRoute: fixture.grant.deviceRoute,
          grantSerial: fixture.grant.grantSerial,
          rootKeyId: fixture.grant.rootKeyId,
          trustEpoch: fixture.grant.trustEpoch,
          signature: Data(repeating: 0xD1, count: 64)
        )
      )
    )
    let transport = try SupervisorTransport(
      generation: generation,
      frames: [
        supervisorFrame(
          generation: generation,
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: fixture.connectionInstance,
            challengeNonce: fixture.challengeNonce
          )
        ),
        terminal,
      ]
    )
    let ingress = SupervisorIngress(outcomes: [.revoked])
    let connection = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()
    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.revoked, iterator: &iterator)
    let terminalBytes = await ingress.receivedFrames.map(\.canonicalBytes)
    XCTAssertEqual(terminalBytes, [terminal.canonicalBytes])

    let unsignedTransport = try SupervisorTransport(
      generation: RelayTransportGeneration(rawValue: 10),
      frames: [
        supervisorFrame(
          generation: RelayTransportGeneration(rawValue: 10),
          body: .challenge(
            relayServerId: fixture.relayServerID,
            connectionInstance: Data(repeating: 0xA2, count: 16),
            challengeNonce: Data(repeating: 0xA3, count: 32)
          )
        ),
        supervisorFrame(
          generation: RelayTransportGeneration(rawValue: 10),
          body: .error(
            RelayV2Failure(
              code: "relay.auth.revoked",
              message: "must stay redacted"
            )
          )
        ),
      ]
    )
    let unsignedIngress = SupervisorIngress(outcomes: [.revoked])
    let unsigned = MachineConnection(
      machineID: "machine-supervisor",
      transportBuilder: { unsignedTransport },
      authenticator: fixture.authenticator,
      verifiedIngress: unsignedIngress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let unsignedUpdates = await unsigned.updates()
    var unsignedIterator = unsignedUpdates.makeAsyncIterator()
    await unsigned.start()
    await assertNextConnectionState(.connecting, iterator: &unsignedIterator)
    await assertNextConnectionState(.securityError, iterator: &unsignedIterator)
    let unsignedReceived = await unsignedIngress.receivedFrames
    XCTAssertTrue(unsignedReceived.isEmpty)
  }

  func testTransientFailuresReconnectWithoutFinishingObservationGeneration() throws {
    let cases: [(MachineConnectionEvent, MachineReconnectReason, SessionConnectionState)] = [
      (.transportFailed, .transportFailure, .reconnecting),
      (.relayUnavailable, .relayUnavailable, .relayUnavailable),
      (.machineOffline, .machineOffline, .machineOffline),
    ]

    for (event, reason, projectedState) in cases {
      var machine = MachineConnectionStateMachine()
      let firstGeneration = RelayTransportGeneration(rawValue: 41)
      machine.handle(.connected(generation: firstGeneration))
      XCTAssertEqual(try machine.requireOnlineGeneration(), firstGeneration)

      machine.handle(event)
      XCTAssertEqual(machine.phase, .reconnecting(reason: reason))
      XCTAssertEqual(machine.connectionState, projectedState)
      XCTAssertFalse(machine.shouldFinishObservations)

      let resumedGeneration = RelayTransportGeneration(rawValue: 42)
      machine.handle(.connected(generation: resumedGeneration))
      XCTAssertEqual(machine.phase, .online(generation: resumedGeneration))
      XCTAssertEqual(machine.connectionState, .connected)
      XCTAssertFalse(machine.shouldFinishObservations)
      XCTAssertEqual(try machine.requireOnlineGeneration(), resumedGeneration)
    }
  }

  func testOfflineSendGateReturnsTypedFailureInsteadOfQueueingWork() {
    let cases: [(MachineConnectionEvent, SessionSourceFailureCode)] = [
      (.machineOffline, .machineOffline),
      (.transportFailed, .transportUnavailable),
      (.relayUnavailable, .transportUnavailable),
    ]

    for (event, expectedCode) in cases {
      var machine = MachineConnectionStateMachine()
      machine.handle(
        .connected(generation: RelayTransportGeneration(rawValue: 1))
      )
      machine.handle(event)

      do {
        _ = try machine.requireOnlineGeneration()
        XCTFail("offline/reconnecting send must fail immediately")
      } catch let failure as SessionSourceFailure {
        XCTAssertEqual(failure.code, expectedCode)
      } catch {
        XCTFail("send gate must return SessionSourceFailure, got \(error)")
      }
    }
  }

  func testOnlyFatalFailuresTerminateAndLateGenerationCannotReviveConnection() {
    let cases: [(MachineConnectionEvent, SessionSourceFailureCode, SessionConnectionState)] = [
      (.revoked, .revoked, .revoked),
      (.incompatible, .incompatible, .incompatible),
      (.securityError, .securityError, .securityError),
    ]

    for (event, expectedCode, projectedState) in cases {
      var machine = MachineConnectionStateMachine()
      machine.handle(
        .connected(generation: RelayTransportGeneration(rawValue: 11))
      )
      machine.handle(event)

      XCTAssertTrue(machine.shouldFinishObservations)
      XCTAssertEqual(machine.connectionState, projectedState)
      guard case .terminal(let failure) = machine.phase else {
        return XCTFail("fatal failure must enter terminal phase")
      }
      XCTAssertEqual(failure.code, expectedCode)

      machine.handle(
        .connected(generation: RelayTransportGeneration(rawValue: 12))
      )
      XCTAssertEqual(machine.phase, .terminal(failure: failure))
      XCTAssertEqual(machine.connectionState, projectedState)
      XCTAssertTrue(machine.shouldFinishObservations)

      do {
        _ = try machine.requireOnlineGeneration()
        XCTFail("terminal connection must reject sends")
      } catch let typed as SessionSourceFailure {
        XCTAssertEqual(typed.code, expectedCode)
      } catch {
        XCTFail("terminal send gate must preserve typed failure, got \(error)")
      }
    }
  }

  func testUnknownHigherRevisionUsesBoundedKeySyncThenFailsClosed() throws {
    var machine = MachineConnectionStateMachine(maximumKeySyncAttempts: 3)
    let generation = RelayTransportGeneration(rawValue: 21)
    machine.handle(.connected(generation: generation))

    machine.handle(.keySyncRequired(observedRevision: 8))
    XCTAssertEqual(
      machine.phase,
      .keySyncing(generation: generation, observedRevision: 8, attempt: 1)
    )
    XCTAssertFalse(machine.shouldFinishObservations)

    machine.handle(.keySyncAttemptFailed(observedRevision: 8))
    XCTAssertEqual(
      machine.phase,
      .keySyncing(generation: generation, observedRevision: 8, attempt: 2)
    )
    machine.handle(.keySyncAttemptFailed(observedRevision: 8))
    XCTAssertEqual(
      machine.phase,
      .keySyncing(generation: generation, observedRevision: 8, attempt: 3)
    )

    machine.handle(.keySyncAttemptFailed(observedRevision: 8))
    guard case .terminal(let failure) = machine.phase else {
      return XCTFail("exhausted bounded key sync must fail closed")
    }
    XCTAssertEqual(failure.code, .securityError)
    XCTAssertEqual(machine.connectionState, .securityError)
    XCTAssertTrue(machine.shouldFinishObservations)

    machine.handle(
      .connected(generation: RelayTransportGeneration(rawValue: 22))
    )
    XCTAssertEqual(machine.phase, .terminal(failure: failure))
  }

  func testSuccessfulKeySyncCanRecoverBeforeAttemptBudgetIsExhausted() throws {
    var machine = MachineConnectionStateMachine(maximumKeySyncAttempts: 3)
    let generation = RelayTransportGeneration(rawValue: 31)
    machine.handle(.connected(generation: generation))
    machine.handle(.keySyncRequired(observedRevision: 9))
    machine.handle(.keySyncAttemptFailed(observedRevision: 9))
    XCTAssertFalse(machine.shouldFinishObservations)

    machine.handle(.keySyncSucceeded(generation: generation, acceptedRevision: 9))
    XCTAssertEqual(machine.phase, .online(generation: generation))
    XCTAssertEqual(machine.connectionState, .connected)
    XCTAssertEqual(try machine.requireOnlineGeneration(), generation)
  }

  func testSilentKeySyncGenerationHitsProductionDeadlineAndFailsClosed() async throws {
    let fixture = try makeSupervisorAuthenticationFixture()
    let generation = RelayTransportGeneration(rawValue: 401)
    let transport = try SupervisorTransport(
      generation: generation,
      frames: try supervisorHandshakeFrames(
        fixture: fixture,
        generation: generation
      ) + [
        supervisorFrame(
          generation: generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0xD1, count: 16))
          )
        )
      ]
    )
    let ingress = SupervisorIngress(
      outcomes: [.keySyncRequired(observedRevision: 8)],
      keySyncDeadlineMilliseconds: 5
    )
    let connection = MachineConnection(
      machineID: "machine-key-sync-deadline",
      transportBuilder: { transport },
      authenticator: fixture.authenticator,
      verifiedIngress: ingress,
      transferBudgetCoordinator: TransferAssemblyBudgetCoordinator(),
      reconnectSleeper: ImmediateMachineConnectionSleeper(),
      clock: FixedMachineConnectionClock(now: 1_000),
      jitterSource: FixedMachineConnectionJitter(value: 0.5)
    )
    let updates = await connection.updates()
    var iterator = updates.makeAsyncIterator()

    await connection.start()
    await assertNextConnectionState(.connecting, iterator: &iterator)
    await assertNextConnectionState(.connected, iterator: &iterator)
    // KeySync 只暂停受影响的 outer stream，transport generation 仍保持在线。
    await assertNextConnectionState(.connected, iterator: &iterator)
    await assertNextConnectionState(.securityError, iterator: &iterator)
    let deadlineClosedGeneration = await eventuallyMachineConnectionTest {
      let closed = await transport.closedGenerations
      let ended = await ingress.endedScopes
      return closed == [generation] && ended.count == 1
    }
    XCTAssertTrue(deadlineClosedGeneration)
    await connection.shutdown()
  }

  func testForgedOrRollbackFrameStopsBeforeReplayAdmission() async throws {
    for failure in [InjectedInboundFailure.trustRollback, .badSignature] {
      let fixture = try makeInboundFixture()
      let spy = InboundPipelineSpy(
        fixture: fixture,
        replayDisposition: .fresh,
        failure: failure
      )
      let pipeline = MachineInboundPipeline(stages: spy)

      do {
        _ = try await pipeline.process(
          wireBytes: fixture.wireBytes,
          context: fixture.context
        )
        XCTFail("untrusted/forged frame must fail")
      } catch let received as InjectedInboundFailure {
        XCTAssertEqual(received, failure)
      }
      let calls = await spy.calls
      let progressCommitCount = await spy.progressCommitCount
      let reducerCount = await spy.reducerCount
      XCTAssertEqual(calls, [.verify])
      XCTAssertEqual(progressCommitCount, 0)
      XCTAssertEqual(reducerCount, 0)
    }
  }

  func testValidSignatureReachesReplayBeforeAEADAndReducer() async throws {
    let fixture = try makeInboundFixture()
    let spy = InboundPipelineSpy(
      fixture: fixture,
      replayDisposition: .fresh
    )
    let pipeline = MachineInboundPipeline(stages: spy)

    let result = try await pipeline.process(
      wireBytes: fixture.wireBytes,
      context: fixture.context
    )

    XCTAssertEqual(result, .applied)
    let calls = await spy.calls
    let progressCommitCount = await spy.progressCommitCount
    let reducerCount = await spy.reducerCount
    XCTAssertEqual(
      calls,
      [
        .verify, .replay, .open, .decodeRuntime, .prepareReduction,
        .commitProgress, .publishReduction,
      ]
    )
    XCTAssertEqual(progressCommitCount, 1)
    XCTAssertEqual(reducerCount, 1)
  }

  func testBadTagAndRuntimeDecodeFailureMakeZeroDurableOrReducerProgress() async throws {
    for failure in [InjectedInboundFailure.badTag, .invalidRuntime] {
      let fixture = try makeInboundFixture()
      let spy = InboundPipelineSpy(
        fixture: fixture,
        replayDisposition: .fresh,
        failure: failure
      )
      let pipeline = MachineInboundPipeline(stages: spy)

      do {
        _ = try await pipeline.process(
          wireBytes: fixture.wireBytes,
          context: fixture.context
        )
        XCTFail("bad tag/Runtime must fail before progress")
      } catch let received as InjectedInboundFailure {
        XCTAssertEqual(received, failure)
      }

      let expected: [InboundPipelineCall]
      if failure == .badTag {
        expected = [.verify, .replay, .open]
      } else {
        expected = [.verify, .replay, .open, .decodeRuntime]
      }
      let calls = await spy.calls
      let progressCommitCount = await spy.progressCommitCount
      let reducerCount = await spy.reducerCount
      XCTAssertEqual(calls, expected)
      XCTAssertEqual(progressCommitCount, 0)
      XCTAssertEqual(reducerCount, 0)
    }
  }

  func testExactDuplicateStillAuthenticatesAEADAndRuntimeButDoesNotReduceAgain() async throws {
    let fixture = try makeInboundFixture()
    let spy = InboundPipelineSpy(
      fixture: fixture,
      replayDisposition: .exactDuplicate
    )
    let pipeline = MachineInboundPipeline(stages: spy)

    let result = try await pipeline.process(
      wireBytes: fixture.wireBytes,
      context: fixture.context
    )

    XCTAssertEqual(result, .exactDuplicate)
    let calls = await spy.calls
    let progressCommitCount = await spy.progressCommitCount
    let reducerCount = await spy.reducerCount
    XCTAssertEqual(
      calls,
      [.verify, .replay, .open, .decodeRuntime]
    )
    XCTAssertEqual(progressCommitCount, 0)
    XCTAssertEqual(reducerCount, 0)
  }

  func testReducerPreparationOrDurableCommitFailureCannotSplitProgressAndReducer() async throws {
    for failure in [
      InjectedInboundFailure.reducerPreparation,
      .progressCommit,
    ] {
      let fixture = try makeInboundFixture()
      let spy = InboundPipelineSpy(
        fixture: fixture,
        replayDisposition: .fresh,
        failure: failure
      )
      let pipeline = MachineInboundPipeline(stages: spy)

      do {
        _ = try await pipeline.process(
          wireBytes: fixture.wireBytes,
          context: fixture.context
        )
        XCTFail("staged reduction failure must not publish partial state")
      } catch let received as InjectedInboundFailure {
        XCTAssertEqual(received, failure)
      }

      let calls = await spy.calls
      let progressCommitCount = await spy.progressCommitCount
      let reducerCount = await spy.reducerCount
      if failure == .reducerPreparation {
        XCTAssertEqual(
          calls,
          [.verify, .replay, .open, .decodeRuntime, .prepareReduction]
        )
      } else {
        XCTAssertEqual(
          calls,
          [
            .verify, .replay, .open, .decodeRuntime, .prepareReduction,
            .commitProgress,
          ]
        )
      }
      XCTAssertEqual(progressCommitCount, 0)
      XCTAssertEqual(reducerCount, 0)
    }
  }

  func testConnectionUpdateChannelBoundsQueueAndSinglePendingProducer() async {
    let channel = MachineConnectionUpdateChannel<Int>(capacity: 1)
    let stream = await channel.stream()
    let firstResult = await channel.send(1)
    XCTAssertEqual(firstResult, .sent)

    let second = Task { await channel.send(2) }
    for _ in 0..<100 {
      if await channel.debugPendingSendCount == 1 { break }
      await Task.yield()
    }
    let pendingCount = await channel.debugPendingSendCount
    XCTAssertEqual(pendingCount, 1)

    let excess = (0..<1_024).map { value in
      Task { await channel.send(value + 3) }
    }
    var excessResults: [MachineConnectionUpdateChannelSendResult] = []
    excessResults.reserveCapacity(excess.count)
    for task in excess {
      excessResults.append(await task.value)
    }
    XCTAssertEqual(
      excessResults.filter { $0 == .producerInvariantViolation }.count,
      1_024
    )
    let stillOnePending = await channel.debugPendingSendCount
    XCTAssertEqual(stillOnePending, 1)

    var iterator = stream.makeAsyncIterator()
    let first = await iterator.next()
    XCTAssertEqual(first, 1)
    let secondResult = await second.value
    XCTAssertEqual(secondResult, .sent)
    let secondValue = await iterator.next()
    XCTAssertEqual(secondValue, 2)
    await channel.finish()
  }
}

private enum InboundPipelineCall: Equatable, Sendable {
  case verify
  case replay
  case open
  case decodeRuntime
  case prepareReduction
  case commitProgress
  case publishReduction
}

private enum InjectedInboundFailure: Error, Equatable, Sendable {
  case trustRollback
  case badSignature
  case badTag
  case invalidRuntime
  case reducerPreparation
  case progressCommit
}

private struct PreparedInboundReduction: Equatable, Sendable {
  let messageID: String
}

private struct InboundFixture: Sendable {
  let wireBytes: Data
  let context: OuterContextV1
  let verified: VerifiedSealedBlobV1
  let openedPayload: Data
  let envelope: RuntimeEnvelopeV2
}

private actor InboundPipelineSpy: MachineInboundPipelineStages {
  nonisolated let fixture: InboundFixture
  nonisolated let replayDisposition: ReplayDisposition
  nonisolated let failure: InjectedInboundFailure?

  private(set) var calls: [InboundPipelineCall] = []
  private(set) var progressCommitCount = 0
  private(set) var reducerCount = 0

  init(
    fixture: InboundFixture,
    replayDisposition: ReplayDisposition,
    failure: InjectedInboundFailure? = nil
  ) {
    self.fixture = fixture
    self.replayDisposition = replayDisposition
    self.failure = failure
  }

  func verify(
    wireBytes: Data,
    context: OuterContextV1
  ) async throws -> VerifiedSealedBlobV1 {
    calls.append(.verify)
    XCTAssertEqual(wireBytes, fixture.wireBytes)
    XCTAssertEqual(context, fixture.context)
    if failure == .trustRollback { throw InjectedInboundFailure.trustRollback }
    if failure == .badSignature { throw InjectedInboundFailure.badSignature }
    return fixture.verified
  }

  func admitReplay(
    _ verified: VerifiedSealedBlobV1
  ) async throws -> ReplayDisposition {
    calls.append(.replay)
    XCTAssertEqual(verified, fixture.verified)
    return replayDisposition
  }

  func open(
    _ verified: VerifiedSealedBlobV1,
    context: OuterContextV1
  ) async throws -> Data {
    calls.append(.open)
    XCTAssertEqual(verified, fixture.verified)
    XCTAssertEqual(context, fixture.context)
    if failure == .badTag { throw InjectedInboundFailure.badTag }
    return fixture.openedPayload
  }

  func decodeRuntime(_ payload: Data) async throws -> RuntimeEnvelopeV2 {
    calls.append(.decodeRuntime)
    XCTAssertEqual(payload, fixture.openedPayload)
    if failure == .invalidRuntime { throw InjectedInboundFailure.invalidRuntime }
    return fixture.envelope
  }

  func prepareReduction(
    _ envelope: RuntimeEnvelopeV2
  ) async throws -> PreparedInboundReduction {
    calls.append(.prepareReduction)
    if failure == .reducerPreparation {
      throw InjectedInboundFailure.reducerPreparation
    }
    return PreparedInboundReduction(messageID: envelope.messageID.rawValue)
  }

  func commitVerifiedProgress(
    _ verified: VerifiedSealedBlobV1,
    preparedReduction: PreparedInboundReduction
  ) async throws {
    calls.append(.commitProgress)
    XCTAssertEqual(verified, fixture.verified)
    XCTAssertEqual(preparedReduction.messageID, fixture.envelope.messageID.rawValue)
    if failure == .progressCommit {
      throw InjectedInboundFailure.progressCommit
    }
    progressCommitCount += 1
  }

  func publish(_ preparedReduction: PreparedInboundReduction) async {
    calls.append(.publishReduction)
    XCTAssertEqual(preparedReduction.messageID, fixture.envelope.messageID.rawValue)
    reducerCount += 1
  }
}

private func makeInboundFixture() throws -> InboundFixture {
  let context = OuterContextV1(
    frameKind: .conversationPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: Data(repeating: 0x51, count: 16),
    deviceRoute: Data(repeating: 0x52, count: 16),
    streamRoute: Data(repeating: 0x53, count: 16),
    requestRoute: nil,
    streamGeneration: Data(repeating: 0x54, count: 16),
    streamCursor: .at(4),
    streamSeq: 4,
    messageKeyEpoch: 5
  )
  let keyID = KeyIDV1(purpose: .conversationDEK, epoch: 5)
  let rawKey = Data(repeating: 0x55, count: 32)
  let signingKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x56, count: 32)
  )
  let openedPayload = Data("runtime-payload".utf8)
  let unsigned = try RelayCrypto.sealSymmetric(
    openedPayload,
    key: AeadSendingKey(
      keyID: keyID,
      epoch: 5,
      keyDirectoryRevision: 7,
      payloadKind: .conversationEvent,
      rawKey: rawKey
    ),
    context: context,
    counter: 9
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: signingKey,
    context: context
  )
  let verified = try RelayCrypto.verifySealed(
    signed,
    key: signingKey.publicKey,
    context: context
  )
  return InboundFixture(
    wireBytes: Data("strict-signed-sealed-wire".utf8),
    context: context,
    verified: verified,
    openedPayload: openedPayload,
    envelope: RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "event-9"),
      body: .request(.catalog(pageCursor: nil))
    )
  )
}

private struct SupervisorAuthenticationFixture {
  let relayServerID: Data
  let connectionInstance: Data
  let challengeNonce: Data
  let deviceSigningKey: Curve25519.Signing.PrivateKey
  let grant: RelayV2Grant
  let authenticator: PairedDeviceConnectionAuthenticator
}

private func makeSupervisorAuthenticationFixture() throws
  -> SupervisorAuthenticationFixture
{
  let relayServerID = Data(repeating: 0xA1, count: 16)
  let rootSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0xA2, count: 32)
  )
  let deviceSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0xA3, count: 32)
  )
  let rootFingerprint = CanonicalCodec.sha256(
    rootSigningKey.publicKey.rawRepresentation
  )
  let unsigned = RelayV2Grant(
    machineRoute: Data(repeating: 0xA4, count: 16),
    deviceRoute: Data(repeating: 0xA5, count: 16),
    deviceSignPubkey: deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: 9,
    rootKeyId: Data(repeating: 0xA6, count: 16),
    trustEpoch: 10,
    signature: Data(repeating: 0, count: 64)
  )
  let grant = RelayV2Grant(
    machineRoute: unsigned.machineRoute,
    deviceRoute: unsigned.deviceRoute,
    deviceSignPubkey: unsigned.deviceSignPubkey,
    grantSerial: unsigned.grantSerial,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    signature: try RelayCrypto.sign(
      RelayGrantCredentialVerifier.toBeSigned(
        unsigned,
        relayServerID: relayServerID,
        machineRootFingerprint: rootFingerprint
      ),
      key: rootSigningKey
    )
  )
  let credential = try RelayGrantCredentialVerifier.verify(
    grant,
    relayServerID: relayServerID,
    machineRootPublicKey: rootSigningKey.publicKey.rawRepresentation,
    machineRootFingerprint: rootFingerprint,
    expectedMachineRoute: grant.machineRoute,
    expectedDeviceRoute: grant.deviceRoute,
    expectedDeviceSignPublicKey: deviceSigningKey.publicKey.rawRepresentation,
    expectedGrantSerial: grant.grantSerial,
    expectedRootKeyID: grant.rootKeyId,
    expectedTrustEpoch: grant.trustEpoch
  )
  return SupervisorAuthenticationFixture(
    relayServerID: relayServerID,
    connectionInstance: Data(repeating: 0xA7, count: 16),
    challengeNonce: Data(repeating: 0xA8, count: 32),
    deviceSigningKey: deviceSigningKey,
    grant: grant,
    authenticator: try PairedDeviceConnectionAuthenticator(
      expectedRelayServerID: relayServerID,
      credential: credential,
      signingKey: deviceSigningKey
    )
  )
}

private func supervisorHandshakeFrames(
  fixture: SupervisorAuthenticationFixture,
  generation: RelayTransportGeneration,
  nonceByte: UInt8? = nil
) throws -> [ReceivedRelayFrame] {
  let nonce = nonceByte ?? fixture.challengeNonce.first!
  return try [
    supervisorFrame(
      generation: generation,
      body: .challenge(
        relayServerId: fixture.relayServerID,
        connectionInstance: Data(repeating: nonce &+ 1, count: 16),
        challengeNonce: Data(repeating: nonce, count: 32)
      )
    ),
    supervisorFrame(
      generation: generation,
      body: .authenticated(heartbeatIntervalSecs: 19)
    ),
  ]
}

private func supervisorFrame(
  generation: RelayTransportGeneration,
  body: RelayV2FrameBody
) throws -> ReceivedRelayFrame {
  let frame = RelayV2Frame(version: relayProtocolVersionV2, body: body)
  return ReceivedRelayFrame(
    generation: generation,
    frame: frame,
    canonicalBytes: try RelayWireCodecV2.encodeFixture(frame)
  )
}

private func supervisorDelivery(machineID: String) -> VerifiedRuntimeDelivery {
  VerifiedRuntimeDelivery(
    fixtureMachineID: machineID,
    target: .catalog(
      subscriptionRequestID: RuntimeMessageID(rawValue: "request-supervisor")
    ),
    streamGeneration: RuntimeStreamGeneration(rawValue: "generation-supervisor"),
    outerCursor: .at(0),
    payload: .typedReply(
      .command(
        .replayed(
          commandID: RuntimeCommandID(rawValue: "command-supervisor"),
          configurationRevision: 0
        )
      )
    )
  )
}

private func supervisorPreparedDelivery(machineID: String) -> VerifiedRuntimeDelivery {
  VerifiedRuntimeDelivery(
    machineID: machineID,
    target: .catalog(
      subscriptionRequestID: RuntimeMessageID(rawValue: "request-prepared")
    ),
    streamGeneration: RuntimeStreamGeneration(rawValue: "generation-prepared"),
    outerCursor: .at(0),
    payload: .typedReply(
      .command(
        .replayed(
          commandID: RuntimeCommandID(rawValue: "command-prepared"),
          configurationRevision: 0
        )
      )
    ),
    ingressPermit: MachineVerifiedDeliveryPermit()
  )
}

private actor SupervisorTransport: MachineConnectionTransport {
  private let generation: RelayTransportGeneration
  private let stream: AsyncThrowingStream<ReceivedRelayFrame, any Error>
  private let continuation: AsyncThrowingStream<ReceivedRelayFrame, any Error>.Continuation
  private let failSendAtIndex: Int?
  private(set) var sentFrames: [RelayV2Frame] = []
  private(set) var closedGenerations: [RelayTransportGeneration] = []
  private(set) var shutdownCount = 0
  private var incomingClaimed = false

  init(
    generation: RelayTransportGeneration,
    frames: [ReceivedRelayFrame] = [],
    finishError: RelayTransportError? = nil,
    failSendAtIndex: Int? = nil
  ) throws {
    var captured: AsyncThrowingStream<ReceivedRelayFrame, any Error>.Continuation?
    let stream = AsyncThrowingStream<ReceivedRelayFrame, any Error> { continuation in
      captured = continuation
    }
    guard let captured else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    self.generation = generation
    self.stream = stream
    self.failSendAtIndex = failSendAtIndex
    continuation = captured
    for frame in frames {
      continuation.yield(frame)
    }
    if let finishError {
      continuation.finish(throwing: finishError)
    }
  }

  func connect() async throws -> RelayTransportGeneration {
    generation
  }

  func incomingFrames(
    on expectedGeneration: RelayTransportGeneration
  ) -> AsyncThrowingStream<ReceivedRelayFrame, any Error> {
    guard expectedGeneration == generation, !incomingClaimed else {
      return AsyncThrowingStream { continuation in
        continuation.finish(throwing: RelayTransportError.staleGeneration)
      }
    }
    incomingClaimed = true
    return stream
  }

  func send(
    _ frame: RelayV2OutboundFrame,
    on expectedGeneration: RelayTransportGeneration
  ) async throws {
    guard expectedGeneration == generation else {
      throw RelayTransportError.staleGeneration
    }
    if let failSendAtIndex, sentFrames.count == failSendAtIndex {
      throw RelayTransportError.outcomeUnknown
    }
    sentFrames.append(
      try RelayWireCodecV2.decode(RelayWireCodecV2.encode(frame))
    )
  }

  func close(generation expectedGeneration: RelayTransportGeneration) async throws {
    guard expectedGeneration == generation else {
      throw RelayTransportError.staleGeneration
    }
    closedGenerations.append(expectedGeneration)
    continuation.finish()
  }

  func shutdown() async {
    shutdownCount += 1
    continuation.finish()
  }

  func finishIncoming(throwing error: RelayTransportError) {
    continuation.finish(throwing: error)
  }
}

private actor SupervisorTransportFactory {
  private var transports: [any MachineConnectionTransport]
  private(set) var makeCount = 0

  init(transports: [any MachineConnectionTransport]) {
    self.transports = transports
  }

  func next() throws -> any MachineConnectionTransport {
    guard !transports.isEmpty else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    makeCount += 1
    return transports.removeFirst()
  }
}

private actor EndpointSupervisorIngress: MachineConnectionVerifiedIngress {
  private struct PendingDirected {
    var reply: RuntimeReplyV2?
    var waiter: CheckedContinuation<RuntimeReplyV2, any Error>?
  }

  private var activeScope: TransferAssemblyScope?
  private var pendingDirected: [MachinePreparedOutboundRequestToken: PendingDirected] = [:]
  private var outcomes: [MachineConnectionVerifiedIngressOutcome]
  private let retirement: MachineSubscriptionRetirement
  private(set) var cancelCount = 0
  private(set) var preparedContracts: [MachineDirectedReplyContract] = []
  private var retiredTargets: [RuntimeSubscriptionTargetV1] = []

  init(
    outcomes: [MachineConnectionVerifiedIngressOutcome] = [],
    retirement: MachineSubscriptionRetirement = MachineSubscriptionRetirement(
      outerUnsubscribe: nil,
      requiresGenerationRollover: false
    )
  ) {
    self.outcomes = outcomes
    self.retirement = retirement
  }

  var pendingDirectedCount: Int { pendingDirected.count }
  var retiredTargetCount: Int { retiredTargets.count }

  func resumeFrames(
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope,
    heartbeatIntervalSeconds: UInt16
  ) async throws -> [RelayV2OutboundFrame] {
    guard generation == scope.generation, heartbeatIntervalSeconds > 0,
      activeScope == nil || activeScope == scope
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    activeScope = scope
    return []
  }

  func receive(
    _: ReceivedRelayFrame,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard activeScope == scope else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    return outcomes.isEmpty ? .ignored : outcomes.removeFirst()
  }

  func commit(_: VerifiedRuntimeDelivery) async throws {}
  func discard(_: VerifiedRuntimeDelivery) async {}
  func awaitResolution(_: VerifiedRuntimeDelivery) async throws {}

  func prepareDirected(
    envelope _: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    guard activeScope == scope else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    preparedContracts.append(contract)
    let token = MachinePreparedOutboundRequestToken()
    pendingDirected[token] = PendingDirected()
    return MachinePreparedOutboundRequest(
      token: token,
      frame: .control(.ping(nonce: 101))
    )
  }

  func prepareSubscription(
    target _: RuntimeSubscriptionTargetV1,
    after _: RuntimeStreamCursorV1,
    requestID _: RuntimeMessageID,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    guard activeScope == scope else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    return MachinePreparedOutboundRequest(
      token: MachinePreparedOutboundRequestToken(),
      frame: .control(.ping(nonce: 202))
    )
  }

  func cancelPrepared(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async {
    guard activeScope == scope else { return }
    cancelCount += 1
    let pending = pendingDirected.removeValue(forKey: token)
    pending?.waiter?.resume(throwing: CancellationError())
  }

  func awaitDirectedReply(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async throws -> RuntimeReplyV2 {
    guard activeScope == scope, var pending = pendingDirected[token] else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    if let reply = pending.reply {
      pendingDirected.removeValue(forKey: token)
      return reply
    }
    return try await withCheckedThrowingContinuation { continuation in
      guard pending.waiter == nil else {
        continuation.resume(throwing: MachineConnectionSupervisorFailure.securityError)
        return
      }
      pending.waiter = continuation
      pendingDirected[token] = pending
    }
  }

  func retireSubscription(
    target: RuntimeSubscriptionTargetV1,
    scope: TransferAssemblyScope
  ) async throws -> MachineSubscriptionRetirement {
    guard activeScope == scope else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    retiredTargets.append(target)
    return retirement
  }

  func completeDirected(_ reply: RuntimeReplyV2) {
    guard let token = pendingDirected.keys.first,
      var pending = pendingDirected[token]
    else {
      return
    }
    if let waiter = pending.waiter {
      pendingDirected.removeValue(forKey: token)
      waiter.resume(returning: reply)
    } else {
      pending.reply = reply
      pendingDirected[token] = pending
    }
  }

  func generationEnded(scope: TransferAssemblyScope) async {
    guard activeScope == scope else { return }
    activeScope = nil
    let waiters = pendingDirected.values.compactMap(\.waiter)
    pendingDirected.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume(throwing: MachineConnectionSupervisorFailure.transport(.connectionClosed))
    }
  }
}

private actor SupervisorIngress: MachineConnectionVerifiedIngress {
  private let resume: [RelayV2OutboundFrame]
  private var outcomes: [MachineConnectionVerifiedIngressOutcome]
  private let reserveBudgetOnResume: Bool
  private let budgetCoordinator: TransferAssemblyBudgetCoordinator?
  private let blocksPreparedResolution: Bool
  private let keySyncDeadlineMilliseconds: UInt64?
  private var keySyncDeadlineActive = false
  private var resolutionWaiters:
    [MachineVerifiedDeliveryPermit: CheckedContinuation<Void, any Error>] = [:]
  private var committedBeforeWait: Set<MachineVerifiedDeliveryPermit> = []
  private var discardedBeforeWait: Set<MachineVerifiedDeliveryPermit> = []
  private var scopeByPermit: [MachineVerifiedDeliveryPermit: TransferAssemblyScope] = [:]
  private var activeScopes: Set<TransferAssemblyScope> = []
  private var terminalScopes: Set<TransferAssemblyScope> = []
  private(set) var heartbeatIntervals: [UInt16] = []
  private(set) var resumedScopes: [TransferAssemblyScope] = []
  private(set) var endedScopes: [TransferAssemblyScope] = []
  private(set) var receivedFrames: [ReceivedRelayFrame] = []

  init(
    resumeFrames: [RelayV2OutboundFrame] = [],
    outcomes: [MachineConnectionVerifiedIngressOutcome] = [],
    reserveBudgetOnResume: Bool = false,
    budgetCoordinator: TransferAssemblyBudgetCoordinator? = nil,
    blocksPreparedResolution: Bool = false,
    keySyncDeadlineMilliseconds: UInt64? = nil
  ) {
    resume = resumeFrames
    self.outcomes = outcomes
    self.reserveBudgetOnResume = reserveBudgetOnResume
    self.budgetCoordinator = budgetCoordinator
    self.blocksPreparedResolution = blocksPreparedResolution
    self.keySyncDeadlineMilliseconds = keySyncDeadlineMilliseconds
  }

  var pendingResolutionCount: Int { resolutionWaiters.count }
  var receivedFrameCount: Int { receivedFrames.count }

  func resumeFrames(
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope,
    heartbeatIntervalSeconds: UInt16
  ) async throws -> [RelayV2OutboundFrame] {
    heartbeatIntervals.append(heartbeatIntervalSeconds)
    resumedScopes.append(scope)
    guard activeScopes.insert(scope).inserted, !terminalScopes.contains(scope) else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    if reserveBudgetOnResume {
      guard let budgetCoordinator else {
        throw MachineConnectionSupervisorFailure.securityError
      }
      _ = try budgetCoordinator.reservePartBytes(
        scope: scope,
        reservation: nil,
        additionalBytes: 8
      )
      _ = try budgetCoordinator.reserveTombstone(scope: scope)
    }
    return resume
  }

  func receive(
    _ frame: ReceivedRelayFrame,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    receivedFrames.append(frame)
    guard !outcomes.isEmpty else { return .ignored }
    let outcome = outcomes.removeFirst()
    switch outcome {
    case .keySyncRequired:
      keySyncDeadlineActive = true
    case .keySyncSucceeded, .revoked, .incompatible, .securityError:
      keySyncDeadlineActive = false
    case .ignored, .delivery, .transportActions, .keySyncAttemptFailed,
      .machineOffline, .relayUnavailable, .streamRecoveryRequired:
      break
    }
    if case .delivery(let delivery) = outcome, let permit = delivery.ingressPermit {
      guard activeScopes.contains(scope), scopeByPermit[permit] == nil else {
        throw MachineConnectionSupervisorFailure.securityError
      }
      scopeByPermit[permit] = scope
    }
    return outcome
  }

  func keySyncDeadlineRemainingMilliseconds(
    scope: TransferAssemblyScope
  ) async throws -> UInt64? {
    guard activeScopes.contains(scope), !terminalScopes.contains(scope) else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    return keySyncDeadlineActive ? keySyncDeadlineMilliseconds : nil
  }

  func commit(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard let permit = delivery.ingressPermit else { return }
    guard blocksPreparedResolution,
      let scope = scopeByPermit[permit],
      activeScopes.contains(scope),
      !terminalScopes.contains(scope),
      !discardedBeforeWait.contains(permit)
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    if let waiter = resolutionWaiters.removeValue(forKey: permit) {
      scopeByPermit.removeValue(forKey: permit)
      waiter.resume()
    } else {
      committedBeforeWait.insert(permit)
    }
  }

  func discard(_ delivery: VerifiedRuntimeDelivery) async {
    guard let permit = delivery.ingressPermit else { return }
    guard committedBeforeWait.remove(permit) == nil else { return }
    if let waiter = resolutionWaiters.removeValue(forKey: permit) {
      scopeByPermit.removeValue(forKey: permit)
      waiter.resume(throwing: MachineConnectionSupervisorFailure.securityError)
    } else if scopeByPermit[permit] != nil {
      discardedBeforeWait.insert(permit)
    }
  }

  func awaitResolution(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard let permit = delivery.ingressPermit else { return }
    guard blocksPreparedResolution,
      let scope = scopeByPermit[permit],
      activeScopes.contains(scope),
      !terminalScopes.contains(scope)
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    if committedBeforeWait.remove(permit) != nil {
      scopeByPermit.removeValue(forKey: permit)
      return
    }
    if discardedBeforeWait.remove(permit) != nil {
      scopeByPermit.removeValue(forKey: permit)
      throw MachineConnectionSupervisorFailure.securityError
    }
    try await withCheckedThrowingContinuation { continuation in
      resolutionWaiters[permit] = continuation
    }
  }

  func generationEnded(scope: TransferAssemblyScope) async {
    endedScopes.append(scope)
    activeScopes.remove(scope)
    terminalScopes.insert(scope)
    keySyncDeadlineActive = false
    let permits = scopeByPermit.compactMap { permit, candidateScope in
      candidateScope == scope ? permit : nil
    }
    let waiters = permits.compactMap { permit in
      committedBeforeWait.remove(permit)
      discardedBeforeWait.remove(permit)
      scopeByPermit.removeValue(forKey: permit)
      return resolutionWaiters.removeValue(forKey: permit)
    }
    for waiter in waiters {
      waiter.resume(throwing: CancellationError())
    }
  }
}

private actor ShutdownCompletionProbe {
  private(set) var isCompleted = false

  func markCompleted() {
    isCompleted = true
  }
}

private func eventuallyMachineConnectionTest(
  _ condition: () async -> Bool
) async -> Bool {
  for _ in 0..<10_000 {
    if await condition() { return true }
    await Task.yield()
  }
  return false
}

private struct ImmediateMachineConnectionSleeper:
  MachineConnectionReconnectSleeping
{
  func sleep(milliseconds: UInt64) async throws {}
}

private actor RecordingLongMachineConnectionSleeper:
  MachineConnectionReconnectSleeping
{
  private(set) var delays: [UInt64] = []

  func sleep(milliseconds: UInt64) async throws {
    delays.append(milliseconds)
    try await Task.sleep(for: .seconds(60))
  }
}

private struct FixedMachineConnectionClock: MachineConnectionClock {
  let now: UInt64

  func nowMilliseconds() -> UInt64 { now }
}

private struct FixedMachineConnectionJitter: MachineConnectionJitterSource {
  let value: Double

  func nextUnitInterval() -> Double { value }
}

extension MachineConnectionUpdate {
  fileprivate var connectionState: SessionConnectionState? {
    guard case .connectionState(let state) = self else { return nil }
    return state
  }
}

extension TransferAssemblyBudgetUsage {
  fileprivate static let zero = TransferAssemblyBudgetUsage(
    reassemblyBytes: 0,
    completedTombstones: 0,
    reservationCount: 0
  )
}

private func assertNextConnectionState(
  _ expected: SessionConnectionState,
  iterator: inout AsyncStream<MachineConnectionUpdate>.Iterator,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  let actual = await iterator.next()?.connectionState
  XCTAssertEqual(actual, expected, file: file, line: line)
}

private func requireSendable<T: Sendable>(_: T.Type) {}
