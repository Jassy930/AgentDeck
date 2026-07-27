import AgentDeckCore
import AgentDeckSessionSource
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class ProductionRelayPairingCommandHandlerTests: XCTestCase {
  func testInspectInviteReturnsPinnedPreviewWithoutOpeningTransport() async throws {
    let fixture = try PairingHandlerFixture(index: 1)
    defer { fixture.removeStateRoot() }
    let factory = PairingHandlerTransportFactory(transports: [])
    let handler = fixture.makeHandler(transportFactory: factory)

    let preview = try await handler.inspectPairInvite(fixture.encodedInvite)

    XCTAssertEqual(preview.name, fixture.invite.machineDisplayName)
    XCTAssertEqual(preview.relayHost, "relay.example.test")
    XCTAssertEqual(preview.rootFingerprint, fixture.invite.machineRootFingerprint)
    XCTAssertEqual(preview.expiresAtMs, fixture.invite.expiresAtMilliseconds)
    XCTAssertEqual(preview.relayServerID, fixture.invite.relayServerID)
    XCTAssertEqual(preview.currentSPKIPin, fixture.invite.currentSPKIPin)
    XCTAssertEqual(preview.nextSPKIPin, fixture.invite.nextSPKIPin)
    XCTAssertEqual(factory.makeCount, 0, "inspect 只能解析 invite，不能提前上网")

    await assertPairingHandlerSessionFailure(.invalidPairInvite) {
      _ = try await handler.inspectPairInvite("agentdeck-pair:v1:not-canonical")
    }
    XCTAssertEqual(factory.makeCount, 0)
  }

  func testDefaultAuthorizationPendingAndSignedTerminalAreFailClosed() async throws {
    for (index, outcome) in [(UInt8(2), PairTerminalOutcomeV1.canceled), (3, .expired)] {
      let fixture = try PairingHandlerFixture(index: index)
      defer { fixture.removeStateRoot() }
      let transport = PairingHandlerScriptedTransport(generation: UInt64(index))
      let factory = PairingHandlerTransportFactory(transports: [transport])
      let handler = fixture.makeHandler(transportFactory: factory)
      let stream = try await handler.pair(fixture.encodedInvite)
      let progressTask = Task { try await pairingHandlerCollect(stream) }

      let sent = await transport.waitForSentFrameCount(2)
      try assertPairingHelloAndRequest(sent, fixture: fixture)
      let requestBytes = try pairDataBytes(sent[1], expectedRoute: fixture.pairRoute)
      let plaintext = try fixture.openPairRequest(requestBytes)
      XCTAssertEqual(plaintext.authorizationRequest.deviceDisplayName, fixture.deviceDisplayName)
      XCTAssertEqual(
        plaintext.authorizationRequest.capabilities,
        AuthorizationCapabilityV1.allCases,
        "production 默认授权必须覆盖完整 MVP capability 集"
      )
      XCTAssertEqual(
        plaintext.authorizationRequest.permissions,
        AuthorizationPermissionV1.allCases,
        "production 默认授权必须覆盖完整 MVP permission 集"
      )

      let prepared = try await fixture.reopenPrepared()
      XCTAssertEqual(prepared.requestCarrier.canonicalBytes, requestBytes)
      if outcome == .canceled {
        try await transport.yieldPairData(
          pairRoute: fixture.pairRoute,
          sealedBlob: fixture.makePairPending(prepared: prepared)
        )
      }
      try await transport.yieldPairData(
        pairRoute: fixture.pairRoute,
        sealedBlob: fixture.makePairTerminal(outcome: outcome, prepared: prepared)
      )

      let progress = try await progressTask.value
      let expected: [PairingProgress] =
        outcome == .canceled
        ? [.preparing, .waitingForLocalConfirmation, .canceled]
        : [.preparing, .expired]
      XCTAssertEqual(progress, expected)
      let pairedRecords = try await fixture.pairedStore.list()
      XCTAssertTrue(pairedRecords.isEmpty)
      let pendingAfterTerminal = try await fixture.pendingStore.resumeIfPresent(
        invite: fixture.invite,
        authorizationRequest: fixture.authorization,
        nowMilliseconds: fixture.nowMilliseconds
      )
      XCTAssertNil(
        pendingAfterTerminal,
        "signed terminal 必须 durable stage 后清理 pending private material 与 marker"
      )
    }
  }

  func testResponsePromotionAndProcessRestartRetryExactRequestAndReceipt() async throws {
    let fixture = try PairingHandlerFixture(index: 4)
    defer { fixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(generation: 41)
    let firstFactory = PairingHandlerTransportFactory(transports: [firstTransport])
    let firstSleeper = PairingHandlerImmediateSleeper()
    let firstHandler = fixture.makeHandler(
      transportFactory: firstFactory,
      sleeper: firstSleeper
    )
    let firstStream = try await firstHandler.pair(fixture.encodedInvite)
    let firstProgressTask = Task { await pairingHandlerCollectResult(firstStream) }

    let firstRequestFrames = await firstTransport.waitForSentFrameCount(2)
    try assertPairingHelloAndRequest(firstRequestFrames, fixture: fixture)
    let firstRequest = try pairDataBytes(
      firstRequestFrames[1],
      expectedRoute: fixture.pairRoute
    )
    let prepared = try await fixture.reopenPrepared()
    XCTAssertEqual(firstRequest, prepared.requestCarrier.canonicalBytes)
    let response = try fixture.makePairResponse(prepared: prepared)
    try await firstTransport.yieldPairData(
      pairRoute: fixture.pairRoute,
      sealedBlob: response
    )

    let firstReceiptFrames = await firstTransport.waitForSentFrameCount(3)
    let firstReceipt = try pairDataBytes(
      firstReceiptFrames[2],
      expectedRoute: fixture.pairRoute
    )
    XCTAssertNoThrow(try PairTerminalEnvelopeCodec.decode(firstReceipt))
    let recordsAfterPromotion = try await fixture.pairedStore.list()
    let connectionAfterPromotion = try await fixture.pairedStore.openConnectionMaterial(
      rootFingerprint: fixture.invite.machineRootFingerprint,
      machineRoute: fixture.machineRoute
    )
    XCTAssertTrue(recordsAfterPromotion.isEmpty)
    XCTAssertNil(
      connectionAfterPromotion,
      "PairRouteClosed 前 durable promotion 必须保持不可见、不可连接"
    )
    let restoredAfterPromotion = try await fixture.pendingStore.resumeIfPresent(
      invite: fixture.invite,
      authorizationRequest: fixture.authorization,
      nowMilliseconds: fixture.nowMilliseconds
    )
    let staged = try XCTUnwrap(restoredAfterPromotion)
    guard case .active(let stagedPrepared) = staged,
      case .responsePrepared(let stagedResponse) = stagedPrepared.record.phase
    else {
      return XCTFail("promotion 后、PairRouteClosed 前必须保留 durable responsePrepared")
    }
    XCTAssertEqual(stagedResponse.receiptCarrier, firstReceipt)

    await firstTransport.finish(throwing: RelayTransportError.connectionClosed)
    let firstResult = await firstProgressTask.value
    guard case .failure = firstResult else {
      return XCTFail("第一进程在 receipt 后断线且无下一 transport 时必须结束为失败")
    }
    let firstDelays = await firstSleeper.delays
    XCTAssertEqual(firstDelays, [250])

    let secondTransport = PairingHandlerScriptedTransport(generation: 42)
    let secondFactory = PairingHandlerTransportFactory(transports: [secondTransport])
    let secondHandler = fixture.makeHandler(transportFactory: secondFactory)
    let secondStream = try await secondHandler.pair(fixture.encodedInvite)
    let secondProgressTask = Task { try await pairingHandlerCollect(secondStream) }

    let secondReceiptFrames = await secondTransport.waitForSentFrameCount(2)
    try assertPairingHello(secondReceiptFrames, fixture: fixture)
    let secondReceipt = try pairDataBytes(
      secondReceiptFrames[1],
      expectedRoute: fixture.pairRoute
    )
    XCTAssertEqual(
      secondReceipt,
      firstReceipt,
      "responsePrepared restart 必须直接重发 persisted exact PairResponseReceived"
    )
    try await secondTransport.yield(
      .pairRouteClosed(pairRoute: fixture.pairRoute, outcome: .alreadyAbsent)
    )

    let secondProgress = try await secondProgressTask.value
    XCTAssertEqual(secondProgress.count, 2)
    XCTAssertEqual(secondProgress.first, .preparing)
    guard case .paired(let machine)? = secondProgress.last else {
      return XCTFail("matching PairRouteClosed readback 后才可发布 paired")
    }
    let records = try await fixture.pairedStore.list()
    XCTAssertEqual(records.count, 1)
    XCTAssertEqual(machine, records[0].pairedMachine)
    let committedConnection = try await fixture.pairedStore.openConnectionMaterial(
      rootFingerprint: fixture.invite.machineRootFingerprint,
      machineRoute: fixture.machineRoute
    )
    XCTAssertNotNil(committedConnection)
    let pendingAfterCompletion = try await fixture.pendingStore.resumeIfPresent(
      invite: fixture.invite,
      authorizationRequest: fixture.authorization,
      nowMilliseconds: fixture.nowMilliseconds
    )
    XCTAssertNil(pendingAfterCompletion)
  }

  func testExactReceiptRouteNotFoundLeavesDurablePromotionStaged()
    async throws
  {
    let fixture = try PairingHandlerFixture(index: 7)
    defer { fixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(generation: 71)
    let routeNotFoundTransport = PairingHandlerScriptedTransport(generation: 72)
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [firstTransport, routeNotFoundTransport]
      ),
      sleeper: PairingHandlerImmediateSleeper()
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let resultTask = Task { await pairingHandlerCollectResult(stream) }

    _ = await firstTransport.waitForSentFrameCount(2)
    let prepared = try await fixture.reopenPrepared()
    try await firstTransport.yieldPairData(
      pairRoute: fixture.pairRoute,
      sealedBlob: fixture.makePairResponse(prepared: prepared)
    )
    let firstReceiptFrames = await firstTransport.waitForSentFrameCount(3)
    let firstReceipt = try pairDataBytes(
      firstReceiptFrames[2],
      expectedRoute: fixture.pairRoute
    )
    await firstTransport.finish(throwing: RelayTransportError.connectionClosed)

    let retriedFrames = await routeNotFoundTransport.waitForSentFrameCount(2)
    try assertPairingHello(retriedFrames, fixture: fixture)
    XCTAssertEqual(
      try pairDataBytes(retriedFrames[1], expectedRoute: fixture.pairRoute),
      firstReceipt
    )
    try await routeNotFoundTransport.yield(
      .error(
        RelayV2Failure(
          code: "relay.route.not_found",
          message: "pair route is unavailable or expired",
          inReplyTo: try pairingHandlerReplyReference(retriedFrames[1])
        )
      )
    )

    assertPairingHandlerRemoteFailure(await resultTask.value)
    try await assertPairingHandlerStagedInvisible(
      fixture,
      nowMilliseconds: fixture.nowMilliseconds
    )
  }

  func testExactPairingHelloRouteNotFoundLeavesDurablePromotionStaged()
    async throws
  {
    let fixture = try PairingHandlerFixture(index: 8)
    defer { fixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(generation: 81)
    let routeNotFoundTransport = PairingHandlerScriptedTransport(
      generation: 82,
      automaticallyAuthenticatePairingHello: false
    )
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [firstTransport, routeNotFoundTransport]
      ),
      sleeper: PairingHandlerImmediateSleeper()
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let resultTask = Task { await pairingHandlerCollectResult(stream) }

    _ = await firstTransport.waitForSentFrameCount(2)
    let prepared = try await fixture.reopenPrepared()
    try await firstTransport.yieldPairData(
      pairRoute: fixture.pairRoute,
      sealedBlob: fixture.makePairResponse(prepared: prepared)
    )
    _ = await firstTransport.waitForSentFrameCount(3)
    await firstTransport.finish(throwing: RelayTransportError.connectionClosed)

    let retriedFrames = await routeNotFoundTransport.waitForSentFrameCount(1)
    XCTAssertEqual(retriedFrames.count, 1, "pre-auth route_not_found 前不得发送 PairRequest")
    try await routeNotFoundTransport.yield(
      .error(
        RelayV2Failure(
          code: "relay.route.not_found",
          message: "pair route is unavailable or expired",
          inReplyTo: try pairingHandlerReplyReference(retriedFrames[0])
        )
      )
    )

    assertPairingHandlerRemoteFailure(await resultTask.value)
    try await assertPairingHandlerStagedInvisible(
      fixture,
      nowMilliseconds: fixture.nowMilliseconds
    )
  }

  func testRouteNotFoundWithWrongHashOrNoPromotionNeverMutatesDurableState()
    async throws
  {
    let promotedFixture = try PairingHandlerFixture(index: 9)
    defer { promotedFixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(generation: 91)
    let wrongHashTransport = PairingHandlerScriptedTransport(
      generation: 92,
      automaticallyAuthenticatePairingHello: false
    )
    let promotedHandler = promotedFixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [firstTransport, wrongHashTransport]
      ),
      sleeper: PairingHandlerImmediateSleeper()
    )
    let promotedStream = try await promotedHandler.pair(promotedFixture.encodedInvite)
    let promotedResultTask = Task { await pairingHandlerCollectResult(promotedStream) }

    _ = await firstTransport.waitForSentFrameCount(2)
    let prepared = try await promotedFixture.reopenPrepared()
    try await firstTransport.yieldPairData(
      pairRoute: promotedFixture.pairRoute,
      sealedBlob: promotedFixture.makePairResponse(prepared: prepared)
    )
    _ = await firstTransport.waitForSentFrameCount(3)
    await firstTransport.finish(throwing: RelayTransportError.connectionClosed)

    _ = await wrongHashTransport.waitForSentFrameCount(1)
    try await wrongHashTransport.yield(
      .error(
        RelayV2Failure(
          code: "relay.route.not_found",
          message: "pair route is unavailable or expired",
          inReplyTo: "frame-sha256:" + String(repeating: "0", count: 64)
        )
      )
    )
    let wrongHashResult = await promotedResultTask.value
    assertPairingHandlerRemoteFailure(wrongHashResult)
    try await assertPairingHandlerStagedInvisible(
      promotedFixture,
      nowMilliseconds: promotedFixture.nowMilliseconds
    )

    let unpromotedFixture = try PairingHandlerFixture(index: 10)
    defer { unpromotedFixture.removeStateRoot() }
    let unpromotedTransport = PairingHandlerScriptedTransport(
      generation: 101,
      automaticallyAuthenticatePairingHello: false
    )
    let unpromotedHandler = unpromotedFixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [unpromotedTransport]
      )
    )
    let unpromotedStream = try await unpromotedHandler.pair(
      unpromotedFixture.encodedInvite
    )
    let unpromotedResultTask = Task {
      await pairingHandlerCollectResult(unpromotedStream)
    }
    let unpromotedFrames = await unpromotedTransport.waitForSentFrameCount(1)
    try await unpromotedTransport.yield(
      .error(
        RelayV2Failure(
          code: "relay.route.not_found",
          message: "pair route is unavailable or expired",
          inReplyTo: try pairingHandlerReplyReference(unpromotedFrames[0])
        )
      )
    )
    assertPairingHandlerRemoteFailure(await unpromotedResultTask.value)
    let unpromotedRecords = try await unpromotedFixture.pairedStore.list()
    XCTAssertTrue(unpromotedRecords.isEmpty)
    guard
      case .active(let requestOnly)? = try await unpromotedFixture.pendingStore.resumeIfPresent(
        invite: unpromotedFixture.invite,
        authorizationRequest: unpromotedFixture.authorization,
        nowMilliseconds: unpromotedFixture.nowMilliseconds
      )
    else {
      return XCTFail("unpromoted exact hash 必须保留原 transaction")
    }
    XCTAssertEqual(requestOnly.record.phase, .requestPrepared)
  }

  func testDeliveredCloseLossRemainsStagedAcrossExpiryAndExactRouteNotFound()
    async throws
  {
    let fixture = try PairingHandlerFixture(index: 11)
    defer { fixture.removeStateRoot() }
    let clock = PairingHandlerManualClock(nowMilliseconds: fixture.nowMilliseconds)
    let firstTransport = PairingHandlerScriptedTransport(generation: 111)
    let firstHandler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [firstTransport]),
      sleeper: PairingHandlerImmediateSleeper(),
      clock: clock
    )
    let firstStream = try await firstHandler.pair(fixture.encodedInvite)
    let firstResultTask = Task { await pairingHandlerCollectResult(firstStream) }
    _ = await firstTransport.waitForSentFrameCount(2)
    let prepared = try await fixture.reopenPrepared()
    try await firstTransport.yieldPairData(
      pairRoute: fixture.pairRoute,
      sealedBlob: fixture.makePairResponse(prepared: prepared)
    )
    _ = await firstTransport.waitForSentFrameCount(3)
    await firstTransport.finish(throwing: RelayTransportError.connectionClosed)
    guard case .failure = await firstResultTask.value else {
      return XCTFail("Close 丢失且本进程无重连 transport 时应保留 durable transaction")
    }
    let hiddenAfterCloseLoss = try await fixture.pairedStore.list()
    XCTAssertTrue(hiddenAfterCloseLoss.isEmpty)

    clock.setNow(fixture.invite.expiresAtMilliseconds + 1)
    let routeNotFoundTransport = PairingHandlerScriptedTransport(
      generation: 112,
      automaticallyAuthenticatePairingHello: false
    )
    let recoveryHandler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [routeNotFoundTransport]
      ),
      clock: clock
    )
    let recoveryStream = try await recoveryHandler.pair(fixture.encodedInvite)
    let recoveryTask = Task { await pairingHandlerCollectResult(recoveryStream) }
    let frames = await routeNotFoundTransport.waitForSentFrameCount(1)
    try assertPairingHello(frames, fixture: fixture)
    let hiddenAfterExpiry = try await fixture.pairedStore.list()
    let stagedConnection = try await fixture.pairedStore.openConnectionMaterial(
      rootFingerprint: fixture.invite.machineRootFingerprint,
      machineRoute: fixture.machineRoute
    )
    XCTAssertTrue(hiddenAfterExpiry.isEmpty)
    XCTAssertNil(stagedConnection)
    try await routeNotFoundTransport.yield(
      .error(
        RelayV2Failure(
          code: "relay.route.not_found",
          message: "pair route is unavailable or expired",
          inReplyTo: try pairingHandlerReplyReference(frames[0])
        )
      )
    )

    assertPairingHandlerRemoteFailure(await recoveryTask.value)
    try await assertPairingHandlerStagedInvisible(
      fixture,
      nowMilliseconds: fixture.invite.expiresAtMilliseconds + 1
    )
  }

  func testReconnectBackoffWaitsUntilAbsoluteExpiryBeforeReportingExpired()
    async throws
  {
    let fixture = try PairingHandlerFixture(index: 12)
    defer { fixture.removeStateRoot() }
    let clock = PairingHandlerManualClock(
      nowMilliseconds: fixture.invite.expiresAtMilliseconds - 100
    )
    let sleeper = PairingHandlerAdvancingSleeper(clock: clock)
    let transport = PairingHandlerScriptedTransport(generation: 121)
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [transport]),
      sleeper: sleeper,
      clock: clock
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let resultTask = Task { await pairingHandlerCollectResult(stream) }
    _ = await transport.waitForSentFrameCount(2)
    await transport.finish(throwing: RelayTransportError.connectionClosed)

    guard case .failure(let error) = await resultTask.value else {
      return XCTFail("requestPrepared 必须在 absolute expiry 收敛为 expired")
    }
    XCTAssertEqual((error as? SessionSourceFailure)?.code, .pairInviteExpired)
    let delays = await sleeper.delays
    XCTAssertEqual(delays, [100])
    XCTAssertEqual(clock.nowMilliseconds(), fixture.invite.expiresAtMilliseconds)
  }

  func testWrongOuterPairRouteNeverPromotes() async throws {
    let fixture = try PairingHandlerFixture(index: 5)
    defer { fixture.removeStateRoot() }
    let transport = PairingHandlerScriptedTransport(generation: 51)
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [transport])
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let resultTask = Task { await pairingHandlerCollectResult(stream) }
    _ = await transport.waitForSentFrameCount(2)
    let prepared = try await fixture.reopenPrepared()
    try await transport.yieldPairData(
      pairRoute: Data(repeating: 0xFE, count: 16),
      sealedBlob: fixture.makePairResponse(prepared: prepared)
    )

    try assertSecurityFailure(await resultTask.value)
    let records = try await fixture.pairedStore.list()
    XCTAssertTrue(records.isEmpty)
  }

  func testForgedPairResponseNeverStagesOrPromotes() async throws {
    let fixture = try PairingHandlerFixture(index: 6)
    defer { fixture.removeStateRoot() }
    let transport = PairingHandlerScriptedTransport(generation: 61)
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [transport])
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let resultTask = Task { await pairingHandlerCollectResult(stream) }
    _ = await transport.waitForSentFrameCount(2)
    let prepared = try await fixture.reopenPrepared()
    var forged = try fixture.makePairResponse(prepared: prepared)
    forged[forged.index(before: forged.endIndex)] ^= 1
    try await transport.yieldPairData(
      pairRoute: fixture.pairRoute,
      sealedBlob: forged
    )

    try assertSecurityFailure(await resultTask.value)
    let records = try await fixture.pairedStore.list()
    XCTAssertTrue(records.isEmpty)
    let restored = try await fixture.pendingStore.resumeIfPresent(
      invite: fixture.invite,
      authorizationRequest: fixture.authorization,
      nowMilliseconds: fixture.nowMilliseconds
    )
    guard case .active(let pending)? = restored else {
      return XCTFail("forged response 不得删除或提升原始 requestPrepared transaction")
    }
    XCTAssertEqual(pending.record.phase, .requestPrepared)
  }

  func testShutdownClosesAndJoinsActivePairingAndRejectsNewPairing() async throws {
    let fixture = try PairingHandlerFixture(index: 13)
    defer { fixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(
      generation: 131,
      blockConnect: true,
      blockShutdown: true
    )
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(
        transports: [firstTransport]
      )
    )
    let firstStream = try await handler.pair(fixture.encodedInvite)
    let firstProgressTask = Task { await pairingHandlerCollectResult(firstStream) }
    await firstTransport.waitForConnectCount(1)

    let firstCompletion = PairingHandlerCompletionProbe()
    let secondCompletion = PairingHandlerCompletionProbe()
    let firstShutdown = Task {
      await handler.shutdown()
      await firstCompletion.markCompleted()
    }
    await firstTransport.waitForShutdownCount(1)
    let firstCompletedEarly = await firstCompletion.completedValue()
    XCTAssertFalse(firstCompletedEarly)

    let secondShutdown = Task {
      await handler.shutdown()
      await secondCompletion.markCompleted()
    }
    for _ in 0..<100 { await Task.yield() }
    let secondCompletedEarly = await secondCompletion.completedValue()
    XCTAssertFalse(
      secondCompletedEarly,
      "并发 shutdown 必须等待同一个 pairing/WSS join barrier"
    )
    await assertPairingHandlerSessionFailure(.commandRejected) {
      try await handler.pair(fixture.encodedInvite)
    }

    await firstTransport.releaseShutdown()
    for _ in 0..<100 { await Task.yield() }
    let completedBeforeWorkerJoin = await firstCompletion.completedValue()
    XCTAssertFalse(
      completedBeforeWorkerJoin,
      "WSS shutdown 返回后，handler 仍必须 join 尚未退出的 pairing worker"
    )
    await firstTransport.releaseConnect()
    _ = await firstShutdown.value
    _ = await secondShutdown.value
    guard case .success(let firstProgress) = await firstProgressTask.value else {
      return XCTFail("shutdown cancellation 应正常结束 pairing progress stream")
    }
    XCTAssertEqual(firstProgress, [.preparing])
    let firstCompleted = await firstCompletion.completedValue()
    let secondCompleted = await secondCompletion.completedValue()
    let firstTransportShutdownCount = await firstTransport.shutdownCount
    XCTAssertTrue(firstCompleted)
    XCTAssertTrue(secondCompleted)
    XCTAssertEqual(firstTransportShutdownCount, 1)

    await handler.shutdown()
    let repeatedFirstCount = await firstTransport.shutdownCount
    XCTAssertEqual(repeatedFirstCount, 1, "重复 shutdown 必须幂等")
    await assertPairingHandlerSessionFailure(.commandRejected) {
      try await handler.pair(fixture.encodedInvite)
    }
  }

  func testReplacementPairCancelsClosesAndJoinsOldWorkerBeforeOpeningNewWSS() async throws {
    let fixture = try PairingHandlerFixture(index: 16)
    defer { fixture.removeStateRoot() }
    let firstTransport = PairingHandlerScriptedTransport(
      generation: 161,
      blockConnect: true,
      blockShutdown: true
    )
    let secondTransport = PairingHandlerScriptedTransport(generation: 162)
    let factory = PairingHandlerTransportFactory(
      transports: [firstTransport, secondTransport]
    )
    let handler = fixture.makeHandler(transportFactory: factory)
    let firstStream = try await handler.pair(fixture.encodedInvite)
    let firstProgressTask = Task { await pairingHandlerCollectResult(firstStream) }
    await firstTransport.waitForConnectCount(1)

    let replacementCompletion = PairingHandlerCompletionProbe()
    let replacement = Task {
      let stream = try await handler.pair(fixture.encodedInvite)
      await replacementCompletion.markCompleted()
      return stream
    }
    await firstTransport.waitForShutdownCount(1)
    XCTAssertEqual(factory.makeCount, 1, "旧 WSS shutdown/join 前不得创建 replacement transport")
    let replacementCompletedBeforeShutdown = await replacementCompletion.completedValue()
    XCTAssertFalse(replacementCompletedBeforeShutdown)

    await firstTransport.releaseShutdown()
    for _ in 0..<100 { await Task.yield() }
    XCTAssertEqual(factory.makeCount, 1, "旧 worker 尚卡在 connect 时仍不得越过 join barrier")
    let replacementCompletedBeforeJoin = await replacementCompletion.completedValue()
    XCTAssertFalse(replacementCompletedBeforeJoin)

    await firstTransport.releaseConnect()
    let secondStream = try await replacement.value
    let secondProgressTask = Task { await pairingHandlerCollectResult(secondStream) }
    await secondTransport.waitForConnectCount(1)
    XCTAssertEqual(factory.makeCount, 2)
    guard case .success(let firstProgress) = await firstProgressTask.value else {
      return XCTFail("superseded pairing stream 应正常结束")
    }
    XCTAssertEqual(firstProgress, [.preparing])

    await handler.shutdown()
    guard case .success(let secondProgress) = await secondProgressTask.value else {
      return XCTFail("replacement pairing stream 应在 shutdown 时正常结束")
    }
    XCTAssertEqual(secondProgress, [.preparing])
    let firstShutdownCount = await firstTransport.shutdownCount
    let secondShutdownCount = await secondTransport.shutdownCount
    XCTAssertEqual(firstShutdownCount, 1)
    XCTAssertEqual(secondShutdownCount, 1)
  }

  func testConsumerCancellationClosesExactTransportAndJoinsWorker() async throws {
    let fixture = try PairingHandlerFixture(index: 14)
    defer { fixture.removeStateRoot() }
    let transport = PairingHandlerScriptedTransport(
      generation: 141,
      blockConnect: true,
      blockShutdown: true
    )
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [transport])
    )
    let stream = try await handler.pair(fixture.encodedInvite)
    let consumer = Task { await pairingHandlerCollectResult(stream) }
    await transport.waitForConnectCount(1)
    let activeCounts = await handler.debugActivePairingLifecycleCounts()
    XCTAssertEqual(activeCounts.workers, 1)
    XCTAssertEqual(activeCounts.transports, 1)

    consumer.cancel()
    guard case .success(let progress) = await consumer.value else {
      return XCTFail("consumer cancellation 应正常结束本地 progress iterator")
    }
    XCTAssertEqual(progress, [.preparing])
    await transport.waitForShutdownCount(1)
    let closingCounts = await handler.debugActivePairingLifecycleCounts()
    XCTAssertEqual(closingCounts.workers, 1, "transport connect 未释放前 worker 必须仍可被 join")
    XCTAssertEqual(closingCounts.transports, 1, "in-flight exact WSS shutdown 必须保持可 join")

    let globalCompletion = PairingHandlerCompletionProbe()
    let globalShutdown = Task {
      await handler.shutdown()
      await globalCompletion.markCompleted()
    }
    for _ in 0..<100 { await Task.yield() }
    let completedBeforeTransportClose = await globalCompletion.completedValue()
    XCTAssertFalse(
      completedBeforeTransportClose,
      "global shutdown 必须 join consumer termination 已启动的 exact WSS shutdown"
    )

    await transport.releaseShutdown()
    for _ in 0..<100 { await Task.yield() }
    let completedBeforeWorkerJoin = await globalCompletion.completedValue()
    XCTAssertFalse(completedBeforeWorkerJoin, "WSS 已关后仍必须 join blocked pairing worker")

    await transport.releaseConnect()
    _ = await globalShutdown.value
    var finalCounts = await handler.debugActivePairingLifecycleCounts()
    for _ in 0..<1_000 where finalCounts.workers != 0 || finalCounts.transports != 0 {
      await Task.yield()
      finalCounts = await handler.debugActivePairingLifecycleCounts()
    }
    XCTAssertEqual(finalCounts.workers, 0)
    XCTAssertEqual(finalCounts.transports, 0)

    await handler.shutdown()
    let shutdownCount = await transport.shutdownCount
    XCTAssertEqual(shutdownCount, 1, "global shutdown 不得重复关闭已由 consumer 回收的 WSS")
  }

  func testDroppingUnconsumedProgressStreamClosesExactTransport() async throws {
    let fixture = try PairingHandlerFixture(index: 15)
    defer { fixture.removeStateRoot() }
    let transport = PairingHandlerScriptedTransport(
      generation: 151,
      blockConnect: true
    )
    let handler = fixture.makeHandler(
      transportFactory: PairingHandlerTransportFactory(transports: [transport])
    )
    var stream: AsyncThrowingStream<PairingProgress, Error>? = try await handler.pair(
      fixture.encodedInvite
    )
    await transport.waitForConnectCount(1)
    XCTAssertNotNil(stream)

    stream = nil
    await transport.waitForShutdownCount(1)
    await transport.releaseConnect()
    var finalCounts = await handler.debugActivePairingLifecycleCounts()
    for _ in 0..<1_000 where finalCounts.workers != 0 || finalCounts.transports != 0 {
      await Task.yield()
      finalCounts = await handler.debugActivePairingLifecycleCounts()
    }
    XCTAssertEqual(finalCounts.workers, 0)
    XCTAssertEqual(finalCounts.transports, 0)

    await handler.shutdown()
    let shutdownCount = await transport.shutdownCount
    XCTAssertEqual(shutdownCount, 1)
  }
}

private final class PairingHandlerFixture: @unchecked Sendable {
  let nowMilliseconds: UInt64 = 1_900_000_000_000
  let clientKind: RelayClientKind = .iOSApp
  let installationID: UUID
  let deviceDisplayName: String
  let relayServerID: Data
  let pairRoute: Data
  let machineRoute: Data
  let deviceRoute: Data
  let rootKeyID: Data
  let grantSerial: UInt64 = 9
  let trustEpoch: UInt64 = 3
  let rootKey: Curve25519.Signing.PrivateKey
  let dataKey: Curve25519.Signing.PrivateKey
  let inviteHPKEKey: Curve25519.KeyAgreement.PrivateKey
  let keyStore = PairingHandlerMemoryKeyStore()
  let stateRootURL: URL
  let pairedStore: PairedMachineStore
  let pendingStore: PendingPairingStore
  let invite: PairInviteV1
  let authorization: AuthorizationRequestV1
  let encodedInvite: String

  init(index: UInt8) throws {
    installationID = UUID(
      uuidString: String(format: "60000000-0000-0000-0000-%012d", Int(index))
    )!
    deviceDisplayName = "Handler Device \(index)"
    relayServerID = Data(repeating: 0x20 &+ index, count: 16)
    pairRoute = Data(repeating: 0x30 &+ index, count: 16)
    machineRoute = Data(repeating: 0x40 &+ index, count: 16)
    deviceRoute = Data(repeating: 0x50 &+ index, count: 16)
    rootKeyID = Data(repeating: 0x60 &+ index, count: 16)
    rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x70 &+ index, count: 32)
    )
    dataKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x80 &+ index, count: 32)
    )
    inviteHPKEKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x90 &+ index, count: 32)
    )
    let rootPublic = rootKey.publicKey.rawRepresentation
    let rootFingerprint = CanonicalCodec.sha256(rootPublic)
    let certificate = try pairingHandlerCertificate(
      rootKey: rootKey,
      dataKey: dataKey,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      rootFingerprint: rootFingerprint,
      rootKeyID: rootKeyID,
      trustEpoch: trustEpoch,
      notAfterMilliseconds: nowMilliseconds + 600_000
    )
    invite = try PairInviteV1(
      pairRoute: pairRoute,
      inviteSecret: Data(repeating: 0xA0 &+ index, count: 32),
      inviteHPKEPublicKey: inviteHPKEKey.publicKey.rawRepresentation,
      wssURL: "wss://relay.example.test/",
      relayServerID: relayServerID,
      currentSPKIPin: Data(repeating: 0xB0 &+ index, count: 32),
      nextSPKIPin: Data(repeating: 0xC0 &+ index, count: 32),
      expiresAtMilliseconds: nowMilliseconds + 300_000,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: rootFingerprint,
      dataSignCertificate: certificate,
      machineDisplayName: "Handler Fixture \(index)"
    )
    authorization = try AuthorizationRequestV1(
      deviceDisplayName: deviceDisplayName,
      capabilities: AuthorizationCapabilityV1.allCases,
      permissions: AuthorizationPermissionV1.allCases
    )
    encodedInvite = try invite.encodeURI(nowMilliseconds: nowMilliseconds)
    stateRootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-pairing-handler-\(installationID.uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: stateRootURL,
      withIntermediateDirectories: true
    )
    pairedStore = PairedMachineStore(
      keyStore: keyStore,
      stateRootURL: stateRootURL,
      clientKind: clientKind,
      installationID: installationID,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    pendingStore = try PendingPairingStore(
      keyStore: keyStore,
      clientKind: clientKind,
      installationID: installationID
    )
  }

  func makeHandler(
    transportFactory: any RelayPairingTransportFactory,
    sleeper: any RelayPairingSleeper = PairingHandlerImmediateSleeper(),
    clock: (any RelayPairingClock)? = nil
  ) -> ProductionRelayPairingCommandHandler {
    ProductionRelayPairingCommandHandler(
      pairedMachineStore: pairedStore,
      transportFactory: transportFactory,
      clock: clock ?? PairingHandlerFixedClock(nowMilliseconds: nowMilliseconds),
      sleeper: sleeper,
      reconnectPolicy: RelayReconnectPolicy(),
      deviceDisplayName: deviceDisplayName
    )
  }

  func reopenPrepared() async throws -> PreparedPendingPairingV1 {
    let result = try await pendingStore.prepare(
      invite: invite,
      authorizationRequest: authorization,
      nowMilliseconds: nowMilliseconds
    )
    guard case .active(let prepared) = result else {
      throw PairingHandlerTestError.unexpectedPhase
    }
    return prepared
  }

  func openPairRequest(_ canonicalBytes: Data) throws -> PairRequestPlaintextV1 {
    let request = try PairRequestCanonicalCodec.decode(canonicalBytes)
    let info = try pairingHandlerRequestInfo(invite: invite)
    let context = pairingHandlerContext(kind: .pairRequest, pairRoute: pairRoute)
    let plaintext = try RelayCrypto.openHPKE(
      HPKEEnvelopeV1(enc: request.encapsulatedKey, ciphertext: request.ciphertext),
      recipient: inviteHPKEKey,
      info: info.canonicalBytes(),
      aad: CanonicalCodec.encodeAAD(context)
    )
    let decoded = try PairRequestPlaintextCanonicalCodec.decode(plaintext)
    let signingKey = try Curve25519.Signing.PublicKey(
      rawRepresentation: decoded.deviceSignPublicKey
    )
    guard
      signingKey.isValidSignature(
        request.deviceProofSignature,
        for: try PairRequestCrypto.signatureTBS(
          request,
          info: info,
          context: context,
          deviceSignFingerprint: CanonicalCodec.sha256(decoded.deviceSignPublicKey)
        )
      )
    else {
      throw PairingHandlerTestError.invalidRequestProof
    }
    return decoded
  }

  func makePairPending(prepared: PreparedPendingPairingV1) throws -> Data {
    let info = try pairingHandlerRequestInfo(invite: invite)
    let context = pairingHandlerContext(kind: .pairPending, pairRoute: pairRoute)
    let unsigned = try CanonicalPairPendingV1(
      requestHash: prepared.record.requestHash,
      signature: Data(repeating: 1, count: 64)
    )
    let pending = try CanonicalPairPendingV1(
      requestHash: unsigned.requestHash,
      signature: dataKey.signature(
        for: PairResponseCrypto.pairPendingSignatureTBS(
          unsigned,
          info: info,
          context: context,
          certificate: invite.dataSignCertificate
        )
      )
    )
    return try pairingHandlerSealControl(
      PairPendingCanonicalCodec.encode(pending),
      recipient: prepared.deviceHPKEPrivateKey.publicKey,
      info: info.canonicalBytes(),
      context: context
    )
  }

  func makePairTerminal(
    outcome: PairTerminalOutcomeV1,
    prepared: PreparedPendingPairingV1
  ) throws -> Data {
    let info = try pairingHandlerRequestInfo(invite: invite)
    let context = pairingHandlerContext(kind: .pairTerminal, pairRoute: pairRoute)
    let verifiedCertificate = try MachineDataCertificateVerifier.verify(
      invite.dataSignCertificate,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: invite.machineRootPublicKey,
      machineRootFingerprint: invite.machineRootFingerprint,
      expectedRootKeyID: rootKeyID,
      expectedTrustEpoch: trustEpoch,
      minimumDataCertificateGeneration: invite.dataSignCertificate.generation,
      nowMilliseconds: nowMilliseconds
    )
    let unsigned = try CanonicalPairTerminalV1(
      machineRoute: machineRoute,
      requestHash: prepared.record.requestHash,
      outcome: outcome,
      signature: Data(repeating: 0, count: 64),
      requireSignature: false
    )
    let terminal = try CanonicalPairTerminalV1(
      machineRoute: unsigned.machineRoute,
      requestHash: unsigned.requestHash,
      outcome: unsigned.outcome,
      signature: dataKey.signature(
        for: PairTerminalVerifier.signatureTBS(
          unsigned,
          info: info,
          context: context,
          verifiedCertificate: verifiedCertificate
        )
      )
    )
    return try pairingHandlerSealControl(
      PairTerminalCanonicalCodec.encode(terminal),
      recipient: prepared.deviceHPKEPrivateKey.publicKey,
      info: info.canonicalBytes(),
      context: context
    )
  }

  func makePairResponse(prepared: PreparedPendingPairingV1) throws -> Data {
    let verifiedCertificate = try MachineDataCertificateVerifier.verify(
      invite.dataSignCertificate,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: invite.machineRootPublicKey,
      machineRootFingerprint: invite.machineRootFingerprint,
      expectedRootKeyID: rootKeyID,
      expectedTrustEpoch: trustEpoch,
      minimumDataCertificateGeneration: invite.dataSignCertificate.generation,
      nowMilliseconds: nowMilliseconds
    )
    let provisionalRecord = try StoredPairedMachineRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      machineID: "handler-provisional-machine",
      machineName: invite.machineDisplayName,
      relayURL: URL(string: invite.wssURL)!,
      relayServerID: relayServerID,
      machineRootPublicKey: invite.machineRootPublicKey,
      machineRootFingerprint: invite.machineRootFingerprint,
      machineDataCertificate: invite.dataSignCertificate,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      currentSPKIPin: invite.currentSPKIPin,
      nextSPKIPin: invite.nextSPKIPin,
      grantSerial: grantSerial,
      trustEpoch: trustEpoch,
      createdAtMS: nowMilliseconds
    )
    let verifier = try KeyDirectoryVerifier(
      record: provisionalRecord,
      verifiedCertificate: verifiedCertificate,
      deviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey
    )
    let directory = try pairingHandlerDirectory(
      verifier: verifier,
      dataKey: dataKey,
      deviceHPKEPublicKey: prepared.deviceHPKEPrivateKey.publicKey,
      deviceRoute: deviceRoute
    )
    return try pairingHandlerResponse(
      invite: invite,
      authorization: authorization,
      prepared: prepared,
      rootKey: rootKey,
      dataKey: dataKey,
      certificate: invite.dataSignCertificate,
      directory: directory,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: grantSerial,
      trustEpoch: trustEpoch
    )
  }

  func removeStateRoot() {
    try? FileManager.default.removeItem(at: stateRootURL)
  }
}

private actor PairingHandlerScriptedTransport: RelayPairingTransportSession {
  private struct FrameWaiter {
    let count: Int
    let continuation: CheckedContinuation<[RelayV2Frame], Never>
  }

  private struct ShutdownWaiter {
    let count: Int
    let continuation: CheckedContinuation<Void, Never>
  }

  private struct ConnectWaiter {
    let count: Int
    let continuation: CheckedContinuation<Void, Never>
  }

  private let generation: RelayTransportGeneration
  private let automaticallyAuthenticatePairingHello: Bool
  private let blockConnect: Bool
  private let blockShutdown: Bool
  private let stream: AsyncThrowingStream<ReceivedRelayFrame, any Error>
  private let continuation: AsyncThrowingStream<ReceivedRelayFrame, any Error>.Continuation
  private var incomingClaimed = false
  private var connectCount = 0
  private var connectWaiters: [ConnectWaiter] = []
  private var connectReleaseWaiters: [CheckedContinuation<Void, Never>] = []
  private var connectReleased = false
  private var sentFrames: [RelayV2Frame] = []
  private var frameWaiters: [FrameWaiter] = []
  private var closedGenerations: [RelayTransportGeneration] = []
  private(set) var shutdownCount = 0
  private var shutdownWaiters: [ShutdownWaiter] = []
  private var shutdownReleaseWaiters: [CheckedContinuation<Void, Never>] = []
  private var shutdownReleased = false

  init(
    generation: UInt64,
    automaticallyAuthenticatePairingHello: Bool = true,
    blockConnect: Bool = false,
    blockShutdown: Bool = false
  ) {
    self.generation = RelayTransportGeneration(rawValue: generation)
    self.automaticallyAuthenticatePairingHello = automaticallyAuthenticatePairingHello
    self.blockConnect = blockConnect
    self.blockShutdown = blockShutdown
    var captured: AsyncThrowingStream<ReceivedRelayFrame, any Error>.Continuation?
    stream = AsyncThrowingStream { captured = $0 }
    continuation = captured!
  }

  func connect() async throws -> RelayTransportGeneration {
    connectCount += 1
    resumeConnectWaiters()
    if blockConnect, !connectReleased {
      await withCheckedContinuation { continuation in
        connectReleaseWaiters.append(continuation)
      }
    }
    return generation
  }

  func waitForConnectCount(_ count: Int) async {
    if connectCount >= count { return }
    await withCheckedContinuation { continuation in
      connectWaiters.append(ConnectWaiter(count: count, continuation: continuation))
    }
  }

  func releaseConnect() {
    connectReleased = true
    let waiters = connectReleaseWaiters
    connectReleaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func incomingFrames(
    on expectedGeneration: RelayTransportGeneration
  ) async -> AsyncThrowingStream<ReceivedRelayFrame, any Error> {
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
    let decoded = try RelayWireCodecV2.decode(RelayWireCodecV2.encode(frame))
    sentFrames.append(decoded)
    resumeFrameWaiters()
    if automaticallyAuthenticatePairingHello, case .pairingHello = decoded.body {
      try yield(.authenticated(heartbeatIntervalSecs: 20))
    }
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
    resumeShutdownWaiters()
    if blockShutdown, !shutdownReleased {
      await withCheckedContinuation { continuation in
        shutdownReleaseWaiters.append(continuation)
      }
    }
    continuation.finish()
  }

  func waitForShutdownCount(_ count: Int) async {
    if shutdownCount >= count { return }
    await withCheckedContinuation { continuation in
      shutdownWaiters.append(ShutdownWaiter(count: count, continuation: continuation))
    }
  }

  func releaseShutdown() {
    shutdownReleased = true
    let waiters = shutdownReleaseWaiters
    shutdownReleaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func waitForSentFrameCount(_ count: Int) async -> [RelayV2Frame] {
    if sentFrames.count >= count { return sentFrames }
    return await withCheckedContinuation { continuation in
      frameWaiters.append(FrameWaiter(count: count, continuation: continuation))
    }
  }

  func yieldPairData(pairRoute: Data, sealedBlob: Data) throws {
    try yield(.pairData(pairRoute: pairRoute, sealedBlob: sealedBlob))
  }

  func yield(_ body: RelayV2FrameBody) throws {
    let frame = RelayV2Frame(version: relayProtocolVersionV2, body: body)
    let canonical = try RelayWireCodecV2.encodeFixture(frame)
    _ = continuation.yield(
      ReceivedRelayFrame(
        generation: generation,
        frame: frame,
        canonicalBytes: canonical
      )
    )
  }

  func finish(throwing error: (any Error)? = nil) {
    continuation.finish(throwing: error)
  }

  private func resumeFrameWaiters() {
    var remaining: [FrameWaiter] = []
    for waiter in frameWaiters {
      if sentFrames.count >= waiter.count {
        waiter.continuation.resume(returning: sentFrames)
      } else {
        remaining.append(waiter)
      }
    }
    frameWaiters = remaining
  }

  private func resumeConnectWaiters() {
    var remaining: [ConnectWaiter] = []
    for waiter in connectWaiters {
      if connectCount >= waiter.count {
        waiter.continuation.resume()
      } else {
        remaining.append(waiter)
      }
    }
    connectWaiters = remaining
  }

  private func resumeShutdownWaiters() {
    var remaining: [ShutdownWaiter] = []
    for waiter in shutdownWaiters {
      if shutdownCount >= waiter.count {
        waiter.continuation.resume()
      } else {
        remaining.append(waiter)
      }
    }
    shutdownWaiters = remaining
  }
}

private actor PairingHandlerCompletionProbe {
  private var completed = false

  func markCompleted() {
    completed = true
  }

  func completedValue() -> Bool { completed }
}

private final class PairingHandlerTransportFactory:
  RelayPairingTransportFactory,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var transports: [any RelayPairingTransportSession]
  private var capturedInvites: [PairInviteV1] = []

  init(transports: [any RelayPairingTransportSession]) {
    self.transports = transports
  }

  var makeCount: Int {
    lock.withLock { capturedInvites.count }
  }

  func makeTransport(
    for invite: PairInviteV1
  ) throws -> any RelayPairingTransportSession {
    try lock.withLock {
      guard !transports.isEmpty else {
        throw PairingHandlerTestError.noTransport
      }
      capturedInvites.append(invite)
      return transports.removeFirst()
    }
  }
}

private struct PairingHandlerFixedClock: RelayPairingClock {
  let fixedMilliseconds: UInt64

  init(nowMilliseconds: UInt64) {
    fixedMilliseconds = nowMilliseconds
  }

  func nowMilliseconds() -> UInt64 { fixedMilliseconds }
}

private final class PairingHandlerManualClock: RelayPairingClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(nowMilliseconds: UInt64) {
    value = nowMilliseconds
  }

  func nowMilliseconds() -> UInt64 {
    lock.withLock { value }
  }

  func setNow(_ milliseconds: UInt64) {
    lock.withLock { value = milliseconds }
  }

  func advance(by milliseconds: UInt64) {
    lock.withLock {
      let advanced = value.addingReportingOverflow(milliseconds)
      value = advanced.overflow ? .max : advanced.partialValue
    }
  }
}

private actor PairingHandlerImmediateSleeper: RelayPairingSleeper {
  private(set) var delays: [UInt64] = []

  func sleep(milliseconds: UInt64) async throws {
    delays.append(milliseconds)
  }
}

private actor PairingHandlerAdvancingSleeper: RelayPairingSleeper {
  private let clock: PairingHandlerManualClock
  private(set) var delays: [UInt64] = []

  init(clock: PairingHandlerManualClock) {
    self.clock = clock
  }

  func sleep(milliseconds: UInt64) async throws {
    delays.append(milliseconds)
    clock.advance(by: milliseconds)
  }
}

private actor PairingHandlerMemoryKeyStore: PairedMarkerListingKeyStore {
  private var values: [KeyStoreKey: Data] = [:]

  func load(_ key: KeyStoreKey) async throws -> Data? {
    values[key]
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let existing = values[key] {
      guard existing == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let existing = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard existing == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values[key] = replacement
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard values[key] == expected else {
      throw KeyStoreError.deleteReadbackFailed
    }
    values.removeValue(forKey: key)
  }

  func pairedCommitMarkerKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pairedMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    return values.keys.filter {
      $0.account.hasPrefix(prefix)
        && $0.account.hasSuffix("/\(PairedKeyStorePurpose.commitMarker.rawValue)")
    }.sorted { $0.account < $1.account }
  }

  func pendingPairingRecoveryKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pendingMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    let suffixes = [
      "/\(PendingKeyStorePurpose.recoveryIntent.rawValue)",
      "/\(PendingKeyStorePurpose.pairingRecord.rawValue)",
    ]
    return values.keys.filter { key in
      key.account.hasPrefix(prefix)
        && suffixes.contains(where: key.account.hasSuffix)
    }.sorted { $0.account < $1.account }
  }
}

private func pairingHandlerCollect(
  _ stream: AsyncThrowingStream<PairingProgress, Error>
) async throws -> [PairingProgress] {
  var values: [PairingProgress] = []
  for try await value in stream { values.append(value) }
  return values
}

private func pairingHandlerCollectResult(
  _ stream: AsyncThrowingStream<PairingProgress, Error>
) async -> Result<[PairingProgress], Error> {
  do {
    return .success(try await pairingHandlerCollect(stream))
  } catch {
    return .failure(error)
  }
}

private func assertPairingHelloAndRequest(
  _ frames: [RelayV2Frame],
  fixture: PairingHandlerFixture,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  try assertPairingHello(frames, fixture: fixture, file: file, line: line)
  XCTAssertGreaterThanOrEqual(frames.count, 2, file: file, line: line)
  _ = try pairDataBytes(frames[1], expectedRoute: fixture.pairRoute)
}

private func assertPairingHello(
  _ frames: [RelayV2Frame],
  fixture: PairingHandlerFixture,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  XCTAssertGreaterThanOrEqual(frames.count, 1, file: file, line: line)
  guard case .pairingHello(let relayServerID, let pairRoute) = frames[0].body else {
    return XCTFail("首个 application frame 必须是 PairingHello", file: file, line: line)
  }
  XCTAssertEqual(relayServerID, fixture.relayServerID, file: file, line: line)
  XCTAssertEqual(pairRoute, fixture.pairRoute, file: file, line: line)
}

private func pairDataBytes(
  _ frame: RelayV2Frame,
  expectedRoute: Data
) throws -> Data {
  guard case .pairData(let pairRoute, let sealedBlob) = frame.body,
    pairRoute == expectedRoute
  else {
    throw PairingHandlerTestError.unexpectedFrame
  }
  return sealedBlob
}

private func pairingHandlerReplyReference(_ frame: RelayV2Frame) throws -> String {
  let digest = CanonicalCodec.sha256(try RelayWireCodecV2.encodeFixture(frame))
  return "frame-sha256:" + digest.map { String(format: "%02x", $0) }.joined()
}

private func assertPairingHandlerRemoteFailure(
  _ result: Result<[PairingProgress], Error>,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  guard case .failure(let error) = result else {
    return XCTFail("Relay error 必须返回 typed failure", file: file, line: line)
  }
  XCTAssertEqual(
    (error as? SessionSourceFailure)?.code,
    .transportUnavailable,
    file: file,
    line: line
  )
}

private func assertPairingHandlerStagedInvisible(
  _ fixture: PairingHandlerFixture,
  nowMilliseconds: UInt64,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let records = try await fixture.pairedStore.list()
  XCTAssertTrue(records.isEmpty, file: file, line: line)
  let connection = try await fixture.pairedStore.openConnectionMaterial(
    rootFingerprint: fixture.invite.machineRootFingerprint,
    machineRoute: fixture.machineRoute
  )
  XCTAssertNil(connection, file: file, line: line)
  guard
    case .active(let prepared)? = try await fixture.pendingStore.resumeIfPresent(
      invite: fixture.invite,
      authorizationRequest: fixture.authorization,
      nowMilliseconds: nowMilliseconds
    ), case .responsePrepared(let response) = prepared.record.phase
  else {
    return XCTFail(
      "route_not_found 后必须保留 responsePrepared",
      file: file,
      line: line
    )
  }
  guard
    case .staged(let record)? = try await fixture.pairedStore.pairingPromotionState(
      prepared: prepared,
      response: response
    )
  else {
    return XCTFail(
      "route_not_found 后必须保留 staged promotion",
      file: file,
      line: line
    )
  }
  XCTAssertEqual(record.machineRoute, fixture.machineRoute, file: file, line: line)
  XCTAssertEqual(record.deviceRoute, fixture.deviceRoute, file: file, line: line)
}

private func assertSecurityFailure(
  _ result: Result<[PairingProgress], Error>,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  guard case .failure(let error) = result else {
    return XCTFail("hostile pairing input 必须 fail-close", file: file, line: line)
  }
  XCTAssertEqual(
    (error as? SessionSourceFailure)?.code,
    .securityError,
    file: file,
    line: line
  )
}

private func assertPairingHandlerSessionFailure<T>(
  _ expected: SessionSourceFailureCode,
  file: StaticString = #filePath,
  line: UInt = #line,
  operation: () async throws -> T
) async {
  do {
    _ = try await operation()
    XCTFail("expected \(expected)", file: file, line: line)
  } catch {
    XCTAssertEqual(
      (error as? SessionSourceFailure)?.code,
      expected,
      file: file,
      line: line
    )
  }
}

private func pairingHandlerCertificate(
  rootKey: Curve25519.Signing.PrivateKey,
  dataKey: Curve25519.Signing.PrivateKey,
  relayServerID: Data,
  machineRoute: Data,
  rootFingerprint: Data,
  rootKeyID: Data,
  trustEpoch: UInt64,
  notAfterMilliseconds: UInt64
) throws -> RelayV2SignedCertificate {
  let unsigned = RelayV2SignedCertificate(
    subjectPubkey: dataKey.publicKey.rawRepresentation,
    certRole: .data,
    generation: 4,
    rootKeyId: rootKeyID,
    trustEpoch: trustEpoch,
    notAfterMs: notAfterMilliseconds,
    signature: Data(repeating: 0, count: 64)
  )
  let tbs = ToBeSignedV1(
    objectType: .dataCert,
    signatureFormatVersion: 1,
    relayProtocolVersion: relayProtocolVersionV2,
    runtimeProtocolVersion: runtimeProtocolVersionCurrent,
    e2eeFormatVersion: 1,
    relayServerID: relayServerID,
    machineRoute: machineRoute,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    roleScope: "machine-data",
    signingKeyFingerprint: rootFingerprint,
    rootKeyID: rootKeyID,
    trustEpoch: trustEpoch,
    serialOrGeneration: unsigned.generation,
    notAfterMS: notAfterMilliseconds,
    signedObjectSHA256: try SignedCertificateCanonicalCodec.unsignedCanonicalSHA256(
      unsigned
    )
  )
  return RelayV2SignedCertificate(
    subjectPubkey: unsigned.subjectPubkey,
    certRole: unsigned.certRole,
    generation: unsigned.generation,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    notAfterMs: unsigned.notAfterMs,
    signature: try RelayCrypto.sign(tbs, key: rootKey)
  )
}

private func pairingHandlerDirectory(
  verifier: KeyDirectoryVerifier,
  dataKey: Curve25519.Signing.PrivateKey,
  deviceHPKEPublicKey: Curve25519.KeyAgreement.PublicKey,
  deviceRoute: Data
) throws -> DeviceKeyDirectoryV1 {
  let revision: UInt64 = 1
  let materials: [(KeyIDV1, Data)] = [
    (KeyIDV1(purpose: .catalog, epoch: 1), Data(repeating: 0xD1, count: 32)),
    (KeyIDV1(purpose: .deviceCommandTx, epoch: 1), Data(repeating: 0xD2, count: 32)),
    (KeyIDV1(purpose: .deviceReplyTx, epoch: 1), Data(repeating: 0xD3, count: 32)),
  ]
  let entries = try materials.map { keyID, material in
    let sealing = try verifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: keyID,
      streamRoute: nil
    )
    let envelope = try RelayCrypto.sealHPKE(
      material,
      recipient: deviceHPKEPublicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    return try DeviceWrappedKeyV1(
      keyID: keyID,
      deviceRoute: deviceRoute,
      streamRoute: nil,
      enc: envelope.enc,
      wrappedKey: envelope.ciphertext
    )
  }
  let unsigned = try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: Data(repeating: 1, count: 64)
  )
  return try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: dataKey.signature(for: verifier.directorySignatureTBS(unsigned))
  )
}

private func pairingHandlerResponse(
  invite: PairInviteV1,
  authorization: AuthorizationRequestV1,
  prepared: PreparedPendingPairingV1,
  rootKey: Curve25519.Signing.PrivateKey,
  dataKey: Curve25519.Signing.PrivateKey,
  certificate: RelayV2SignedCertificate,
  directory: DeviceKeyDirectoryV1,
  machineRoute: Data,
  deviceRoute: Data,
  grantSerial: UInt64,
  trustEpoch: UInt64
) throws -> Data {
  let unsignedGrant = RelayV2Grant(
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignPubkey: prepared.deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: grantSerial,
    rootKeyId: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: Data(repeating: 0, count: 64)
  )
  let grant = RelayV2Grant(
    machineRoute: unsignedGrant.machineRoute,
    deviceRoute: unsignedGrant.deviceRoute,
    deviceSignPubkey: unsignedGrant.deviceSignPubkey,
    grantSerial: unsignedGrant.grantSerial,
    rootKeyId: unsignedGrant.rootKeyId,
    trustEpoch: unsignedGrant.trustEpoch,
    signature: try RelayCrypto.sign(
      RelayGrantCredentialVerifier.toBeSigned(
        unsignedGrant,
        relayServerID: invite.relayServerID,
        machineRootFingerprint: invite.machineRootFingerprint
      ),
      key: rootKey
    )
  )
  let grantBytes = try RelayGrantCanonicalCodec.encode(grant)
  let unsignedAuthorization = try CanonicalDeviceAuthorizationV1(
    grantHash: CanonicalCodec.sha256(grantBytes),
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignFingerprint: CanonicalCodec.sha256(
      prepared.deviceSigningKey.publicKey.rawRepresentation
    ),
    grantSerial: grantSerial,
    deviceHPKEPublicKey: prepared.deviceHPKEPrivateKey.publicKey.rawRepresentation,
    capabilities: authorization.capabilities,
    permissions: authorization.permissions,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: Data(repeating: 0, count: 64),
    requireSignature: false
  )
  let authorizationTBS = ToBeSignedV1(
    objectType: .deviceAuthorization,
    signatureFormatVersion: 1,
    relayProtocolVersion: relayProtocolVersionV2,
    runtimeProtocolVersion: runtimeProtocolVersionCurrent,
    e2eeFormatVersion: 1,
    relayServerID: invite.relayServerID,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    roleScope: "device-authorization",
    signingKeyFingerprint: invite.machineRootFingerprint,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    serialOrGeneration: grantSerial,
    notAfterMS: nil,
    signedObjectSHA256:
      try DeviceAuthorizationCanonicalCodec
      .unsignedCanonicalSHA256(unsignedAuthorization)
  )
  let deviceAuthorization = try CanonicalDeviceAuthorizationV1(
    grantHash: unsignedAuthorization.grantHash,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignFingerprint: unsignedAuthorization.deviceSignFingerprint,
    grantSerial: grantSerial,
    deviceHPKEPublicKey: unsignedAuthorization.deviceHPKEPublicKey,
    capabilities: authorization.capabilities,
    permissions: authorization.permissions,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: RelayCrypto.sign(authorizationTBS, key: rootKey)
  )
  let authorizationBytes = try DeviceAuthorizationCanonicalCodec.encode(
    deviceAuthorization
  )
  let directoryBytes = try KeyDirectoryCanonicalCodec.encode(directory)
  let plaintext = CanonicalPairResponsePlaintextV1(
    formatVersion: 1,
    requestHash: prepared.record.requestHash,
    relayGrant: grant,
    relayGrantCanonicalBytes: grantBytes,
    deviceAuthorization: deviceAuthorization,
    deviceAuthorizationCanonicalBytes: authorizationBytes,
    keyDirectory: directory,
    keyDirectoryCanonicalBytes: directoryBytes
  )
  let plaintextBytes = try PairResponsePlaintextCanonicalCodec.encode(plaintext)
  let info = try PairResponseInfoV1(
    relayServerID: invite.relayServerID,
    pairRoute: invite.pairRoute,
    inviteHash: invite.canonicalSHA256(),
    expiryMilliseconds: invite.expiresAtMilliseconds,
    requestHash: prepared.record.requestHash,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    grantSerial: grantSerial,
    rootTrustEpoch: trustEpoch
  )
  let context = pairingHandlerContext(kind: .pairResponse, pairRoute: invite.pairRoute)
  let envelope = try RelayCrypto.sealHPKE(
    plaintextBytes,
    recipient: prepared.deviceHPKEPrivateKey.publicKey,
    info: info.canonicalBytes(),
    aad: CanonicalCodec.encodeAAD(context)
  )
  let unsignedResponse = try CanonicalPairResponseV1(
    info: info,
    encapsulatedKey: envelope.enc,
    ciphertext: envelope.ciphertext,
    machineDataSignature: Data(repeating: 0, count: 64),
    requireSignature: false
  )
  let signatureTBS = try PairResponseCrypto.responseSignatureTBS(
    unsignedResponse,
    context: context,
    signingKeyFingerprint: CanonicalCodec.sha256(certificate.subjectPubkey),
    signingKeyGeneration: certificate.generation,
    signingCredentialSHA256: SignedCertificateCanonicalCodec.canonicalSHA256(
      certificate
    )
  )
  return try PairResponseCanonicalCodec.encode(
    CanonicalPairResponseV1(
      info: info,
      encapsulatedKey: envelope.enc,
      ciphertext: envelope.ciphertext,
      machineDataSignature: dataKey.signature(for: signatureTBS)
    )
  )
}

private func pairingHandlerRequestInfo(invite: PairInviteV1) throws -> PairRequestInfoV1 {
  try PairRequestInfoV1(
    relayServerID: invite.relayServerID,
    pairRoute: invite.pairRoute,
    inviteHash: invite.canonicalSHA256(),
    expiryMilliseconds: invite.expiresAtMilliseconds
  )
}

private func pairingHandlerContext(
  kind: OuterFrameKind,
  pairRoute: Data
) -> OuterContextV1 {
  OuterContextV1(
    frameKind: kind,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: nil,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: 0,
    pairRoute: pairRoute
  )
}

private func pairingHandlerSealControl(
  _ plaintext: Data,
  recipient: Curve25519.KeyAgreement.PublicKey,
  info: Data,
  context: OuterContextV1
) throws -> Data {
  let sealed = try RelayCrypto.sealHPKE(
    plaintext,
    recipient: recipient,
    info: info,
    aad: CanonicalCodec.encodeAAD(context)
  )
  return try PairTerminalEnvelopeCodec.encode(
    CanonicalPairingControlEnvelopeV1(
      formatVersion: 1,
      encapsulatedKey: sealed.enc,
      ciphertext: sealed.ciphertext
    )
  )
}

private enum PairingHandlerTestError: Error {
  case noTransport
  case unexpectedPhase
  case unexpectedFrame
  case invalidRequestProof
}
