import AgentDeckCore
import CryptoKit
import Dispatch
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class ProductionMachineConnectionVerifiedIngressTests: XCTestCase {
  func testColdOpenResumeAndSignedDirectedReplyCompletesWaiter() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(1)

    let resume = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 17
    )
    XCTAssertTrue(resume.isEmpty)
    let messageID = RuntimeMessageID(rawValue: "production-directed-1")
    let prepared = try await ingress.prepareDirected(
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .request(.catalog(pageCursor: nil))
      ),
      contract: .revocation(expectedGrantSerial: fixture.material.record.grantSerial),
      scope: scope
    )
    let outbound = try productionIngressSend(prepared.frame)
    XCTAssertEqual(outbound.deviceRoute, fixture.crypto.deviceRoute)

    async let awaitedReply = ingress.awaitDirectedReply(prepared.token, scope: scope)
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: outbound.requestRoute)
          )
        ),
        scope: scope
      )
    )
    let reply = RuntimeReplyV2.revocation(
      .committed(RuntimeGrantSerial(rawValue: fixture.material.record.grantSerial))
    )
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressRuntimeReplyFrame(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: outbound.requestRoute,
          envelope: RuntimeEnvelopeV2(
            version: runtimeProtocolVersionCurrent,
            messageID: messageID,
            body: .reply(reply)
          ),
          counter: 1
        ),
        scope: scope
      )
    )

    switch try await awaitedReply {
    case .revocation(.committed(let serial)):
      XCTAssertEqual(serial.rawValue, fixture.material.record.grantSerial)
    default:
      XCTFail("waiter must receive the exact verified directed reply")
    }
    let actions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(actions.isEmpty)
  }

  func testVerifiedPreSubscriptionFailureCommitsOwnerAndMapsRetryPolicy() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(79)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 17
    )

    let fencedMessageID = RuntimeMessageID(rawValue: "subscription-fenced")
    let fencedPrepared = try await ingress.prepareSubscription(
      target: .catalog,
      after: .beforeFirst,
      requestID: fencedMessageID,
      scope: scope
    )
    let fencedPendingBeforeReply = try await ingress.preparedSubscriptionIsPending(
      fencedPrepared.token,
      scope: scope
    )
    XCTAssertTrue(fencedPendingBeforeReply)
    let fencedOutbound = try productionIngressSend(fencedPrepared.frame)
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: fencedOutbound.requestRoute)
          )
        ),
        scope: scope
      )
    )
    let fencedOutcome = try await ingress.receive(
      try productionIngressRuntimeReplyFrame(
        fixture: fixture,
        generation: scope.generation,
        requestRoute: fencedOutbound.requestRoute,
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: fencedMessageID,
          body: .reply(
            .failure(
              RuntimeFailureV1(
                code: "daemon.remote.transition.business_fenced",
                message: "business requests remain fenced"
              )
            )
          )
        ),
        counter: 1
      ),
      scope: scope
    )
    guard case .relayUnavailable = fencedOutcome else {
      return XCTFail("transition fence 必须成为可重连 transient outcome")
    }
    let fencedPendingAfterReply = try await ingress.preparedSubscriptionIsPending(
      fencedPrepared.token,
      scope: scope
    )
    XCTAssertFalse(fencedPendingAfterReply)

    let snapshotMessageID = RuntimeMessageID(rawValue: "subscription-snapshot-required")
    let snapshotPrepared = try await ingress.prepareSubscription(
      target: .catalog,
      after: .at(9),
      requestID: snapshotMessageID,
      scope: scope
    )
    let snapshotOutbound = try productionIngressSend(snapshotPrepared.frame)
    let snapshotOutcome = try await ingress.receive(
      try productionIngressRuntimeReplyFrame(
        fixture: fixture,
        generation: scope.generation,
        requestRoute: snapshotOutbound.requestRoute,
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: snapshotMessageID,
          body: .reply(
            .failure(
              RuntimeFailureV1(
                code: "daemon.runtime.snapshot_required",
                message: "retained range requires a new snapshot"
              )
            )
          )
        ),
        counter: 2
      ),
      scope: scope
    )
    guard
      case .streamRecoveryRequired(
        .catalog(let deliveredRequestID),
        .snapshotRequired
      ) = snapshotOutcome
    else {
      return XCTFail("snapshot prerequisite 必须保留 exact target 并 fresh-recover")
    }
    XCTAssertEqual(deliveredRequestID, snapshotMessageID)

    let retryPrepared = try await ingress.prepareSubscription(
      target: .catalog,
      after: .beforeFirst,
      requestID: RuntimeMessageID(rawValue: "subscription-owner-reused"),
      scope: scope
    )
    await ingress.cancelPrepared(retryPrepared.token, scope: scope)
    let pendingAfterCancel = try await ingress.preparedSubscriptionIsPending(
      retryPrepared.token,
      scope: scope
    )
    XCTAssertFalse(pendingAfterCancel)
  }

  func testExactNextProbeQueuesSignedKeySyncAndDurableUpdateSetQueuesAck() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(2)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 19
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-first"
    )

    let probeOutcome = try await ingress.receive(
      try productionIngressExactNextProbe(
        fixture: fixture,
        generation: scope.generation,
        counter: 1
      ),
      scope: scope
    )
    guard case .keySyncRequired(let observedRevision) = probeOutcome else {
      return XCTFail("exact-next signed probe must request KeySync")
    }
    XCTAssertEqual(observedRevision, fixture.nextRevision)

    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(keySyncActions.count, 1)
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))
    let keySyncControl = try productionIngressOpenDeviceControl(
      keySyncOutbound,
      fixture: fixture
    )
    guard case .keySync(let keySync) = keySyncControl else {
      return XCTFail("first transport action must be a signed KeySync request")
    }
    XCTAssertEqual(keySync.knownKeyDirectoryRevision, fixture.currentRevision)
    XCTAssertEqual(keySync.requestedKeyDirectoryRevision, fixture.nextRevision)
    XCTAssertEqual(keySync.keyID, fixture.nextCatalogKeyID)
    XCTAssertNil(keySync.streamRoute)
    XCTAssertEqual(keySync.attempt, 1)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: keySyncOutbound.requestRoute)
          )
        ),
        scope: scope
      )
    )
    let updateSet = try fixture.nextUpdateSet()
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: keySyncOutbound.requestRoute,
          updateSet: updateSet,
          counter: 4
        ),
        scope: scope
      )
    )

    let loaded = try await fixture.stateStore.load()
    let persisted = try XCTUnwrap(loaded)
    XCTAssertEqual(
      persisted.state.keyLifecycle?.stagedTransition?.toRevision,
      fixture.nextRevision
    )
    XCTAssertEqual(
      persisted.state.keyLifecycle?.stagedTransition?.updateSetSHA256,
      CanonicalCodec.sha256(updateSet)
    )

    let acknowledgementActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(acknowledgementActions.count, 1)
    let acknowledgementOutbound = try productionIngressSend(
      try XCTUnwrap(acknowledgementActions.first)
    )
    let acknowledgement = try productionIngressOpenDeviceControl(
      acknowledgementOutbound,
      fixture: fixture
    )
    guard case .keyUpdateAck(let ack) = acknowledgement else {
      return XCTFail("durable UpdateSet readback must mint one signed KeyUpdateAck")
    }
    XCTAssertEqual(ack.keyDirectoryRevision, fixture.nextRevision)
    XCTAssertEqual(ack.updateSetSHA256, CanonicalCodec.sha256(updateSet))
    XCTAssertEqual(ack.authority.machineRoute, fixture.crypto.machineRoute)
    XCTAssertEqual(ack.authority.deviceRoute, fixture.crypto.deviceRoute)
  }

  func testExactDuplicateUpdateSetResendsSignedAckWithoutRestagingAndReconnectRecoversAck()
    async throws
  {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(7)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 41
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-duplicate"
    )

    guard
      case .keySyncRequired = try await ingress.receive(
        try productionIngressExactNextProbe(
          fixture: fixture,
          generation: scope.generation,
          counter: 1
        ),
        scope: scope
      )
    else {
      return XCTFail("fixture must begin exact-next KeySync")
    }
    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))
    let updateSet = try fixture.nextUpdateSet()
    let exactReply = try productionIngressKeyUpdateReply(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: keySyncOutbound.requestRoute,
      updateSet: updateSet,
      counter: 4
    )
    try await assertProductionIngressIgnored(
      ingress.receive(exactReply, scope: scope)
    )

    let firstActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(firstActions.count, 1)
    let firstOutbound = try productionIngressSend(try XCTUnwrap(firstActions.first))
    let firstAck = try productionIngressOpenDeviceControl(firstOutbound, fixture: fixture)
    guard case .keyUpdateAck = firstAck else {
      return XCTFail("first durable stage must emit KeyUpdateAck")
    }
    let stagedValue = try await fixture.stateStore.load()
    let staged = try XCTUnwrap(stagedValue)

    try await assertProductionIngressIgnored(
      ingress.receive(exactReply, scope: scope)
    )
    let retryActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(retryActions.count, 1)
    let retryOutbound = try productionIngressSend(try XCTUnwrap(retryActions.first))
    XCTAssertNotEqual(retryOutbound.requestRoute, firstOutbound.requestRoute)
    XCTAssertEqual(
      try productionIngressOpenDeviceControl(retryOutbound, fixture: fixture),
      firstAck
    )
    let afterDuplicateValue = try await fixture.stateStore.load()
    let afterDuplicate = try XCTUnwrap(afterDuplicateValue)
    XCTAssertEqual(afterDuplicate.commitment, staged.commitment)
    XCTAssertEqual(
      afterDuplicate.state.keyLifecycle?.stagedTransition?.updateSetSHA256,
      CanonicalCodec.sha256(updateSet)
    )
    XCTAssertEqual(
      afterDuplicate.state.senderCounter.keyDirectoryRevision,
      fixture.currentRevision,
      "duplicate ACK must not activate the staged revision"
    )

    await ingress.generationEnded(scope: scope)
    let resumedScope = productionIngressScope(8)
    let resume = try await ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 43
    )
    XCTAssertEqual(resume.count, 1)
    let recoveredOutbound = try productionIngressSend(try XCTUnwrap(resume.first))
    XCTAssertEqual(
      try productionIngressOpenDeviceControl(recoveredOutbound, fixture: fixture),
      firstAck
    )
    let afterResumeValue = try await fixture.stateStore.load()
    let afterResume = try XCTUnwrap(afterResumeValue)
    XCTAssertEqual(afterResume.commitment, staged.commitment)
    XCTAssertEqual(afterResume.state.keySyncEpisode, staged.state.keySyncEpisode)

    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: resumedScope,
      name: "key-sync-staged-rebind",
      firstCounter: 5
    )
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressCatalogPublishFrame(
          fixture: fixture,
          generation: resumedScope.generation,
          streamRoute: productionIngressKeySyncStreamRoute,
          streamGeneration: productionIngressKeySyncStreamGeneration,
          streamSequence: 0,
          catalogRevision: 0,
          counter: 2
        ),
        scope: resumedScope
      )
    )
    let pausedReadbackValue = try await fixture.stateStore.load()
    let pausedReadback = try XCTUnwrap(pausedReadbackValue)
    XCTAssertEqual(pausedReadback.state.streamStates[0].outerCursor, .beforeFirst)
    XCTAssertEqual(pausedReadback.state.keySyncEpisode, staged.state.keySyncEpisode)

    let barrier = try DeviceEpochBarrierV1(
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamCursor: .beforeFirst,
      innerCursor: .catalog(.beforeFirst),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: fixture.nextRevision
    )
    let activation = try await ingress.receive(
      try productionIngressEpochBarrierPublish(
        fixture: fixture,
        generation: resumedScope.generation,
        barrier: barrier,
        counter: 2
      ),
      scope: resumedScope
    )
    guard
      case .keySyncSucceeded(_, let recoveryTargets) = activation,
      recoveryTargets.count == 1,
      case .catalog = recoveryTargets[0]
    else {
      return XCTFail("rebind must restore the latest affected-stream recovery target")
    }
  }

  func testKeySyncAbsoluteDeadlineDoesNotResetAcrossRetryAndFailsClosedAtThirtySeconds()
    async throws
  {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let clock = ProductionIngressMutableClock(
      nowMS: ProductionIngressCryptoFixture.fixedTimeMS
    )
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { clock.nowMS }
    )
    let scope = productionIngressScope(9)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 47
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-deadline"
    )
    guard
      case .keySyncRequired = try await ingress.receive(
        try productionIngressExactNextProbe(
          fixture: fixture,
          generation: scope.generation,
          counter: 1
        ),
        scope: scope
      )
    else {
      return XCTFail("fixture must begin exact-next KeySync")
    }
    let firstActions = try await ingress.drainTransportActions(scope: scope)
    let firstOutbound = try productionIngressSend(try XCTUnwrap(firstActions.first))

    clock.setNowMS(ProductionIngressCryptoFixture.fixedTimeMS + 29_999)
    let directoryCurrent = try DaemonDirectoryCurrentV1(
      authority: DeviceKeyControlAuthorityV1(
        machineRoute: fixture.crypto.machineRoute,
        deviceRoute: fixture.crypto.deviceRoute,
        grantSerial: fixture.material.record.grantSerial,
        rootTrustEpoch: fixture.material.record.trustEpoch
      ),
      currentKeyDirectoryRevision: fixture.currentRevision,
      requestedKeyDirectoryRevision: fixture.nextRevision
    )
    guard
      case .keySyncAttemptFailed(let revision) = try await ingress.receive(
        try productionIngressExactNextKeySyncReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: firstOutbound.requestRoute,
          control: .directoryCurrent(directoryCurrent),
          counter: 4
        ),
        scope: scope
      )
    else {
      return XCTFail("DirectoryCurrent before the deadline must consume one retry")
    }
    XCTAssertEqual(revision, fixture.nextRevision)
    let retryActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(retryActions.count, 1)
    let retryOutbound = try productionIngressSend(try XCTUnwrap(retryActions.first))
    guard
      case .keySync(let retry) = try productionIngressOpenDeviceControl(
        retryOutbound,
        fixture: fixture
      )
    else {
      return XCTFail("retry must be a signed KeySync request")
    }
    XCTAssertEqual(retry.attempt, 2)
    let beforeTimeoutValue = try await fixture.stateStore.load()
    let beforeTimeout = try XCTUnwrap(beforeTimeoutValue)

    clock.setNowMS(ProductionIngressCryptoFixture.fixedTimeMS + 30_000)
    do {
      _ = try await ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: retryOutbound.requestRoute,
          updateSet: fixture.nextUpdateSet(),
          counter: 5
        ),
        scope: scope
      )
      XCTFail("the half-open 30 second deadline must fail closed at its boundary")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .keySyncTimedOut
      )
    }
    let afterTimeoutValue = try await fixture.stateStore.load()
    let afterTimeout = try XCTUnwrap(afterTimeoutValue)
    XCTAssertEqual(afterTimeout.commitment, beforeTimeout.commitment)
    XCTAssertNil(afterTimeout.state.keyLifecycle?.stagedTransition)
    let timeoutActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(timeoutActions.isEmpty)
  }

  func testWrongRouteAndSignatureDoNotStageOrQueueAcknowledgement() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(3)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 23
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-failure"
    )
    let probeOutcome = try await ingress.receive(
      try productionIngressExactNextProbe(
        fixture: fixture,
        generation: scope.generation,
        counter: 1
      ),
      scope: scope
    )
    guard case .keySyncRequired = probeOutcome else {
      return XCTFail("fixture must establish a pending KeySync request")
    }
    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))
    let updateSet = try fixture.nextUpdateSet()
    let stableBeforeFailureValue = try await fixture.stateStore.load()
    let stableBeforeFailure = try XCTUnwrap(stableBeforeFailureValue)

    var wrongRoute = keySyncOutbound.requestRoute
    wrongRoute[wrongRoute.startIndex] ^= 0x01
    do {
      _ = try await ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: keySyncOutbound.requestRoute,
          outerRequestRoute: wrongRoute,
          updateSet: updateSet,
          counter: 4
        ),
        scope: scope
      )
      XCTFail("outer requestRoute substitution must fail closed")
    } catch {
      XCTAssertEqual(error as? RelayCryptoError, .badSignature)
    }
    let afterWrongRouteValue = try await fixture.stateStore.load()
    let afterWrongRoute = try XCTUnwrap(afterWrongRouteValue)
    XCTAssertEqual(afterWrongRoute.commitment, stableBeforeFailure.commitment)
    XCTAssertNil(afterWrongRoute.state.keyLifecycle?.stagedTransition)
    let wrongRouteActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(wrongRouteActions.isEmpty)

    do {
      _ = try await ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: keySyncOutbound.requestRoute,
          updateSet: updateSet,
          counter: 4,
          tamperSignature: true
        ),
        scope: scope
      )
      XCTFail("tampered MachineDataSign must fail closed")
    } catch {
      XCTAssertEqual(error as? RelayCryptoError, .badSignature)
    }
    let afterBadSignatureValue = try await fixture.stateStore.load()
    let afterBadSignature = try XCTUnwrap(afterBadSignatureValue)
    XCTAssertEqual(afterBadSignature.commitment, stableBeforeFailure.commitment)
    XCTAssertNil(afterBadSignature.state.keyLifecycle?.stagedTransition)
    let badSignatureActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(badSignatureActions.isEmpty)
  }

  func testKeySyncPausesOnlyAffectedStreamAndRecoversOnlyItsTarget() async throws {
    let conversationRoute = Data(repeating: 0xD1, count: 16)
    let conversationGeneration = Data(repeating: 0xD2, count: 16)
    let conversationID = RuntimeConversationID(rawValue: "key-sync-unaffected")
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: [conversationRoute]
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [conversationRoute],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(30)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 29
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-affected-catalog"
    )
    _ = try await productionIngressBootstrapConversation(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "key-sync-unaffected-conversation"),
      conversationID: conversationID,
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      firstCounter: 4
    )

    let initialCatalog = try await ingress.receive(
      try productionIngressCatalogPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        streamRoute: productionIngressKeySyncStreamRoute,
        streamGeneration: productionIngressKeySyncStreamGeneration,
        streamSequence: 0,
        catalogRevision: 0,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let initialCatalogDelivery) = initialCatalog else {
      return XCTFail("catalog fixture must establish a durable cut")
    }
    try await ingress.commit(initialCatalogDelivery)
    try await ingress.awaitResolution(initialCatalogDelivery)
    _ = try await ingress.drainTransportActions(scope: scope)

    let initialConversation = try await ingress.receive(
      try productionIngressConversationPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        conversationID: conversationID,
        streamRoute: conversationRoute,
        streamGeneration: conversationGeneration,
        streamSequence: 0,
        eventSequence: 0,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let initialConversationDelivery) = initialConversation else {
      return XCTFail("conversation fixture must establish a durable cut")
    }
    try await ingress.commit(initialConversationDelivery)
    try await ingress.awaitResolution(initialConversationDelivery)
    _ = try await ingress.drainTransportActions(scope: scope)

    guard
      case .keySyncRequired = try await ingress.receive(
        try productionIngressExactNextProbe(
          fixture: fixture,
          generation: scope.generation,
          counter: 1
        ),
        scope: scope
      )
    else {
      return XCTFail("catalog next revision must begin KeySync")
    }
    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressCatalogPublishFrame(
          fixture: fixture,
          generation: scope.generation,
          streamRoute: productionIngressKeySyncStreamRoute,
          streamGeneration: productionIngressKeySyncStreamGeneration,
          streamSequence: 1,
          catalogRevision: 1,
          counter: 2
        ),
        scope: scope
      )
    )
    let afterPausedValue = try await fixture.stateStore.load()
    let afterPaused = try XCTUnwrap(afterPausedValue)
    let catalogState = try XCTUnwrap(
      afterPaused.state.streamStates.first(where: {
        $0.streamRoute == productionIngressKeySyncStreamRoute
      })
    )
    XCTAssertEqual(catalogState.outerCursor, .at(0))
    XCTAssertEqual(catalogState.innerCursor, .catalog(.at(0)))

    let unaffected = try await ingress.receive(
      try productionIngressConversationPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        conversationID: conversationID,
        streamRoute: conversationRoute,
        streamGeneration: conversationGeneration,
        streamSequence: 1,
        eventSequence: 1,
        counter: 2
      ),
      scope: scope
    )
    guard case .delivery(let unaffectedDelivery) = unaffected else {
      return XCTFail("其它 current-key stream 必须在 KeySync 期间继续 delivery")
    }
    try await ingress.commit(unaffectedDelivery)
    try await ingress.awaitResolution(unaffectedDelivery)
    let unaffectedActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(unaffectedActions.count, 1)
    guard
      case .ack(let unaffectedRoute, let unaffectedGeneration, let unaffectedSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(unaffectedActions.first)).body
    else {
      return XCTFail("unaffected durable Publish must ACK normally")
    }
    XCTAssertEqual(unaffectedRoute, conversationRoute)
    XCTAssertEqual(unaffectedGeneration, conversationGeneration)
    XCTAssertEqual(unaffectedSequence, 1)

    let updateSet = try fixture.nextUpdateSet()
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: keySyncOutbound.requestRoute,
          updateSet: updateSet,
          counter: 7
        ),
        scope: scope
      )
    )
    let updateAckActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(updateAckActions.count, 1)

    let barrier = try DeviceEpochBarrierV1(
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamCursor: .at(0),
      innerCursor: .catalog(.at(0)),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: fixture.nextRevision
    )
    let activation = try await ingress.receive(
      try productionIngressEpochBarrierPublish(
        fixture: fixture,
        generation: scope.generation,
        barrier: barrier,
        counter: 2
      ),
      scope: scope
    )
    guard
      case .keySyncSucceeded(let acceptedRevision, let recoveryTargets) = activation,
      acceptedRevision == fixture.nextRevision,
      recoveryTargets.count == 1,
      case .catalog = recoveryTargets[0]
    else {
      return XCTFail("activation must recover only the affected catalog target")
    }
    let activationActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(activationActions.count, 2)
    let deviceAckOutbound = try productionIngressSend(activationActions[0])
    guard
      case .streamAppliedAck(let deviceAck) = try productionIngressOpenDeviceControl(
        deviceAckOutbound,
        fixture: fixture
      )
    else {
      return XCTFail("durable barrier must emit Device StreamAppliedAck first")
    }
    XCTAssertEqual(deviceAck.streamRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(deviceAck.streamGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(deviceAck.appliedStreamSequence, 1)
    guard
      case .ack(let relayAckRoute, let relayAckGeneration, let relayAckSequence) =
        try productionIngressDecodedFrame(activationActions[1]).body
    else {
      return XCTFail("durable barrier must also emit Relay outer ACK")
    }
    XCTAssertEqual(relayAckRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(relayAckGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(relayAckSequence, 1)

    let activatedValue = try await fixture.stateStore.load()
    let activated = try XCTUnwrap(activatedValue)
    XCTAssertNil(activated.state.keySyncEpisode)
    XCTAssertEqual(activated.state.senderCounter.keyDirectoryRevision, fixture.nextRevision)
    let activatedConversation = try XCTUnwrap(
      activated.state.streamStates.first(where: { $0.streamRoute == conversationRoute })
    )
    XCTAssertEqual(activatedConversation.outerCursor, .at(1))

    await ingress.generationEnded(scope: scope)
    let resumedScope = productionIngressScope(31)
    let recoveredFrames = try await ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 29
    )
    XCTAssertEqual(recoveredFrames.count, 1)
    let recoveredDeviceAck = try productionIngressSend(
      try XCTUnwrap(recoveredFrames.first)
    )
    guard
      case .streamAppliedAck(let recoveredAck) = try productionIngressOpenDeviceControl(
        recoveredDeviceAck,
        fixture: fixture
      )
    else {
      return XCTFail("cold-open must recover durable StreamAppliedAck basis")
    }
    XCTAssertEqual(recoveredAck.epochBarrierSHA256, barrier.canonicalSHA256)

    let rebound = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: resumedScope,
      messageID: RuntimeMessageID(rawValue: "key-sync-activated-rebind"),
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      firstCounter: 8,
      after: .at(0),
      synchronizedOuterCursor: .at(1),
      bindingCursor: .at(1),
      keyDirectoryRevision: fixture.nextRevision,
      catalogKeyEpoch: 2
    )
    XCTAssertEqual(rebound.count, 2)
    guard
      case .subscribe = try productionIngressDecodedFrame(rebound[0]).body,
      case .ack(_, _, let reboundSequence) =
        try productionIngressDecodedFrame(rebound[1]).body
    else {
      return XCTFail("cold-open binding must restore Relay lease then cumulative ACK")
    }
    XCTAssertEqual(reboundSequence, 1)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressEpochBarrierPublish(
          fixture: fixture,
          generation: resumedScope.generation,
          barrier: barrier,
          counter: 2
        ),
        scope: resumedScope
      )
    )
    let duplicateBarrierActions = try await ingress.drainTransportActions(scope: resumedScope)
    XCTAssertEqual(duplicateBarrierActions.count, 1)
    guard
      case .ack(_, _, let duplicateBarrierSequence) =
        try productionIngressDecodedFrame(duplicateBarrierActions[0]).body
    else {
      return XCTFail("in-flight semantic ACK must single-flight and only replenish Relay ACK")
    }
    XCTAssertEqual(duplicateBarrierSequence, 1)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: resumedScope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: recoveredDeviceAck.requestRoute)
          )
        ),
        scope: resumedScope
      )
    )
    let actionsAfterRecoveredAcceptance = try await ingress.drainTransportActions(
      scope: resumedScope
    )
    XCTAssertTrue(actionsAfterRecoveredAcceptance.isEmpty)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressEpochBarrierPublish(
          fixture: fixture,
          generation: resumedScope.generation,
          barrier: barrier,
          counter: 2
        ),
        scope: resumedScope
      )
    )
    let acceptedDuplicateActions = try await ingress.drainTransportActions(scope: resumedScope)
    XCTAssertEqual(acceptedDuplicateActions.count, 2)
    _ = try productionIngressSend(acceptedDuplicateActions[0])
    guard
      case .ack(_, _, let acceptedDuplicateSequence) =
        try productionIngressDecodedFrame(acceptedDuplicateActions[1]).body
    else {
      return XCTFail("accepted semantic ACK slot must allow exact duplicate to recover both layers")
    }
    XCTAssertEqual(acceptedDuplicateSequence, 1)

    let replacementSemanticAck = try productionIngressSend(acceptedDuplicateActions[0])
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: resumedScope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: replacementSemanticAck.requestRoute)
          )
        ),
        scope: resumedScope
      )
    )
    let actionsAfterReplacementAcceptance = try await ingress.drainTransportActions(
      scope: resumedScope
    )
    XCTAssertTrue(actionsAfterReplacementAcceptance.isEmpty)

    let replacementRoute = Data(repeating: 0xDA, count: 16)
    let replacementGeneration = Data(repeating: 0xDB, count: 16)
    let replacementBindingActions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: resumedScope,
      messageID: RuntimeMessageID(rawValue: "key-sync-physical-rebind"),
      streamRoute: replacementRoute,
      streamGeneration: replacementGeneration,
      firstCounter: 11,
      after: .at(0),
      synchronizedOuterCursor: .at(0),
      bindingCursor: .at(0),
      keyDirectoryRevision: fixture.nextRevision,
      catalogKeyEpoch: 2
    )
    XCTAssertEqual(replacementBindingActions.count, 3)
    guard
      case .unsubscribe(let retiredRoute, let retiredGeneration) =
        try productionIngressDecodedFrame(replacementBindingActions[0]).body,
      case .subscribe(let replacementSubscribedRoute, let replacementSubscribedGeneration, _) =
        try productionIngressDecodedFrame(replacementBindingActions[1]).body
    else {
      return XCTFail(
        "physical rebind must unsubscribe the proof route before subscribing replacement")
    }
    XCTAssertEqual(retiredRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(retiredGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(replacementSubscribedRoute, replacementRoute)
    XCTAssertEqual(replacementSubscribedGeneration, replacementGeneration)
    guard
      case .ack(let replacementAckRoute, let replacementAckGeneration, let replacementAckSequence) =
        try productionIngressDecodedFrame(replacementBindingActions[2]).body
    else {
      return XCTFail("physical rebind must restore the replacement cumulative ACK last")
    }
    XCTAssertEqual(replacementAckRoute, replacementRoute)
    XCTAssertEqual(replacementAckGeneration, replacementGeneration)
    XCTAssertEqual(replacementAckSequence, 0)

    let physicallyReboundValue = try await fixture.stateStore.load()
    let physicallyRebound = try XCTUnwrap(physicallyReboundValue)
    XCTAssertFalse(
      physicallyRebound.state.streamStates.contains(where: {
        $0.streamRoute == productionIngressKeySyncStreamRoute
          && $0.generation == productionIngressKeySyncStreamGeneration
      })
    )
    XCTAssertTrue(
      physicallyRebound.state.streamStates.contains(where: {
        $0.streamRoute == replacementRoute && $0.generation == replacementGeneration
      })
    )

    await ingress.generationEnded(scope: resumedScope)
    let physicallyResumedScope = productionIngressScope(32)
    let proofRecovery = try await ingress.resumeFrames(
      generation: physicallyResumedScope.generation,
      scope: physicallyResumedScope,
      heartbeatIntervalSeconds: 29
    )
    XCTAssertEqual(proofRecovery.count, 1)
    let physicallyRecoveredSemanticAck = try productionIngressSend(
      try XCTUnwrap(proofRecovery.first)
    )
    guard
      case .streamAppliedAck(let physicallyRecoveredAck) =
        try productionIngressOpenDeviceControl(physicallyRecoveredSemanticAck, fixture: fixture)
    else {
      return XCTFail("cold-open after physical rebind must retain durable proof ACK basis")
    }
    XCTAssertEqual(physicallyRecoveredAck.epochBarrierSHA256, barrier.canonicalSHA256)

    let physicallyReboundLease = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: physicallyResumedScope,
      messageID: RuntimeMessageID(rawValue: "key-sync-physical-rebind-resumed"),
      streamRoute: replacementRoute,
      streamGeneration: replacementGeneration,
      firstCounter: 14,
      after: .at(0),
      synchronizedOuterCursor: .at(0),
      bindingCursor: .at(0),
      keyDirectoryRevision: fixture.nextRevision,
      catalogKeyEpoch: 2
    )
    XCTAssertEqual(physicallyReboundLease.count, 2)
    guard
      case .subscribe(let resumedRoute, let resumedGeneration, _) =
        try productionIngressDecodedFrame(physicallyReboundLease[0]).body
    else {
      return XCTFail("reconnect must restore only the replacement physical lease")
    }
    XCTAssertEqual(resumedRoute, replacementRoute)
    XCTAssertEqual(resumedGeneration, replacementGeneration)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: physicallyResumedScope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: physicallyRecoveredSemanticAck.requestRoute)
          )
        ),
        scope: physicallyResumedScope
      )
    )
    let actionsAfterPhysicalRecoveryAcceptance = try await ingress.drainTransportActions(
      scope: physicallyResumedScope
    )
    XCTAssertTrue(actionsAfterPhysicalRecoveryAcceptance.isEmpty)

    let beforeOldRouteProbeValue = try await fixture.stateStore.load()
    let beforeOldRouteProbe = try XCTUnwrap(beforeOldRouteProbeValue)
    let oldRouteOrdinaryData = try productionIngressCatalogPublishFrame(
      fixture: fixture,
      generation: physicallyResumedScope.generation,
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamSequence: barrier.appliedStreamSequence,
      catalogRevision: 1,
      counter: 3,
      keyDirectoryRevision: fixture.nextRevision,
      keyEpoch: 2,
      rawKeyByte: 0x51
    )
    do {
      _ = try await ingress.receive(
        oldRouteOrdinaryData,
        scope: physicallyResumedScope
      )
      XCTFail("fresh ordinary data must not cross the proof alias replay gate")
    } catch {
      XCTAssertEqual(
        error as? MachineDataVerifierError,
        .activatedPendingReplayAdmissionRequired
      )
    }
    let freshOldRouteActions = try await ingress.drainTransportActions(
      scope: physicallyResumedScope
    )
    XCTAssertTrue(freshOldRouteActions.isEmpty)

    do {
      _ = try await ingress.receive(
        oldRouteOrdinaryData,
        scope: physicallyResumedScope
      )
      XCTFail("exact replay must still match the durable key-control proof payload")
    } catch {
      XCTAssertEqual(error as? MachineDataVerifierError, .activationProofMismatch)
    }
    let duplicateOldRouteActions = try await ingress.drainTransportActions(
      scope: physicallyResumedScope
    )
    XCTAssertTrue(duplicateOldRouteActions.isEmpty)
    let afterOldRouteProbeValue = try await fixture.stateStore.load()
    let afterOldRouteProbe = try XCTUnwrap(afterOldRouteProbeValue)
    XCTAssertEqual(afterOldRouteProbe.state.streamStates, beforeOldRouteProbe.state.streamStates)
    XCTAssertEqual(afterOldRouteProbe.state.keyLifecycle, beforeOldRouteProbe.state.keyLifecycle)
    XCTAssertEqual(afterOldRouteProbe.state.senderCounter, beforeOldRouteProbe.state.senderCounter)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressEpochBarrierPublish(
          fixture: fixture,
          generation: physicallyResumedScope.generation,
          barrier: barrier,
          counter: 2
        ),
        scope: physicallyResumedScope
      )
    )
    let oldProofAliasActions = try await ingress.drainTransportActions(
      scope: physicallyResumedScope
    )
    XCTAssertEqual(oldProofAliasActions.count, 2)
    let aliasSemanticOutbound = try productionIngressSend(oldProofAliasActions[0])
    guard
      case .streamAppliedAck(let aliasSemanticAck) =
        try productionIngressOpenDeviceControl(aliasSemanticOutbound, fixture: fixture),
      case .ack(let proofRoute, let proofGeneration, let proofSequence) =
        try productionIngressDecodedFrame(oldProofAliasActions[1]).body
    else {
      return XCTFail("accepted old-route proof alias must recover semantic then outer ACK")
    }
    XCTAssertEqual(aliasSemanticAck.epochBarrierSHA256, barrier.canonicalSHA256)
    XCTAssertEqual(aliasSemanticAck.streamRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(aliasSemanticAck.streamGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(aliasSemanticAck.appliedStreamSequence, 1)
    XCTAssertEqual(proofRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(proofGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(proofSequence, 1)
  }

  func testTwoSlotKeySyncPartiallyActivatesCatalogBeforeConversationFinalizesRevision()
    async throws
  {
    let conversationRoute = Data(repeating: 0xD8, count: 16)
    let conversationGeneration = Data(repeating: 0xD9, count: 16)
    let conversationID = RuntimeConversationID(rawValue: "key-sync-partial-conversation")
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: [conversationRoute]
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [conversationRoute],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(64)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "key-sync-partial-catalog"
    )
    _ = try await productionIngressBootstrapConversation(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "key-sync-partial-conversation-subscribe"),
      conversationID: conversationID,
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      firstCounter: 4
    )

    let initialCatalog = try await ingress.receive(
      try productionIngressCatalogPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        streamRoute: productionIngressKeySyncStreamRoute,
        streamGeneration: productionIngressKeySyncStreamGeneration,
        streamSequence: 0,
        catalogRevision: 0,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let initialCatalogDelivery) = initialCatalog else {
      return XCTFail("catalog fixture must establish its current-revision cut")
    }
    try await ingress.commit(initialCatalogDelivery)
    try await ingress.awaitResolution(initialCatalogDelivery)
    _ = try await ingress.drainTransportActions(scope: scope)

    let initialConversation = try await ingress.receive(
      try productionIngressConversationPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        conversationID: conversationID,
        streamRoute: conversationRoute,
        streamGeneration: conversationGeneration,
        streamSequence: 0,
        eventSequence: 0,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let initialConversationDelivery) = initialConversation else {
      return XCTFail("conversation fixture must establish its current-revision cut")
    }
    try await ingress.commit(initialConversationDelivery)
    try await ingress.awaitResolution(initialConversationDelivery)
    _ = try await ingress.drainTransportActions(scope: scope)

    guard
      case .keySyncRequired = try await ingress.receive(
        try productionIngressExactNextProbe(
          fixture: fixture,
          generation: scope.generation,
          counter: 1
        ),
        scope: scope
      )
    else {
      return XCTFail("catalog next revision must begin the two-slot KeySync")
    }
    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressKeyUpdateReply(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: keySyncOutbound.requestRoute,
          updateSet: fixture.rotatingConversationUpdateSet(route: conversationRoute),
          counter: 7
        ),
        scope: scope
      )
    )
    let updateAckActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(updateAckActions.count, 1)

    let catalogBarrier = try DeviceEpochBarrierV1(
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamCursor: .at(0),
      innerCursor: .catalog(.at(0)),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: fixture.nextRevision
    )
    let partial = try await ingress.receive(
      try productionIngressEpochBarrierPublish(
        fixture: fixture,
        generation: scope.generation,
        barrier: catalogBarrier,
        counter: 2
      ),
      scope: scope
    )
    guard case .streamRecoveryRequired(.catalog, .snapshotRequired) = partial else {
      return XCTFail("first barrier must recover only the activated catalog stream")
    }
    let partialActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(partialActions.count, 2)
    let catalogSemanticAck = try productionIngressSend(partialActions[0])
    guard
      case .streamAppliedAck(let partialDeviceAck) = try productionIngressOpenDeviceControl(
        catalogSemanticAck,
        fixture: fixture
      ),
      case .ack(let partialRoute, let partialGeneration, let partialSequence) =
        try productionIngressDecodedFrame(partialActions[1]).body
    else {
      return XCTFail("partial activation must queue semantic then outer ACK")
    }
    XCTAssertEqual(partialDeviceAck.epochBarrierSHA256, catalogBarrier.canonicalSHA256)
    XCTAssertEqual(partialRoute, productionIngressKeySyncStreamRoute)
    XCTAssertEqual(partialGeneration, productionIngressKeySyncStreamGeneration)
    XCTAssertEqual(partialSequence, 1)

    let partiallyActivatedValue = try await fixture.stateStore.load()
    let partiallyActivated = try XCTUnwrap(partiallyActivatedValue)
    let partialLifecycle = try XCTUnwrap(partiallyActivated.state.keyLifecycle)
    XCTAssertNotNil(partialLifecycle.stagedTransition)
    XCTAssertNotNil(partiallyActivated.state.keySyncEpisode)
    XCTAssertEqual(
      partiallyActivated.state.senderCounter.keyDirectoryRevision,
      fixture.currentRevision
    )
    let partialCatalogSlot = try XCTUnwrap(
      partialLifecycle.slot(purpose: .catalog, streamRoute: nil)
    )
    XCTAssertEqual(partialCatalogSlot.current?.keyID.epoch, 2)
    XCTAssertNil(partialCatalogSlot.staged)
    let partialConversationSlot = try XCTUnwrap(
      partialLifecycle.slot(purpose: .conversationDEK, streamRoute: conversationRoute)
    )
    XCTAssertEqual(partialConversationSlot.current?.keyID.epoch, 1)
    XCTAssertEqual(partialConversationSlot.staged?.keyID.epoch, 2)

    let nextCatalog = try await ingress.receive(
      try productionIngressCatalogPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        streamRoute: productionIngressKeySyncStreamRoute,
        streamGeneration: productionIngressKeySyncStreamGeneration,
        streamSequence: 2,
        catalogRevision: 1,
        counter: 3,
        keyDirectoryRevision: fixture.nextRevision,
        keyEpoch: 2,
        rawKeyByte: 0x51
      ),
      scope: scope
    )
    guard case .delivery(let nextCatalogDelivery) = nextCatalog else {
      return XCTFail("activated catalog slot must decrypt ordinary next-revision data")
    }
    try await ingress.commit(nextCatalogDelivery)
    try await ingress.awaitResolution(nextCatalogDelivery)
    let nextCatalogActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(nextCatalogActions.count, 1)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressEpochBarrierPublish(
          fixture: fixture,
          generation: scope.generation,
          barrier: catalogBarrier,
          counter: 2
        ),
        scope: scope
      )
    )
    let inFlightDuplicateActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(inFlightDuplicateActions.count, 1)
    guard
      case .ack(_, _, let inFlightDuplicateSequence) =
        try productionIngressDecodedFrame(inFlightDuplicateActions[0]).body
    else {
      return XCTFail("in-flight semantic proof must only replenish the Relay ACK")
    }
    XCTAssertEqual(inFlightDuplicateSequence, 1)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: catalogSemanticAck.requestRoute)
          )
        ),
        scope: scope
      )
    )
    let actionsAfterSemanticAcceptance = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(actionsAfterSemanticAcceptance.isEmpty)

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressEpochBarrierPublish(
          fixture: fixture,
          generation: scope.generation,
          barrier: catalogBarrier,
          counter: 2
        ),
        scope: scope
      )
    )
    let acceptedDuplicateActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(acceptedDuplicateActions.count, 2)
    let replacementSemanticAck = try productionIngressSend(acceptedDuplicateActions[0])
    guard
      case .streamAppliedAck(let replacementDeviceAck) =
        try productionIngressOpenDeviceControl(replacementSemanticAck, fixture: fixture),
      case .ack(_, _, let acceptedDuplicateSequence) =
        try productionIngressDecodedFrame(acceptedDuplicateActions[1]).body
    else {
      return XCTFail("accepted semantic slot must let the exact proof recover both ACK layers")
    }
    XCTAssertEqual(replacementDeviceAck.epochBarrierSHA256, catalogBarrier.canonicalSHA256)
    XCTAssertEqual(acceptedDuplicateSequence, 1)

    let conversationBarrier = try DeviceEpochBarrierV1(
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      streamCursor: .at(0),
      innerCursor: .conversation(id: conversationID.rawValue, cursor: .at(0)),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: fixture.nextRevision
    )
    let completed = try await ingress.receive(
      try productionIngressConversationEpochBarrierPublish(
        fixture: fixture,
        generation: scope.generation,
        barrier: conversationBarrier,
        counter: 2
      ),
      scope: scope
    )
    guard
      case .keySyncSucceeded(let acceptedRevision, let recoveryTargets) = completed,
      acceptedRevision == fixture.nextRevision,
      recoveryTargets.count == 1,
      case .conversation(let recoveredConversationID, _) = recoveryTargets[0],
      recoveredConversationID == conversationID
    else {
      return XCTFail("last barrier must finalize the revision and recover only conversation")
    }
    let completionActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(completionActions.count, 2)

    let completedValue = try await fixture.stateStore.load()
    let completedState = try XCTUnwrap(completedValue)
    let completedLifecycle = try XCTUnwrap(completedState.state.keyLifecycle)
    XCTAssertNil(completedLifecycle.stagedTransition)
    XCTAssertNil(completedState.state.keySyncEpisode)
    XCTAssertEqual(completedLifecycle.activeRevision, fixture.nextRevision)
    XCTAssertEqual(
      completedState.state.senderCounter.keyDirectoryRevision,
      fixture.nextRevision
    )
    XCTAssertEqual(
      completedLifecycle.slot(purpose: .catalog, streamRoute: nil)?.current?.keyID.epoch,
      2
    )
    XCTAssertEqual(
      completedLifecycle.slot(
        purpose: .conversationDEK,
        streamRoute: conversationRoute
      )?.current?.keyID.epoch,
      2
    )
  }

  func testRecoveredStreamAppliedAcknowledgementsBatchSixtyFiveAndReplayAfterReconnect()
    async throws
  {
    let routes = (1...65).map { Data(repeating: UInt8($0), count: 16) }
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: routes,
      preactivatedBarrierCount: routes.count
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: routes,
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(62)
    let firstBatch = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    XCTAssertEqual(firstBatch.count, 64)
    var proofHashes = Set<Data>()
    var firstRequestRoute: Data?
    for (index, frame) in firstBatch.enumerated() {
      let outbound = try productionIngressSend(frame)
      if index == 0 { firstRequestRoute = outbound.requestRoute }
      guard
        case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
          outbound,
          fixture: fixture
        )
      else {
        return XCTFail("recovery batch must contain only StreamAppliedAck")
      }
      XCTAssertTrue(proofHashes.insert(acknowledgement.epochBarrierSHA256).inserted)
    }

    do {
      _ = try await ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: Data(repeating: 0xFE, count: 16))
          )
        ),
        scope: scope
      )
      XCTFail("unknown RouteAccepted must not consume a recovery slot")
    } catch {
      XCTAssertEqual(error as? MachineRequestCorrelationError, .unknownRoute)
    }
    let afterUnknown = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(afterUnknown.isEmpty)

    let acceptedRoute = try XCTUnwrap(firstRequestRoute)
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(accepted: .request(requestRoute: acceptedRoute))
        ),
        scope: scope
      )
    )
    let refill = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(refill.count, 1)
    let refillOutbound = try productionIngressSend(try XCTUnwrap(refill.first))
    guard
      case .streamAppliedAck(let refillAcknowledgement) =
        try productionIngressOpenDeviceControl(refillOutbound, fixture: fixture)
    else {
      return XCTFail("exact RouteAccepted must refill exactly the 65th proof")
    }
    XCTAssertTrue(proofHashes.insert(refillAcknowledgement.epochBarrierSHA256).inserted)
    XCTAssertEqual(proofHashes.count, 65)

    await ingress.generationEnded(scope: scope)
    let resumedScope = productionIngressScope(63)
    let replayedBatch = try await ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 31
    )
    XCTAssertEqual(
      replayedBatch.count,
      64,
      "RouteAccepted is flow control only and must not consume durable proof basis"
    )
    let replayedProofs = try Set(
      replayedBatch.map { frame in
        let outbound = try productionIngressSend(frame)
        guard
          case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
            outbound,
            fixture: fixture
          )
        else {
          throw ProductionIngressTestHarnessError.expectedTransportActions
        }
        return acknowledgement.epochBarrierSHA256
      })
    XCTAssertEqual(replayedProofs.count, 64)
    XCTAssertTrue(replayedProofs.isSubset(of: proofHashes))
  }

  func testDirectoryRevisionAdvanceDuplicateUsesExactPredecessorAliasAcrossReconnect()
    async throws
  {
    let conversationRoute = Data(repeating: 0xD7, count: 16)
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: [conversationRoute],
      stagedConversationActivation: conversationRoute
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [conversationRoute],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(64)
    let recoveredUpdateAck = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    XCTAssertEqual(recoveredUpdateAck.count, 1)
    let updateAckOutbound = try productionIngressSend(
      try XCTUnwrap(recoveredUpdateAck.first)
    )
    guard
      case .keyUpdateAck = try productionIngressOpenDeviceControl(
        updateAckOutbound,
        fixture: fixture
      )
    else {
      return XCTFail("cold-open staged activation must recover KeyUpdateAck")
    }

    let streamRoute = productionIngressKeySyncStreamRoute
    let streamGeneration = productionIngressKeySyncStreamGeneration
    _ = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "directory-advance-bootstrap"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 1
    )
    let advance = try DeviceDirectoryRevisionAdvanceV1(
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      streamSequence: 0,
      fromRevision: fixture.currentRevision,
      toRevision: fixture.nextRevision
    )
    let frame = try productionIngressDirectoryRevisionAdvancePublish(
      fixture: fixture,
      generation: scope.generation,
      advance: advance,
      counter: 1
    )
    let activation = try await ingress.receive(frame, scope: scope)
    guard
      case .keySyncSucceeded(let acceptedRevision, let recoveryTargets) = activation,
      acceptedRevision == fixture.nextRevision,
      recoveryTargets.count == 1,
      case .catalog = recoveryTargets[0]
    else {
      return XCTFail("fresh DirectoryRevisionAdvance must activate the staged conversation")
    }
    let firstActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(firstActions.count, 1)
    guard
      case .ack(let firstRoute, let firstGeneration, let firstSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(firstActions.first)).body
    else {
      return XCTFail("durable DirectoryRevisionAdvance must queue its outer ACK")
    }
    XCTAssertEqual(firstRoute, streamRoute)
    XCTAssertEqual(firstGeneration, streamGeneration)
    XCTAssertEqual(firstSequence, 0)
    let committedValue = try await fixture.stateStore.load()
    let committed = try XCTUnwrap(committedValue)
    XCTAssertEqual(committed.state.keyLifecycle?.lastDirectoryAdvanceProof, advance)

    try await assertProductionIngressIgnored(ingress.receive(frame, scope: scope))
    let duplicateActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(duplicateActions.count, 1)
    guard
      case .ack(_, _, let duplicateSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(duplicateActions.first)).body
    else {
      return XCTFail("same-generation predecessor duplicate must recover only outer ACK")
    }
    XCTAssertEqual(duplicateSequence, 0)

    await ingress.generationEnded(scope: scope)
    let resumedScope = productionIngressScope(65)
    let resumedFrames = try await ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 31
    )
    XCTAssertTrue(resumedFrames.isEmpty)
    let rebound = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: resumedScope,
      messageID: RuntimeMessageID(rawValue: "directory-advance-rebind"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 4,
      after: .at(0),
      synchronizedOuterCursor: .at(0),
      bindingCursor: .at(0),
      keyDirectoryRevision: fixture.nextRevision,
      catalogKeyEpoch: 1
    )
    XCTAssertEqual(rebound.count, 2)
    let replayedFrame = try productionIngressDirectoryRevisionAdvancePublish(
      fixture: fixture,
      generation: resumedScope.generation,
      advance: advance,
      counter: 1
    )
    try await assertProductionIngressIgnored(
      ingress.receive(replayedFrame, scope: resumedScope)
    )
    let coldDuplicateActions = try await ingress.drainTransportActions(scope: resumedScope)
    XCTAssertEqual(coldDuplicateActions.count, 1)
    guard
      case .ack(_, _, let coldDuplicateSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(coldDuplicateActions.first)).body
    else {
      return XCTFail("cold-open predecessor alias must recover exact outer ACK")
    }
    XCTAssertEqual(coldDuplicateSequence, 0)
  }

  func testSubscriptionBindingDurableReadbackAndReplacementOrdersTransportActions() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(4)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 29
    )

    let firstRoute = Data(repeating: 0xB1, count: 16)
    let firstGeneration = Data(repeating: 0xB2, count: 16)
    let firstActions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "catalog-bootstrap-first"),
      streamRoute: firstRoute,
      streamGeneration: firstGeneration,
      firstCounter: 1
    )
    XCTAssertEqual(firstActions.count, 1)
    let firstAction = try productionIngressDecodedFrame(try XCTUnwrap(firstActions.first))
    guard
      case .subscribe(
        let subscribedRoute,
        let subscribedGeneration,
        let subscribedCursor
      ) = firstAction.body
    else {
      return XCTFail("first durable binding must emit one Subscribe")
    }
    XCTAssertEqual(subscribedRoute, firstRoute)
    XCTAssertEqual(subscribedGeneration, firstGeneration)
    XCTAssertEqual(subscribedCursor, .beforeFirst)
    let firstReadbackValue = try await fixture.stateStore.load()
    let firstReadback = try XCTUnwrap(firstReadbackValue)
    XCTAssertTrue(firstReadback.state.pendingStreamBindings.isEmpty)
    XCTAssertEqual(firstReadback.state.streamStates.count, 1)
    XCTAssertEqual(firstReadback.state.streamStates[0].streamRoute, firstRoute)
    XCTAssertEqual(firstReadback.state.streamStates[0].generation, firstGeneration)

    let replacementRoute = Data(repeating: 0xB3, count: 16)
    let replacementGeneration = Data(repeating: 0xB4, count: 16)
    let replacementActions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "catalog-bootstrap-replacement"),
      streamRoute: replacementRoute,
      streamGeneration: replacementGeneration,
      firstCounter: 4
    )
    XCTAssertEqual(replacementActions.count, 2)
    let unsubscribe = try productionIngressDecodedFrame(replacementActions[0])
    guard
      case .unsubscribe(let retiredRoute, let retiredGeneration) = unsubscribe.body
    else {
      return XCTFail("replacement must retire the old binding first")
    }
    XCTAssertEqual(retiredRoute, firstRoute)
    XCTAssertEqual(retiredGeneration, firstGeneration)
    let subscribe = try productionIngressDecodedFrame(replacementActions[1])
    guard
      case .subscribe(let liveRoute, let liveGeneration, let liveCursor) = subscribe.body
    else {
      return XCTFail("replacement must subscribe the new binding second")
    }
    XCTAssertEqual(liveRoute, replacementRoute)
    XCTAssertEqual(liveGeneration, replacementGeneration)
    XCTAssertEqual(liveCursor, .beforeFirst)

    let replacementReadbackValue = try await fixture.stateStore.load()
    let replacementReadback = try XCTUnwrap(replacementReadbackValue)
    XCTAssertTrue(replacementReadback.state.pendingStreamBindings.isEmpty)
    XCTAssertEqual(replacementReadback.state.streamStates.count, 1)
    XCTAssertEqual(
      replacementReadback.state.streamStates[0].streamRoute,
      replacementRoute
    )
    XCTAssertEqual(
      replacementReadback.state.streamStates[0].generation,
      replacementGeneration
    )
  }

  func testReconnectConversationWarmResumePreservesDurableCursorFloor() async throws {
    let conversationRoute = Data(repeating: 0xB5, count: 16)
    let conversationGeneration = Data(repeating: 0xB6, count: 16)
    let conversationID = RuntimeConversationID(rawValue: "conversation-warm-reconnect")
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: [conversationRoute]
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [conversationRoute],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let firstScope = productionIngressScope(66)
    _ = try await ingress.resumeFrames(
      generation: firstScope.generation,
      scope: firstScope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapConversation(
      ingress: ingress,
      fixture: fixture,
      scope: firstScope,
      messageID: RuntimeMessageID(rawValue: "conversation-warm-first"),
      conversationID: conversationID,
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      firstCounter: 1
    )
    let published = try await ingress.receive(
      try productionIngressConversationPublishFrame(
        fixture: fixture,
        generation: firstScope.generation,
        conversationID: conversationID,
        streamRoute: conversationRoute,
        streamGeneration: conversationGeneration,
        streamSequence: 0,
        eventSequence: 0,
        counter: 1
      ),
      scope: firstScope
    )
    guard case .delivery(let delivery) = published else {
      return XCTFail("测试必须先建立 conversation durable cursor")
    }
    try await ingress.commit(delivery)
    try await ingress.awaitResolution(delivery)
    _ = try await ingress.drainTransportActions(scope: firstScope)

    await ingress.generationEnded(scope: firstScope)
    let reconnectScope = productionIngressScope(67)
    _ = try await ingress.resumeFrames(
      generation: reconnectScope.generation,
      scope: reconnectScope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapConversation(
      ingress: ingress,
      fixture: fixture,
      scope: reconnectScope,
      messageID: RuntimeMessageID(rawValue: "conversation-warm-second"),
      conversationID: conversationID,
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      firstCounter: 4,
      after: .at(0),
      synchronizedOuterCursor: .at(0),
      bindingCursor: .at(0)
    )

    let readbackValue = try await fixture.stateStore.load()
    let readback = try XCTUnwrap(readbackValue)
    let stream = try XCTUnwrap(
      readback.state.streamStates.first(where: {
        $0.streamRoute == conversationRoute
      })
    )
    XCTAssertEqual(stream.outerCursor, .at(0))
    XCTAssertEqual(stream.innerCursor, .conversation(id: conversationID.rawValue, cursor: .at(0)))
  }

  func testReconnectBackfillOverlapAdvancesOnlyDurableOuterCursor() async throws {
    let conversationRoute = Data(repeating: 0xB7, count: 16)
    let conversationGeneration = Data(repeating: 0xB8, count: 16)
    let conversationID = RuntimeConversationID(rawValue: "conversation-reconnect-overlap")
    let fixture = try await ProductionIngressCryptoFixture.make(
      conversationRoutes: [conversationRoute]
    )
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [conversationRoute],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(68)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapConversation(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "conversation-overlap-bootstrap"),
      conversationID: conversationID,
      streamRoute: conversationRoute,
      streamGeneration: conversationGeneration,
      firstCounter: 1,
      after: .at(0),
      synchronizedOuterCursor: .at(0),
      synchronizedInnerCursor: .at(1),
      bindingCursor: .at(0)
    )

    let overlap = try await ingress.receive(
      try productionIngressConversationPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        conversationID: conversationID,
        streamRoute: conversationRoute,
        streamGeneration: conversationGeneration,
        streamSequence: 1,
        eventSequence: 1,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let delivery) = overlap else {
      return XCTFail("Runtime backfill 已覆盖的 publication overlap 仍须交付 durable outer commit")
    }
    try await ingress.commit(delivery)
    try await ingress.awaitResolution(delivery)

    let readbackValue = try await fixture.stateStore.load()
    let readback = try XCTUnwrap(readbackValue)
    let stream = try XCTUnwrap(
      readback.state.streamStates.first(where: {
        $0.streamRoute == conversationRoute
      })
    )
    XCTAssertEqual(stream.outerCursor, .at(1))
    XCTAssertEqual(
      stream.innerCursor,
      .conversation(id: conversationID.rawValue, cursor: .at(1))
    )
  }

  func testPublishAckWaitsForDurableCommitAndReconnectResendsAfterSubscribe() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(40)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    let streamRoute = Data(repeating: 0xC1, count: 16)
    let streamGeneration = Data(repeating: 0xC2, count: 16)
    _ = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "ack-bootstrap-first"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 1
    )

    let publishFrame = try productionIngressCatalogPublishFrame(
      fixture: fixture,
      generation: scope.generation,
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      streamSequence: 0,
      catalogRevision: 0,
      counter: 1
    )
    let outcome = try await ingress.receive(publishFrame, scope: scope)
    guard case .delivery(let delivery) = outcome else {
      return XCTFail("fresh Publish must cross the verified delivery boundary")
    }
    let actionsBeforeCommit = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(
      actionsBeforeCommit.isEmpty,
      "reducer/durable commit 前不得提前 ACK"
    )
    let beforeCommitValue = try await fixture.stateStore.load()
    let beforeCommit = try XCTUnwrap(beforeCommitValue)
    XCTAssertEqual(beforeCommit.state.streamStates[0].outerCursor, .beforeFirst)

    async let firstCommit: Void = ingress.commit(delivery)
    async let duplicateCommit: Void = ingress.commit(delivery)
    _ = try await (firstCommit, duplicateCommit)
    try await ingress.awaitResolution(delivery)
    let committedActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(committedActions.count, 1)
    guard
      case .ack(let ackRoute, let ackGeneration, let upToSeq) =
        try productionIngressDecodedFrame(try XCTUnwrap(committedActions.first)).body
    else {
      return XCTFail("durable Publish commit 必须排入 exact outer ACK")
    }
    XCTAssertEqual(ackRoute, streamRoute)
    XCTAssertEqual(ackGeneration, streamGeneration)
    XCTAssertEqual(upToSeq, 0)
    let afterCommitValue = try await fixture.stateStore.load()
    let afterCommit = try XCTUnwrap(afterCommitValue)
    XCTAssertEqual(afterCommit.state.streamStates[0].outerCursor, .at(0))

    try await assertProductionIngressIgnored(
      ingress.receive(publishFrame, scope: scope)
    )
    let duplicateActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(duplicateActions.count, 1)
    guard
      case .ack(let duplicateRoute, let duplicateGeneration, let duplicateSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(duplicateActions.first)).body
    else {
      return XCTFail("durable exact duplicate 必须重发 cumulative ACK")
    }
    XCTAssertEqual(duplicateRoute, streamRoute)
    XCTAssertEqual(duplicateGeneration, streamGeneration)
    XCTAssertEqual(duplicateSequence, 0)

    let discardedFrame = try productionIngressCatalogPublishFrame(
      fixture: fixture,
      generation: scope.generation,
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      streamSequence: 1,
      catalogRevision: 1,
      counter: 2
    )
    let discardedOutcome = try await ingress.receive(discardedFrame, scope: scope)
    guard case .delivery(let discarded) = discardedOutcome else {
      return XCTFail("second fresh Publish must produce one delivery")
    }
    await ingress.discard(discarded)
    try await ingress.awaitResolution(discarded)
    let actionsAfterDiscard = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(actionsAfterDiscard.isEmpty)
    let afterDiscardValue = try await fixture.stateStore.load()
    let afterDiscard = try XCTUnwrap(afterDiscardValue)
    XCTAssertEqual(afterDiscard.state.streamStates[0].outerCursor, .at(0))

    let replayedDiscard = try await ingress.receive(discardedFrame, scope: scope)
    guard case .delivery(let replayedDelivery) = replayedDiscard else {
      return XCTFail("discarded exact duplicate must be eligible for reducer redelivery")
    }
    await ingress.discard(replayedDelivery)
    try await ingress.awaitResolution(replayedDelivery)
    let replayedDiscardActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(replayedDiscardActions.isEmpty)

    let transferFrames = try productionIngressCatalogTransferFrames(
      fixture: fixture,
      generation: scope.generation,
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstStreamSequence: 1,
      catalogRevision: 1,
      firstCounter: 3
    )
    try await assertProductionIngressIgnored(
      ingress.receive(transferFrames[0], scope: scope)
    )
    let completedTransfer = try await ingress.receive(transferFrames[1], scope: scope)
    guard case .delivery(let transferDelivery) = completedTransfer else {
      return XCTFail("completed compact Publish must produce one logical delivery")
    }
    try await ingress.commit(transferDelivery)
    try await ingress.awaitResolution(transferDelivery)
    let transferActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(transferActions.count, 1)
    guard
      case .ack(_, _, let transferUpToSequence) =
        try productionIngressDecodedFrame(try XCTUnwrap(transferActions.first)).body
    else {
      return XCTFail("compact Publish must ACK its last outer sequence")
    }
    XCTAssertEqual(transferUpToSequence, 2)
    let afterTransferValue = try await fixture.stateStore.load()
    let afterTransfer = try XCTUnwrap(afterTransferValue)
    XCTAssertEqual(afterTransfer.state.streamStates[0].outerCursor, .at(2))

    await ingress.generationEnded(scope: scope)
    let resumedScope = productionIngressScope(41)
    _ = try await ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 31
    )
    let resumedActions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: resumedScope,
      messageID: RuntimeMessageID(rawValue: "ack-bootstrap-resumed"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 4,
      after: .at(1),
      synchronizedOuterCursor: .at(2),
      bindingCursor: .at(2)
    )
    XCTAssertEqual(resumedActions.count, 2)
    guard
      case .subscribe(let subscribedRoute, let subscribedGeneration, let cursor) =
        try productionIngressDecodedFrame(resumedActions[0]).body,
      case .ack(let resumedRoute, let resumedGeneration, let resumedSequence) =
        try productionIngressDecodedFrame(resumedActions[1]).body
    else {
      return XCTFail("reconnect 必须先建立 Relay lease，再重发 durable ACK")
    }
    XCTAssertEqual(resumedRoute, streamRoute)
    XCTAssertEqual(resumedGeneration, streamGeneration)
    XCTAssertEqual(resumedSequence, 2)
    XCTAssertEqual(subscribedRoute, streamRoute)
    XCTAssertEqual(subscribedGeneration, streamGeneration)
    XCTAssertEqual(cursor, .at(2))
  }

  func testGapAndReplayCompleteRequireExactLiveBindingAndDurableCursor() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(42)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    let streamRoute = Data(repeating: 0xC3, count: 16)
    let streamGeneration = Data(repeating: 0xC4, count: 16)
    _ = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "gap-bootstrap"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 1
    )

    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .replayComplete(
            streamRoute: streamRoute,
            generation: streamGeneration,
            currentCursor: .beforeFirst
          )
        ),
        scope: scope
      )
    )
    let gap = try await ingress.receive(
      try productionIngressReceivedFrame(
        generation: scope.generation,
        body: .gap(
          streamRoute: streamRoute,
          generation: streamGeneration,
          needStreamSeq: 0,
          oldestStreamSeq: 1
        )
      ),
      scope: scope
    )
    guard case .streamRecoveryRequired(.catalog, .cursorGap) = gap else {
      return XCTFail("exact durable needSeq 的 Gap 必须成为可观察 recovery")
    }
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .replayComplete(
            streamRoute: streamRoute,
            generation: streamGeneration,
            currentCursor: .beforeFirst
          )
        ),
        scope: scope
      )
    )
    let reboundActions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "gap-bootstrap-same-binding"),
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      firstCounter: 4
    )
    XCTAssertEqual(reboundActions.count, 1)
    guard
      case .subscribe(let reboundRoute, let reboundGeneration, let reboundCursor) =
        try productionIngressDecodedFrame(try XCTUnwrap(reboundActions.first)).body
    else {
      return XCTFail("same physical binding recovery must not Unsubscribe itself")
    }
    XCTAssertEqual(reboundRoute, streamRoute)
    XCTAssertEqual(reboundGeneration, streamGeneration)
    XCTAssertEqual(reboundCursor, .beforeFirst)
    let ahead = try await ingress.receive(
      try productionIngressReceivedFrame(
        generation: scope.generation,
        body: .replayComplete(
          streamRoute: streamRoute,
          generation: streamGeneration,
          currentCursor: .at(0)
        )
      ),
      scope: scope
    )
    guard case .streamRecoveryRequired(.catalog, .cursorGap) = ahead else {
      return XCTFail("Relay cursor ahead of durable cut must request recovery")
    }

    do {
      _ = try await ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .gap(
            streamRoute: streamRoute,
            generation: streamGeneration,
            needStreamSeq: 0,
            oldestStreamSeq: 0
          )
        ),
        scope: scope
      )
      XCTFail("malformed non-gap control must fail closed")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .noncanonicalFrame
      )
    }

    let publish = try await ingress.receive(
      try productionIngressCatalogPublishFrame(
        fixture: fixture,
        generation: scope.generation,
        streamRoute: streamRoute,
        streamGeneration: streamGeneration,
        streamSequence: 0,
        catalogRevision: 0,
        counter: 1
      ),
      scope: scope
    )
    guard case .delivery(let delivery) = publish else {
      return XCTFail("fixture Publish must reach delivery")
    }
    try await ingress.commit(delivery)
    try await ingress.awaitResolution(delivery)
    _ = try await ingress.drainTransportActions(scope: scope)

    do {
      _ = try await ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .replayComplete(
            streamRoute: streamRoute,
            generation: streamGeneration,
            currentCursor: .beforeFirst
          )
        ),
        scope: scope
      )
      XCTFail("ReplayComplete rollback below durable cursor must fail closed")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .noncanonicalFrame
      )
    }
  }

  func testCatalogBootstrapKeepsRuntimeAndRelayGenerationsIndependent() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(43)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    let streamRoute = Data(repeating: 0xD3, count: 16)
    let relayGeneration = Data(repeating: 0xD4, count: 16)
    let runtimeGeneration = Data(repeating: 0xD5, count: 16)

    let actions = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "independent-runtime-relay-generation"),
      streamRoute: streamRoute,
      streamGeneration: relayGeneration,
      runtimeStreamGeneration: runtimeGeneration,
      firstCounter: 1
    )

    guard
      case .subscribe(let subscribedRoute, let subscribedGeneration, _) =
        try productionIngressDecodedFrame(try XCTUnwrap(actions.first)).body
    else {
      return XCTFail("durable binding must subscribe the Relay publication generation")
    }
    XCTAssertEqual(subscribedRoute, streamRoute)
    XCTAssertEqual(subscribedGeneration, relayGeneration)
    XCTAssertNotEqual(runtimeGeneration, relayGeneration)
  }

  func testGenerationEndedReleasesPendingDirectedReplyWaiter() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(5)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    let prepared = try await ingress.prepareDirected(
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: "generation-ended-waiter"),
        body: .request(.catalog(pageCursor: nil))
      ),
      contract: .revocation(expectedGrantSerial: fixture.material.record.grantSerial),
      scope: scope
    )
    let waiter = Task {
      try await ingress.awaitDirectedReply(prepared.token, scope: scope)
    }
    try await Task.sleep(for: .milliseconds(10))
    await ingress.generationEnded(scope: scope)

    do {
      _ = try await waiter.value
      XCTFail("generation teardown must release the pending waiter")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .generationEnded
      )
    }
  }

  func testCompactDirectedReplyReassemblesOutOfOrderAndCompletesExactWaiter() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS }
    )
    let scope = productionIngressScope(6)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 37
    )
    let messageID = RuntimeMessageID(rawValue: "compact-directed-reply")
    let prepared = try await ingress.prepareDirected(
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .request(.catalog(pageCursor: nil))
      ),
      contract: .revocation(expectedGrantSerial: fixture.material.record.grantSerial),
      scope: scope
    )
    let outbound = try productionIngressSend(prepared.frame)
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: outbound.requestRoute)
          )
        ),
        scope: scope
      )
    )

    let expectedReply = RuntimeReplyV2.revocation(
      .committed(RuntimeGrantSerial(rawValue: fixture.material.record.grantSerial))
    )
    let assembled = try RuntimeWireCodec.encode(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(expectedReply)
      )
    )
    let split = assembled.count / 2
    let parts = [Data(assembled[..<split]), Data(assembled[split...])]
    XCTAssertTrue(parts.allSatisfy { !$0.isEmpty })
    let totalHash = Data(SHA256.hash(data: assembled))
    let transferID = RuntimeTransferID(rawValue: "compact-directed-transfer")
    let waiter = Task {
      try await ingress.awaitDirectedReply(prepared.token, scope: scope)
    }

    let secondPartFirst = try RuntimeWireCodec.encode(
      RuntimeTransferCarrierV2(
        messageID: messageID,
        channel: .reply,
        transferID: transferID,
        partIndex: 1,
        partCount: 2,
        totalSHA256: totalHash,
        totalBytes: UInt64(assembled.count),
        part: parts[1]
      )
    )
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressTransferReplyFrame(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: outbound.requestRoute,
          carrier: secondPartFirst,
          counter: 1
        ),
        scope: scope
      )
    )
    let firstPartLast = try RuntimeWireCodec.encode(
      RuntimeTransferCarrierV2(
        messageID: messageID,
        channel: .reply,
        transferID: transferID,
        partIndex: 0,
        partCount: 2,
        totalSHA256: totalHash,
        totalBytes: UInt64(assembled.count),
        part: parts[0]
      )
    )
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressTransferReplyFrame(
          fixture: fixture,
          generation: scope.generation,
          requestRoute: outbound.requestRoute,
          carrier: firstPartLast,
          counter: 2
        ),
        scope: scope
      )
    )

    switch try await waiter.value {
    case .revocation(.committed(let serial)):
      XCTAssertEqual(serial.rawValue, fixture.material.record.grantSerial)
    default:
      XCTFail("completed compact transfer must resume the exact directed waiter")
    }
  }

  func testTransferExpiryTimerSweepsSilentPartialAndReleasesGlobalBudget() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let coordinator = TransferAssemblyBudgetCoordinator()
    let clock = ProductionIngressAdvancingClock(
      baseMS: ProductionIngressCryptoFixture.fixedTimeMS
    )
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { clock.nowMS },
      transferBudgetCoordinator: coordinator,
      transferTTLMilliseconds: 40
    )
    let scope = productionIngressScope(60)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 37
    )
    let transfer = try await productionIngressPrepareDirectedTransfer(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "silent-timer"
    )

    try await assertProductionIngressIgnored(
      productionIngressReceiveDirectedTransferPart(
        ingress: ingress,
        fixture: fixture,
        scope: scope,
        transfer: transfer,
        partIndex: 0,
        counter: 1
      )
    )
    XCTAssertEqual(
      coordinator.usage,
      TransferAssemblyBudgetUsage(
        reassemblyBytes: UInt64(transfer.parts[0].count),
        completedTombstones: 0,
        reservationCount: 1
      )
    )

    let released = await productionIngressEventually {
      coordinator.usage
        == TransferAssemblyBudgetUsage(
          reassemblyBytes: 0,
          completedTombstones: 0,
          reservationCount: 0
        )
    }
    XCTAssertTrue(released, "Relay 静默时 production timer 必须主动释放 partial reservation")
    await ingress.generationEnded(scope: scope)
  }

  func testTransferExpiryTimerReordersDeadlineAfterOwnerCompletion() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let coordinator = TransferAssemblyBudgetCoordinator()
    let clock = ProductionIngressMutableClock(
      nowMS: ProductionIngressCryptoFixture.fixedTimeMS
    )
    let sleeper = ProductionIngressNonCooperativeTransferExpirySleeper()
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { clock.nowMS },
      transferBudgetCoordinator: coordinator,
      transferTTLMilliseconds: 100,
      transferExpirySleeper: sleeper
    )
    let scope = productionIngressScope(61)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 37
    )
    let first = try await productionIngressPrepareDirectedTransfer(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "deadline-first"
    )
    try await assertProductionIngressIgnored(
      productionIngressReceiveDirectedTransferPart(
        ingress: ingress,
        fixture: fixture,
        scope: scope,
        transfer: first,
        partIndex: 0,
        counter: 1
      )
    )
    let firstTimerInstalled = await productionIngressEventually {
      await sleeper.pendingMilliseconds == [100]
    }
    XCTAssertTrue(firstTimerInstalled)

    clock.setNowMS(ProductionIngressCryptoFixture.fixedTimeMS + 10)
    let second = try await productionIngressPrepareDirectedTransfer(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "deadline-second"
    )
    try await assertProductionIngressIgnored(
      productionIngressReceiveDirectedTransferPart(
        ingress: ingress,
        fixture: fixture,
        scope: scope,
        transfer: second,
        partIndex: 0,
        counter: 2
      )
    )

    clock.setNowMS(ProductionIngressCryptoFixture.fixedTimeMS + 20)
    try await assertProductionIngressIgnored(
      productionIngressReceiveDirectedTransferPart(
        ingress: ingress,
        fixture: fixture,
        scope: scope,
        transfer: first,
        partIndex: 1,
        counter: 3
      )
    )
    let reordered = await productionIngressEventually {
      (await sleeper.pendingMilliseconds).sorted() == [90, 100]
    }
    XCTAssertTrue(reordered, "earliest expiry removal must replace the old deadline")
    let usageAfterReorder = coordinator.usage
    XCTAssertEqual(
      usageAfterReorder,
      TransferAssemblyBudgetUsage(
        reassemblyBytes: UInt64(second.parts[0].count),
        completedTombstones: 1,
        reservationCount: 2
      )
    )

    await ingress.generationEnded(scope: scope)
    XCTAssertEqual(
      coordinator.usage,
      TransferAssemblyBudgetUsage(
        reassemblyBytes: 0,
        completedTombstones: 0,
        reservationCount: 0
      )
    )
    await sleeper.resumeAll()
  }

  func testGenerationEndedCancelsTransferExpiryTimerAndReleasesExactGlobalBudget() async throws {
    let fixture = try await ProductionIngressCryptoFixture.make()
    defer { fixture.removeSandbox() }
    let coordinator = TransferAssemblyBudgetCoordinator()
    let clock = ProductionIngressMutableClock(
      nowMS: ProductionIngressCryptoFixture.fixedTimeMS
    )
    let sleeper = ProductionIngressManualTransferExpirySleeper()
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { clock.nowMS },
      transferBudgetCoordinator: coordinator,
      transferTTLMilliseconds: 100,
      transferExpirySleeper: sleeper
    )
    let scope = productionIngressScope(62)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 37
    )
    let transfer = try await productionIngressPrepareDirectedTransfer(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "disconnect-cancel"
    )
    try await assertProductionIngressIgnored(
      productionIngressReceiveDirectedTransferPart(
        ingress: ingress,
        fixture: fixture,
        scope: scope,
        transfer: transfer,
        partIndex: 0,
        counter: 1
      )
    )
    let timerInstalled = await productionIngressEventually {
      await sleeper.pendingMilliseconds == [100]
    }
    XCTAssertTrue(timerInstalled)
    XCTAssertEqual(coordinator.usage.reservationCount, 1)

    await ingress.generationEnded(scope: scope)
    let timerCanceled = await productionIngressEventually {
      let pending = await sleeper.pendingMilliseconds
      let cancellationCount = await sleeper.cancellationCount
      return pending.isEmpty && cancellationCount == 1
    }
    XCTAssertTrue(timerCanceled, "disconnect 必须 cancel exact generation timer")
    XCTAssertEqual(
      coordinator.usage,
      TransferAssemblyBudgetUsage(
        reassemblyBytes: 0,
        completedTombstones: 0,
        reservationCount: 0
      )
    )
  }

  func testBootstrapBarrierExactRetryCompletesReplayAdmissionActivationGap() async throws {
    let routes = ProductionIngressRequestRouteSequence(
      bootstrapFallback: { throw ProductionIngressTestHarnessError.requestRouteExhausted }
    )
    routes.enqueue([Data(repeating: 0xD1, count: 16)])
    let harness = try await productionIngressBootstrapCatalogBarrierHarness(
      scopeIndex: 79,
      requestRouteGenerator: { try routes.next() }
    )
    defer { harness.fixture.removeSandbox() }

    let beforeFailureValue = try await harness.fixture.stateStore.load()
    let beforeFailure = try XCTUnwrap(beforeFailureValue)
    XCTAssertNil(beforeFailure.state.keyLifecycle)
    do {
      _ = try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
      XCTFail("injected reservation failure must interrupt before bootstrap activation")
    } catch {
      XCTAssertEqual(
        error as? ProductionIngressTestHarnessError,
        .requestRouteExhausted
      )
    }

    let admittedValue = try await harness.fixture.stateStore.load()
    let admitted = try XCTUnwrap(admittedValue)
    XCTAssertNil(admitted.state.keyLifecycle, "replay CAS must not imply activation proof")
    XCTAssertEqual(admitted.state.stateRevision, beforeFailure.state.stateRevision + 1)
    XCTAssertEqual(
      admitted.state.replayStates.first(where: {
        $0.scope.keyID == KeyIDV1(purpose: .catalog, epoch: 1)
          && $0.scope.streamRoute == nil
      })?.window.highWater,
      1
    )
    let failedActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertTrue(failedActions.isEmpty)

    await harness.ingress.generationEnded(scope: harness.scope)
    let reopened = try await ProductionMachineConnectionVerifiedIngress.open(
      material: PairedMachineConnectionMaterial(
        record: harness.fixture.material.record,
        deviceSigningKey: harness.fixture.material.deviceSigningKey,
        deviceHPKEPrivateKey: harness.fixture.material.deviceHPKEPrivateKey,
        relayGrant: harness.fixture.material.relayGrant,
        machineDataCertificate: harness.fixture.material.machineDataCertificate,
        auditedCryptoState: admitted,
        cryptoStateStore: harness.fixture.material.cryptoStateStore,
        cryptoStateCoordinator: harness.fixture.material.cryptoStateCoordinator
      ),
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS },
      requestRouteGenerator: { try routes.next() }
    )
    let reopenedScope = productionIngressScope(81)
    _ = try await reopened.resumeFrames(
      generation: reopenedScope.generation,
      scope: reopenedScope,
      heartbeatIntervalSeconds: 31
    )
    let retryFrame = try productionIngressEpochBarrierPublish(
      fixture: harness.fixture,
      generation: reopenedScope.generation,
      barrier: harness.barrier,
      counter: 1,
      keyDirectoryRevision: harness.fixture.currentRevision,
      rawKeyByte: 0x41,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )

    // recoverCommitted 会先用一条 route 核对 durable proof；发现 admission-only cut 后
    // 释放该 reservation，再用第二条 route 补做 activation + ACK。
    routes.enqueue([
      Data(repeating: 0xD2, count: 16),
      Data(repeating: 0xD3, count: 16),
    ])
    assertProductionIngressIgnored(
      try await reopened.receive(
        retryFrame,
        scope: reopenedScope
      )
    )
    let actions = try await reopened.drainTransportActions(scope: reopenedScope)
    XCTAssertEqual(actions.count, 2)
    let semantic = try productionIngressSend(try XCTUnwrap(actions.first))
    XCTAssertEqual(semantic.requestRoute, Data(repeating: 0xD3, count: 16))
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        semantic,
        fixture: harness.fixture
      ),
      case .ack(let streamRoute, let generation, let upToSeq) =
        try productionIngressDecodedFrame(actions[1]).body
    else {
      return XCTFail("gap recovery must order semantic StreamAppliedAck before outer ACK")
    }
    XCTAssertEqual(
      acknowledgement.authority,
      try DeviceKeyControlAuthorityV1(
        machineRoute: harness.fixture.crypto.machineRoute,
        deviceRoute: harness.fixture.crypto.deviceRoute,
        grantSerial: harness.fixture.material.record.grantSerial,
        rootTrustEpoch: harness.fixture.material.record.trustEpoch
      )
    )
    XCTAssertEqual(acknowledgement.streamRoute, harness.barrier.streamRoute)
    XCTAssertEqual(acknowledgement.streamGeneration, harness.barrier.streamGeneration)
    XCTAssertEqual(
      acknowledgement.appliedStreamSequence,
      harness.barrier.appliedStreamSequence
    )
    XCTAssertEqual(acknowledgement.innerCursor, .catalog(cursor: .beforeFirst))
    XCTAssertEqual(
      acknowledgement.keyDirectoryRevision,
      harness.barrier.keyDirectoryRevision
    )
    XCTAssertEqual(acknowledgement.keyEpoch, harness.barrier.newEpoch)
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
    XCTAssertEqual(streamRoute, harness.barrier.streamRoute)
    XCTAssertEqual(generation, harness.barrier.streamGeneration)
    XCTAssertEqual(upToSeq, harness.barrier.appliedStreamSequence)

    let activatedValue = try await harness.fixture.stateStore.load()
    let activated = try XCTUnwrap(activatedValue)
    let catalog = try XCTUnwrap(
      activated.state.keyLifecycle?.slot(purpose: .catalog, streamRoute: nil)
    )
    XCTAssertEqual(catalog.current?.activationProof, harness.barrier)
    XCTAssertNil(catalog.staged)
    XCTAssertTrue(catalog.retired.isEmpty, "epoch-0 sentinel must not create a predecessor")
    XCTAssertEqual(
      activated.state.senderCounter.keyDirectoryRevision,
      harness.fixture.currentRevision
    )
    XCTAssertFalse(activated.state.replayStates.contains { $0.scope.keyID.epoch == 0 })
    await reopened.generationEnded(scope: reopenedScope)
  }

  func testBootstrapBarrierStaleCounterHasZeroMutationAndZeroAction() async throws {
    let harness = try await productionIngressBootstrapCatalogBarrierHarness(scopeIndex: 82)
    defer { harness.fixture.removeSandbox() }

    let highCounterFrame = try productionIngressEpochBarrierPublish(
      fixture: harness.fixture,
      generation: harness.scope.generation,
      barrier: harness.barrier,
      counter: ReplayWindow.windowSize,
      keyDirectoryRevision: harness.fixture.currentRevision,
      rawKeyByte: 0x41,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )
    assertProductionIngressIgnored(
      try await harness.ingress.receive(highCounterFrame, scope: harness.scope)
    )
    let committedActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(committedActions.count, 2)

    let stateBeforeValue = try await harness.fixture.stateStore.load()
    let stateBefore = try XCTUnwrap(stateBeforeValue)
    let keyStoreMutationsBefore = await harness.fixture.keyStore.mutationCount
    await harness.fixture.persistenceRecorder.reset()

    let staleFrame = try productionIngressEpochBarrierPublish(
      fixture: harness.fixture,
      generation: harness.scope.generation,
      barrier: harness.barrier,
      counter: 0,
      keyDirectoryRevision: harness.fixture.currentRevision,
      rawKeyByte: 0x41,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )
    assertProductionIngressIgnored(
      try await harness.ingress.receive(staleFrame, scope: harness.scope)
    )

    let staleActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    let persistenceStages = await harness.fixture.persistenceRecorder.snapshot()
    let stateAfter = try await harness.fixture.stateStore.load()
    let keyStoreMutationsAfter = await harness.fixture.keyStore.mutationCount
    XCTAssertTrue(staleActions.isEmpty)
    XCTAssertEqual(persistenceStages, [])
    XCTAssertEqual(stateAfter, stateBefore)
    XCTAssertEqual(keyStoreMutationsAfter, keyStoreMutationsBefore)
  }

  func testBootstrapBarrierFreshResealCannotRemintAcknowledgement() async throws {
    let harness = try await productionIngressBootstrapCatalogBarrierHarness(scopeIndex: 80)
    defer { harness.fixture.removeSandbox() }

    assertProductionIngressIgnored(
      try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
    )
    let firstActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(firstActions.count, 2)
    let firstSemantic = try productionIngressSend(try XCTUnwrap(firstActions.first))
    try await assertProductionIngressIgnored(
      harness.ingress.receive(
        try productionIngressReceivedFrame(
          generation: harness.scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: firstSemantic.requestRoute)
          )
        ),
        scope: harness.scope
      )
    )
    let routeAcceptedActions = try await harness.ingress.drainTransportActions(
      scope: harness.scope
    )
    XCTAssertTrue(routeAcceptedActions.isEmpty)
    let committedValue = try await harness.fixture.stateStore.load()
    let committed = try XCTUnwrap(committedValue)

    let freshReseal = try productionIngressEpochBarrierPublish(
      fixture: harness.fixture,
      generation: harness.scope.generation,
      barrier: harness.barrier,
      counter: 2,
      keyDirectoryRevision: harness.fixture.currentRevision,
      rawKeyByte: 0x41,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )
    do {
      _ = try await harness.ingress.receive(freshReseal, scope: harness.scope)
      XCTFail("fresh counter/ciphertext must not turn a committed semantic barrier into a new ACK")
    } catch {
      XCTAssertEqual(error as? DeviceKeyLifecycleError, .invalidBarrier)
    }
    let rejectedActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertTrue(rejectedActions.isEmpty)

    let rejectedValue = try await harness.fixture.stateStore.load()
    let rejected = try XCTUnwrap(rejectedValue)
    XCTAssertEqual(rejected.state.keyLifecycle, committed.state.keyLifecycle)
    XCTAssertEqual(rejected.state.streamStates, committed.state.streamStates)
    XCTAssertEqual(rejected.state.senderCounter, committed.state.senderCounter)
    XCTAssertEqual(rejected.state.keyDirectory, committed.state.keyDirectory)
    XCTAssertEqual(rejected.state.stateRevision, committed.state.stateRevision + 1)
    XCTAssertEqual(
      rejected.state.replayStates.first(where: {
        $0.scope.keyID == KeyIDV1(purpose: .catalog, epoch: 1)
          && $0.scope.streamRoute == nil
      })?.window.highWater,
      2
    )

    // 原始 ciphertext 的 exact duplicate 仍是唯一允许重封 ACK 的 recovery 路径。
    assertProductionIngressIgnored(
      try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
    )
    let recoveredActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(recoveredActions.count, 2)
  }

  func testConcurrentDirectedPrepareCannotOverwriteCommittedBarrierActions() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 70)
    defer {
      harness.fixture.removeSandbox()
      Task { await harness.signatureProducer.releaseAll() }
    }
    let ingress = harness.ingress
    let scope = harness.scope

    try await productionIngressCommitBarrierForDuplicateConcurrency(harness)

    let blockedCalls = await harness.signatureProducer.blockNext(2)
    let preparedTask = Task {
      try await ingress.prepareDirected(
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "reservation-concurrent-prepare"),
          body: .request(.catalog(pageCursor: nil))
        ),
        contract: .revocation(
          expectedGrantSerial: harness.fixture.material.record.grantSerial
        ),
        scope: scope
      )
    }
    let prepareBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[0])
    }
    guard prepareBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("directed prepare must pause inside the injected signer")
    }

    let duplicateTask = Task {
      try await ingress.receive(harness.barrierFrame, scope: scope)
    }
    let barrierBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[1])
    }
    guard barrierBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("barrier duplicate must hold its hard reservation while signing")
    }

    await harness.signatureProducer.release(blockedCalls[1])
    let duplicateOutcome = try await duplicateTask.value
    assertProductionIngressIgnored(duplicateOutcome)
    await harness.signatureProducer.release(blockedCalls[0])
    let prepared = try await preparedTask.value

    let preservedActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(preservedActions.count, 2)
    let preservedSemanticAck = try productionIngressSend(preservedActions[0])
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        preservedSemanticAck,
        fixture: harness.fixture
      )
    else {
      return XCTFail("concurrent prepare must not erase the registered semantic ACK")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: preservedSemanticAck.requestRoute)
          )
        ),
        scope: scope
      )
    )
    await ingress.cancelPrepared(prepared.token, scope: scope)
  }

  func testConcurrentDirectedPrepareCannotOverwriteInFlightBarrierReservation() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 76)
    defer {
      harness.fixture.removeSandbox()
      Task { await harness.signatureProducer.releaseAll() }
    }
    let ingress = harness.ingress
    let scope = harness.scope

    try await productionIngressCommitBarrierForDuplicateConcurrency(harness)

    let blockedCalls = await harness.signatureProducer.blockNext(2)
    let preparedTask = Task {
      try await ingress.prepareDirected(
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "reservation-directed-in-flight"),
          body: .request(.catalog(pageCursor: nil))
        ),
        contract: .revocation(
          expectedGrantSerial: harness.fixture.material.record.grantSerial
        ),
        scope: scope
      )
    }
    let prepareBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[0])
    }
    guard prepareBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("directed prepare must pause inside the injected signer")
    }

    let duplicateTask = Task {
      try await ingress.receive(harness.barrierFrame, scope: scope)
    }
    let barrierBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[1])
    }
    guard barrierBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("barrier duplicate must hold its hard reservation while signing")
    }

    await harness.signatureProducer.release(blockedCalls[0])
    let prepared = try await preparedTask.value
    let actionsWhileBarrierReserved = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(actionsWhileBarrierReserved.isEmpty)

    await harness.signatureProducer.release(blockedCalls[1])
    let duplicateOutcome = try await duplicateTask.value
    assertProductionIngressIgnored(duplicateOutcome)

    let actions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(actions.count, 2)
    let semanticAck = try productionIngressSend(try XCTUnwrap(actions.first))
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        semanticAck,
        fixture: harness.fixture
      )
    else {
      await ingress.cancelPrepared(prepared.token, scope: scope)
      return XCTFail("barrier reservation must survive directed prepare completion")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
    await ingress.cancelPrepared(prepared.token, scope: scope)
  }

  func testConcurrentSubscriptionPrepareCannotOverwriteInFlightBarrierReservation() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 77)
    defer {
      harness.fixture.removeSandbox()
      Task { await harness.signatureProducer.releaseAll() }
    }
    let ingress = harness.ingress
    let scope = harness.scope

    try await productionIngressCommitBarrierForDuplicateConcurrency(harness)

    let blockedCalls = await harness.signatureProducer.blockNext(2)
    let preparedTask = Task {
      try await ingress.prepareSubscription(
        target: .catalog,
        after: .beforeFirst,
        requestID: RuntimeMessageID(rawValue: "reservation-subscription-in-flight"),
        scope: scope
      )
    }
    let prepareBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[0])
    }
    guard prepareBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("subscription prepare must pause inside the injected signer")
    }

    let duplicateTask = Task {
      try await ingress.receive(harness.barrierFrame, scope: scope)
    }
    let barrierBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[1])
    }
    guard barrierBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("barrier duplicate must hold its hard reservation while signing")
    }

    await harness.signatureProducer.release(blockedCalls[0])
    let prepared = try await preparedTask.value
    let actionsWhileBarrierReserved = try await ingress.drainTransportActions(scope: scope)
    XCTAssertTrue(actionsWhileBarrierReserved.isEmpty)

    await harness.signatureProducer.release(blockedCalls[1])
    let duplicateOutcome = try await duplicateTask.value
    assertProductionIngressIgnored(duplicateOutcome)

    let actions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(actions.count, 2)
    let semanticAck = try productionIngressSend(try XCTUnwrap(actions.first))
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        semanticAck,
        fixture: harness.fixture
      )
    else {
      await ingress.cancelPrepared(prepared.token, scope: scope)
      return XCTFail("barrier reservation must survive subscription prepare completion")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
    await ingress.cancelPrepared(prepared.token, scope: scope)
  }

  func testConcurrentSubscriptionPrepareCannotOverwriteCommittedBarrierActions() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 78)
    defer {
      harness.fixture.removeSandbox()
      Task { await harness.signatureProducer.releaseAll() }
    }
    let ingress = harness.ingress
    let scope = harness.scope

    try await productionIngressCommitBarrierForDuplicateConcurrency(harness)

    let blockedCalls = await harness.signatureProducer.blockNext(2)
    let preparedTask = Task {
      try await ingress.prepareSubscription(
        target: .catalog,
        after: .beforeFirst,
        requestID: RuntimeMessageID(rawValue: "reservation-subscription-committed"),
        scope: scope
      )
    }
    let prepareBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[0])
    }
    guard prepareBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("subscription prepare must pause inside the injected signer")
    }

    let duplicateTask = Task {
      try await ingress.receive(harness.barrierFrame, scope: scope)
    }
    let barrierBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[1])
    }
    guard barrierBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("barrier duplicate must hold its hard reservation while signing")
    }

    await harness.signatureProducer.release(blockedCalls[1])
    let duplicateOutcome = try await duplicateTask.value
    assertProductionIngressIgnored(duplicateOutcome)
    await harness.signatureProducer.release(blockedCalls[0])
    let prepared = try await preparedTask.value

    let preservedActions = try await ingress.drainTransportActions(scope: scope)
    XCTAssertEqual(preservedActions.count, 2)
    let semanticAck = try productionIngressSend(try XCTUnwrap(preservedActions.first))
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        semanticAck,
        fixture: harness.fixture
      )
    else {
      await ingress.cancelPrepared(prepared.token, scope: scope)
      return XCTFail("subscription prepare must not erase committed barrier actions")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
    await ingress.cancelPrepared(prepared.token, scope: scope)
  }

  func testBarrierSigningFailureReleasesReservationAndDuplicateRecoversOutcome() async throws {
    let routes = ProductionIngressRequestRouteSequence()
    let harness = try await productionIngressStagedCatalogBarrierHarness(
      scopeIndex: 71,
      requestRouteGenerator: { try routes.next() }
    )
    defer { harness.fixture.removeSandbox() }
    let reusedRoute = Data(repeating: 0xE7, count: 16)
    routes.enqueue([reusedRoute, reusedRoute])
    let failedCalls = await harness.signatureProducer.failNext(1)

    do {
      _ = try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
      XCTFail("injected post-CAS signing failure must propagate")
    } catch {
      XCTAssertEqual(error as? DeviceRequestSignerError, .signingFailed)
    }
    let failedCallReached = await harness.signatureProducer.hasReached(failedCalls[0])
    XCTAssertTrue(failedCallReached)
    let failedActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertTrue(failedActions.isEmpty)
    let durableValue = try await harness.fixture.stateStore.load()
    let durable = try XCTUnwrap(durableValue)
    XCTAssertEqual(
      durable.state.senderCounter.keyDirectoryRevision,
      harness.fixture.nextRevision
    )

    let recovered = try await harness.ingress.receive(
      harness.barrierFrame,
      scope: harness.scope
    )
    guard
      case .keySyncSucceeded(let revision, let recoveryTargets) = recovered,
      recoveryTargets.count == 1,
      case .catalog = recoveryTargets[0]
    else {
      return XCTFail("exact retry after post-CAS failure must restore the lost activation outcome")
    }
    XCTAssertEqual(revision, harness.fixture.nextRevision)
    let recoveredActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(recoveredActions.count, 2)
    let semanticAck = try productionIngressSend(try XCTUnwrap(recoveredActions.first))
    XCTAssertEqual(semanticAck.requestRoute, reusedRoute)
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        semanticAck,
        fixture: harness.fixture
      )
    else {
      return XCTFail("recovered barrier must emit a decryptable semantic ACK")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
  }

  func testGenerationTeardownDuringBarrierSigningRecoversDurableProofOnReconnect() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 72)
    defer {
      harness.fixture.removeSandbox()
      Task { await harness.signatureProducer.releaseAll() }
    }
    let blockedCalls = await harness.signatureProducer.blockNext(1)
    let activationTask = Task {
      try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
    }
    let signingBlocked = await productionIngressEventually {
      await harness.signatureProducer.hasReached(blockedCalls[0])
    }
    guard signingBlocked else {
      await harness.signatureProducer.releaseAll()
      return XCTFail("fresh barrier must pause after its durable CAS")
    }

    await harness.ingress.generationEnded(scope: harness.scope)
    await harness.signatureProducer.release(blockedCalls[0])
    do {
      _ = try await activationTask.value
      XCTFail("ended generation must reject the stale signed action")
    } catch {
      let ingressError = error as? ProductionMachineConnectionVerifiedIngressError
      XCTAssertTrue(
        ingressError == .generationEnded || ingressError == .generationNotActive
      )
    }

    let resumedScope = productionIngressScope(73)
    let recovered = try await harness.ingress.resumeFrames(
      generation: resumedScope.generation,
      scope: resumedScope,
      heartbeatIntervalSeconds: 31
    )
    XCTAssertEqual(recovered.count, 1)
    let recoveredOutbound = try productionIngressSend(try XCTUnwrap(recovered.first))
    guard
      case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
        recoveredOutbound,
        fixture: harness.fixture
      )
    else {
      return XCTFail("new generation must recover the durable proof exactly once")
    }
    XCTAssertEqual(acknowledgement.epochBarrierSHA256, harness.barrier.canonicalSHA256)
  }

  func testKeyUpdateAcknowledgementControlRoutesAreHardCapped() async throws {
    let harness = try await productionIngressStagedCatalogBarrierHarness(scopeIndex: 74)
    defer { harness.fixture.removeSandbox() }
    var firstLiveRoute: Data?

    for index in 0..<512 {
      try await assertProductionIngressIgnored(
        harness.ingress.receive(harness.updateReply, scope: harness.scope)
      )
      let actions = try await harness.ingress.drainTransportActions(scope: harness.scope)
      XCTAssertEqual(actions.count, 1, "duplicate ACK \(index) must consume one bounded slot")
      let outbound = try productionIngressSend(try XCTUnwrap(actions.first))
      if firstLiveRoute == nil { firstLiveRoute = outbound.requestRoute }
    }

    do {
      _ = try await harness.ingress.receive(harness.updateReply, scope: harness.scope)
      XCTFail("the 513th unaccepted control route must fail closed")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .outboundCapacity
      )
    }
    let overflowActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertTrue(overflowActions.isEmpty)

    try await assertProductionIngressIgnored(
      harness.ingress.receive(
        try productionIngressReceivedFrame(
          generation: harness.scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: try XCTUnwrap(firstLiveRoute))
          )
        ),
        scope: harness.scope
      )
    )
    try await assertProductionIngressIgnored(
      harness.ingress.receive(harness.updateReply, scope: harness.scope)
    )
    let refilled = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(refilled.count, 1)
  }

  func testBarrierControlRouteCannotCollideWithLivePreparedRequest() async throws {
    let liveRoute = Data(repeating: 0xE4, count: 16)
    let replacementRoute = Data(repeating: 0xE6, count: 16)
    let routes = ProductionIngressRequestRouteSequence()
    let harness = try await productionIngressStagedCatalogBarrierHarness(
      scopeIndex: 75,
      requestRouteGenerator: { try routes.next() }
    )
    defer { harness.fixture.removeSandbox() }
    routes.enqueue([liveRoute, liveRoute, replacementRoute])
    let prepared = try await harness.ingress.prepareDirected(
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: "reservation-route-collision"),
        body: .request(.catalog(pageCursor: nil))
      ),
      contract: .revocation(
        expectedGrantSerial: harness.fixture.material.record.grantSerial
      ),
      scope: harness.scope
    )
    XCTAssertEqual(try productionIngressSend(prepared.frame).requestRoute, liveRoute)

    do {
      _ = try await harness.ingress.receive(
        harness.barrierFrame,
        scope: harness.scope
      )
      XCTFail("control reservation must reject a live prepared request route")
    } catch {
      XCTAssertEqual(
        error as? ProductionMachineConnectionVerifiedIngressError,
        .invalidConfiguration
      )
    }
    let collisionActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertTrue(collisionActions.isEmpty)

    let recovered = try await harness.ingress.receive(
      harness.barrierFrame,
      scope: harness.scope
    )
    guard case .keySyncSucceeded = recovered else {
      return XCTFail("released collision reservation must allow the exact retry to finish")
    }
    let recoveredActions = try await harness.ingress.drainTransportActions(scope: harness.scope)
    XCTAssertEqual(recoveredActions.count, 2)
    XCTAssertEqual(
      try productionIngressSend(recoveredActions[0]).requestRoute,
      replacementRoute
    )
    await harness.ingress.cancelPrepared(prepared.token, scope: harness.scope)
  }
}

private actor ProductionIngressScriptedSignatureProducer: DeviceSignatureProducing {
  private enum ScriptFailure: Error {
    case requested
  }

  nonisolated let publicKeyRawRepresentation: Data

  private let key: Curve25519.Signing.PrivateKey
  private var callCount = 0
  private var blockedCalls: Set<Int> = []
  private var failingCalls: Set<Int> = []
  private var reachedCalls: Set<Int> = []
  private var releasedCalls: Set<Int> = []
  private var continuations: [Int: CheckedContinuation<Void, Never>] = [:]

  init(key: Curve25519.Signing.PrivateKey) {
    self.key = key
    publicKeyRawRepresentation = key.publicKey.rawRepresentation
  }

  func blockNext(_ count: Int) -> [Int] {
    precondition(count > 0)
    let calls = (1...count).map { callCount + $0 }
    blockedCalls.formUnion(calls)
    return calls
  }

  func failNext(_ count: Int) -> [Int] {
    precondition(count > 0)
    let calls = (1...count).map { callCount + $0 }
    failingCalls.formUnion(calls)
    return calls
  }

  func hasReached(_ call: Int) -> Bool {
    reachedCalls.contains(call)
  }

  func release(_ call: Int) {
    if let continuation = continuations.removeValue(forKey: call) {
      continuation.resume()
    } else {
      releasedCalls.insert(call)
    }
  }

  func releaseAll() {
    let pending = Array(continuations.values)
    continuations.removeAll(keepingCapacity: false)
    releasedCalls.formUnion(blockedCalls)
    for continuation in pending {
      continuation.resume()
    }
  }

  func signature(for message: Data) async throws -> Data {
    callCount += 1
    let call = callCount
    reachedCalls.insert(call)
    if failingCalls.remove(call) != nil {
      throw ScriptFailure.requested
    }
    if blockedCalls.remove(call) != nil {
      await withCheckedContinuation { continuation in
        if releasedCalls.remove(call) != nil {
          continuation.resume()
        } else {
          continuations[call] = continuation
        }
      }
    }
    return try key.signature(for: message)
  }
}

private final class ProductionIngressRequestRouteSequence: @unchecked Sendable {
  private let lock = NSLock()
  private let bootstrapFallback: @Sendable () throws -> Data
  private var queuedRoutes: [Data] = []

  init(
    bootstrapFallback: @escaping @Sendable () throws -> Data = {
      var uuid = UUID().uuid
      return withUnsafeBytes(of: &uuid) { Data($0) }
    }
  ) {
    self.bootstrapFallback = bootstrapFallback
  }

  func enqueue(_ routes: [Data]) {
    lock.withLock {
      queuedRoutes.append(contentsOf: routes)
    }
  }

  func next() throws -> Data {
    try lock.withLock {
      if !queuedRoutes.isEmpty {
        return queuedRoutes.removeFirst()
      }
      return try bootstrapFallback()
    }
  }
}

private final class ProductionIngressMutableClock: @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64

  init(nowMS: UInt64) {
    value = nowMS
  }

  var nowMS: UInt64 {
    lock.withLock { value }
  }

  func setNowMS(_ nowMS: UInt64) {
    lock.withLock { value = nowMS }
  }
}

private final class ProductionIngressAdvancingClock: @unchecked Sendable {
  private let baseMS: UInt64
  private let startNanoseconds: UInt64

  init(baseMS: UInt64) {
    self.baseMS = baseMS
    startNanoseconds = DispatchTime.now().uptimeNanoseconds
  }

  var nowMS: UInt64 {
    let current = DispatchTime.now().uptimeNanoseconds
    let elapsedNanoseconds = current >= startNanoseconds ? current - startNanoseconds : 0
    let elapsedMilliseconds = elapsedNanoseconds / 1_000_000
    let advanced = baseMS.addingReportingOverflow(elapsedMilliseconds)
    return advanced.overflow ? .max : advanced.partialValue
  }
}

private actor ProductionIngressManualTransferExpirySleeper:
  ProductionTransferExpirySleeping
{
  private struct Waiter {
    let id: UInt64
    let milliseconds: UInt64
    let continuation: CheckedContinuation<Void, any Error>
  }

  private var waiters: [Waiter] = []
  private var nextWaiterID: UInt64 = 1
  private(set) var cancellationCount = 0

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

  private func cancel(id: UInt64) {
    guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
    let waiter = waiters.remove(at: index)
    cancellationCount += 1
    waiter.continuation.resume(throwing: CancellationError())
  }
}

private actor ProductionIngressNonCooperativeTransferExpirySleeper:
  ProductionTransferExpirySleeping
{
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
    waiters.removeAll()
    for waiter in pending {
      waiter.continuation.resume()
    }
  }
}

private struct ProductionIngressCryptoFixture {
  static let fixedTimeMS: UInt64 = 2_000_000_000_000

  let rootURL: URL
  let crypto: KeyUpdateSetCryptoFixture
  let keyVerifier: KeyDirectoryVerifier
  let material: PairedMachineConnectionMaterial
  let stateStore: FileCryptoStateStore
  let keyStore: ProductionIngressMemoryKeyStore
  let persistenceRecorder: ProductionIngressPersistenceStageRecorder
  let conversationKeyBytes: [Data: UInt8]

  var currentRevision: UInt64 { crypto.revision - 1 }
  var nextRevision: UInt64 { crypto.revision }
  var nextCatalogKeyID: KeyIDV1 { KeyIDV1(purpose: .catalog, epoch: 2) }

  static func make(
    conversationRoutes: [Data] = [],
    preactivatedBarrierCount: Int = 0,
    stagedConversationActivation: Data? = nil,
    materializeInitialLifecycle: Bool = true
  ) async throws -> Self {
    precondition(preactivatedBarrierCount >= 0)
    precondition(preactivatedBarrierCount == 0 || stagedConversationActivation == nil)
    precondition(
      preactivatedBarrierCount == 0 || preactivatedBarrierCount == conversationRoutes.count)
    precondition(stagedConversationActivation.map({ conversationRoutes.contains($0) }) ?? true)
    precondition(
      materializeInitialLifecycle
        || (preactivatedBarrierCount == 0 && stagedConversationActivation == nil)
    )
    let crypto = try KeyUpdateSetCryptoFixture()
    let conversationKeyBytes = Dictionary(
      uniqueKeysWithValues: conversationRoutes.enumerated().map { index, route in
        (route, UInt8(0x60 + index))
      }
    )
    let rootSigningKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x85, count: 32)
    )
    let rootPublicKey = rootSigningKey.publicKey.rawRepresentation
    let rootFingerprint = CanonicalCodec.sha256(rootPublicKey)
    let deviceSigningKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x91, count: 32)
    )
    let certificate = try productionIngressDataCertificate(
      crypto: crypto,
      rootSigningKey: rootSigningKey,
      rootFingerprint: rootFingerprint
    )
    let installationID = UUID(uuidString: "91000000-0000-0000-0000-000000000001")!
    let record = try StoredPairedMachineRecordV1(
      clientKind: .macOSApp,
      installationID: installationID,
      machineID: "production-ingress-machine",
      machineName: "Production Ingress Machine",
      relayURL: URL(string: "wss://relay.example.com:8443/")!,
      relayServerID: crypto.relayServerID,
      machineRootPublicKey: rootPublicKey,
      machineRootFingerprint: rootFingerprint,
      machineDataCertificate: certificate,
      machineRoute: crypto.machineRoute,
      deviceRoute: crypto.deviceRoute,
      currentSPKIPin: Data(repeating: 0x92, count: 32),
      nextSPKIPin: nil,
      grantSerial: 9,
      trustEpoch: 3,
      createdAtMS: 1
    )
    let verifiedCertificate = try MachineDataCertificateVerifier.verify(
      certificate,
      relayServerID: crypto.relayServerID,
      machineRoute: crypto.machineRoute,
      machineRootPublicKey: rootPublicKey,
      machineRootFingerprint: rootFingerprint,
      expectedRootKeyID: crypto.rootKeyID,
      expectedTrustEpoch: 3,
      minimumDataCertificateGeneration: certificate.generation,
      nowMilliseconds: fixedTimeMS
    )
    let keyVerifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: verifiedCertificate,
      deviceHPKEPrivateKey: crypto.hpkePrivateKey
    )
    let relayGrant = try productionIngressRelayGrant(
      record: record,
      deviceSigningKey: deviceSigningKey,
      rootSigningKey: rootSigningKey
    )
    let verifiedGrant = try RelayGrantCredentialVerifier.verify(
      relayGrant,
      relayServerID: record.relayServerID,
      machineRootPublicKey: record.machineRootPublicKey,
      machineRootFingerprint: record.machineRootFingerprint,
      expectedMachineRoute: record.machineRoute,
      expectedDeviceRoute: record.deviceRoute,
      expectedDeviceSignPublicKey: deviceSigningKey.publicKey.rawRepresentation,
      expectedGrantSerial: record.grantSerial,
      expectedRootKeyID: crypto.rootKeyID,
      expectedTrustEpoch: record.trustEpoch
    )

    let bootstrapConversationRoutes = conversationRoutes.filter {
      $0 != stagedConversationActivation
    }
    let bootstrap = try productionIngressSignedDirectory(
      crypto: crypto,
      keyVerifier: keyVerifier,
      revision: crypto.revision - 1,
      materials: lifecycleBootstrapMaterials(
        conversations: bootstrapConversationRoutes.map { route in
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 1,
            streamRoute: route,
            rawKeyByte: conversationKeyBytes[route]!
          )
        }
      )
    )
    let preactivatedStreams = try conversationRoutes.enumerated().map { index, route in
      try DeviceStreamCursorStateV1(
        streamRoute: route,
        generation: Data(repeating: UInt8(0x20 + index), count: 16),
        outerCursor: .beforeFirst,
        innerCursor: .conversation(
          id: "recovered-conversation-\(index)",
          cursor: .beforeFirst
        )
      )
    }
    var initialState = try lifecycleState(
      fixture: crypto,
      directory: bootstrap.directory,
      streamStates: preactivatedBarrierCount > 0 ? preactivatedStreams : []
    )
    let setVerifier = KeyUpdateSetVerifier(keyVerifier: keyVerifier)
    if let stagedConversationActivation {
      initialState = try initialState.startingOrResumingKeySyncEpisode(
        targetRevision: crypto.revision,
        observedKeyID: KeyIDV1(purpose: .catalog, epoch: 1),
        streamRoute: nil,
        observedAtMS: fixedTimeMS
      )
      initialState = try setVerifier.prepareDurableStage(
        state: initialState,
        canonicalBytes: productionIngressSignedUpdateSet(
          crypto: crypto,
          keyVerifier: keyVerifier,
          revision: crypto.revision,
          materials: [
            LifecycleTestMaterial(
              purpose: .catalog,
              epoch: 1,
              streamRoute: nil,
              rawKeyByte: 0x41
            ),
            LifecycleTestMaterial(
              purpose: .conversationDEK,
              epoch: 1,
              streamRoute: stagedConversationActivation,
              rawKeyByte: conversationKeyBytes[stagedConversationActivation]!
            ),
            LifecycleTestMaterial(
              purpose: .deviceCommandTx,
              epoch: 1,
              streamRoute: nil,
              rawKeyByte: 0x42
            ),
            LifecycleTestMaterial(
              purpose: .deviceReplyTx,
              epoch: 1,
              streamRoute: nil,
              rawKeyByte: 0x43
            ),
          ]
        ),
        expectedConversationRoutes: conversationRoutes
      )
    } else if preactivatedBarrierCount > 0 {
      initialState = try setVerifier.prepareDurableStage(
        state: initialState,
        canonicalBytes: productionIngressSignedUpdateSet(
          crypto: crypto,
          keyVerifier: keyVerifier,
          revision: crypto.revision,
          materials: [
            LifecycleTestMaterial(
              purpose: .catalog,
              epoch: 1,
              streamRoute: nil,
              rawKeyByte: 0x41
            )
          ]
            + conversationRoutes.enumerated().map { index, route in
              LifecycleTestMaterial(
                purpose: .conversationDEK,
                epoch: 2,
                streamRoute: route,
                rawKeyByte: UInt8(0xB0 + index)
              )
            } + [
              LifecycleTestMaterial(
                purpose: .deviceCommandTx,
                epoch: 1,
                streamRoute: nil,
                rawKeyByte: 0x42
              ),
              LifecycleTestMaterial(
                purpose: .deviceReplyTx,
                epoch: 1,
                streamRoute: nil,
                rawKeyByte: 0x43
              ),
            ]
        ),
        expectedConversationRoutes: conversationRoutes
      )
      for (index, stream) in preactivatedStreams.enumerated() {
        initialState = try initialState.applyingEpochBarrier(
          DeviceEpochBarrierV1(
            streamRoute: stream.streamRoute,
            streamGeneration: stream.generation,
            streamCursor: .beforeFirst,
            innerCursor: stream.innerCursor,
            oldEpoch: 1,
            newEpoch: 2,
            keyDirectoryRevision: crypto.revision
          ),
          activatedAtMS: fixedTimeMS - UInt64(preactivatedStreams.count - index)
        )
      }
    }
    initialState = try DeviceCryptoStateV1(
      stateRevision: 1,
      trustScope: initialState.trustScope,
      keyDirectory: initialState.keyDirectory,
      senderCounter: initialState.senderCounter,
      securityState: initialState.securityState,
      replayStates: initialState.replayStates,
      streamStates: initialState.streamStates,
      keyLifecycle: materializeInitialLifecycle ? initialState.keyLifecycle : nil,
      pendingStreamBindings: initialState.pendingStreamBindings,
      keySyncEpisode: initialState.keySyncEpisode
    )
    let initialSnapshot = try CryptoStateSnapshot(
      initialState
    )
    let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckProductionIngressTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    let identity = try CryptoStateIdentity(
      clientKind: record.clientKind,
      installationID: record.installationID,
      machineID: record.machineID,
      machineRootFingerprint: record.machineRootFingerprint,
      machineRoute: record.machineRoute
    )
    let storageKey = try DeviceStorageKEK(
      rawRepresentation: Data(repeating: 0x93, count: 32)
    )
    let stateStore = try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: storageKey,
      testHooks: .none,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    guard try await stateStore.commitInitial(initialSnapshot) == .created else {
      throw ProductionIngressTestHarnessError.initialStateNotCreated
    }
    let keyStore = ProductionIngressMemoryKeyStore()
    let persistenceRecorder = ProductionIngressPersistenceStageRecorder()
    let guardKey = try KeyStoreKey.paired(
      clientKind: record.clientKind,
      installationID: record.installationID,
      rootFingerprint: record.machineRootFingerprint,
      machineRoute: record.machineRoute,
      purpose: .counterGuard
    )
    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: rootURL,
      identity: identity,
      stateStore: stateStore,
      keyStore: keyStore,
      guardKey: guardKey,
      observer: { stage in
        await persistenceRecorder.record(stage)
      },
      reservationIDGenerator: {
        var uuid = UUID().uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
      },
      clock: { fixedTimeMS }
    )
    _ = try await coordinator.bootstrap(
      CounterBootstrapPermit(
        snapshot: initialSnapshot,
        promotionID: Data(repeating: 0x94, count: 32)
      )
    )
    let auditedValue = try await stateStore.load()
    let audited = try XCTUnwrap(auditedValue)
    let material = PairedMachineConnectionMaterial(
      record: record,
      deviceSigningKey: deviceSigningKey,
      deviceHPKEPrivateKey: crypto.hpkePrivateKey,
      relayGrant: verifiedGrant,
      machineDataCertificate: verifiedCertificate,
      auditedCryptoState: audited,
      cryptoStateStore: stateStore,
      cryptoStateCoordinator: coordinator
    )
    return Self(
      rootURL: rootURL,
      crypto: crypto,
      keyVerifier: keyVerifier,
      material: material,
      stateStore: stateStore,
      keyStore: keyStore,
      persistenceRecorder: persistenceRecorder,
      conversationKeyBytes: conversationKeyBytes
    )
  }

  func nextUpdateSet() throws -> Data {
    try productionIngressSignedUpdateSet(
      crypto: crypto,
      keyVerifier: keyVerifier,
      revision: nextRevision,
      materials: [
        LifecycleTestMaterial(
          purpose: .catalog,
          epoch: nextCatalogKeyID.epoch,
          streamRoute: nil,
          rawKeyByte: 0x51
        )
      ]
        + conversationKeyBytes.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }).map {
          route, rawKeyByte in
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: 1,
            streamRoute: route,
            rawKeyByte: rawKeyByte
          )
        } + [
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
    )
  }

  func rotatingConversationUpdateSet(route rotatingRoute: Data) throws -> Data {
    guard conversationKeyBytes[rotatingRoute] != nil else {
      throw ProductionIngressTestHarnessError.unexpectedDelivery
    }
    return try productionIngressSignedUpdateSet(
      crypto: crypto,
      keyVerifier: keyVerifier,
      revision: nextRevision,
      materials: [
        LifecycleTestMaterial(
          purpose: .catalog,
          epoch: nextCatalogKeyID.epoch,
          streamRoute: nil,
          rawKeyByte: 0x51
        )
      ]
        + conversationKeyBytes.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }).map {
          route, rawKeyByte in
          LifecycleTestMaterial(
            purpose: .conversationDEK,
            epoch: route == rotatingRoute ? 2 : 1,
            streamRoute: route,
            rawKeyByte: route == rotatingRoute ? 0x71 : rawKeyByte
          )
        } + [
          LifecycleTestMaterial(
            purpose: .deviceCommandTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x42
          ),
          LifecycleTestMaterial(
            purpose: .deviceReplyTx,
            epoch: 1,
            streamRoute: nil,
            rawKeyByte: 0x43
          ),
        ]
    )
  }

  func removeSandbox() {
    try? FileManager.default.removeItem(at: rootURL)
  }
}

private actor ProductionIngressMemoryKeyStore: KeyStore {
  private var values: [KeyStoreKey: Data] = [:]
  private(set) var mutationCount = 0

  func load(_ key: KeyStoreKey) async throws -> Data? {
    values[key]
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let current = values[key] {
      guard current == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    mutationCount += 1
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values[key] = replacement
    mutationCount += 1
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values.removeValue(forKey: key)
    mutationCount += 1
  }
}

private actor ProductionIngressPersistenceStageRecorder {
  private var stages: [CryptoStatePersistenceStage] = []

  func record(_ stage: CryptoStatePersistenceStage) {
    stages.append(stage)
  }

  func reset() {
    stages.removeAll(keepingCapacity: true)
  }

  func snapshot() -> [CryptoStatePersistenceStage] {
    stages
  }
}

private enum ProductionIngressTestHarnessError: Error, Equatable {
  case initialStateNotCreated
  case expectedSend
  case expectedDelivery
  case unexpectedDelivery
  case expectedTransportActions
  case requestRouteExhausted
}

private struct ProductionIngressOutboundSend {
  let deviceRoute: Data
  let requestRoute: Data
  let sealedBlob: Data
}

private struct ProductionIngressDirectedTransferParts {
  let messageID: RuntimeMessageID
  let transferID: RuntimeTransferID
  let requestRoute: Data
  let totalSHA256: Data
  let totalBytes: UInt64
  let parts: [Data]
}

private func productionIngressPrepareDirectedTransfer(
  ingress: ProductionMachineConnectionVerifiedIngress,
  fixture: ProductionIngressCryptoFixture,
  scope: TransferAssemblyScope,
  name: String
) async throws -> ProductionIngressDirectedTransferParts {
  let messageID = RuntimeMessageID(rawValue: "\(name)-message")
  let prepared = try await ingress.prepareDirected(
    envelope: RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: messageID,
      body: .request(.catalog(pageCursor: nil))
    ),
    contract: .revocation(expectedGrantSerial: fixture.material.record.grantSerial),
    scope: scope
  )
  let outbound = try productionIngressSend(prepared.frame)
  try await assertProductionIngressIgnored(
    ingress.receive(
      try productionIngressReceivedFrame(
        generation: scope.generation,
        body: .routeAccepted(
          accepted: .request(requestRoute: outbound.requestRoute)
        )
      ),
      scope: scope
    )
  )

  let assembled = try RuntimeWireCodec.encode(
    RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: messageID,
      body: .reply(
        .revocation(
          .committed(RuntimeGrantSerial(rawValue: fixture.material.record.grantSerial))
        )
      )
    )
  )
  let split = assembled.count / 2
  let parts = [Data(assembled[..<split]), Data(assembled[split...])]
  precondition(parts.allSatisfy { !$0.isEmpty })
  return ProductionIngressDirectedTransferParts(
    messageID: messageID,
    transferID: RuntimeTransferID(rawValue: "\(name)-transfer"),
    requestRoute: outbound.requestRoute,
    totalSHA256: Data(SHA256.hash(data: assembled)),
    totalBytes: UInt64(assembled.count),
    parts: parts
  )
}

private func productionIngressReceiveDirectedTransferPart(
  ingress: ProductionMachineConnectionVerifiedIngress,
  fixture: ProductionIngressCryptoFixture,
  scope: TransferAssemblyScope,
  transfer: ProductionIngressDirectedTransferParts,
  partIndex: Int,
  counter: UInt64
) async throws -> MachineConnectionVerifiedIngressOutcome {
  precondition(transfer.parts.indices.contains(partIndex))
  let carrier = try RuntimeWireCodec.encode(
    RuntimeTransferCarrierV2(
      messageID: transfer.messageID,
      channel: .reply,
      transferID: transfer.transferID,
      partIndex: UInt32(partIndex),
      partCount: UInt32(transfer.parts.count),
      totalSHA256: transfer.totalSHA256,
      totalBytes: transfer.totalBytes,
      part: transfer.parts[partIndex]
    )
  )
  return try await ingress.receive(
    try productionIngressTransferReplyFrame(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: transfer.requestRoute,
      carrier: carrier,
      counter: counter
    ),
    scope: scope
  )
}

private struct ProductionIngressStagedCatalogBarrierHarness {
  let fixture: ProductionIngressCryptoFixture
  let ingress: ProductionMachineConnectionVerifiedIngress
  let scope: TransferAssemblyScope
  let signatureProducer: ProductionIngressScriptedSignatureProducer
  let barrier: DeviceEpochBarrierV1
  let barrierFrame: ReceivedRelayFrame
  let updateReply: ReceivedRelayFrame
}

private struct ProductionIngressBootstrapCatalogBarrierHarness {
  let fixture: ProductionIngressCryptoFixture
  let ingress: ProductionMachineConnectionVerifiedIngress
  let scope: TransferAssemblyScope
  let barrier: DeviceEpochBarrierV1
  let barrierFrame: ReceivedRelayFrame
}

private func productionIngressBootstrapCatalogBarrierHarness(
  scopeIndex: UInt64,
  requestRouteGenerator: @escaping @Sendable () throws -> Data = {
    var uuid = UUID().uuid
    return withUnsafeBytes(of: &uuid) { Data($0) }
  }
) async throws -> ProductionIngressBootstrapCatalogBarrierHarness {
  let fixture = try await ProductionIngressCryptoFixture.make(
    materializeInitialLifecycle: false
  )
  do {
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS },
      requestRouteGenerator: requestRouteGenerator
    )
    let scope = productionIngressScope(scopeIndex)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      messageID: RuntimeMessageID(rawValue: "bootstrap-barrier-\(scopeIndex)"),
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      firstCounter: 1
    )
    let barrier = try DeviceEpochBarrierV1(
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamCursor: .beforeFirst,
      innerCursor: .catalog(.beforeFirst),
      oldEpoch: 0,
      newEpoch: 1,
      keyDirectoryRevision: fixture.currentRevision
    )
    let barrierFrame = try productionIngressEpochBarrierPublish(
      fixture: fixture,
      generation: scope.generation,
      barrier: barrier,
      counter: 1,
      keyDirectoryRevision: fixture.currentRevision,
      rawKeyByte: 0x41,
      keyID: KeyIDV1(purpose: .catalog, epoch: 1)
    )
    return ProductionIngressBootstrapCatalogBarrierHarness(
      fixture: fixture,
      ingress: ingress,
      scope: scope,
      barrier: barrier,
      barrierFrame: barrierFrame
    )
  } catch {
    fixture.removeSandbox()
    throw error
  }
}

private func productionIngressStagedCatalogBarrierHarness(
  scopeIndex: UInt64,
  requestRouteGenerator: @escaping @Sendable () throws -> Data = {
    var uuid = UUID().uuid
    return withUnsafeBytes(of: &uuid) { Data($0) }
  }
) async throws -> ProductionIngressStagedCatalogBarrierHarness {
  let fixture = try await ProductionIngressCryptoFixture.make()
  do {
    let signatureProducer = ProductionIngressScriptedSignatureProducer(
      key: fixture.material.deviceSigningKey
    )
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: fixture.material,
      expectedConversationRoutes: [],
      clock: { ProductionIngressCryptoFixture.fixedTimeMS },
      requestRouteGenerator: requestRouteGenerator,
      deviceSignatureProducer: signatureProducer
    )
    let scope = productionIngressScope(scopeIndex)
    _ = try await ingress.resumeFrames(
      generation: scope.generation,
      scope: scope,
      heartbeatIntervalSeconds: 31
    )
    _ = try await productionIngressBootstrapKeySyncCatalog(
      ingress: ingress,
      fixture: fixture,
      scope: scope,
      name: "reservation-harness-\(scopeIndex)"
    )
    guard
      case .keySyncRequired = try await ingress.receive(
        try productionIngressExactNextProbe(
          fixture: fixture,
          generation: scope.generation,
          counter: 1
        ),
        scope: scope
      )
    else {
      throw ProductionIngressTestHarnessError.unexpectedDelivery
    }
    let keySyncActions = try await ingress.drainTransportActions(scope: scope)
    guard keySyncActions.count == 1 else {
      throw ProductionIngressTestHarnessError.expectedTransportActions
    }
    let keySyncOutbound = try productionIngressSend(try XCTUnwrap(keySyncActions.first))
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: keySyncOutbound.requestRoute)
          )
        ),
        scope: scope
      )
    )
    _ = try await ingress.drainTransportActions(scope: scope)

    let updateReply = try productionIngressKeyUpdateReply(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: keySyncOutbound.requestRoute,
      updateSet: fixture.nextUpdateSet(),
      counter: 4
    )
    try await assertProductionIngressIgnored(
      ingress.receive(updateReply, scope: scope)
    )
    let updateAckActions = try await ingress.drainTransportActions(scope: scope)
    guard updateAckActions.count == 1 else {
      throw ProductionIngressTestHarnessError.expectedTransportActions
    }
    let updateAckOutbound = try productionIngressSend(try XCTUnwrap(updateAckActions.first))
    try await assertProductionIngressIgnored(
      ingress.receive(
        try productionIngressReceivedFrame(
          generation: scope.generation,
          body: .routeAccepted(
            accepted: .request(requestRoute: updateAckOutbound.requestRoute)
          )
        ),
        scope: scope
      )
    )
    _ = try await ingress.drainTransportActions(scope: scope)

    let barrier = try DeviceEpochBarrierV1(
      streamRoute: productionIngressKeySyncStreamRoute,
      streamGeneration: productionIngressKeySyncStreamGeneration,
      streamCursor: .beforeFirst,
      innerCursor: .catalog(.beforeFirst),
      oldEpoch: 1,
      newEpoch: 2,
      keyDirectoryRevision: fixture.nextRevision
    )
    let barrierFrame = try productionIngressEpochBarrierPublish(
      fixture: fixture,
      generation: scope.generation,
      barrier: barrier,
      counter: 2
    )
    return ProductionIngressStagedCatalogBarrierHarness(
      fixture: fixture,
      ingress: ingress,
      scope: scope,
      signatureProducer: signatureProducer,
      barrier: barrier,
      barrierFrame: barrierFrame,
      updateReply: updateReply
    )
  } catch {
    fixture.removeSandbox()
    throw error
  }
}

private func productionIngressCommitBarrierForDuplicateConcurrency(
  _ harness: ProductionIngressStagedCatalogBarrierHarness
) async throws {
  let activation = try await harness.ingress.receive(
    harness.barrierFrame,
    scope: harness.scope
  )
  guard
    case .keySyncSucceeded(let acceptedRevision, let recoveryTargets) = activation,
    acceptedRevision == harness.fixture.nextRevision,
    recoveryTargets.count == 1,
    case .catalog = recoveryTargets[0]
  else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }

  let actions = try await harness.ingress.drainTransportActions(scope: harness.scope)
  guard actions.count == 2 else {
    throw ProductionIngressTestHarnessError.expectedTransportActions
  }
  let semanticAck = try productionIngressSend(try XCTUnwrap(actions.first))
  guard
    case .streamAppliedAck(let acknowledgement) = try productionIngressOpenDeviceControl(
      semanticAck,
      fixture: harness.fixture
    ),
    acknowledgement.epochBarrierSHA256 == harness.barrier.canonicalSHA256
  else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }

  try await assertProductionIngressIgnored(
    harness.ingress.receive(
      try productionIngressReceivedFrame(
        generation: harness.scope.generation,
        body: .routeAccepted(
          accepted: .request(requestRoute: semanticAck.requestRoute)
        )
      ),
      scope: harness.scope
    )
  )
  let followup = try await harness.ingress.drainTransportActions(scope: harness.scope)
  guard followup.isEmpty else {
    throw ProductionIngressTestHarnessError.expectedTransportActions
  }
}

private func productionIngressScope(_ generation: UInt64) -> TransferAssemblyScope {
  TransferAssemblyScope(
    connectionID: UUID(uuidString: "92000000-0000-0000-0000-000000000001")!,
    generation: RelayTransportGeneration(rawValue: generation)
  )
}

private let productionIngressKeySyncStreamRoute = Data(repeating: 0xA1, count: 16)
private let productionIngressKeySyncStreamGeneration = Data(repeating: 0xA2, count: 16)

private func productionIngressBootstrapKeySyncCatalog(
  ingress: ProductionMachineConnectionVerifiedIngress,
  fixture: ProductionIngressCryptoFixture,
  scope: TransferAssemblyScope,
  name: String,
  firstCounter: UInt64 = 1
) async throws -> [RelayV2OutboundFrame] {
  try await productionIngressBootstrapCatalog(
    ingress: ingress,
    fixture: fixture,
    scope: scope,
    messageID: RuntimeMessageID(rawValue: name),
    streamRoute: productionIngressKeySyncStreamRoute,
    streamGeneration: productionIngressKeySyncStreamGeneration,
    firstCounter: firstCounter
  )
}

private func productionIngressBootstrapCatalog(
  ingress: ProductionMachineConnectionVerifiedIngress,
  fixture: ProductionIngressCryptoFixture,
  scope: TransferAssemblyScope,
  messageID: RuntimeMessageID,
  streamRoute: Data,
  streamGeneration: Data,
  runtimeStreamGeneration: Data? = nil,
  firstCounter: UInt64,
  after: RuntimeStreamCursorV1 = .beforeFirst,
  synchronizedOuterCursor: RuntimeStreamCursorV1? = nil,
  bindingCursor: StreamCursor = .beforeFirst,
  keyDirectoryRevision: UInt64? = nil,
  catalogKeyEpoch: UInt64 = 1
) async throws -> [RelayV2OutboundFrame] {
  let effectiveKeyDirectoryRevision = keyDirectoryRevision ?? fixture.currentRevision
  let runtimeGeneration = RuntimeStreamGeneration(
    rawValue: productionIngressCanonicalUUIDString(
      runtimeStreamGeneration ?? streamGeneration
    )
  )
  let prepared = try await ingress.prepareSubscription(
    target: .catalog,
    after: after,
    requestID: messageID,
    scope: scope
  )
  let outbound = try productionIngressSend(prepared.frame)
  try await assertProductionIngressIgnored(
    ingress.receive(
      try productionIngressReceivedFrame(
        generation: scope.generation,
        body: .routeAccepted(
          accepted: .request(requestRoute: outbound.requestRoute)
        )
      ),
      scope: scope
    )
  )

  let subscribedOutcome = try await ingress.receive(
    try productionIngressRuntimeReplyFrame(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(
          .subscription(.subscribed(streamGeneration: runtimeGeneration))
        )
      ),
      counter: firstCounter,
      keyDirectoryRevision: effectiveKeyDirectoryRevision
    ),
    scope: scope
  )
  guard case .delivery(let subscribedDelivery) = subscribedOutcome else {
    throw ProductionIngressTestHarnessError.expectedDelivery
  }
  guard
    case .typedReply(.subscription(.subscribed(let deliveredGeneration))) =
      subscribedDelivery.payload,
    deliveredGeneration.rawValue == runtimeGeneration.rawValue
  else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }
  try await ingress.commit(subscribedDelivery)
  try await ingress.awaitResolution(subscribedDelivery)

  let sync = try productionIngressSyncComplete(
    streamGeneration: runtimeGeneration,
    streamCursor: synchronizedOuterCursor ?? after,
    innerCursor: .catalog(cursor: after),
    keyDirectoryRevision: effectiveKeyDirectoryRevision
  )
  let syncOutcome = try await ingress.receive(
    try productionIngressRuntimeReplyFrame(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(.syncComplete(sync))
      ),
      counter: firstCounter + 1,
      keyDirectoryRevision: effectiveKeyDirectoryRevision
    ),
    scope: scope
  )
  guard case .delivery(let syncDelivery) = syncOutcome else {
    throw ProductionIngressTestHarnessError.expectedDelivery
  }
  guard
    case .syncComplete(let deliveredSync) = syncDelivery.payload,
    deliveredSync.streamGeneration.rawValue == runtimeGeneration.rawValue,
    deliveredSync.keyDirectoryRevision == effectiveKeyDirectoryRevision
  else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }
  try await ingress.commit(syncDelivery)
  try await ingress.awaitResolution(syncDelivery)

  let binding = try DaemonStreamBindingV1(
    authority: DeviceKeyControlAuthorityV1(
      machineRoute: fixture.crypto.machineRoute,
      deviceRoute: fixture.crypto.deviceRoute,
      grantSerial: fixture.material.record.grantSerial,
      rootTrustEpoch: fixture.material.record.trustEpoch
    ),
    streamRoute: streamRoute,
    streamGeneration: streamGeneration,
    streamCursor: bindingCursor,
    innerCursor: .catalog(cursor: after),
    keyDirectoryRevision: effectiveKeyDirectoryRevision,
    keyID: KeyIDV1(purpose: .catalog, epoch: catalogKeyEpoch)
  )
  let bindingOutcome = try await ingress.receive(
    try productionIngressDaemonControlReply(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      control: .streamBinding(binding),
      counter: firstCounter + 2,
      keyDirectoryRevision: effectiveKeyDirectoryRevision
    ),
    scope: scope
  )
  guard case .transportActions(let actions) = bindingOutcome else {
    throw ProductionIngressTestHarnessError.expectedTransportActions
  }
  return actions
}

private func productionIngressBootstrapConversation(
  ingress: ProductionMachineConnectionVerifiedIngress,
  fixture: ProductionIngressCryptoFixture,
  scope: TransferAssemblyScope,
  messageID: RuntimeMessageID,
  conversationID: RuntimeConversationID,
  streamRoute: Data,
  streamGeneration: Data,
  firstCounter: UInt64,
  after: RuntimeStreamCursorV1 = .beforeFirst,
  synchronizedOuterCursor: RuntimeStreamCursorV1? = nil,
  synchronizedInnerCursor: RuntimeStreamCursorV1? = nil,
  bindingCursor: StreamCursor = .beforeFirst
) async throws -> [RelayV2OutboundFrame] {
  let runtimeGeneration = RuntimeStreamGeneration(
    rawValue: productionIngressCanonicalUUIDString(streamGeneration)
  )
  let prepared = try await ingress.prepareSubscription(
    target: .conversation(conversationID: conversationID),
    after: after,
    requestID: messageID,
    scope: scope
  )
  let outbound = try productionIngressSend(prepared.frame)
  try await assertProductionIngressIgnored(
    ingress.receive(
      try productionIngressReceivedFrame(
        generation: scope.generation,
        body: .routeAccepted(
          accepted: .request(requestRoute: outbound.requestRoute)
        )
      ),
      scope: scope
    )
  )

  let subscribedOutcome = try await ingress.receive(
    try productionIngressRuntimeReplyFrame(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(
          .subscription(.subscribed(streamGeneration: runtimeGeneration))
        )
      ),
      counter: firstCounter
    ),
    scope: scope
  )
  guard case .delivery(let subscribedDelivery) = subscribedOutcome else {
    throw ProductionIngressTestHarnessError.expectedDelivery
  }
  try await ingress.commit(subscribedDelivery)
  try await ingress.awaitResolution(subscribedDelivery)

  let innerCursor = RuntimeInnerCursorV1.conversation(
    conversationID: conversationID,
    cursor: synchronizedInnerCursor ?? after
  )
  let sync = try productionIngressSyncComplete(
    streamGeneration: runtimeGeneration,
    streamCursor: synchronizedOuterCursor ?? after,
    innerCursor: innerCursor,
    keyDirectoryRevision: fixture.currentRevision
  )
  let syncOutcome = try await ingress.receive(
    try productionIngressRuntimeReplyFrame(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(.syncComplete(sync))
      ),
      counter: firstCounter + 1
    ),
    scope: scope
  )
  guard case .delivery(let syncDelivery) = syncOutcome else {
    throw ProductionIngressTestHarnessError.expectedDelivery
  }
  try await ingress.commit(syncDelivery)
  try await ingress.awaitResolution(syncDelivery)

  let binding = try DaemonStreamBindingV1(
    authority: DeviceKeyControlAuthorityV1(
      machineRoute: fixture.crypto.machineRoute,
      deviceRoute: fixture.crypto.deviceRoute,
      grantSerial: fixture.material.record.grantSerial,
      rootTrustEpoch: fixture.material.record.trustEpoch
    ),
    streamRoute: streamRoute,
    streamGeneration: streamGeneration,
    streamCursor: bindingCursor,
    innerCursor: .conversation(conversationID: conversationID, cursor: after),
    keyDirectoryRevision: fixture.currentRevision,
    keyID: KeyIDV1(purpose: .conversationDEK, epoch: 1)
  )
  let bindingOutcome = try await ingress.receive(
    try productionIngressDaemonControlReply(
      fixture: fixture,
      generation: scope.generation,
      requestRoute: outbound.requestRoute,
      control: .streamBinding(binding),
      counter: firstCounter + 2
    ),
    scope: scope
  )
  guard case .transportActions(let actions) = bindingOutcome else {
    throw ProductionIngressTestHarnessError.expectedTransportActions
  }
  return actions
}

private struct ProductionIngressSyncCompleteFixture: Encodable {
  let streamGeneration: RuntimeStreamGeneration
  let streamCursor: RuntimeStreamCursorV1
  let innerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
}

private func productionIngressSyncComplete(
  streamGeneration: RuntimeStreamGeneration,
  streamCursor: RuntimeStreamCursorV1,
  innerCursor: RuntimeInnerCursorV1,
  keyDirectoryRevision: UInt64
) throws -> RuntimeSyncCompleteV1 {
  try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: JSONEncoder().encode(
      ProductionIngressSyncCompleteFixture(
        streamGeneration: streamGeneration,
        streamCursor: streamCursor,
        innerCursor: innerCursor,
        keyDirectoryRevision: keyDirectoryRevision
      )
    )
  )
}

private func productionIngressCanonicalUUIDString(_ bytes: Data) -> String {
  precondition(bytes.count == 16)
  let hex = bytes.map { String(format: "%02x", $0) }.joined()
  return "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-"
    + "\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
}

private func productionIngressSend(
  _ outbound: RelayV2OutboundFrame
) throws -> ProductionIngressOutboundSend {
  let frame = try RelayWireCodecV2.decode(RelayWireCodecV2.encode(outbound))
  guard case .send(let deviceRoute, let requestRoute, let sealedBlob) = frame.body else {
    throw ProductionIngressTestHarnessError.expectedSend
  }
  return ProductionIngressOutboundSend(
    deviceRoute: deviceRoute,
    requestRoute: requestRoute,
    sealedBlob: sealedBlob
  )
}

private func productionIngressDecodedFrame(
  _ outbound: RelayV2OutboundFrame
) throws -> RelayV2Frame {
  try RelayWireCodecV2.decode(RelayWireCodecV2.encode(outbound))
}

private func productionIngressReceivedFrame(
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

private func productionIngressRuntimeReplyFrame(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  requestRoute: Data,
  envelope: RuntimeEnvelopeV2,
  counter: UInt64,
  keyDirectoryRevision: UInt64? = nil
) throws -> ReceivedRelayFrame {
  let context = productionIngressReplyContext(
    fixture: fixture,
    requestRoute: requestRoute
  )
  let signed = try productionIngressSignedPayload(
    payload: RuntimeWireCodec.encode(envelope),
    payloadKind: .commandReceipt,
    keyDirectoryRevision: keyDirectoryRevision ?? fixture.currentRevision,
    rawKey: Data(repeating: 0x43, count: 32),
    keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .reply(
      deviceRoute: fixture.crypto.deviceRoute,
      requestRoute: requestRoute,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressTransferReplyFrame(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  requestRoute: Data,
  carrier: Data,
  counter: UInt64
) throws -> ReceivedRelayFrame {
  let context = productionIngressReplyContext(
    fixture: fixture,
    requestRoute: requestRoute
  )
  let signed = try productionIngressSignedPayload(
    payload: carrier,
    payloadKind: .transferPart,
    keyDirectoryRevision: fixture.currentRevision,
    rawKey: Data(repeating: 0x43, count: 32),
    keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .reply(
      deviceRoute: fixture.crypto.deviceRoute,
      requestRoute: requestRoute,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressCatalogPublishFrame(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  streamRoute: Data,
  streamGeneration: Data,
  streamSequence: UInt64,
  catalogRevision: UInt64,
  counter: UInt64,
  keyDirectoryRevision: UInt64? = nil,
  keyEpoch: UInt64 = 1,
  rawKeyByte: UInt8 = 0x41
) throws -> ReceivedRelayFrame {
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: streamGeneration,
    streamCursor: nil,
    streamSeq: streamSequence,
    messageKeyEpoch: keyEpoch
  )
  let envelope = RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: "catalog-publish-\(streamSequence)"),
    body: .stream(
      .catalogDelta(
        RuntimeCatalogDeltaV2(catalogRevision: catalogRevision, changes: [])
      ))
  )
  let signed = try productionIngressSignedPayload(
    payload: RuntimeWireCodec.encode(envelope),
    payloadKind: .catalogDelta,
    keyDirectoryRevision: keyDirectoryRevision ?? fixture.currentRevision,
    rawKey: Data(repeating: rawKeyByte, count: 32),
    keyID: KeyIDV1(purpose: .catalog, epoch: keyEpoch),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: streamRoute,
      generation: streamGeneration,
      streamSeq: streamSequence,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressCatalogTransferFrames(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  streamRoute: Data,
  streamGeneration: Data,
  firstStreamSequence: UInt64,
  catalogRevision: UInt64,
  firstCounter: UInt64
) throws -> [ReceivedRelayFrame] {
  let messageID = RuntimeMessageID(rawValue: "catalog-transfer-\(firstStreamSequence)")
  let envelope = RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: messageID,
    body: .stream(
      .catalogDelta(
        RuntimeCatalogDeltaV2(catalogRevision: catalogRevision, changes: [])
      ))
  )
  let assembled = try RuntimeWireCodec.encode(envelope)
  let split = assembled.count / 2
  let parts = [Data(assembled[..<split]), Data(assembled[split...])]
  precondition(parts.allSatisfy { !$0.isEmpty })
  let transferID = RuntimeTransferID(rawValue: "catalog-transfer-id-\(firstStreamSequence)")
  let totalSHA256 = Data(SHA256.hash(data: assembled))
  return try parts.enumerated().map { index, part in
    let streamSequence = firstStreamSequence + UInt64(index)
    let carrier = try RuntimeWireCodec.encode(
      RuntimeTransferCarrierV2(
        messageID: messageID,
        channel: .stream,
        transferID: transferID,
        partIndex: UInt32(index),
        partCount: UInt32(parts.count),
        totalSHA256: totalSHA256,
        totalBytes: UInt64(assembled.count),
        part: part
      )
    )
    let context = OuterContextV1(
      frameKind: .catalogPublish,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: fixture.crypto.machineRoute,
      deviceRoute: nil,
      streamRoute: streamRoute,
      requestRoute: nil,
      streamGeneration: streamGeneration,
      streamCursor: nil,
      streamSeq: streamSequence,
      messageKeyEpoch: 1
    )
    let signed = try productionIngressSignedPayload(
      payload: carrier,
      payloadKind: .transferPart,
      keyDirectoryRevision: fixture.currentRevision,
      rawKey: Data(repeating: 0x41, count: 32),
      keyID: KeyIDV1(purpose: .catalog, epoch: 1),
      counter: firstCounter + UInt64(index),
      context: context,
      signingKey: fixture.crypto.dataSigningKey
    )
    return try productionIngressReceivedFrame(
      generation: generation,
      body: .publish(
        streamRoute: streamRoute,
        generation: streamGeneration,
        streamSeq: streamSequence,
        sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
          signed,
          maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
        )
      )
    )
  }
}

private func productionIngressConversationPublishFrame(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  conversationID: RuntimeConversationID,
  streamRoute: Data,
  streamGeneration: Data,
  streamSequence: UInt64,
  eventSequence: UInt64,
  counter: UInt64
) throws -> ReceivedRelayFrame {
  guard let rawKeyByte = fixture.conversationKeyBytes[streamRoute] else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }
  let context = OuterContextV1(
    frameKind: .conversationPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: streamGeneration,
    streamCursor: nil,
    streamSeq: streamSequence,
    messageKeyEpoch: 1
  )
  let event = try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: "key-sync-event-\(eventSequence)"),
    eventSeq: eventSequence,
    commandID: nil,
    itemID: nil,
    entityID: nil,
    body: .error(RuntimeFailureV1(code: "fixture", message: "fixture"))
  )
  let envelope = RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: "conversation-publish-\(streamSequence)"),
    body: .stream(.event(event))
  )
  let signed = try productionIngressSignedPayload(
    payload: RuntimeWireCodec.encode(envelope),
    payloadKind: .conversationEvent,
    keyDirectoryRevision: fixture.currentRevision,
    rawKey: Data(repeating: rawKeyByte, count: 32),
    keyID: KeyIDV1(purpose: .conversationDEK, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: streamRoute,
      generation: streamGeneration,
      streamSeq: streamSequence,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressExactNextProbe(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  counter: UInt64
) throws -> ReceivedRelayFrame {
  let streamRoute = productionIngressKeySyncStreamRoute
  let streamGeneration = productionIngressKeySyncStreamGeneration
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: streamGeneration,
    streamCursor: nil,
    streamSeq: 1,
    messageKeyEpoch: fixture.nextCatalogKeyID.epoch
  )
  let signed = try productionIngressSignedPayload(
    payload: Data("exact-next-probe".utf8),
    payloadKind: .catalogDelta,
    keyDirectoryRevision: fixture.nextRevision,
    rawKey: Data(repeating: 0x51, count: 32),
    keyID: fixture.nextCatalogKeyID,
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: streamRoute,
      generation: streamGeneration,
      streamSeq: 1,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressEpochBarrierPublish(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  barrier: DeviceEpochBarrierV1,
  counter: UInt64,
  keyDirectoryRevision: UInt64? = nil,
  rawKeyByte: UInt8 = 0x51,
  keyID: KeyIDV1? = nil
) throws -> ReceivedRelayFrame {
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: barrier.streamRoute,
    requestRoute: nil,
    streamGeneration: barrier.streamGeneration,
    streamCursor: nil,
    streamSeq: barrier.appliedStreamSequence,
    messageKeyEpoch: barrier.newEpoch
  )
  let signed = try productionIngressSignedPayload(
    payload: DaemonKeyControlCanonicalCodec.encode(.epochBarrier(barrier)),
    payloadKind: .keyUpdate,
    keyDirectoryRevision: keyDirectoryRevision ?? fixture.nextRevision,
    rawKey: Data(repeating: rawKeyByte, count: 32),
    keyID: keyID ?? fixture.nextCatalogKeyID,
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: barrier.streamRoute,
      generation: barrier.streamGeneration,
      streamSeq: barrier.appliedStreamSequence,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressConversationEpochBarrierPublish(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  barrier: DeviceEpochBarrierV1,
  counter: UInt64,
  rawKeyByte: UInt8 = 0x71
) throws -> ReceivedRelayFrame {
  guard case .conversation = barrier.innerCursor else {
    throw ProductionIngressTestHarnessError.unexpectedDelivery
  }
  let context = OuterContextV1(
    frameKind: .conversationPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: barrier.streamRoute,
    requestRoute: nil,
    streamGeneration: barrier.streamGeneration,
    streamCursor: nil,
    streamSeq: barrier.appliedStreamSequence,
    messageKeyEpoch: barrier.newEpoch
  )
  let signed = try productionIngressSignedPayload(
    payload: DaemonKeyControlCanonicalCodec.encode(.epochBarrier(barrier)),
    payloadKind: .keyUpdate,
    keyDirectoryRevision: fixture.nextRevision,
    rawKey: Data(repeating: rawKeyByte, count: 32),
    keyID: KeyIDV1(purpose: .conversationDEK, epoch: barrier.newEpoch),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: barrier.streamRoute,
      generation: barrier.streamGeneration,
      streamSeq: barrier.appliedStreamSequence,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressDirectoryRevisionAdvancePublish(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  advance: DeviceDirectoryRevisionAdvanceV1,
  counter: UInt64
) throws -> ReceivedRelayFrame {
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: nil,
    streamRoute: advance.streamRoute,
    requestRoute: nil,
    streamGeneration: advance.streamGeneration,
    streamCursor: nil,
    streamSeq: advance.streamSequence,
    messageKeyEpoch: 1
  )
  let daemonAdvance = try DaemonDirectoryRevisionAdvanceV1(
    fromRevision: advance.fromRevision,
    toRevision: advance.toRevision
  )
  let signed = try productionIngressSignedPayload(
    payload: DaemonKeyControlCanonicalCodec.encode(
      .directoryRevisionAdvance(daemonAdvance)
    ),
    payloadKind: .keyUpdate,
    keyDirectoryRevision: advance.fromRevision,
    rawKey: Data(repeating: 0x41, count: 32),
    keyID: KeyIDV1(purpose: .catalog, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .publish(
      streamRoute: advance.streamRoute,
      generation: advance.streamGeneration,
      streamSeq: advance.streamSequence,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressKeyUpdateReply(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  requestRoute: Data,
  outerRequestRoute: Data? = nil,
  updateSet: Data,
  counter: UInt64,
  tamperSignature: Bool = false
) throws -> ReceivedRelayFrame {
  try productionIngressExactNextKeySyncReply(
    fixture: fixture,
    generation: generation,
    requestRoute: requestRoute,
    outerRequestRoute: outerRequestRoute,
    control: .updateSet(try KeyUpdateSetCanonicalCodec.decode(updateSet)),
    counter: counter,
    tamperSignature: tamperSignature
  )
}

private func productionIngressExactNextKeySyncReply(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  requestRoute: Data,
  outerRequestRoute: Data? = nil,
  control: DaemonKeyControlV1,
  counter: UInt64,
  tamperSignature: Bool = false
) throws -> ReceivedRelayFrame {
  let context = productionIngressReplyContext(
    fixture: fixture,
    requestRoute: requestRoute
  )
  var signed = try productionIngressSignedPayload(
    payload: DaemonKeyControlCanonicalCodec.encode(control),
    payloadKind: .keyUpdate,
    keyDirectoryRevision: fixture.nextRevision,
    rawKey: Data(repeating: 0x43, count: 32),
    keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  if tamperSignature {
    signed.signature[signed.signature.startIndex] ^= 0x01
  }
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .reply(
      deviceRoute: fixture.crypto.deviceRoute,
      requestRoute: outerRequestRoute ?? requestRoute,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressDaemonControlReply(
  fixture: ProductionIngressCryptoFixture,
  generation: RelayTransportGeneration,
  requestRoute: Data,
  control: DaemonKeyControlV1,
  counter: UInt64,
  keyDirectoryRevision: UInt64? = nil
) throws -> ReceivedRelayFrame {
  let context = productionIngressReplyContext(
    fixture: fixture,
    requestRoute: requestRoute
  )
  let signed = try productionIngressSignedPayload(
    payload: DaemonKeyControlCanonicalCodec.encode(control),
    payloadKind: .keyUpdate,
    keyDirectoryRevision: keyDirectoryRevision ?? fixture.currentRevision,
    rawKey: Data(repeating: 0x43, count: 32),
    keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: 1),
    counter: counter,
    context: context,
    signingKey: fixture.crypto.dataSigningKey
  )
  return try productionIngressReceivedFrame(
    generation: generation,
    body: .reply(
      deviceRoute: fixture.crypto.deviceRoute,
      requestRoute: requestRoute,
      sealedBlob: try RelayV2SignedSealedBlobCodec.encode(
        signed,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      )
    )
  )
}

private func productionIngressSignedPayload(
  payload: Data,
  payloadKind: SealedPayloadKind,
  keyDirectoryRevision: UInt64,
  rawKey: Data,
  keyID: KeyIDV1,
  counter: UInt64,
  context: OuterContextV1,
  signingKey: Curve25519.Signing.PrivateKey
) throws -> SignedSealedBlobV1 {
  let unsigned = try RelayCrypto.sealSymmetric(
    payload,
    key: AeadSendingKey(
      keyID: keyID,
      epoch: keyID.epoch,
      keyDirectoryRevision: keyDirectoryRevision,
      payloadKind: payloadKind,
      rawKey: rawKey
    ),
    context: context,
    counter: counter
  )
  return try RelayCrypto.signSealed(unsigned, key: signingKey, context: context)
}

private func productionIngressReplyContext(
  fixture: ProductionIngressCryptoFixture,
  requestRoute: Data
) -> OuterContextV1 {
  OuterContextV1(
    frameKind: .directedReply,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: fixture.crypto.deviceRoute,
    streamRoute: nil,
    requestRoute: requestRoute,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: 1
  )
}

private func productionIngressOpenDeviceControl(
  _ outbound: ProductionIngressOutboundSend,
  fixture: ProductionIngressCryptoFixture
) throws -> DeviceKeyControlRequestV1 {
  let signed = try RelayV2SignedSealedBlobCodec.decode(
    outbound.sealedBlob,
    maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
  )
  let context = OuterContextV1(
    frameKind: .uplinkSend,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.crypto.machineRoute,
    deviceRoute: fixture.crypto.deviceRoute,
    streamRoute: nil,
    requestRoute: outbound.requestRoute,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: signed.inner.keyEpoch
  )
  let verified = try RelayCrypto.verifySealed(
    signed,
    key: fixture.material.deviceSigningKey.publicKey,
    context: context
  )
  let opened = try RelayCrypto.openSealedPayload(
    verified,
    key: AeadReceivingKey(
      keyID: signed.inner.keyID,
      epoch: signed.inner.keyEpoch,
      rawKey: Data(repeating: 0x42, count: 32)
    ),
    context: context
  )
  XCTAssertEqual(opened.payloadKind, .keyUpdate)
  return try KeyControlCanonicalCodec.decode(opened.payload)
}

private func productionIngressSignedDirectory(
  crypto: KeyUpdateSetCryptoFixture,
  keyVerifier: KeyDirectoryVerifier,
  revision: UInt64,
  materials: [LifecycleTestMaterial]
) throws -> (directory: DeviceKeyDirectoryV1, canonical: Data) {
  let entries = try materials.map { material in
    let keyID = KeyIDV1(purpose: material.purpose, epoch: material.epoch)
    let sealing = try keyVerifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: keyID,
      streamRoute: material.streamRoute
    )
    let envelope = try RelayCrypto.sealHPKE(
      material.rawKey,
      recipient: crypto.hpkePrivateKey.publicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    return try DeviceWrappedKeyV1(
      keyID: keyID,
      deviceRoute: crypto.deviceRoute,
      streamRoute: material.streamRoute,
      enc: envelope.enc,
      wrappedKey: envelope.ciphertext
    )
  }
  let unsigned = try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: Data(repeating: 1, count: 64)
  )
  let signed = try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: crypto.dataSigningKey.signature(
      for: keyVerifier.directorySignatureTBS(unsigned)
    )
  )
  return (signed, try KeyDirectoryCanonicalCodec.encode(signed))
}

private func productionIngressSignedUpdateSet(
  crypto: KeyUpdateSetCryptoFixture,
  keyVerifier: KeyDirectoryVerifier,
  revision: UInt64,
  materials: [LifecycleTestMaterial]
) throws -> Data {
  let updates = try materials.map { material in
    let keyID = KeyIDV1(purpose: material.purpose, epoch: material.epoch)
    let sealing = try keyVerifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: keyID,
      streamRoute: material.streamRoute
    )
    let envelope = try RelayCrypto.sealHPKE(
      material.rawKey,
      recipient: crypto.hpkePrivateKey.publicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    let unsigned = try CanonicalKeyUpdateV1(
      keyDirectoryRevision: revision,
      keyID: keyID,
      deviceRoute: crypto.deviceRoute,
      streamRoute: material.streamRoute,
      enc: envelope.enc,
      wrappedKey: envelope.ciphertext,
      signature: Data(repeating: 0, count: 64),
      requireSignature: false
    )
    return try CanonicalKeyUpdateV1(
      keyDirectoryRevision: unsigned.keyDirectoryRevision,
      keyID: unsigned.keyID,
      deviceRoute: unsigned.deviceRoute,
      streamRoute: unsigned.streamRoute,
      enc: unsigned.enc,
      wrappedKey: unsigned.wrappedKey,
      signature: crypto.dataSigningKey.signature(
        for: keyVerifier.keyUpdateSignatureTBS(unsigned, sealing: sealing)
      )
    )
  }
  return try KeyUpdateSetCanonicalCodec.encode(
    CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: revision,
      deviceRoute: crypto.deviceRoute,
      updates: updates
    )
  )
}

private func productionIngressDataCertificate(
  crypto: KeyUpdateSetCryptoFixture,
  rootSigningKey: Curve25519.Signing.PrivateKey,
  rootFingerprint: Data
) throws -> RelayV2SignedCertificate {
  let unsigned = RelayV2SignedCertificate(
    subjectPubkey: crypto.dataSigningKey.publicKey.rawRepresentation,
    certRole: .data,
    generation: 4,
    rootKeyId: crypto.rootKeyID,
    trustEpoch: 3,
    notAfterMs: 4_000_000_000_000,
    signature: Data(repeating: 1, count: 64)
  )
  let signature = try RelayCrypto.sign(
    ToBeSignedV1(
      objectType: .dataCert,
      signatureFormatVersion: 1,
      relayProtocolVersion: relayProtocolVersionV2,
      runtimeProtocolVersion: runtimeProtocolVersionCurrent,
      e2eeFormatVersion: 1,
      relayServerID: crypto.relayServerID,
      machineRoute: crypto.machineRoute,
      deviceRoute: nil,
      streamRoute: nil,
      requestRoute: nil,
      streamGeneration: nil,
      streamCursor: nil,
      roleScope: "machine-data",
      signingKeyFingerprint: rootFingerprint,
      rootKeyID: crypto.rootKeyID,
      trustEpoch: 3,
      serialOrGeneration: unsigned.generation,
      notAfterMS: unsigned.notAfterMs,
      signedObjectSHA256: try SignedCertificateCanonicalCodec.unsignedCanonicalSHA256(
        unsigned
      )
    ),
    key: rootSigningKey
  )
  return RelayV2SignedCertificate(
    subjectPubkey: unsigned.subjectPubkey,
    certRole: unsigned.certRole,
    generation: unsigned.generation,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    notAfterMs: unsigned.notAfterMs,
    signature: signature
  )
}

private func productionIngressRelayGrant(
  record: StoredPairedMachineRecordV1,
  deviceSigningKey: Curve25519.Signing.PrivateKey,
  rootSigningKey: Curve25519.Signing.PrivateKey
) throws -> RelayV2Grant {
  let unsigned = RelayV2Grant(
    machineRoute: record.machineRoute,
    deviceRoute: record.deviceRoute,
    deviceSignPubkey: deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: record.grantSerial,
    rootKeyId: record.machineDataCertificate.rootKeyId,
    trustEpoch: record.trustEpoch,
    signature: Data(repeating: 1, count: 64)
  )
  return RelayV2Grant(
    machineRoute: unsigned.machineRoute,
    deviceRoute: unsigned.deviceRoute,
    deviceSignPubkey: unsigned.deviceSignPubkey,
    grantSerial: unsigned.grantSerial,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    signature: try RelayCrypto.sign(
      RelayGrantCredentialVerifier.toBeSigned(
        unsigned,
        relayServerID: record.relayServerID,
        machineRootFingerprint: record.machineRootFingerprint
      ),
      key: rootSigningKey
    )
  )
}

private func assertProductionIngressIgnored(
  _ outcome: MachineConnectionVerifiedIngressOutcome,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  guard case .ignored = outcome else {
    return XCTFail("expected ignored outcome", file: file, line: line)
  }
}

private func productionIngressEventually(
  attempts: Int = 500,
  _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await predicate() { return true }
    try? await Task.sleep(for: .milliseconds(2))
  }
  return false
}
