import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class MachineRequestCorrelationTests: XCTestCase {
  func testSelfRevocationCorrelationRequiresExactGrantSerial() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x09, count: 16)
    let messageID = RuntimeMessageID(rawValue: "revoke-self-1")
    try await owner.registerDirectedRequest(
      requestRoute: route,
      messageID: messageID,
      contract: .revocation(expectedGrantSerial: 41)
    )

    do {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: messageID,
          body: .reply(.revocation(.committed(RuntimeGrantSerial(rawValue: 42))))
        )
      )
      XCTFail("wrong grant serial must not satisfy revoke-self correlation")
    } catch {
      XCTAssertEqual(
        error as? MachineRequestCorrelationError,
        .unexpectedReply
      )
    }

    let accepted = try await owner.correlate(
      requestRoute: route,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: messageID,
        body: .reply(.revocation(.committed(RuntimeGrantSerial(rawValue: 41))))
      )
    )
    guard case .active(let reply) = accepted else {
      return XCTFail("exact grant serial should complete revoke-self")
    }
    XCTAssertTrue(reply.completesRequest)
  }

  func testDirectedReplyRequiresExactRouteMessageAndContract() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x11, count: 16)
    let messageID = RuntimeMessageID(rawValue: "prompt-1")
    try await owner.registerDirectedRequest(
      requestRoute: route,
      messageID: messageID,
      contract: .command(expectedConfigurationRevision: 1)
    )

    let accepted = try await owner.acceptRoute(route)
    guard case .accepted(.request(let acceptedMessageID)) = accepted else {
      return XCTFail("RouteAccepted must preserve the pending request owner")
    }
    XCTAssertEqual(acceptedMessageID, messageID)
    let acceptedPendingCount = await owner.pendingCount
    XCTAssertEqual(acceptedPendingCount, 1, "RouteAccepted is not a daemon terminal reply")

    await assertCorrelationError(.messageIDMismatch) {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: commandEnvelope(messageID: "prompt-other")
      )
    }
    await assertCorrelationError(.unexpectedReply) {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: approvalEnvelope(messageID: messageID.rawValue)
      )
    }
    await assertCorrelationError(.unexpectedReply) {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: commandEnvelope(
          messageID: messageID.rawValue,
          configurationRevision: 2
        )
      )
    }

    let result = try await owner.correlate(
      requestRoute: route,
      envelope: commandEnvelope(messageID: messageID.rawValue)
    )
    guard case .active(let correlated) = result else {
      return XCTFail("exact reply must correlate")
    }
    XCTAssertTrue(correlated.completesRequest)
    guard case .request(let targetID) = correlated.target else {
      return XCTFail("directed request target must remain typed")
    }
    XCTAssertEqual(targetID, messageID)
    XCTAssertNil(correlated.outerStreamBinding)
    let pendingCount = await owner.pendingCount
    XCTAssertEqual(pendingCount, 0)
  }

  func testApprovalCorrelationBindsApprovalIDAndRetryReceiptContract() async throws {
    let owner = MachineRequestCorrelationOwner()
    let resolveRoute = Data(repeating: 0x12, count: 16)
    let resolveMessageID = RuntimeMessageID(rawValue: "approval-resolve")
    try await owner.registerDirectedRequest(
      requestRoute: resolveRoute,
      messageID: resolveMessageID,
      contract: .approval(
        expectedApprovalID: RuntimeApprovalID(rawValue: "approval-expected"),
        isRetry: false
      )
    )
    await assertCorrelationError(.unexpectedReply) {
      _ = try await owner.correlate(
        requestRoute: resolveRoute,
        envelope: approvalEnvelope(
          messageID: resolveMessageID.rawValue,
          approvalID: "approval-other"
        )
      )
    }
    guard
      case .active = try await owner.correlate(
        requestRoute: resolveRoute,
        envelope: approvalEnvelope(
          messageID: resolveMessageID.rawValue,
          approvalID: "approval-expected"
        )
      )
    else {
      return XCTFail("resolve approval must accept the exact approval ID")
    }

    let retryRoute = Data(repeating: 0x13, count: 16)
    let retryMessageID = RuntimeMessageID(rawValue: "approval-retry")
    try await owner.registerDirectedRequest(
      requestRoute: retryRoute,
      messageID: retryMessageID,
      contract: .approval(
        expectedApprovalID: RuntimeApprovalID(rawValue: "approval-retry-id"),
        isRetry: true
      )
    )
    await assertCorrelationError(.unexpectedReply) {
      _ = try await owner.correlate(
        requestRoute: retryRoute,
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: retryMessageID,
          body: .reply(
            .approval(.claimed(RuntimeApprovalID(rawValue: "approval-retry-id")))
          )
        )
      )
    }
    guard
      case .active = try await owner.correlate(
        requestRoute: retryRoute,
        envelope: RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: retryMessageID,
          body: .reply(
            .approval(.applied(RuntimeApprovalID(rawValue: "approval-retry-id")))
          )
        )
      )
    else {
      return XCTFail("retry approval must accept an allowed exact-ID receipt")
    }
  }

  func testPreparedSubscriptionCorrelationDoesNotMutateUntilCommit() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x18, count: 16)
    let streamRoute = Data(repeating: 0x28, count: 16)
    let relayGeneration = Data(repeating: 0x38, count: 16)
    let messageID = RuntimeMessageID(rawValue: "catalog-transactional")
    try await owner.registerPendingSubscription(
      requestRoute: route,
      messageID: messageID,
      target: .catalog
    )

    let first = try await owner.prepareCorrelation(
      requestRoute: route,
      envelope: subscriptionEnvelope(
        messageID: messageID.rawValue,
        generation: "runtime-generation-transactional"
      )
    )
    guard case .active(let prepared) = first else {
      return XCTFail("live subscription reply must produce a prepared mutation")
    }
    await assertCorrelationError(.preparedMutationPending) {
      _ = try await owner.prepareCorrelation(
        requestRoute: route,
        envelope: subscriptionEnvelope(
          messageID: messageID.rawValue,
          generation: "runtime-generation-transactional"
        )
      )
    }
    await assertCorrelationError(.unknownRoute) {
      _ = try await owner.correlateStream(
        streamRoute: streamRoute,
        relayGeneration: relayGeneration,
        streamSeq: 0,
        envelope: catalogStreamEnvelope(sequence: 1)
      )
    }

    await owner.discardPreparedCorrelation(prepared)
    await assertCorrelationError(.unknownRoute) {
      _ = try await owner.correlateStream(
        streamRoute: streamRoute,
        relayGeneration: relayGeneration,
        streamSeq: 0,
        envelope: catalogStreamEnvelope(sequence: 1)
      )
    }

    guard
      case .active(let retry) = try await owner.prepareCorrelation(
        requestRoute: route,
        envelope: subscriptionEnvelope(
          messageID: messageID.rawValue,
          generation: "runtime-generation-transactional"
        )
      )
    else {
      return XCTFail("discard must leave the exact correlation retryable")
    }
    guard case .active(let committed) = try await owner.commitPreparedCorrelation(retry) else {
      return XCTFail("durable caller commit must install the prepared mutation")
    }
    XCTAssertEqual(
      committed.streamGeneration,
      RuntimeStreamGeneration(rawValue: "runtime-generation-transactional")
    )
    let pendingCount = await owner.pendingCount
    let activeStreamCount = await owner.activeStreamCount
    XCTAssertEqual(pendingCount, 1)
    XCTAssertEqual(activeStreamCount, 0, "Subscribed 仍不能伪装成 durable live binding")
  }

  func testPreparedCorrelationBecomesSupersededWhenSubscriptionIsReplaced() async throws {
    let owner = MachineRequestCorrelationOwner()
    let oldRoute = Data(repeating: 0x19, count: 16)
    let conversation = RuntimeConversationID(rawValue: "conversation-transactional")
    try await owner.registerPendingSubscription(
      requestRoute: oldRoute,
      messageID: RuntimeMessageID(rawValue: "subscription-transactional-old"),
      target: .conversation(conversationID: conversation)
    )
    guard
      case .active(let prepared) = try await owner.prepareCorrelation(
        requestRoute: oldRoute,
        envelope: subscriptionEnvelope(
          messageID: "subscription-transactional-old",
          generation: "runtime-generation-old"
        )
      )
    else {
      return XCTFail("old subscription must prepare before replacement")
    }

    await assertCorrelationError(.preparedMutationPending) {
      _ = try await owner.registerPendingSubscription(
        requestRoute: Data(repeating: 0x1A, count: 16),
        messageID: RuntimeMessageID(rawValue: "subscription-transactional-new"),
        target: .conversation(conversationID: conversation)
      )
    }
    await owner.discardPreparedCorrelation(prepared)
    let replaced = try await owner.registerPendingSubscription(
      requestRoute: Data(repeating: 0x1A, count: 16),
      messageID: RuntimeMessageID(rawValue: "subscription-transactional-new"),
      target: .conversation(conversationID: conversation)
    )
    XCTAssertEqual(replaced, oldRoute)
  }

  func testSubscriptionReplacementTombstonesLateFramesWithoutNewOwnership() async throws {
    let owner = MachineRequestCorrelationOwner()
    let oldRoute = Data(repeating: 0x21, count: 16)
    let newRoute = Data(repeating: 0x22, count: 16)
    let conversation = RuntimeConversationID(rawValue: "conversation-1")
    let oldStreamRoute = Data(repeating: 0x41, count: 16)
    let oldGeneration = correlationIdentifier(marker: 0x51, index: 0)
    let oldRuntimeGeneration = canonicalUUIDString(oldGeneration)

    try await owner.registerPendingSubscription(
      requestRoute: oldRoute,
      messageID: RuntimeMessageID(rawValue: "subscription-old"),
      target: .conversation(conversationID: conversation)
    )
    _ = try await owner.correlate(
      requestRoute: oldRoute,
      envelope: subscriptionEnvelope(
        messageID: "subscription-old",
        generation: oldRuntimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: oldRoute,
      envelope: try syncEnvelope(
        messageID: "subscription-old",
        generation: oldRuntimeGeneration,
        innerCursor: .conversation(
          conversationID: conversation,
          cursor: .beforeFirst
        )
      )
    )
    _ = try await commitPreparedBinding(
      owner: owner,
      requestRoute: oldRoute,
      binding: durableConversationBinding(
        conversationID: conversation,
        streamRoute: oldStreamRoute,
        generation: oldGeneration
      )
    )

    let replaced = try await owner.registerPendingSubscription(
      requestRoute: newRoute,
      messageID: RuntimeMessageID(rawValue: "subscription-new"),
      target: .conversation(conversationID: conversation)
    )
    XCTAssertNil(replaced, "live owner remains separate until the new binding is durable")
    guard case .superseded = try await owner.acceptRoute(oldRoute) else {
      return XCTFail("completed request route must stay tombstoned")
    }
    guard
      case .active = try await owner.correlateStream(
        streamRoute: oldStreamRoute,
        relayGeneration: oldGeneration,
        streamSeq: 1,
        envelope: conversationStreamEnvelope(conversationID: conversation, sequence: 1)
      )
    else {
      return XCTFail("old live binding must remain active while replacement bootstraps")
    }

    let newStreamRoute = Data(repeating: 0x42, count: 16)
    let newGeneration = correlationIdentifier(marker: 0x52, index: 0)
    let newRuntimeGeneration = canonicalUUIDString(newGeneration)
    guard
      case .active(let correlated) = try await owner.correlate(
        requestRoute: newRoute,
        envelope: subscriptionEnvelope(
          messageID: "subscription-new",
          generation: newRuntimeGeneration
        )
      )
    else {
      return XCTFail("replacement subscription must own its pending request")
    }
    XCTAssertNil(correlated.outerStreamBinding)
    _ = try await owner.correlate(
      requestRoute: newRoute,
      envelope: try syncEnvelope(
        messageID: "subscription-new",
        generation: newRuntimeGeneration,
        innerCursor: .conversation(
          conversationID: conversation,
          cursor: .beforeFirst
        )
      )
    )
    let committed = try await commitPreparedBinding(
      owner: owner,
      requestRoute: newRoute,
      binding: durableConversationBinding(
        conversationID: conversation,
        streamRoute: newStreamRoute,
        generation: newGeneration
      )
    )
    XCTAssertEqual(
      committed.retiredBinding,
      MachineOuterStreamBinding(
        streamRoute: oldStreamRoute,
        streamGeneration: oldGeneration
      )
    )

    guard
      case .active(let live) = try await owner.correlateStream(
        streamRoute: newStreamRoute,
        relayGeneration: newGeneration,
        streamSeq: 2,
        envelope: conversationStreamEnvelope(conversationID: conversation, sequence: 2)
      )
    else {
      return XCTFail("fresh outer binding must own live delivery")
    }
    XCTAssertEqual(live.streamGeneration.rawValue, newRuntimeGeneration)
    guard
      case .superseded = try await owner.correlateStream(
        streamRoute: oldStreamRoute,
        relayGeneration: oldGeneration,
        streamSeq: 2,
        envelope: conversationStreamEnvelope(conversationID: conversation, sequence: 2)
      )
    else {
      return XCTFail("old binding must tombstone only after replacement commit")
    }

    guard
      case .active(.conversation(let controlConversation, let controlRequest)) =
        try await owner.correlateStreamControl(
          streamRoute: newStreamRoute,
          relayGeneration: newGeneration
        )
    else {
      return XCTFail("stream control must preserve exact active target")
    }
    XCTAssertEqual(controlConversation, conversation)
    XCTAssertEqual(controlRequest.rawValue, "subscription-new")
    guard
      case .superseded = try await owner.correlateStreamControl(
        streamRoute: oldStreamRoute,
        relayGeneration: oldGeneration
      )
    else {
      return XCTFail("old stream control must remain tombstoned")
    }
  }

  func testDirectedUnregisterLeavesLateRouteTombstone() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x31, count: 16)
    let messageID = RuntimeMessageID(rawValue: "command-cancelled-before-send")
    try await owner.registerDirectedRequest(
      requestRoute: route,
      messageID: messageID,
      contract: .command(expectedConfigurationRevision: 1)
    )

    let drained = try await owner.unregisterDirectedRequest(requestRoute: route)
    XCTAssertEqual(drained?.requestRoute, route)
    XCTAssertEqual(drained?.messageID, messageID)
    let accepted = try await owner.acceptRoute(route)
    guard case .superseded = accepted else {
      return XCTFail("unregistered request route must remain a tombstone")
    }
    let lateReply = try await owner.correlate(
      requestRoute: route,
      envelope: commandEnvelope(messageID: messageID.rawValue)
    )
    guard case .superseded = lateReply else {
      return XCTFail("late reply must not reacquire a canceled waiter")
    }
  }

  func testSubscriptionRequiresSubscribedBeforeSyncAndCompletesOnExactBarrier() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x31, count: 16)
    let messageID = RuntimeMessageID(rawValue: "catalog-subscription")
    let streamRoute = Data(repeating: 0x61, count: 16)
    let relayGeneration = correlationIdentifier(marker: 0x62, index: 0)
    let runtimeGeneration = canonicalUUIDString(
      correlationIdentifier(marker: 0x63, index: 0)
    )
    try await owner.registerPendingSubscription(
      requestRoute: route,
      messageID: messageID,
      target: .catalog
    )

    await assertCorrelationError(.subscriptionMismatch) {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: try syncEnvelope(
          messageID: messageID.rawValue,
          generation: runtimeGeneration,
          innerCursor: .catalog(cursor: .beforeFirst)
        )
      )
    }
    _ = try await owner.correlate(
      requestRoute: route,
      envelope: subscriptionEnvelope(
        messageID: messageID.rawValue,
        generation: runtimeGeneration
      )
    )
    await assertCorrelationError(.subscriptionMismatch) {
      _ = try await owner.correlate(
        requestRoute: route,
        envelope: try syncEnvelope(
          messageID: messageID.rawValue,
          generation: "generation-other",
          innerCursor: .catalog(cursor: .beforeFirst)
        )
      )
    }

    let synchronized = try await owner.correlate(
      requestRoute: route,
      envelope: try syncEnvelope(
        messageID: messageID.rawValue,
        generation: runtimeGeneration,
        innerCursor: .catalog(cursor: .beforeFirst)
      )
    )
    guard case .active(let correlated) = synchronized else {
      return XCTFail("exact SyncComplete must reach awaiting-binding state")
    }
    XCTAssertFalse(correlated.completesRequest)
    var pendingCount = await owner.pendingCount
    XCTAssertEqual(pendingCount, 1)
    await assertCorrelationError(.unknownRoute) {
      _ = try await owner.correlateStream(
        streamRoute: streamRoute,
        relayGeneration: relayGeneration,
        streamSeq: 7,
        envelope: catalogStreamEnvelope(sequence: 7)
      )
    }

    let durable = try durableCatalogBinding(
      streamRoute: streamRoute,
      generation: relayGeneration
    )
    guard
      case .active(let prepared) = try await owner.prepareStreamBinding(
        requestRoute: route,
        binding: durable
      )
    else {
      return XCTFail("verified binding must reserve an opaque owner mutation")
    }
    await owner.discardPreparedStreamBinding(prepared)
    let committed = try await commitPreparedBinding(
      owner: owner,
      requestRoute: route,
      binding: durable
    )
    XCTAssertEqual(committed.synchronizedInnerCursor, .catalog(cursor: .beforeFirst))
    pendingCount = await owner.pendingCount
    XCTAssertEqual(pendingCount, 0)

    let streamResult = try await owner.correlateStream(
      streamRoute: streamRoute,
      relayGeneration: relayGeneration,
      streamSeq: 7,
      envelope: RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: "catalog-live-7"),
        body: .stream(
          .catalogDelta(RuntimeCatalogDeltaV2(catalogRevision: 0, changes: []))
        )
      )
    )
    guard case .active(let stream) = streamResult else {
      return XCTFail("current binding must remain live after SyncComplete")
    }
    XCTAssertEqual(stream.streamGeneration.rawValue, runtimeGeneration)
    XCTAssertEqual(stream.outerCursor, .at(7))
    guard case .catalog(let activeRequestID) = stream.target else {
      return XCTFail("live publish must retain the active subscription owner")
    }
    XCTAssertEqual(activeRequestID, messageID)
  }

  func testStreamBindingAcceptsSynchronizedInnerCursorAtOrAfterDurableCut() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x32, count: 16)
    let streamRoute = Data(repeating: 0x63, count: 16)
    let relayGeneration = correlationIdentifier(marker: 0x64, index: 0)
    let runtimeGeneration = canonicalUUIDString(relayGeneration)
    try await owner.registerPendingSubscription(
      requestRoute: route,
      messageID: RuntimeMessageID(rawValue: "catalog-monotonic-inner-cut"),
      target: .catalog
    )
    _ = try await owner.correlate(
      requestRoute: route,
      envelope: subscriptionEnvelope(
        messageID: "catalog-monotonic-inner-cut",
        generation: runtimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: route,
      envelope: try syncEnvelope(
        messageID: "catalog-monotonic-inner-cut",
        generation: runtimeGeneration,
        innerCursor: .catalog(cursor: .at(0))
      )
    )

    let committed = try await commitPreparedBinding(
      owner: owner,
      requestRoute: route,
      binding: durableCatalogBinding(
        streamRoute: streamRoute,
        generation: relayGeneration,
        innerCursor: .beforeFirst
      )
    )
    XCTAssertEqual(committed.bindingCursor, .beforeFirst)
    XCTAssertEqual(committed.synchronizedInnerCursor, .catalog(cursor: .at(0)))
  }

  func testStreamBindingRejectsSynchronizedInnerCursorBeforeDurableCut() async throws {
    let owner = MachineRequestCorrelationOwner()
    let route = Data(repeating: 0x33, count: 16)
    let streamRoute = Data(repeating: 0x65, count: 16)
    let relayGeneration = correlationIdentifier(marker: 0x66, index: 0)
    let runtimeGeneration = canonicalUUIDString(relayGeneration)
    try await owner.registerPendingSubscription(
      requestRoute: route,
      messageID: RuntimeMessageID(rawValue: "catalog-regressed-inner-cut"),
      target: .catalog
    )
    _ = try await owner.correlate(
      requestRoute: route,
      envelope: subscriptionEnvelope(
        messageID: "catalog-regressed-inner-cut",
        generation: runtimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: route,
      envelope: try syncEnvelope(
        messageID: "catalog-regressed-inner-cut",
        generation: runtimeGeneration,
        innerCursor: .catalog(cursor: .at(0))
      )
    )

    await assertCorrelationError(.subscriptionMismatch) {
      _ = try await owner.prepareStreamBinding(
        requestRoute: route,
        binding: durableCatalogBinding(
          streamRoute: streamRoute,
          generation: relayGeneration,
          innerCursor: .at(1)
        )
      )
    }
  }

  func testRegistryBoundsAndGenerationTeardownAreExact() async throws {
    let owner = MachineRequestCorrelationOwner()
    for index in 0..<MachineRequestCorrelationOwner.maximumPendingRoutes {
      var route = Data(repeating: 0, count: 16)
      route.replaceSubrange(8..<16, with: UInt64(index + 1).bigEndianBytes)
      try await owner.registerDirectedRequest(
        requestRoute: route,
        messageID: RuntimeMessageID(rawValue: "request-\(index)"),
        contract: .command(expectedConfigurationRevision: 1)
      )
    }
    let pendingCount = await owner.pendingCount
    XCTAssertEqual(pendingCount, MachineRequestCorrelationOwner.maximumPendingRoutes)

    await assertCorrelationError(.capacityExceeded) {
      _ = try await owner.registerDirectedRequest(
        requestRoute: Data(repeating: 0xFF, count: 16),
        messageID: RuntimeMessageID(rawValue: "overflow"),
        contract: .command(expectedConfigurationRevision: 1)
      )
    }
    let drain = await owner.generationEnded()
    XCTAssertEqual(drain.requests.count, MachineRequestCorrelationOwner.maximumPendingRoutes)
    XCTAssertTrue(drain.streams.isEmpty)
    let finalPendingCount = await owner.pendingCount
    let finalSupersededCount = await owner.supersededCount
    XCTAssertEqual(finalPendingCount, 0)
    XCTAssertEqual(finalSupersededCount, 0)
    let ended = await owner.isEnded
    XCTAssertTrue(ended)
    await assertCorrelationError(.generationEnded) {
      try await owner.registerDirectedRequest(
        requestRoute: Data(repeating: 0xEF, count: 16),
        messageID: RuntimeMessageID(rawValue: "after-end"),
        contract: .command(expectedConfigurationRevision: 1)
      )
    }
    let repeatedDrain = await owner.generationEnded()
    XCTAssertTrue(repeatedDrain.requests.isEmpty)
    XCTAssertTrue(repeatedDrain.streams.isEmpty)
  }

  func testPreparedCompletionReservesTheLastRequestTombstoneBeforeDurableCommit() async throws {
    let owner = MachineRequestCorrelationOwner()
    for index in 0..<(MachineRequestCorrelationOwner.maximumSupersededRoutes - 1) {
      let route = correlationIdentifier(marker: 0xA1, index: index)
      let messageID = "completed-before-reservation-\(index)"
      try await owner.registerDirectedRequest(
        requestRoute: route,
        messageID: RuntimeMessageID(rawValue: messageID),
        contract: .command(expectedConfigurationRevision: 1)
      )
      guard
        case .active = try await owner.correlate(
          requestRoute: route,
          envelope: commandEnvelope(messageID: messageID)
        )
      else {
        return XCTFail("fixture completion must consume one tombstone")
      }
    }

    let firstRoute = Data(repeating: 0xB1, count: 16)
    let secondRoute = Data(repeating: 0xB2, count: 16)
    try await owner.registerDirectedRequest(
      requestRoute: firstRoute,
      messageID: RuntimeMessageID(rawValue: "last-tombstone-first"),
      contract: .command(expectedConfigurationRevision: 1)
    )
    try await owner.registerDirectedRequest(
      requestRoute: secondRoute,
      messageID: RuntimeMessageID(rawValue: "last-tombstone-second"),
      contract: .command(expectedConfigurationRevision: 1)
    )
    guard
      case .active(let reserved) = try await owner.prepareCorrelation(
        requestRoute: firstRoute,
        envelope: commandEnvelope(messageID: "last-tombstone-first")
      )
    else {
      return XCTFail("first completion must reserve the final tombstone")
    }
    await assertCorrelationError(.capacityExceeded) {
      _ = try await owner.prepareCorrelation(
        requestRoute: secondRoute,
        envelope: commandEnvelope(messageID: "last-tombstone-second")
      )
    }
    guard case .active = try await owner.commitPreparedCorrelation(reserved) else {
      return XCTFail("reserved commit must remain non-capacity-failing after durable await")
    }
    let tombstoneCount = await owner.supersededCount
    XCTAssertEqual(tombstoneCount, MachineRequestCorrelationOwner.maximumSupersededRoutes)
  }

  func testFailureAndUnregisterRetireExactStreamBinding() async throws {
    let owner = MachineRequestCorrelationOwner()
    let failedRoute = Data(repeating: 0x71, count: 16)
    let failedStreamRoute = Data(repeating: 0x72, count: 16)
    let failedGeneration = Data(repeating: 0x73, count: 16)
    try await owner.registerPendingSubscription(
      requestRoute: failedRoute,
      messageID: RuntimeMessageID(rawValue: "failed-subscription"),
      target: .catalog
    )
    let failure = try await owner.correlate(
      requestRoute: failedRoute,
      envelope: failureEnvelope(messageID: "failed-subscription")
    )
    guard case .active(let correlatedFailure) = failure else {
      return XCTFail("current failure must complete its exact pending owner")
    }
    XCTAssertTrue(correlatedFailure.completesRequest)
    var activeCount = await owner.activeStreamCount
    var tombstoneCount = await owner.supersededStreamBindingCount
    XCTAssertEqual(activeCount, 0)
    XCTAssertEqual(tombstoneCount, 0)
    guard case .superseded = try await owner.acceptRoute(failedRoute) else {
      return XCTFail("completed failure request route must remain a tombstone")
    }
    await assertCorrelationError(.unknownRoute) {
      _ = try await owner.correlateStream(
        streamRoute: failedStreamRoute,
        relayGeneration: failedGeneration,
        streamSeq: 1,
        envelope: catalogStreamEnvelope(sequence: 1)
      )
    }

    let pendingRoute = Data(repeating: 0x74, count: 16)
    try await owner.registerPendingSubscription(
      requestRoute: pendingRoute,
      messageID: RuntimeMessageID(rawValue: "pending-unregister"),
      target: .catalog
    )
    let unregisteredPending = try await owner.unregisterPendingSubscription(
      requestRoute: pendingRoute
    )
    XCTAssertEqual(unregisteredPending?.requestRoute, pendingRoute)
    let lateAccepted = try await owner.acceptRoute(pendingRoute)
    guard case .superseded = lateAccepted else {
      return XCTFail("unregistered pending request must retain a request tombstone")
    }
    activeCount = await owner.activeStreamCount
    tombstoneCount = await owner.supersededStreamBindingCount
    XCTAssertEqual(activeCount, 0)
    XCTAssertEqual(tombstoneCount, 0)

    let liveRoute = Data(repeating: 0x77, count: 16)
    let liveStreamRoute = Data(repeating: 0x78, count: 16)
    let liveGeneration = correlationIdentifier(marker: 0x79, index: 0)
    let liveRuntimeGeneration = canonicalUUIDString(liveGeneration)
    try await owner.registerPendingSubscription(
      requestRoute: liveRoute,
      messageID: RuntimeMessageID(rawValue: "live-unregister"),
      target: .catalog
    )
    _ = try await owner.correlate(
      requestRoute: liveRoute,
      envelope: subscriptionEnvelope(
        messageID: "live-unregister",
        generation: liveRuntimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: liveRoute,
      envelope: try syncEnvelope(
        messageID: "live-unregister",
        generation: liveRuntimeGeneration,
        innerCursor: .catalog(cursor: .beforeFirst)
      )
    )
    _ = try await commitPreparedBinding(
      owner: owner,
      requestRoute: liveRoute,
      binding: durableCatalogBinding(
        streamRoute: liveStreamRoute,
        generation: liveGeneration
      )
    )
    let unregisteredLiveRoute = try await owner.unregisterSubscription(
      streamRoute: liveStreamRoute,
      relayGeneration: liveGeneration
    )
    XCTAssertEqual(unregisteredLiveRoute, liveRoute)
    guard case .superseded = try await owner.acceptRoute(liveRoute) else {
      return XCTFail("completed live subscription route must remain a tombstone")
    }
    guard
      case .superseded = try await owner.correlate(
        requestRoute: liveRoute,
        envelope: subscriptionEnvelope(
          messageID: "live-unregister",
          generation: liveRuntimeGeneration
        )
      )
    else {
      return XCTFail("late live subscription reply must not become unknownRoute")
    }
    activeCount = await owner.activeStreamCount
    tombstoneCount = await owner.supersededStreamBindingCount
    XCTAssertEqual(activeCount, 0)
    XCTAssertEqual(tombstoneCount, 1)
  }

  func testActiveStreamRegistryHasExactGenerationBound() async throws {
    let owner = MachineRequestCorrelationOwner()
    for index in 0..<MachineRequestCorrelationOwner.maximumTrackedStreamBindings {
      let conversationID = RuntimeConversationID(rawValue: "conversation-\(index)")
      let messageID = "subscription-\(index)"
      let requestRoute = correlationIdentifier(marker: 0x81, index: index)
      let streamRoute = correlationIdentifier(marker: 0x82, index: index)
      let relayGeneration = correlationIdentifier(marker: 0x83, index: index)
      let runtimeGeneration = canonicalUUIDString(relayGeneration)
      try await owner.registerPendingSubscription(
        requestRoute: requestRoute,
        messageID: RuntimeMessageID(rawValue: messageID),
        target: .conversation(conversationID: conversationID)
      )
      _ = try await owner.correlate(
        requestRoute: requestRoute,
        envelope: subscriptionEnvelope(
          messageID: messageID,
          generation: runtimeGeneration
        )
      )
      _ = try await owner.correlate(
        requestRoute: requestRoute,
        envelope: try syncEnvelope(
          messageID: messageID,
          generation: runtimeGeneration,
          innerCursor: .conversation(
            conversationID: conversationID,
            cursor: .beforeFirst
          )
        )
      )
      _ = try await commitPreparedBinding(
        owner: owner,
        requestRoute: requestRoute,
        binding: durableConversationBinding(
          conversationID: conversationID,
          streamRoute: streamRoute,
          generation: relayGeneration
        )
      )
    }
    let activeCount = await owner.activeStreamCount
    XCTAssertEqual(
      activeCount,
      MachineRequestCorrelationOwner.maximumTrackedStreamBindings
    )
    let overflowRoute = Data(repeating: 0x91, count: 16)
    let overflowGeneration = correlationIdentifier(marker: 0x93, index: 0)
    let overflowRuntimeGeneration = canonicalUUIDString(overflowGeneration)
    try await owner.registerPendingSubscription(
      requestRoute: overflowRoute,
      messageID: RuntimeMessageID(rawValue: "stream-overflow"),
      target: .catalog
    )
    _ = try await owner.correlate(
      requestRoute: overflowRoute,
      envelope: subscriptionEnvelope(
        messageID: "stream-overflow",
        generation: overflowRuntimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: overflowRoute,
      envelope: try syncEnvelope(
        messageID: "stream-overflow",
        generation: overflowRuntimeGeneration,
        innerCursor: .catalog(cursor: .beforeFirst)
      )
    )
    await assertCorrelationError(.capacityExceeded) {
      _ = try await owner.prepareStreamBinding(
        requestRoute: overflowRoute,
        binding: durableCatalogBinding(
          streamRoute: Data(repeating: 0x92, count: 16),
          generation: overflowGeneration
        )
      )
    }
    let drain = await owner.generationEnded()
    XCTAssertEqual(drain.requests.map(\.requestRoute), [overflowRoute])
    XCTAssertEqual(
      drain.streams.count,
      MachineRequestCorrelationOwner.maximumTrackedStreamBindings
    )
  }

  func testSequentialTargetUnsubscribeRetiresExactFiveHundredTwelveBindings() async throws {
    let owner = MachineRequestCorrelationOwner()
    for index in 0..<MachineRequestCorrelationOwner.maximumTrackedStreamBindings {
      let conversationID = RuntimeConversationID(rawValue: "sequential-\(index)")
      let target = RuntimeSubscriptionTargetV1.conversation(
        conversationID: conversationID
      )
      let messageID = "sequential-subscription-\(index)"
      let requestRoute = correlationIdentifier(marker: 0xA4, index: index)
      let streamRoute = correlationIdentifier(marker: 0xA5, index: index)
      let relayGeneration = correlationIdentifier(marker: 0xA6, index: index)
      let runtimeGeneration = canonicalUUIDString(relayGeneration)
      try await owner.registerPendingSubscription(
        requestRoute: requestRoute,
        messageID: RuntimeMessageID(rawValue: messageID),
        target: target
      )
      _ = try await owner.correlate(
        requestRoute: requestRoute,
        envelope: subscriptionEnvelope(
          messageID: messageID,
          generation: runtimeGeneration
        )
      )
      _ = try await owner.correlate(
        requestRoute: requestRoute,
        envelope: try syncEnvelope(
          messageID: messageID,
          generation: runtimeGeneration,
          innerCursor: .conversation(
            conversationID: conversationID,
            cursor: .beforeFirst
          )
        )
      )
      _ = try await commitPreparedBinding(
        owner: owner,
        requestRoute: requestRoute,
        binding: durableConversationBinding(
          conversationID: conversationID,
          streamRoute: streamRoute,
          generation: relayGeneration
        )
      )

      let retired = try await owner.unregisterSubscription(target: target)
      XCTAssertEqual(retired.outerBinding?.streamRoute, streamRoute)
      XCTAssertEqual(retired.outerBinding?.streamGeneration, relayGeneration)
      XCTAssertEqual(retired.requiresGenerationRollover, index == 511)
      let activeCount = await owner.activeStreamCount
      XCTAssertEqual(activeCount, 0)
    }

    let pendingCount = await owner.pendingCount
    let routeTombstones = await owner.supersededCount
    let streamTombstones = await owner.supersededStreamBindingCount
    XCTAssertEqual(pendingCount, 0)
    XCTAssertEqual(routeTombstones, 512)
    XCTAssertEqual(streamTombstones, 512)
  }

  func testTombstoneOverflowRequiresExactGenerationTeardown() async throws {
    let owner = MachineRequestCorrelationOwner()
    for index in 0..<MachineRequestCorrelationOwner.maximumSupersededRoutes {
      let route = correlationIdentifier(marker: 0xA4, index: index)
      try await owner.registerDirectedRequest(
        requestRoute: route,
        messageID: RuntimeMessageID(rawValue: "tombstone-overflow-\(index)"),
        contract: .command(expectedConfigurationRevision: 1)
      )
      _ = try await owner.unregisterDirectedRequest(requestRoute: route)
    }

    let overflowRoute = correlationIdentifier(marker: 0xA5, index: 0)
    try await owner.registerDirectedRequest(
      requestRoute: overflowRoute,
      messageID: RuntimeMessageID(rawValue: "tombstone-overflow-final"),
      contract: .command(expectedConfigurationRevision: 1)
    )
    await assertCorrelationError(.capacityExceeded) {
      _ = try await owner.unregisterDirectedRequest(requestRoute: overflowRoute)
    }

    let drain = await owner.generationEnded()
    XCTAssertEqual(drain.requests.map(\.requestRoute), [overflowRoute])
    XCTAssertTrue(drain.streams.isEmpty)
    let pendingCount = await owner.pendingCount
    let tombstoneCount = await owner.supersededCount
    XCTAssertEqual(pendingCount, 0)
    XCTAssertEqual(tombstoneCount, 0)
    await assertCorrelationError(.generationEnded) {
      _ = try await owner.acceptRoute(overflowRoute)
    }
  }

  func testPreparedSubscriptionCancelFailureClosesGenerationBeforeBindingCanCommit() async throws {
    let owner = MachineRequestCorrelationOwner()
    let requestRoute = Data(repeating: 0xA6, count: 16)
    let messageID = RuntimeMessageID(rawValue: "prepared-cancel-race")
    try await owner.registerPendingSubscription(
      requestRoute: requestRoute,
      messageID: messageID,
      target: .catalog
    )
    guard
      case .active(let prepared) = try await owner.prepareCorrelation(
        requestRoute: requestRoute,
        envelope: subscriptionEnvelope(
          messageID: messageID.rawValue,
          generation: "prepared-cancel-generation"
        )
      )
    else {
      return XCTFail("fixture must hold a prepared subscription mutation")
    }

    await assertCorrelationError(.preparedMutationPending) {
      _ = try await owner.unregisterPendingSubscription(requestRoute: requestRoute)
    }
    let drain = await owner.generationEnded()
    XCTAssertEqual(drain.requests.map(\.requestRoute), [requestRoute])
    await assertCorrelationError(.generationEnded) {
      _ = try await owner.commitPreparedCorrelation(prepared)
    }
  }

  func testPreparedStreamBindingCancelFailureCannotPromoteSubscribeAfterTeardown() async throws {
    let owner = MachineRequestCorrelationOwner()
    let requestRoute = Data(repeating: 0xAB, count: 16)
    let streamRoute = Data(repeating: 0xAC, count: 16)
    let relayGeneration = correlationIdentifier(marker: 0xAD, index: 0)
    let runtimeGeneration = canonicalUUIDString(relayGeneration)
    let messageID = RuntimeMessageID(rawValue: "prepared-binding-cancel-race")
    try await owner.registerPendingSubscription(
      requestRoute: requestRoute,
      messageID: messageID,
      target: .catalog
    )
    _ = try await owner.correlate(
      requestRoute: requestRoute,
      envelope: subscriptionEnvelope(
        messageID: messageID.rawValue,
        generation: runtimeGeneration
      )
    )
    _ = try await owner.correlate(
      requestRoute: requestRoute,
      envelope: try syncEnvelope(
        messageID: messageID.rawValue,
        generation: runtimeGeneration,
        innerCursor: .catalog(cursor: .beforeFirst)
      )
    )
    guard
      case .active(let prepared) = try await owner.prepareStreamBinding(
        requestRoute: requestRoute,
        binding: durableCatalogBinding(
          streamRoute: streamRoute,
          generation: relayGeneration
        )
      )
    else {
      return XCTFail("fixture must hold a prepared stream binding mutation")
    }

    await assertCorrelationError(.preparedMutationPending) {
      _ = try await owner.unregisterPendingSubscription(requestRoute: requestRoute)
    }
    let drain = await owner.generationEnded()
    XCTAssertEqual(drain.requests.map(\.requestRoute), [requestRoute])
    await assertCorrelationError(.generationEnded) {
      _ = try await owner.commitPreparedStreamBinding(prepared)
    }
  }

  func testControlRouteClaimRejectsPendingAndHistoricalBusinessRoutes() async throws {
    let owner = MachineRequestCorrelationOwner()
    let pendingRoute = Data(repeating: 0xA7, count: 16)
    try await owner.registerDirectedRequest(
      requestRoute: pendingRoute,
      messageID: RuntimeMessageID(rawValue: "control-collision-pending"),
      contract: .command(expectedConfigurationRevision: 1)
    )
    await assertCorrelationError(.routeCollision) {
      _ = try await owner.claimControlRequestRoute(pendingRoute)
    }

    _ = try await owner.unregisterDirectedRequest(requestRoute: pendingRoute)
    await assertCorrelationError(.routeCollision) {
      _ = try await owner.claimControlRequestRoute(pendingRoute)
    }

    let claimedRoute = Data(repeating: 0xA8, count: 16)
    let claim = try await owner.claimControlRequestRoute(claimedRoute)
    await assertCorrelationError(.routeCollision) {
      try await owner.registerDirectedRequest(
        requestRoute: claimedRoute,
        messageID: RuntimeMessageID(rawValue: "control-claim-owner"),
        contract: .command(expectedConfigurationRevision: 1)
      )
    }
    await owner.releaseControlRequestRoute(claim)
    try await owner.registerDirectedRequest(
      requestRoute: claimedRoute,
      messageID: RuntimeMessageID(rawValue: "control-claim-owner"),
      contract: .command(expectedConfigurationRevision: 1)
    )
  }

  func testControlRouteClaimsAreBoundedAndTokenSpecific() async throws {
    let owner = MachineRequestCorrelationOwner()
    var claims: [MachineControlRequestRouteClaim] = []
    for index in 0..<MachineRequestCorrelationOwner.maximumControlRouteClaims {
      claims.append(
        try await owner.claimControlRequestRoute(
          correlationIdentifier(marker: 0xA9, index: index)
        )
      )
    }
    let claimCount = await owner.controlRouteClaimCount
    XCTAssertEqual(claimCount, MachineRequestCorrelationOwner.maximumControlRouteClaims)
    await assertCorrelationError(.capacityExceeded) {
      _ = try await owner.claimControlRequestRoute(Data(repeating: 0xAA, count: 16))
    }

    let first = claims.removeFirst()
    await owner.releaseControlRequestRoute(first)
    await owner.releaseControlRequestRoute(first)
    let replacement = try await owner.claimControlRequestRoute(first.requestRoute)
    await owner.releaseControlRequestRoute(first)
    let countAfterStaleRelease = await owner.controlRouteClaimCount
    XCTAssertEqual(
      countAfterStaleRelease,
      MachineRequestCorrelationOwner.maximumControlRouteClaims
    )
    await owner.releaseControlRequestRoute(replacement)
    for claim in claims {
      await owner.releaseControlRequestRoute(claim)
    }
    let finalClaimCount = await owner.controlRouteClaimCount
    XCTAssertEqual(finalClaimCount, 0)
  }
}

private func commandEnvelope(
  messageID: String,
  configurationRevision: UInt64 = 1
) -> RuntimeEnvelopeV2 {
  return RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: messageID),
    body: .reply(
      .command(
        .replayed(
          commandID: RuntimeCommandID(rawValue: "command-1"),
          configurationRevision: configurationRevision
        )
      )
    )
  )
}

private func approvalEnvelope(
  messageID: String,
  approvalID: String = "approval-1"
) -> RuntimeEnvelopeV2 {
  RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: messageID),
    body: .reply(.approval(.applied(RuntimeApprovalID(rawValue: approvalID))))
  )
}

private func failureEnvelope(messageID: String) -> RuntimeEnvelopeV2 {
  RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: messageID),
    body: .reply(
      .failure(RuntimeFailureV1(code: "remote.subscription.failed", message: "fixture"))
    )
  )
}

private func catalogStreamEnvelope(sequence: UInt64) -> RuntimeEnvelopeV2 {
  RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: "catalog-live-\(sequence)"),
    body: .stream(
      .catalogDelta(RuntimeCatalogDeltaV2(catalogRevision: sequence, changes: []))
    )
  )
}

private func conversationStreamEnvelope(
  conversationID: RuntimeConversationID,
  sequence: UInt64
) throws -> RuntimeEnvelopeV2 {
  RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: "conversation-live-\(sequence)"),
    body: .stream(
      .event(
        try RuntimeEventV2(
          conversationID: conversationID,
          eventID: RuntimeEventID(rawValue: "event-\(sequence)"),
          eventSeq: sequence,
          commandID: nil,
          itemID: nil,
          entityID: nil,
          body: .error(RuntimeFailureV1(code: "fixture", message: "fixture"))
        )
      )
    )
  )
}

private func subscriptionEnvelope(
  messageID: String,
  generation: String
) -> RuntimeEnvelopeV2 {
  RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: messageID),
    body: .reply(
      .subscription(
        .subscribed(
          streamGeneration: RuntimeStreamGeneration(rawValue: generation)
        )
      )
    )
  )
}

private func syncEnvelope(
  messageID: String,
  generation: String,
  innerCursor: RuntimeInnerCursorV1
) throws -> RuntimeEnvelopeV2 {
  let fixture = SyncCompleteFixture(
    streamGeneration: RuntimeStreamGeneration(rawValue: generation),
    streamCursor: .beforeFirst,
    innerCursor: innerCursor,
    keyDirectoryRevision: 1
  )
  let sync = try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: JSONEncoder().encode(fixture)
  )
  return RuntimeEnvelopeV2(
    version: runtimeProtocolVersionCurrent,
    messageID: RuntimeMessageID(rawValue: messageID),
    body: .reply(
      .syncComplete(sync)
    )
  )
}

private struct SyncCompleteFixture: Encodable {
  let streamGeneration: RuntimeStreamGeneration
  let streamCursor: RuntimeStreamCursorV1
  let innerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
}

private func assertCorrelationError(
  _ expected: MachineRequestCorrelationError,
  operation: () async throws -> Void,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    try await operation()
    XCTFail("expected \(expected)", file: file, line: line)
  } catch let error as MachineRequestCorrelationError {
    XCTAssertEqual(error, expected, file: file, line: line)
  } catch {
    XCTFail("unexpected error \(error)", file: file, line: line)
  }
}

private func correlationIdentifier(marker: UInt8, index: Int) -> Data {
  var value = Data(repeating: marker, count: 8)
  value.append(UInt64(index + 1).bigEndianBytes)
  return value
}

private func canonicalUUIDString(_ bytes: Data) -> String {
  precondition(bytes.count == 16)
  let hex = bytes.map { String(format: "%02x", $0) }.joined()
  return "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-"
    + "\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
}

private func durableCatalogBinding(
  streamRoute: Data,
  generation: Data,
  outerCursor: StreamCursor = .beforeFirst,
  innerCursor: StreamCursor = .beforeFirst
) throws -> DeviceDurableStreamBindingV1 {
  try DeviceDurableStreamBindingV1(
    streamRoute: streamRoute,
    streamGeneration: generation,
    streamCursor: outerCursor,
    innerCursor: .catalog(innerCursor),
    keyDirectoryRevision: 1,
    keyID: KeyIDV1(purpose: .catalog, epoch: 1)
  )
}

private func durableConversationBinding(
  conversationID: RuntimeConversationID,
  streamRoute: Data,
  generation: Data,
  outerCursor: StreamCursor = .beforeFirst,
  innerCursor: StreamCursor = .beforeFirst
) throws -> DeviceDurableStreamBindingV1 {
  try DeviceDurableStreamBindingV1(
    streamRoute: streamRoute,
    streamGeneration: generation,
    streamCursor: outerCursor,
    innerCursor: .conversation(id: conversationID.rawValue, cursor: innerCursor),
    keyDirectoryRevision: 1,
    keyID: KeyIDV1(purpose: .conversationDEK, epoch: 1)
  )
}

@discardableResult
private func commitPreparedBinding(
  owner: MachineRequestCorrelationOwner,
  requestRoute: Data,
  binding: DeviceDurableStreamBindingV1
) async throws -> MachineCorrelatedStreamBinding {
  guard
    case .active(let prepared) = try await owner.prepareStreamBinding(
      requestRoute: requestRoute,
      binding: binding
    ),
    case .active(let committed) = try await owner.commitPreparedStreamBinding(prepared)
  else {
    throw MachineRequestCorrelationError.subscriptionMismatch
  }
  return committed
}

extension UInt64 {
  fileprivate var bigEndianBytes: Data {
    var value = bigEndian
    return Swift.withUnsafeBytes(of: &value) { Data($0) }
  }
}
