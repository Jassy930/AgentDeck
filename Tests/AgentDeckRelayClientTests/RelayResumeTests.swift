import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class RelayResumeTests: XCTestCase {
  func testColdProcessIgnoresPersistedCursorAndRequiresFreshSnapshotBarrier() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let generation = RuntimeStreamGeneration(rawValue: "generation-1")
    var coordinator = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: .at(41),
      inMemoryBaseline: nil
    )

    XCTAssertEqual(
      coordinator.requestedCursor,
      .beforeFirst,
      "持久化 cursor 不是 transcript；cold process 必须从 fresh snapshot 建 baseline"
    )
    XCTAssertNil(coordinator.committedProjection)

    XCTAssertEqual(
      try coordinator.accept(subscriptionDelivery(generation: generation)),
      .staged
    )
    let snapshot = try resumeSnapshot(conversationID: conversationID, base: .at(0))
    XCTAssertEqual(
      try coordinator.accept(
        delivery(generation: generation, payload: .conversationSnapshot(snapshot))
      ),
      .staged
    )

    let live = try resumeEvent(
      conversationID: conversationID,
      sequence: 1,
      eventID: "event-1"
    )
    XCTAssertEqual(
      try coordinator.accept(
        delivery(
          generation: generation,
          outerCursor: .at(11),
          payload: .conversationEvent(live)
        )
      ),
      .suppressedUntilBarrier
    )
    XCTAssertNil(coordinator.committedProjection)

    XCTAssertEqual(
      try coordinator.accept(
        delivery(
          generation: generation,
          payload: .syncComplete(
            try resumeSyncComplete(
              generation: generation,
              conversationID: conversationID,
              outerCursor: .at(10),
              innerCursor: .at(0)
            )
          )
        )
      ),
      .synchronized
    )
    XCTAssertEqual(coordinator.committedProjection?.cursor, .at(1))
    XCTAssertEqual(coordinator.synchronizedEvents.map(\.eventID.rawValue), ["event-1"])

    XCTAssertEqual(
      try coordinator.accept(
        delivery(
          generation: generation,
          outerCursor: .at(11),
          payload: .conversationEvent(live)
        )
      ),
      .duplicate
    )
    XCTAssertEqual(coordinator.committedProjection?.cursor, .at(1))
  }

  func testColdBootstrapPublishesSnapshotThenBackfillEventsWithoutTranscriptGap() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let generation = RuntimeStreamGeneration(rawValue: "generation-1")
    var coordinator = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: .at(99),
      inMemoryBaseline: nil
    )
    _ = try coordinator.accept(subscriptionDelivery(generation: generation))
    let snapshot = try resumeSnapshot(conversationID: conversationID, base: .beforeFirst)
    _ = try coordinator.accept(
      delivery(generation: generation, payload: .conversationSnapshot(snapshot))
    )
    let event = try resumeEvent(
      conversationID: conversationID,
      sequence: 0,
      eventID: "event-backfill-0"
    )
    let backfill = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try resumeCapabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
      events: [event]
    )
    _ = try coordinator.accept(
      delivery(generation: generation, payload: .conversationBackfill(backfill))
    )
    _ = try coordinator.accept(
      delivery(
        generation: generation,
        payload: .syncComplete(
          try resumeSyncComplete(
            generation: generation,
            conversationID: conversationID,
            outerCursor: .at(10),
            innerCursor: .at(0)
          )
        )
      )
    )

    XCTAssertEqual(coordinator.synchronizedSnapshot?.baseEventCursor, .beforeFirst)
    XCTAssertEqual(
      coordinator.synchronizedEvents.map(\.eventID.rawValue),
      ["event-backfill-0"]
    )
    XCTAssertEqual(coordinator.committedProjection?.cursor, .at(0))

    XCTAssertEqual(coordinator.retainedBootstrapItemCount, 2)
    let synchronized = coordinator.takeSynchronizedDelivery()
    XCTAssertEqual(synchronized.snapshot?.baseEventCursor, .beforeFirst)
    XCTAssertEqual(synchronized.events.map(\.eventID.rawValue), ["event-backfill-0"])
    XCTAssertEqual(
      coordinator.retainedBootstrapItemCount,
      0,
      "成功交给 broadcaster 后不得继续保留完整 snapshot/backfill payload"
    )
  }

  func testBootstrapReplayBeyondConversationCapacityFailsBeforeRetentionAndCanRetry() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let generation = RuntimeStreamGeneration(rawValue: "generation-1")
    var coordinator = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: nil,
      inMemoryBaseline: nil
    )
    _ = try coordinator.accept(subscriptionDelivery(generation: generation))
    _ = try coordinator.accept(
      delivery(
        generation: generation,
        payload: .conversationSnapshot(
          try resumeSnapshot(conversationID: conversationID, base: .beforeFirst)
        )
      )
    )
    let oversizedEvents = try (0..<512).map { index in
      try resumeEvent(
        conversationID: conversationID,
        sequence: UInt64(index),
        eventID: "event-\(index)"
      )
    }
    let oversized = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try resumeCapabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(511)),
      events: oversizedEvents
    )

    XCTAssertThrowsError(
      try coordinator.accept(
        delivery(generation: generation, payload: .conversationBackfill(oversized))
      )
    )
    XCTAssertNil(coordinator.committedProjection)
    XCTAssertTrue(coordinator.synchronizedEvents.isEmpty)

    let oneEvent = Array(oversizedEvents.prefix(1))
    let retry = RuntimeBackfillChunkV2.conversation(
      conversationID: conversationID,
      capabilitiesPreamble: try resumeCapabilities(),
      range: try RuntimeBackfillRangeV1(after: .beforeFirst, through: .at(0)),
      events: oneEvent
    )
    XCTAssertEqual(
      try coordinator.accept(
        delivery(generation: generation, payload: .conversationBackfill(retry))
      ),
      .staged
    )
  }

  func testWarmResumeRequiresARealInMemoryProjectionMatchingPersistedCursor() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let reducer = try ConversationReducer(
      machineID: "machine-1",
      snapshot: resumeSnapshot(conversationID: conversationID, base: .at(41))
    )

    let warm = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: .at(41),
      inMemoryBaseline: reducer.projection
    )
    XCTAssertEqual(warm.requestedCursor, .at(41))

    XCTAssertThrowsError(
      try RelayConversationResumeCoordinator(
        machineID: "machine-1",
        conversationID: conversationID,
        persistedCursor: .at(42),
        inMemoryBaseline: reducer.projection
      )
    )

    var noOp = warm
    let generation = RuntimeStreamGeneration(rawValue: "generation-warm")
    XCTAssertEqual(
      try noOp.accept(subscriptionDelivery(generation: generation)),
      .staged
    )
    XCTAssertEqual(
      try noOp.accept(
        delivery(
          generation: generation,
          payload: .syncComplete(
            try resumeSyncComplete(
              generation: generation,
              conversationID: conversationID,
              outerCursor: .at(10),
              innerCursor: .at(41)
            )
          )
        )
      ),
      .synchronized
    )
    XCTAssertEqual(noOp.committedProjection?.cursor, .at(41))
    XCTAssertNil(noOp.synchronizedSnapshot)
    XCTAssertTrue(noOp.synchronizedEvents.isEmpty)
  }

  func testBarrierMismatchAndFailedStagingNeverSwapCommittedProjection() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let generation = RuntimeStreamGeneration(rawValue: "generation-1")
    var coordinator = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: nil,
      inMemoryBaseline: nil
    )
    _ = try coordinator.accept(subscriptionDelivery(generation: generation))
    _ = try coordinator.accept(
      delivery(
        generation: generation,
        payload: .conversationSnapshot(
          try resumeSnapshot(conversationID: conversationID, base: .at(0))
        )
      )
    )

    let wrongInner = try resumeSyncComplete(
      generation: generation,
      conversationID: conversationID,
      outerCursor: .at(10),
      innerCursor: .at(1)
    )
    XCTAssertThrowsError(
      try coordinator.accept(
        delivery(generation: generation, payload: .syncComplete(wrongInner))
      )
    )
    XCTAssertNil(coordinator.committedProjection)

    let wrongGeneration = try resumeSyncComplete(
      generation: RuntimeStreamGeneration(rawValue: "generation-other"),
      conversationID: conversationID,
      outerCursor: .at(10),
      innerCursor: .at(0)
    )
    XCTAssertThrowsError(
      try coordinator.accept(
        delivery(generation: generation, payload: .syncComplete(wrongGeneration))
      )
    )
    XCTAssertNil(coordinator.committedProjection)
  }

  func testRecoveryRejectsOldRuntimeGenerationAndCommitsOnlyFreshBarrier() throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-1")
    let oldGeneration = RuntimeStreamGeneration(rawValue: "generation-old")
    let freshGeneration = RuntimeStreamGeneration(rawValue: "generation-fresh")
    var coordinator = try RelayConversationResumeCoordinator(
      machineID: "machine-1",
      conversationID: conversationID,
      persistedCursor: .at(7),
      inMemoryBaseline: nil
    )

    _ = try coordinator.accept(subscriptionDelivery(generation: oldGeneration))
    _ = try coordinator.accept(
      delivery(
        generation: oldGeneration,
        payload: .conversationSnapshot(
          try resumeSnapshot(conversationID: conversationID, base: .at(7))
        )
      )
    )
    _ = try coordinator.accept(
      delivery(
        generation: oldGeneration,
        outerCursor: .at(20),
        payload: .syncComplete(
          try resumeSyncComplete(
            generation: oldGeneration,
            conversationID: conversationID,
            outerCursor: .at(20),
            innerCursor: .at(7)
          )
        )
      )
    )
    XCTAssertEqual(coordinator.committedProjection?.cursor, .at(7))

    coordinator.beginRecovery()
    XCTAssertEqual(coordinator.requestedCursor, .beforeFirst)
    _ = try coordinator.accept(subscriptionDelivery(generation: freshGeneration))

    let lateOldEvent = try resumeEvent(
      conversationID: conversationID,
      sequence: 8,
      eventID: "late-old"
    )
    XCTAssertEqual(
      try coordinator.accept(
        delivery(
          generation: oldGeneration,
          outerCursor: .at(21),
          payload: .conversationEvent(lateOldEvent)
        )
      ),
      .staleGeneration
    )
    XCTAssertEqual(
      coordinator.committedProjection?.cursor,
      .at(7),
      "recovery 期间可保留旧 projection 作为 stale UI，但旧 generation 不能继续归约"
    )

    _ = try coordinator.accept(
      delivery(
        generation: freshGeneration,
        payload: .conversationSnapshot(
          try resumeSnapshot(conversationID: conversationID, base: .at(9))
        )
      )
    )
    _ = try coordinator.accept(
      delivery(
        generation: freshGeneration,
        outerCursor: .at(30),
        payload: .syncComplete(
          try resumeSyncComplete(
            generation: freshGeneration,
            conversationID: conversationID,
            outerCursor: .at(30),
            innerCursor: .at(9)
          )
        )
      )
    )
    XCTAssertEqual(coordinator.committedProjection?.cursor, .at(9))
  }
}

private func subscriptionDelivery(
  generation: RuntimeStreamGeneration
) -> VerifiedRuntimeDelivery {
  delivery(
    generation: generation,
    payload: .typedReply(.subscription(.subscribed(streamGeneration: generation)))
  )
}

private func delivery(
  generation: RuntimeStreamGeneration,
  outerCursor: RuntimeStreamCursorV1 = .at(10),
  payload: VerifiedRuntimePayload
) -> VerifiedRuntimeDelivery {
  VerifiedRuntimeDelivery(
    fixtureMachineID: "machine-1",
    target: .conversation(
      conversationID: RuntimeConversationID(rawValue: "conversation-1"),
      subscriptionRequestID: RuntimeMessageID(rawValue: "subscription-1")
    ),
    streamGeneration: generation,
    outerCursor: outerCursor,
    payload: payload
  )
}

private func resumeSnapshot(
  conversationID: RuntimeConversationID,
  base: RuntimeStreamCursorV1
) throws -> ConversationSnapshotV2 {
  try ConversationSnapshotV2(
    conversationID: conversationID,
    baseEventCursor: base,
    configurationState: RuntimeConversationConfigurationStateV2(
      configurationRevision: 0,
      configuration: nil
    ),
    items: [.capabilities(try resumeCapabilities())]
  )
}

private func resumeEvent(
  conversationID: RuntimeConversationID,
  sequence: UInt64,
  eventID: String
) throws -> RuntimeEventV2 {
  try RuntimeEventV2(
    conversationID: conversationID,
    eventID: RuntimeEventID(rawValue: eventID),
    eventSeq: sequence,
    commandID: nil,
    itemID: nil,
    entityID: nil,
    body: .capabilities(try resumeCapabilities())
  )
}

private func resumeCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try resumeDecode(
    RuntimeSessionCapabilitiesV1.self,
    [
      "agentKind": "codex",
      "agentVersion": "test",
      "features": [],
      "vendor": [
        "agentKind": "codex",
        "sandboxModes": ["workspace-write"],
        "persistenceSupported": true,
        "reasoningEffortLevels": ["medium"],
      ],
    ]
  )
}

private func resumeSyncComplete(
  generation: RuntimeStreamGeneration,
  conversationID: RuntimeConversationID,
  outerCursor: RuntimeStreamCursorV1,
  innerCursor: RuntimeStreamCursorV1
) throws -> RuntimeSyncCompleteV1 {
  let encodedOuterCursor = resumeCursorObject(outerCursor)
  let encodedInnerCursor = resumeCursorObject(innerCursor)
  return try resumeDecode(
    RuntimeSyncCompleteV1.self,
    [
      "streamGeneration": generation.rawValue,
      "streamCursor": encodedOuterCursor,
      "innerCursor": [
        "scope": "conversation",
        "conversationId": conversationID.rawValue,
        "cursor": encodedInnerCursor,
      ],
      "keyDirectoryRevision": 1,
    ]
  )
}

private func resumeCursorObject(_ cursor: RuntimeStreamCursorV1) -> Any {
  switch cursor {
  case .beforeFirst: "beforeFirst"
  case .at(let value): ["at": value]
  }
}

private func resumeDecode<Value: Decodable>(
  _ type: Value.Type,
  _ object: Any
) throws -> Value {
  let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  return try JSONDecoder().decode(type, from: data)
}
