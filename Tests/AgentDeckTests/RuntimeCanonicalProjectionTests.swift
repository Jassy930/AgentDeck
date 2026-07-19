import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

final class RuntimeCanonicalProjectionTests: XCTestCase {
  func testSnapshotAndEventShareCanonicalProjectionWithoutSyntheticIdentity() throws {
    let item = RuntimeAgentItemV1.assistantMessage(
      text: "canonical answer",
      meta: RuntimeAgentItemMetaV1()
    )
    let snapshot = SnapshotItemV1.item(
      itemID: itemID("canonical-item-42"),
      entityID: entityID("canonical-entity-42"),
      commandID: commandID("canonical-command-42"),
      item: item
    )
    let event = try RuntimeEventV2(
      conversationID: conversationID("conversation-1"),
      eventID: eventID("event-1"),
      eventSeq: 0,
      commandID: commandID("canonical-command-42"),
      itemID: itemID("canonical-item-42"),
      entityID: entityID("canonical-entity-42"),
      body: .item(item)
    )

    let snapshotProjection = try RuntimeCanonicalItemProjection(snapshotItem: snapshot)
    let eventProjection = try RuntimeCanonicalItemProjection(event: event)

    XCTAssertEqual(snapshotProjection.identity, eventProjection.identity)
    XCTAssertEqual(snapshotProjection.identity.itemID.rawValue, "canonical-item-42")
    XCTAssertEqual(snapshotProjection.identity.entityID.rawValue, "canonical-entity-42")
    XCTAssertEqual(snapshotProjection.identity.commandID?.rawValue, "canonical-command-42")

    var store = AgentItemStore()
    var identities = RuntimeCanonicalIdentityState()
    try snapshotProjection.applySnapshot(into: &store, identities: &identities)

    XCTAssertEqual(store.items.map(\.id), ["canonical-item-42"])
    XCTAssertEqual(store.items.first?.text, "canonical answer")
    XCTAssertFalse(store.items[0].id.hasPrefix("ai-"))
  }

  func testEventUpdateKeepsFirstPositionAndFailsClosedOnIdentityDrift() throws {
    let initial = try projection(
      itemID: "item-1",
      entityID: "entity-1",
      commandID: "command-1",
      text: "partial"
    )
    let cumulative = try projection(
      itemID: "item-1",
      entityID: "entity-1",
      commandID: "command-1",
      text: "complete"
    )
    let second = try projection(
      itemID: "item-2",
      entityID: "entity-2",
      commandID: nil,
      text: "second"
    )

    var store = AgentItemStore()
    var identities = RuntimeCanonicalIdentityState()
    try initial.applyEvent(into: &store, identities: &identities)
    try second.applyEvent(into: &store, identities: &identities)
    try cumulative.applyEvent(into: &store, identities: &identities)

    XCTAssertEqual(store.items.map(\.id), ["item-1", "item-2"])
    XCTAssertEqual(store.items[0].text, "complete")
    XCTAssertEqual(identities.count, 2)

    let itemCollision = try projection(
      itemID: "item-1",
      entityID: "entity-other",
      commandID: "command-1",
      text: "tampered"
    )
    let entityCollision = try projection(
      itemID: "item-other",
      entityID: "entity-2",
      commandID: nil,
      text: "tampered"
    )
    let commandCollision = try projection(
      itemID: "item-1",
      entityID: "entity-1",
      commandID: "command-other",
      text: "tampered"
    )
    let kindCollision = try RuntimeCanonicalItemProjection(
      itemID: itemID("item-1"),
      entityID: entityID("entity-1"),
      commandID: commandID("command-1"),
      item: .shell(
        command: "false",
        status: .failed,
        exitCode: 1,
        durationMs: nil,
        meta: RuntimeAgentItemMetaV1()
      )
    )

    XCTAssertThrowsError(
      try itemCollision.applyEvent(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .itemIdentityConflict)
    }
    XCTAssertThrowsError(
      try entityCollision.applyEvent(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .entityIdentityConflict)
    }
    XCTAssertThrowsError(
      try commandCollision.applyEvent(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .commandIdentityConflict)
    }
    XCTAssertThrowsError(
      try kindCollision.applyEvent(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .itemKindConflict)
    }
    XCTAssertEqual(store.items.map(\.text), ["complete", "second"])
    XCTAssertEqual(identities.count, 2)
  }

  func testSnapshotRejectsDuplicateFinalItemAndEntityIdentities() throws {
    let first = try projection(
      itemID: "item-1",
      entityID: "entity-1",
      commandID: nil,
      text: "first"
    )
    let duplicateItem = try projection(
      itemID: "item-1",
      entityID: "entity-1",
      commandID: nil,
      text: "replacement"
    )
    let duplicateEntity = try projection(
      itemID: "item-2",
      entityID: "entity-1",
      commandID: nil,
      text: "collision"
    )

    var store = AgentItemStore()
    var identities = RuntimeCanonicalIdentityState()
    try first.applySnapshot(into: &store, identities: &identities)

    XCTAssertThrowsError(
      try duplicateItem.applySnapshot(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .duplicateSnapshotItem)
    }
    XCTAssertThrowsError(
      try duplicateEntity.applySnapshot(into: &store, identities: &identities)
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .duplicateSnapshotEntity)
    }
    XCTAssertEqual(store.items.map(\.text), ["first"])
    XCTAssertEqual(identities.count, 1)
  }

  func testAllRuntimeAgentItemVariantsUseExistingUIShape() throws {
    let diff = try decodeItem([
      "kind": "diff",
      "files": [["path": "Sources/App.swift", "status": "modified", "patch": "+new"]],
    ])
    let plan = try decodeItem([
      "kind": "plan",
      "steps": [["title": "Implement", "status": "inProgress", "detail": "C3a"]],
    ])
    let variants: [RuntimeAgentItemV1] = [
      .userMessage(text: "question", meta: RuntimeAgentItemMetaV1()),
      .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1()),
      .reasoning(text: "reason", meta: RuntimeAgentItemMetaV1()),
      .shell(
        command: "swift test",
        status: .completed,
        exitCode: 0,
        durationMs: 12,
        meta: RuntimeAgentItemMetaV1()
      ),
      diff,
      plan,
      .imageReference(
        savedPath: "/tmp/image.png",
        originalPath: "/source/image.png",
        meta: RuntimeAgentItemMetaV1()
      ),
      .toolCall(
        name: "search",
        args: AnyCodable(["query": "relay"]),
        result: AnyCodable(["count": 1]),
        meta: RuntimeAgentItemMetaV1()
      ),
      .raw(rawKind: "future", rawPayload: "opaque", meta: RuntimeAgentItemMetaV1()),
    ]

    var store = AgentItemStore()
    var identities = RuntimeCanonicalIdentityState()
    for (index, item) in variants.enumerated() {
      let projection = try RuntimeCanonicalItemProjection(
        itemID: itemID("item-\(index)"),
        entityID: entityID("entity-\(index)"),
        commandID: index == 0 ? commandID("command-0") : nil,
        item: item
      )
      try projection.applySnapshot(into: &store, identities: &identities)
    }

    XCTAssertEqual(
      store.items.map(\.kind),
      [
        "user", "message", "reasoning", "shell", "fileEdit", "plan", "media", "toolCall",
        "raw",
      ])
    XCTAssertEqual(store.items[0].text, "question")
    XCTAssertEqual(store.items[1].text, "answer")
    XCTAssertEqual(store.items[2].text, "reason")
    XCTAssertEqual(store.items[3].command, "swift test")
    XCTAssertEqual(store.items[3].statusName, "completed")
    XCTAssertEqual(store.items[3].exitCode, 0)
    XCTAssertEqual(store.items[3].durationMs, 12)
    XCTAssertEqual(store.items[4].path, "Sources/App.swift")
    XCTAssertEqual(store.items[4].diff, "+new")
    XCTAssertEqual(store.items[4].changes.first?.changeKind, "modified")
    XCTAssertEqual(store.items[5].text, "[inProgress] Implement: C3a")
    XCTAssertEqual(store.items[6].savedPath, "/tmp/image.png")
    XCTAssertEqual(store.items[6].path, "/source/image.png")
    XCTAssertEqual(store.items[7].tool, "search")
    XCTAssertEqual(store.items[7].arguments, #"{"query":"relay"}"#)
    XCTAssertEqual(store.items[7].result, #"{"count":1}"#)
    XCTAssertEqual(store.items[8].descriptionText, "unsupported item type: future")
    XCTAssertEqual(store.items[8].text, "opaque")
  }

  func testProjectionRejectsMissingOrEmptyCanonicalIdentity() throws {
    XCTAssertThrowsError(
      try RuntimeCanonicalItemProjection(
        itemID: itemID(""),
        entityID: entityID("entity-1"),
        commandID: nil,
        item: .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1())
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .emptyItemID)
    }
    XCTAssertThrowsError(
      try RuntimeCanonicalItemProjection(
        itemID: itemID("item-1"),
        entityID: entityID(""),
        commandID: nil,
        item: .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1())
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .emptyEntityID)
    }
    XCTAssertThrowsError(
      try RuntimeCanonicalItemProjection(
        itemID: itemID("item-1"),
        entityID: entityID("entity-1"),
        commandID: commandID(""),
        item: .assistantMessage(text: "answer", meta: RuntimeAgentItemMetaV1())
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .emptyCommandID)
    }
    XCTAssertThrowsError(
      try RuntimeCanonicalItemProjection(
        itemID: itemID("item-1"),
        entityID: entityID("entity-1"),
        commandID: nil,
        item: .userMessage(text: "question", meta: RuntimeAgentItemMetaV1())
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .userMessageRequiresCommandID)
    }
    XCTAssertThrowsError(
      try RuntimeCanonicalItemProjection(
        snapshotItem: .capabilities(try capabilities())
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .snapshotDoesNotContainItem)
    }

    let nonItemEvent = try RuntimeEventV2(
      conversationID: conversationID("conversation-1"),
      eventID: eventID("event-turn-started"),
      eventSeq: 0,
      commandID: commandID("command-1"),
      itemID: nil,
      entityID: nil,
      body: .turnStarted(turnID: RuntimeTurnID(rawValue: "turn-1"))
    )
    XCTAssertThrowsError(try RuntimeCanonicalItemProjection(event: nonItemEvent)) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .eventDoesNotContainItem)
    }
  }

  func testEventCursorRequiresConversationAndExactContiguousSequence() throws {
    var state = try RuntimeCanonicalEventCursorState(
      conversationID: conversationID("conversation-1"),
      baseCursor: .beforeFirst
    )
    let event0 = try runtimeEvent(sequence: 0, eventID: "event-0")
    state = try state.reducing(event0)
    XCTAssertEqual(state.cursor, .at(0))
    XCTAssertEqual(state.lastEventID?.rawValue, "event-0")

    XCTAssertThrowsError(
      try state.reducing(runtimeEvent(sequence: 1, eventID: "event-0"))
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .duplicateEventID)
    }

    XCTAssertThrowsError(try state.reducing(event0)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 1, actual: 0)
      )
    }
    XCTAssertThrowsError(try state.reducing(runtimeEvent(sequence: 2, eventID: "event-2"))) {
      error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedEventSequence(expected: 1, actual: 2)
      )
    }
    XCTAssertThrowsError(
      try state.reducing(
        runtimeEvent(
          sequence: 1,
          eventID: "event-1",
          conversationID: "conversation-other"
        )
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .conversationMismatch)
    }
    XCTAssertThrowsError(try state.reducing(runtimeEvent(sequence: 1, eventID: ""))) {
      error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .emptyEventID)
    }

    let exhausted = try RuntimeCanonicalEventCursorState(
      conversationID: conversationID("conversation-1"),
      baseCursor: .at(UInt64.max)
    )
    XCTAssertThrowsError(
      try exhausted.reducing(runtimeEvent(sequence: UInt64.max, eventID: "event-max"))
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .eventCursorExhausted)
    }

    XCTAssertThrowsError(
      try RuntimeCanonicalEventCursorState(
        conversationID: conversationID(""),
        baseCursor: .beforeFirst
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .emptyConversationID)
    }
  }

  func testRevisionReducerRequiresExactNextRevision() throws {
    var state = RuntimeCanonicalRevisionState(baseCursor: .beforeFirst)
    state = try state.reducing(0)
    state = try state.reducing(1)
    XCTAssertEqual(state.cursor, .at(1))

    XCTAssertThrowsError(try state.reducing(1)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedRevision(expected: 2, actual: 1)
      )
    }
    XCTAssertThrowsError(try state.reducing(3)) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedRevision(expected: 2, actual: 3)
      )
    }

    let exhausted = RuntimeCanonicalRevisionState(baseCursor: .at(UInt64.max))
    XCTAssertThrowsError(try exhausted.reducing(UInt64.max)) { error in
      XCTAssertEqual(error as? RuntimeCanonicalProjectionError, .revisionExhausted)
    }
  }

  func testRuntimeActionDecisionPublicInitializerKeepsWireShape() throws {
    let decision = RuntimeActionDecisionV1(
      requestID: "approval-1",
      decision: .approve,
      persist: true
    )
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(decision)) as? [String: Any]
    )

    XCTAssertEqual(object["requestId"] as? String, "approval-1")
    XCTAssertEqual(object["decision"] as? String, "approve")
    XCTAssertEqual(object["persist"] as? Bool, true)
    XCTAssertEqual(Set(object.keys), ["requestId", "decision", "persist"])
  }

  private func projection(
    itemID itemIDValue: String,
    entityID entityIDValue: String,
    commandID commandIDValue: String?,
    text: String
  ) throws -> RuntimeCanonicalItemProjection {
    try RuntimeCanonicalItemProjection(
      itemID: itemID(itemIDValue),
      entityID: entityID(entityIDValue),
      commandID: commandIDValue.map(commandID),
      item: .assistantMessage(text: text, meta: RuntimeAgentItemMetaV1())
    )
  }

  private func runtimeEvent(
    sequence: UInt64,
    eventID eventIDValue: String,
    conversationID conversationIDValue: String = "conversation-1"
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: conversationID(conversationIDValue),
      eventID: eventID(eventIDValue),
      eventSeq: sequence,
      commandID: nil,
      itemID: itemID("item-\(sequence)"),
      entityID: entityID("entity-\(sequence)"),
      body: .item(
        .assistantMessage(
          text: "event \(sequence)",
          meta: RuntimeAgentItemMetaV1()
        )
      )
    )
  }

  private func decodeItem(_ object: [String: Any]) throws -> RuntimeAgentItemV1 {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(RuntimeAgentItemV1.self, from: data)
  }

  private func capabilities() throws -> RuntimeSessionCapabilitiesV1 {
    let object: [String: Any] = [
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
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return try JSONDecoder().decode(RuntimeSessionCapabilitiesV1.self, from: data)
  }

  private func conversationID(_ value: String) -> RuntimeConversationID {
    RuntimeConversationID(rawValue: value)
  }

  private func eventID(_ value: String) -> RuntimeEventID {
    RuntimeEventID(rawValue: value)
  }

  private func itemID(_ value: String) -> RuntimeItemID {
    RuntimeItemID(rawValue: value)
  }

  private func entityID(_ value: String) -> RuntimeEntityID {
    RuntimeEntityID(rawValue: value)
  }

  private func commandID(_ value: String) -> RuntimeCommandID {
    RuntimeCommandID(rawValue: value)
  }
}
