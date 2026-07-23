import AgentDeckCore
import XCTest

@testable import AgentDeck

final class RuntimeCatalogModelTests: XCTestCase {
  func testSnapshotPagesProduceBoundedCanonicalStableOrdering() throws {
    let first = try page(
      base: .at(7),
      entries: [
        entry("conversation-a", lastActiveMs: 100, entryRevision: 1),
        entry("conversation-b", lastActiveMs: 300, entryRevision: 2),
      ],
      next: "page-2"
    )
    let second = try page(
      base: .at(7),
      entries: [
        entry("conversation-a", lastActiveMs: 100, entryRevision: 1),
        entry("conversation-c", lastActiveMs: 300, entryRevision: 0),
      ],
      current: "page-2",
      next: nil
    )

    let model = try RuntimeCatalogModel(
      snapshotPages: [first, second],
      maximumEntries: 3
    )

    XCTAssertEqual(model.cursor, .at(7))
    XCTAssertEqual(model.count, 3)
    XCTAssertEqual(
      model.entries.map(\.conversationID.rawValue),
      ["conversation-b", "conversation-c", "conversation-a"]
    )
  }

  func testSnapshotRequiresOneConsistentTerminatedPageChain() throws {
    XCTAssertThrowsError(try RuntimeCatalogModel(snapshotPages: [])) { error in
      XCTAssertEqual(error as? RuntimeCatalogModelError, .missingSnapshotPage)
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(base: .at(7), entries: [], next: "page-2"),
          try page(base: .at(8), entries: [], current: "page-2", next: nil),
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .snapshotBaseCursorMismatch(expected: .at(7), actual: .at(8), pageIndex: 1)
      )
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(base: .beforeFirst, entries: [], next: nil),
          try page(base: .beforeFirst, entries: [], next: nil),
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .snapshotEndedBeforeLastPage(pageIndex: 0)
      )
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(base: .beforeFirst, entries: [], next: "page-2")
        ]
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeCatalogModelError, .snapshotDidNotTerminate)
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(base: .beforeFirst, entries: [], next: "same-page"),
          try page(
            base: .beforeFirst, entries: [], current: "same-page", next: "same-page"
          ),
          try page(base: .beforeFirst, entries: [], current: "same-page", next: nil),
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .repeatedPageCursor(pageCursor("same-page"))
      )
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(base: .beforeFirst, entries: [], next: "page-2"),
          try page(base: .beforeFirst, entries: [], current: "page-3", next: nil),
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .snapshotPageCursorMismatch(
          expected: pageCursor("page-2"),
          actual: pageCursor("page-3"),
          pageIndex: 1
        )
      )
    }
  }

  func testSnapshotRejectsConflictingDuplicatesAndEntryOverflow() throws {
    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(
            base: .beforeFirst,
            entries: [
              entry("conversation-a", title: "old", entryRevision: 1),
              entry("conversation-a", title: "new", entryRevision: 1),
            ],
            next: nil
          )
        ]
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .duplicateConversationConflict(conversationID("conversation-a"))
      )
    }

    XCTAssertThrowsError(
      try RuntimeCatalogModel(
        snapshotPages: [
          try page(
            base: .beforeFirst,
            entries: [entry("conversation-a"), entry("conversation-b")],
            next: nil
          )
        ],
        maximumEntries: 1
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .catalogEntryLimitExceeded(maximum: 1)
      )
    }
  }

  func testDeltaUsesExactNextRevisionAndAppliesUpsertRemoveAtomically() throws {
    let model = try RuntimeCatalogModel(
      snapshotPages: [
        try page(
          base: .at(4),
          entries: [
            entry("conversation-a", title: "old", lastActiveMs: 10, entryRevision: 2),
            entry("conversation-b", lastActiveMs: 20, entryRevision: 0),
          ],
          next: nil
        )
      ]
    )

    let updated = try model.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 5,
        changes: [
          .upserted(
            entry: entry(
              "conversation-a",
              title: "new",
              lastActiveMs: 40,
              entryRevision: 3
            )
          ),
          .removed(conversationID: conversationID("conversation-b")),
          .upserted(
            entry: entry("conversation-c", lastActiveMs: 30, entryRevision: 0)
          ),
        ]
      )
    )

    XCTAssertEqual(updated.cursor, .at(5))
    XCTAssertEqual(
      updated.entries.map(\.conversationID.rawValue),
      ["conversation-a", "conversation-c"]
    )
    XCTAssertEqual(updated.entries.first?.title, "new")

    let advanced = try updated.reducing(
      RuntimeCatalogDeltaV2(catalogRevision: 6, changes: [])
    )
    XCTAssertEqual(advanced.cursor, .at(6))

    XCTAssertThrowsError(
      try model.reducing(RuntimeCatalogDeltaV2(catalogRevision: 6, changes: []))
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCanonicalProjectionError,
        .unexpectedRevision(expected: 5, actual: 6)
      )
    }
  }

  func testDeltaBoundsActiveEntriesAndRetainedRevisionTombstones() throws {
    let original = try RuntimeCatalogModel(
      snapshotPages: [
        try page(
          base: .beforeFirst,
          entries: [entry("conversation-a", entryRevision: 0)],
          next: nil
        )
      ],
      maximumEntries: 1,
      maximumTrackedEntries: 2
    )

    XCTAssertThrowsError(
      try original.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 0,
          changes: [.upserted(entry: entry("conversation-b", entryRevision: 0))]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .catalogEntryLimitExceeded(maximum: 1)
      )
    }
    XCTAssertEqual(original.cursor, .beforeFirst)
    XCTAssertEqual(original.entries.map(\.conversationID.rawValue), ["conversation-a"])

    let removedA = try original.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 0,
        changes: [.removed(conversationID: conversationID("conversation-a"))]
      )
    )
    let insertedB = try removedA.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 1,
        changes: [.upserted(entry: entry("conversation-b", entryRevision: 0))]
      )
    )
    let removedB = try insertedB.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 2,
        changes: [.removed(conversationID: conversationID("conversation-b"))]
      )
    )

    XCTAssertThrowsError(
      try removedB.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 3,
          changes: [.upserted(entry: entry("conversation-c", entryRevision: 0))]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .catalogTrackedEntryLimitExceeded(maximum: 2)
      )
    }

    let reinsertedKnownIdentity = try removedB.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 3,
        changes: [.upserted(entry: entry("conversation-a", entryRevision: 1))]
      )
    )
    XCTAssertEqual(
      reinsertedKnownIdentity.entries.map(\.conversationID.rawValue),
      ["conversation-a"]
    )
  }

  func testDeltaRejectsRevisionRollbackAndEqualRevisionConflictWithoutMutation() throws {
    let original = try RuntimeCatalogModel(
      snapshotPages: [
        try page(
          base: .beforeFirst,
          entries: [entry("conversation-a", title: "old", entryRevision: 3)],
          next: nil
        )
      ]
    )

    XCTAssertThrowsError(
      try original.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 0,
          changes: [
            .upserted(
              entry: entry("conversation-a", title: "rollback", entryRevision: 2)
            )
          ]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .entryRevisionRegressed(
          conversationID: conversationID("conversation-a"),
          current: 3,
          actual: 2
        )
      )
    }

    XCTAssertThrowsError(
      try original.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 0,
          changes: [
            .upserted(
              entry: entry("conversation-a", title: "conflict", entryRevision: 3)
            )
          ]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .entryRevisionConflict(
          conversationID: conversationID("conversation-a"),
          revision: 3
        )
      )
    }

    let unchanged = try original.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 0,
        changes: [
          .upserted(entry: entry("conversation-a", title: "old", entryRevision: 3))
        ]
      )
    )
    XCTAssertEqual(unchanged.cursor, .at(0))
    XCTAssertEqual(unchanged.entries.first?.title, "old")
    XCTAssertEqual(original.cursor, .beforeFirst)
    XCTAssertEqual(original.entries.first?.title, "old")
  }

  func testUnknownRemoveFailsTypedAndRemovedEntryCannotReappearAtOldRevision() throws {
    let original = try RuntimeCatalogModel(
      snapshotPages: [
        try page(
          base: .beforeFirst,
          entries: [entry("conversation-a", entryRevision: 3)],
          next: nil
        )
      ]
    )

    XCTAssertThrowsError(
      try original.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 0,
          changes: [.removed(conversationID: conversationID("unknown"))]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .unknownRemoval(conversationID("unknown"))
      )
    }

    let removed = try original.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 0,
        changes: [.removed(conversationID: conversationID("conversation-a"))]
      )
    )
    XCTAssertTrue(removed.entries.isEmpty)

    XCTAssertThrowsError(
      try removed.reducing(
        RuntimeCatalogDeltaV2(
          catalogRevision: 1,
          changes: [
            .upserted(entry: entry("conversation-a", entryRevision: 3))
          ]
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeCatalogModelError,
        .entryRevisionDidNotAdvanceAfterRemoval(
          conversationID: conversationID("conversation-a"),
          current: 3,
          actual: 3
        )
      )
    }

    let reinserted = try removed.reducing(
      RuntimeCatalogDeltaV2(
        catalogRevision: 1,
        changes: [
          .upserted(entry: entry("conversation-a", entryRevision: 4))
        ]
      )
    )
    XCTAssertEqual(reinserted.entries.first?.entryRevision, 4)
  }

  private func page(
    base: RuntimeStreamCursorV1,
    entries: [RuntimeConversationEntryV2],
    current: String? = nil,
    next: String?
  ) throws -> RuntimeCatalogSnapshotV2 {
    try RuntimeCatalogSnapshotV2(
      baseCatalogCursor: base,
      entries: entries,
      currentPageCursor: current.map(pageCursor),
      nextPageCursor: next.map(pageCursor)
    )
  }

  private func entry(
    _ id: String,
    title: String? = nil,
    cwd: String? = nil,
    lastActiveMs: UInt64 = 0,
    archived: Bool = false,
    entryRevision: UInt64 = 0
  ) -> RuntimeConversationEntryV2 {
    RuntimeConversationEntryV2(
      conversationID: conversationID(id),
      agentKind: .codex,
      title: title,
      cwd: cwd,
      lastActiveMs: lastActiveMs,
      archived: archived,
      entryRevision: entryRevision
    )
  }

  private func conversationID(_ value: String) -> RuntimeConversationID {
    RuntimeConversationID(rawValue: value)
  }

  private func pageCursor(_ value: String) -> RuntimeCatalogPageCursor {
    RuntimeCatalogPageCursor(rawValue: value)
  }
}
