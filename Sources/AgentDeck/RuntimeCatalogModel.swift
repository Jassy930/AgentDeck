import AgentDeckCore

/// 完整 catalog snapshot 与后续 delta 的本地纯值校验错误。
enum RuntimeCatalogModelError: Error, Equatable, Sendable {
  case missingSnapshotPage
  case invalidMaximumEntries(Int)
  case invalidMaximumTrackedEntries(Int)
  case snapshotBaseCursorMismatch(
    expected: RuntimeStreamCursorV1,
    actual: RuntimeStreamCursorV1,
    pageIndex: Int
  )
  case snapshotEndedBeforeLastPage(pageIndex: Int)
  case snapshotDidNotTerminate
  case repeatedPageCursor(RuntimeCatalogPageCursor)
  case emptyConversationID
  case duplicateConversationConflict(RuntimeConversationID)
  case catalogEntryLimitExceeded(maximum: Int)
  case catalogTrackedEntryLimitExceeded(maximum: Int)
  case entryRevisionRegressed(
    conversationID: RuntimeConversationID,
    current: UInt64,
    actual: UInt64
  )
  case entryRevisionConflict(conversationID: RuntimeConversationID, revision: UInt64)
  case entryRevisionDidNotAdvanceAfterRemoval(
    conversationID: RuntimeConversationID,
    current: UInt64,
    actual: UInt64
  )
  case unknownRemoval(RuntimeConversationID)
}

/// App 使用的 canonical catalog 纯值状态。
///
/// Snapshot 必须完整收齐后一次性构造；delta reducer 返回新值，任何校验失败都不会推进
/// catalog cursor，也不会留下部分 upsert/remove。模型只保留 daemon 签发的 conversation
/// identity，不生成 thread/session 等替代身份。
struct RuntimeCatalogModel: Sendable {
  /// 与 daemon 的 live catalog 硬上界一致。
  static let maximumEntryCount = 1_024
  /// 同时覆盖 live 与 native non-live identity，限制 revision tombstone 常驻内存。
  static let maximumTrackedEntryCount = 9_216

  private let activeEntriesByID: [RuntimeConversationID: RuntimeConversationEntryV2]
  private let latestEntriesByID: [RuntimeConversationID: RuntimeConversationEntryV2]
  private let revisionState: RuntimeCanonicalRevisionState
  private let maximumEntries: Int
  private let maximumTrackedEntries: Int

  var cursor: RuntimeStreamCursorV1 { revisionState.cursor }
  var count: Int { activeEntriesByID.count }

  /// 最近活跃优先；时间相同时以 daemon conversationId 字典序固定顺序。
  var entries: [RuntimeConversationEntryV2] {
    activeEntriesByID.values.sorted { lhs, rhs in
      if lhs.lastActiveMs != rhs.lastActiveMs {
        return lhs.lastActiveMs > rhs.lastActiveMs
      }
      return lhs.conversationID.rawValue < rhs.conversationID.rawValue
    }
  }

  init(
    snapshotPages: [RuntimeCatalogSnapshotV2],
    maximumEntries: Int = Self.maximumEntryCount,
    maximumTrackedEntries: Int = Self.maximumTrackedEntryCount
  ) throws {
    guard maximumEntries > 0, maximumEntries <= Self.maximumEntryCount else {
      throw RuntimeCatalogModelError.invalidMaximumEntries(maximumEntries)
    }
    guard maximumTrackedEntries >= maximumEntries,
      maximumTrackedEntries <= Self.maximumTrackedEntryCount
    else {
      throw RuntimeCatalogModelError.invalidMaximumTrackedEntries(maximumTrackedEntries)
    }
    guard let firstPage = snapshotPages.first else {
      throw RuntimeCatalogModelError.missingSnapshotPage
    }

    let baseCursor = firstPage.baseCatalogCursor
    var activeEntries: [RuntimeConversationID: RuntimeConversationEntryV2] = [:]
    var latestEntries: [RuntimeConversationID: RuntimeConversationEntryV2] = [:]
    var seenPageCursors: Set<RuntimeCatalogPageCursor> = []

    for (pageIndex, page) in snapshotPages.enumerated() {
      guard page.baseCatalogCursor == baseCursor else {
        throw RuntimeCatalogModelError.snapshotBaseCursorMismatch(
          expected: baseCursor,
          actual: page.baseCatalogCursor,
          pageIndex: pageIndex
        )
      }

      let isLastPage = pageIndex == snapshotPages.index(before: snapshotPages.endIndex)
      if isLastPage {
        guard page.nextPageCursor == nil else {
          throw RuntimeCatalogModelError.snapshotDidNotTerminate
        }
      } else {
        guard let nextPageCursor = page.nextPageCursor else {
          throw RuntimeCatalogModelError.snapshotEndedBeforeLastPage(pageIndex: pageIndex)
        }
        guard seenPageCursors.insert(nextPageCursor).inserted else {
          throw RuntimeCatalogModelError.repeatedPageCursor(nextPageCursor)
        }
      }

      for entry in page.entries {
        try Self.validateConversationID(entry.conversationID)
        if let existing = latestEntries[entry.conversationID] {
          guard Self.entriesExactlyMatch(existing, entry) else {
            throw RuntimeCatalogModelError.duplicateConversationConflict(entry.conversationID)
          }
          continue
        }
        guard activeEntries.count < maximumEntries else {
          throw RuntimeCatalogModelError.catalogEntryLimitExceeded(maximum: maximumEntries)
        }
        activeEntries[entry.conversationID] = entry
        latestEntries[entry.conversationID] = entry
      }
    }

    self.init(
      activeEntriesByID: activeEntries,
      latestEntriesByID: latestEntries,
      revisionState: RuntimeCanonicalRevisionState(baseCursor: baseCursor),
      maximumEntries: maximumEntries,
      maximumTrackedEntries: maximumTrackedEntries
    )
  }

  /// 只接受当前 catalog cursor 的 exact-next delta，并以原子纯值方式应用全部变化。
  func reducing(_ delta: RuntimeCatalogDeltaV2) throws -> Self {
    let nextRevisionState = try revisionState.reducing(delta.catalogRevision)
    var activeEntries = activeEntriesByID
    var latestEntries = latestEntriesByID

    for change in delta.changes {
      switch change {
      case .upserted(let entry):
        try Self.validateConversationID(entry.conversationID)
        try Self.reduceUpsert(
          entry,
          activeEntries: &activeEntries,
          latestEntries: &latestEntries,
          maximumEntries: maximumEntries,
          maximumTrackedEntries: maximumTrackedEntries
        )
      case .removed(let conversationID):
        try Self.validateConversationID(conversationID)
        guard activeEntries.removeValue(forKey: conversationID) != nil else {
          throw RuntimeCatalogModelError.unknownRemoval(conversationID)
        }
      }
    }

    return Self(
      activeEntriesByID: activeEntries,
      latestEntriesByID: latestEntries,
      revisionState: nextRevisionState,
      maximumEntries: maximumEntries,
      maximumTrackedEntries: maximumTrackedEntries
    )
  }

  private init(
    activeEntriesByID: [RuntimeConversationID: RuntimeConversationEntryV2],
    latestEntriesByID: [RuntimeConversationID: RuntimeConversationEntryV2],
    revisionState: RuntimeCanonicalRevisionState,
    maximumEntries: Int,
    maximumTrackedEntries: Int
  ) {
    self.activeEntriesByID = activeEntriesByID
    self.latestEntriesByID = latestEntriesByID
    self.revisionState = revisionState
    self.maximumEntries = maximumEntries
    self.maximumTrackedEntries = maximumTrackedEntries
  }

  private static func reduceUpsert(
    _ entry: RuntimeConversationEntryV2,
    activeEntries: inout [RuntimeConversationID: RuntimeConversationEntryV2],
    latestEntries: inout [RuntimeConversationID: RuntimeConversationEntryV2],
    maximumEntries: Int,
    maximumTrackedEntries: Int
  ) throws {
    let conversationID = entry.conversationID
    if let activeEntry = activeEntries[conversationID] {
      try validateRevision(entry, against: activeEntry)
      activeEntries[conversationID] = entry
      latestEntries[conversationID] = entry
      return
    }

    let removedEntry = latestEntries[conversationID]
    if let removedEntry {
      guard entry.entryRevision > removedEntry.entryRevision else {
        if entry.entryRevision < removedEntry.entryRevision {
          throw RuntimeCatalogModelError.entryRevisionRegressed(
            conversationID: conversationID,
            current: removedEntry.entryRevision,
            actual: entry.entryRevision
          )
        }
        throw RuntimeCatalogModelError.entryRevisionDidNotAdvanceAfterRemoval(
          conversationID: conversationID,
          current: removedEntry.entryRevision,
          actual: entry.entryRevision
        )
      }
    }

    guard activeEntries.count < maximumEntries else {
      throw RuntimeCatalogModelError.catalogEntryLimitExceeded(maximum: maximumEntries)
    }
    if removedEntry == nil {
      guard latestEntries.count < maximumTrackedEntries else {
        throw RuntimeCatalogModelError.catalogTrackedEntryLimitExceeded(
          maximum: maximumTrackedEntries
        )
      }
    }
    activeEntries[conversationID] = entry
    latestEntries[conversationID] = entry
  }

  private static func validateRevision(
    _ entry: RuntimeConversationEntryV2,
    against existing: RuntimeConversationEntryV2
  ) throws {
    guard entry.entryRevision >= existing.entryRevision else {
      throw RuntimeCatalogModelError.entryRevisionRegressed(
        conversationID: entry.conversationID,
        current: existing.entryRevision,
        actual: entry.entryRevision
      )
    }
    if entry.entryRevision == existing.entryRevision,
      !entriesExactlyMatch(existing, entry)
    {
      throw RuntimeCatalogModelError.entryRevisionConflict(
        conversationID: entry.conversationID,
        revision: entry.entryRevision
      )
    }
  }

  private static func validateConversationID(_ conversationID: RuntimeConversationID) throws {
    guard !conversationID.rawValue.isEmpty else {
      throw RuntimeCatalogModelError.emptyConversationID
    }
  }

  private static func entriesExactlyMatch(
    _ lhs: RuntimeConversationEntryV2,
    _ rhs: RuntimeConversationEntryV2
  ) -> Bool {
    lhs.conversationID == rhs.conversationID
      && lhs.agentKind == rhs.agentKind
      && lhs.title == rhs.title
      && lhs.cwd == rhs.cwd
      && lhs.lastActiveMs == rhs.lastActiveMs
      && lhs.archived == rhs.archived
      && lhs.entryRevision == rhs.entryRevision
  }
}
