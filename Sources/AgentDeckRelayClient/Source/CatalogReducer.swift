import AgentDeckCore
import AgentDeckSessionSource
import Foundation

enum RelayReducerApplyResult: Equatable, Sendable {
  case applied
  case duplicate
}

enum RelaySourceReducerError: Error, Equatable, Sendable {
  case emptyMachineID
  case emptyConversationID
  case emptyEventID
  case emptyTurnID
  case emptyCommandID
  case emptyApprovalID
  case emptyRequestID
  case missingSnapshotPage
  case snapshotBaseMismatch
  case snapshotPageMismatch
  case snapshotDidNotTerminate
  case duplicateSnapshotConflict
  case unexpectedCursor(expected: RuntimeStreamCursorV1, actual: RuntimeStreamCursorV1)
  case cursorExhausted
  case duplicateConflict(sequence: UInt64)
  case catalogEntryRevisionRegressed
  case catalogEntryRevisionConflict
  case catalogEntryMustAdvanceAfterRemoval
  case unknownCatalogRemoval
  case catalogCapacity
  case conversationBootstrapCapacity
  case wrongBackfillScope
  case conversationMismatch
  case capabilitiesRequired
  case capabilitiesConflict
  case configurationRevision
  case activeTurnConflict
  case turnStartRequired
  case turnIdentityMismatch
  case approvalConflict
  case approvalIdentityMismatch
  case unresolvedApproval
  case invalidBootstrapOrder
  case subscriptionMismatch
  case staleSubscriptionGeneration
  case syncCompleteMismatch
  case missingInMemoryBaseline
}

struct CatalogProjection: Sendable {
  let machineID: String
  let cursor: RuntimeStreamCursorV1
  let summaries: [ConversationSummary]

  var revision: UInt64 {
    guard case .at(let value) = cursor else { return 0 }
    return value
  }
}

/// Relay source 内的 Catalog 纯值 reducer。每个入口都先在副本完整归约，成功后
/// 才 swap；duplicate/conflict/gap 不会产生半份 summaries 或 cursor。
struct CatalogReducer: Sendable {
  private static let maximumEntries = 10_000
  private static let maximumFingerprints = 4_096

  let machineID: String
  private(set) var cursor: RuntimeStreamCursorV1

  private var activeEntries: [RuntimeConversationID: RuntimeConversationEntryV2]
  private var latestEntries: [RuntimeConversationID: RuntimeConversationEntryV2]
  private var deltaFingerprints: [UInt64: Data] = [:]
  private var fingerprintOrder: [UInt64] = []

  var projection: CatalogProjection {
    let summaries = activeEntries.values
      .sorted { lhs, rhs in
        if lhs.lastActiveMs != rhs.lastActiveMs {
          return lhs.lastActiveMs > rhs.lastActiveMs
        }
        return lhs.conversationID.rawValue < rhs.conversationID.rawValue
      }
      .map { entry in
        ConversationSummary(
          id: entry.conversationID.rawValue,
          machineID: machineID,
          title: entry.title ?? entry.conversationID.rawValue,
          cwd: entry.cwd ?? "",
          agentKind: entry.agentKind,
          group: .recent,
          lastActiveMs: entry.lastActiveMs,
          archived: entry.archived,
          revision: entry.entryRevision
        )
      }
    return CatalogProjection(machineID: machineID, cursor: cursor, summaries: summaries)
  }

  init(
    machineID: String,
    snapshotPages: [RuntimeCatalogSnapshotV2]
  ) throws {
    guard !machineID.isEmpty else { throw RelaySourceReducerError.emptyMachineID }
    guard let first = snapshotPages.first else {
      throw RelaySourceReducerError.missingSnapshotPage
    }

    var active: [RuntimeConversationID: RuntimeConversationEntryV2] = [:]
    var latest: [RuntimeConversationID: RuntimeConversationEntryV2] = [:]
    var expectedPage: RuntimeCatalogPageCursor?
    var seenPages: Set<RuntimeCatalogPageCursor> = []

    for (index, page) in snapshotPages.enumerated() {
      guard page.baseCatalogCursor == first.baseCatalogCursor else {
        throw RelaySourceReducerError.snapshotBaseMismatch
      }
      guard page.currentPageCursor == expectedPage else {
        throw RelaySourceReducerError.snapshotPageMismatch
      }

      let isLast = index == snapshotPages.index(before: snapshotPages.endIndex)
      if isLast {
        guard page.nextPageCursor == nil else {
          throw RelaySourceReducerError.snapshotDidNotTerminate
        }
      } else {
        guard let next = page.nextPageCursor, seenPages.insert(next).inserted else {
          throw RelaySourceReducerError.snapshotPageMismatch
        }
        expectedPage = next
      }

      for entry in page.entries {
        try Self.validate(entry)
        if let existing = latest[entry.conversationID] {
          guard try canonicalBytes(existing) == canonicalBytes(entry) else {
            throw RelaySourceReducerError.duplicateSnapshotConflict
          }
          continue
        }
        guard active.count < Self.maximumEntries else {
          throw RelaySourceReducerError.catalogCapacity
        }
        active[entry.conversationID] = entry
        latest[entry.conversationID] = entry
      }
    }

    self.machineID = machineID
    cursor = first.baseCatalogCursor
    activeEntries = active
    latestEntries = latest
  }

  @discardableResult
  mutating func apply(_ delta: RuntimeCatalogDeltaV2) throws -> RelayReducerApplyResult {
    let fingerprint = try canonicalBytes(delta)
    if isAtOrBehindCurrent(delta.catalogRevision) {
      guard deltaFingerprints[delta.catalogRevision] == fingerprint else {
        throw RelaySourceReducerError.duplicateConflict(sequence: delta.catalogRevision)
      }
      return .duplicate
    }

    let expected: UInt64
    do {
      expected = try cursor.checkedNext()
    } catch {
      throw RelaySourceReducerError.cursorExhausted
    }
    guard delta.catalogRevision == expected else {
      throw RelaySourceReducerError.unexpectedCursor(
        expected: .at(expected),
        actual: .at(delta.catalogRevision)
      )
    }

    var next = self
    try next.reduceChanges(delta.changes)
    next.cursor = .at(delta.catalogRevision)
    next.rememberFingerprint(fingerprint, sequence: delta.catalogRevision)
    self = next
    return .applied
  }

  @discardableResult
  mutating func apply(_ backfill: RuntimeBackfillChunkV2) throws -> RelayReducerApplyResult {
    guard case .catalog(let range, let deltas) = backfill else {
      throw RelaySourceReducerError.wrongBackfillScope
    }
    guard range.after == cursor else {
      throw RelaySourceReducerError.unexpectedCursor(expected: cursor, actual: range.after)
    }

    var next = self
    for delta in deltas {
      guard try next.apply(delta) == .applied else {
        throw RelaySourceReducerError.duplicateConflict(sequence: delta.catalogRevision)
      }
    }
    guard next.cursor == range.through else {
      throw RelaySourceReducerError.unexpectedCursor(
        expected: range.through,
        actual: next.cursor
      )
    }
    self = next
    return .applied
  }

  private func isAtOrBehindCurrent(_ sequence: UInt64) -> Bool {
    guard case .at(let current) = cursor else { return false }
    return sequence <= current
  }

  private mutating func reduceChanges(_ changes: [RuntimeCatalogChangeV2]) throws {
    for change in changes {
      switch change {
      case .upserted(let entry):
        try Self.validate(entry)
        if let current = activeEntries[entry.conversationID] {
          guard entry.entryRevision >= current.entryRevision else {
            throw RelaySourceReducerError.catalogEntryRevisionRegressed
          }
          if entry.entryRevision == current.entryRevision {
            guard try canonicalBytes(entry) == canonicalBytes(current) else {
              throw RelaySourceReducerError.catalogEntryRevisionConflict
            }
          }
          activeEntries[entry.conversationID] = entry
          latestEntries[entry.conversationID] = entry
          continue
        }

        if let removed = latestEntries[entry.conversationID] {
          guard entry.entryRevision > removed.entryRevision else {
            throw RelaySourceReducerError.catalogEntryMustAdvanceAfterRemoval
          }
        }
        guard activeEntries.count < Self.maximumEntries else {
          throw RelaySourceReducerError.catalogCapacity
        }
        activeEntries[entry.conversationID] = entry
        latestEntries[entry.conversationID] = entry

      case .removed(let conversationID):
        guard !conversationID.rawValue.isEmpty else {
          throw RelaySourceReducerError.emptyConversationID
        }
        guard activeEntries.removeValue(forKey: conversationID) != nil else {
          throw RelaySourceReducerError.unknownCatalogRemoval
        }
      }
    }
  }

  private mutating func rememberFingerprint(_ fingerprint: Data, sequence: UInt64) {
    deltaFingerprints[sequence] = fingerprint
    fingerprintOrder.append(sequence)
    if fingerprintOrder.count > Self.maximumFingerprints {
      let removed = fingerprintOrder.removeFirst()
      deltaFingerprints.removeValue(forKey: removed)
    }
  }

  private static func validate(_ entry: RuntimeConversationEntryV2) throws {
    guard !entry.conversationID.rawValue.isEmpty else {
      throw RelaySourceReducerError.emptyConversationID
    }
  }
}

func canonicalBytes<Value: Encodable>(_ value: Value) throws -> Data {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try encoder.encode(value)
}
