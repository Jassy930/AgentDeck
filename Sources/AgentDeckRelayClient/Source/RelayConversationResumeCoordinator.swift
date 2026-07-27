import AgentDeckCore
import Foundation

enum RelayResumeDeliveryResult: Equatable, Sendable {
  case staged
  case suppressedUntilBarrier
  case synchronized
  case live
  case duplicate
  case staleGeneration
}

struct RelaySynchronizedConversationDelivery: Sendable {
  let snapshot: ConversationSnapshotV2?
  let events: [RuntimeEventV2]
}

/// 单个 conversation observation 的 bootstrap/barrier owner。
///
/// durable cursor 只用于 authenticated transport resume；没有真实进程内 reducer baseline
/// 时一律从 BeforeFirst 请求 daemon snapshot。所有 bootstrap 数据只写 staged reducer，
/// `SyncComplete` 完整匹配后才原子替换 committed projection。
struct RelayConversationResumeCoordinator: Sendable {
  private static let maximumPublishedBootstrapItems = 512
  private static let maximumPublishedBootstrapBytes = 64 * 1_024 * 1_024

  let machineID: String
  let conversationID: RuntimeConversationID

  private(set) var requestedCursor: RuntimeStreamCursorV1
  private(set) var synchronizedSnapshot: ConversationSnapshotV2?
  private(set) var synchronizedEvents: [RuntimeEventV2] = []

  private var committedReducer: ConversationReducer?
  private var stagedReducer: ConversationReducer?
  private var stagedSnapshot: ConversationSnapshotV2?
  private var stagedEvents: [RuntimeEventV2] = []
  private var deferredLiveEvents: [RuntimeEventV2] = []
  private var deferredLiveReducer: ConversationReducer?
  private var publishedBootstrapBytes = 0
  private var activeGeneration: RuntimeStreamGeneration?
  private var subscriptionSeen = false
  private var synchronized = false
  private var backfillStarted = false

  var committedProjection: ConversationProjection? { committedReducer?.projection }

  var retainedBootstrapItemCount: Int {
    (stagedSnapshot == nil ? 0 : 1)
      + (synchronizedSnapshot == nil ? 0 : 1)
      + stagedEvents.count
      + deferredLiveEvents.count
      + synchronizedEvents.count
  }

  init(
    machineID: String,
    conversationID: RuntimeConversationID,
    persistedCursor: RuntimeStreamCursorV1?,
    inMemoryBaseline: ConversationProjection?
  ) throws {
    guard !machineID.isEmpty else { throw RelaySourceReducerError.emptyMachineID }
    guard !conversationID.rawValue.isEmpty else {
      throw RelaySourceReducerError.emptyConversationID
    }
    self.machineID = machineID
    self.conversationID = conversationID

    if let baseline = inMemoryBaseline {
      guard baseline.machineID == machineID,
        baseline.conversationID == conversationID.rawValue
      else {
        throw RelaySourceReducerError.missingInMemoryBaseline
      }
      if let persistedCursor, persistedCursor != baseline.cursor {
        throw RelaySourceReducerError.unexpectedCursor(
          expected: baseline.cursor,
          actual: persistedCursor
        )
      }
      requestedCursor = baseline.cursor
      committedReducer = baseline.resumeReducer
    } else {
      // Cold process 不持久化 transcript。即使 durable cursor 非零也不能把它当 baseline。
      _ = persistedCursor
      requestedCursor = .beforeFirst
      committedReducer = nil
    }
  }

  mutating func beginRecovery() {
    requestedCursor = .beforeFirst
    stagedReducer = nil
    stagedSnapshot = nil
    synchronizedSnapshot = nil
    synchronizedEvents = []
    stagedEvents = []
    deferredLiveEvents = []
    deferredLiveReducer = nil
    publishedBootstrapBytes = 0
    activeGeneration = nil
    subscriptionSeen = false
    synchronized = false
    backfillStarted = false
  }

  /// Source 完成一次 barrier 后只能消费同步 payload 一次。Committed reducer 只保留
  /// 有界 projection state；完整 snapshot/backfill bytes 在交给 broadcaster 后立即释放。
  mutating func takeSynchronizedDelivery() -> RelaySynchronizedConversationDelivery {
    let delivery = RelaySynchronizedConversationDelivery(
      snapshot: synchronizedSnapshot,
      events: synchronizedEvents
    )
    synchronizedSnapshot = nil
    synchronizedEvents.removeAll(keepingCapacity: false)
    return delivery
  }

  @discardableResult
  mutating func accept(
    _ delivery: VerifiedRuntimeDelivery
  ) throws -> RelayResumeDeliveryResult {
    guard delivery.machineID == machineID else {
      throw RelaySourceReducerError.emptyMachineID
    }
    guard case .conversation(let targetConversationID, _) = delivery.target,
      targetConversationID == conversationID
    else {
      throw RelaySourceReducerError.conversationMismatch
    }

    if case .typedReply(.subscription(let receipt)) = delivery.payload {
      return try acceptSubscription(receipt, delivery: delivery)
    }

    guard subscriptionSeen, let activeGeneration else {
      throw RelaySourceReducerError.invalidBootstrapOrder
    }
    guard delivery.streamGeneration == activeGeneration else {
      return .staleGeneration
    }

    switch delivery.payload {
    case .conversationSnapshot(let snapshot):
      guard !synchronized, stagedSnapshot == nil, !backfillStarted,
        snapshot.conversationID == conversationID,
        !cursorIsBefore(snapshot.baseEventCursor, requestedCursor)
      else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      let reducer = try ConversationReducer(machineID: machineID, snapshot: snapshot)
      let snapshotBytes = try canonicalBytes(snapshot).count
      guard snapshotBytes <= Self.maximumPublishedBootstrapBytes else {
        throw RelaySourceReducerError.conversationBootstrapCapacity
      }
      stagedReducer = reducer
      stagedSnapshot = snapshot
      publishedBootstrapBytes = snapshotBytes
      return .staged

    case .conversationBackfill(let backfill):
      guard !synchronized, deferredLiveEvents.isEmpty, var reducer = stagedReducer,
        case .conversation(_, _, _, let events) = backfill
      else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      let nextPublishedBytes = try checkedPublishedBootstrapBytes(events)
      _ = try reducer.apply(backfill)
      stagedReducer = reducer
      stagedEvents.append(contentsOf: events)
      publishedBootstrapBytes = nextPublishedBytes
      backfillStarted = true
      return .staged

    case .conversationEvent(let event):
      guard synchronized else {
        guard var reducer = deferredLiveReducer ?? stagedReducer else {
          throw RelaySourceReducerError.invalidBootstrapOrder
        }
        let nextPublishedBytes = try checkedPublishedBootstrapBytes([event])
        _ = try reducer.apply(event)
        deferredLiveReducer = reducer
        deferredLiveEvents.append(event)
        publishedBootstrapBytes = nextPublishedBytes
        return .suppressedUntilBarrier
      }
      guard var reducer = committedReducer else {
        throw RelaySourceReducerError.missingInMemoryBaseline
      }
      let result = try reducer.apply(event)
      committedReducer = reducer
      requestedCursor = reducer.cursor
      return result == .duplicate ? .duplicate : .live

    case .syncComplete(let value):
      guard !synchronized, let stagedReducer else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      guard value.streamGeneration == activeGeneration,
        value.streamCursor == delivery.outerCursor,
        value.keyDirectoryRevision > 0,
        case .conversation(let actualConversationID, let innerCursor) = value.innerCursor,
        actualConversationID == conversationID,
        innerCursor == stagedReducer.cursor
      else {
        throw RelaySourceReducerError.syncCompleteMismatch
      }
      if requestedCursor == .beforeFirst, stagedSnapshot == nil {
        throw RelaySourceReducerError.syncCompleteMismatch
      }

      let committed = deferredLiveReducer ?? stagedReducer
      committedReducer = committed
      requestedCursor = committed.cursor
      synchronizedSnapshot = stagedSnapshot
      synchronizedEvents = stagedEvents + deferredLiveEvents
      self.stagedReducer = nil
      stagedSnapshot = nil
      stagedEvents = []
      deferredLiveEvents = []
      deferredLiveReducer = nil
      publishedBootstrapBytes = 0
      synchronized = true
      return .synchronized

    case .commandState:
      guard synchronized else { return .suppressedUntilBarrier }
      return .live

    case .typedReply:
      throw RelaySourceReducerError.invalidBootstrapOrder

    case .catalogSnapshot, .catalogBackfill, .catalogDelta:
      throw RelaySourceReducerError.wrongBackfillScope
    }
  }

  private mutating func acceptSubscription(
    _ receipt: RuntimeSubscriptionReceiptV1,
    delivery: VerifiedRuntimeDelivery
  ) throws -> RelayResumeDeliveryResult {
    guard !subscriptionSeen, !synchronized else {
      throw RelaySourceReducerError.invalidBootstrapOrder
    }
    guard case .subscribed(let generation) = receipt,
      generation == delivery.streamGeneration
    else {
      throw RelaySourceReducerError.subscriptionMismatch
    }

    activeGeneration = generation
    subscriptionSeen = true
    if requestedCursor == .beforeFirst {
      stagedReducer = nil
    } else {
      guard let committedReducer, committedReducer.cursor == requestedCursor else {
        throw RelaySourceReducerError.missingInMemoryBaseline
      }
      stagedReducer = committedReducer
    }
    return .staged
  }

  private func checkedPublishedBootstrapBytes(
    _ events: [RuntimeEventV2]
  ) throws -> Int {
    let snapshotCount = stagedSnapshot == nil ? 0 : 1
    let (currentEvents, currentOverflow) = stagedEvents.count.addingReportingOverflow(
      deferredLiveEvents.count
    )
    let (nextEvents, nextOverflow) = currentEvents.addingReportingOverflow(events.count)
    guard !currentOverflow, !nextOverflow,
      snapshotCount + nextEvents <= Self.maximumPublishedBootstrapItems
    else {
      throw RelaySourceReducerError.conversationBootstrapCapacity
    }

    var additionalBytes = 0
    for event in events {
      let encoded = try canonicalBytes(event).count
      let (next, overflow) = additionalBytes.addingReportingOverflow(encoded)
      guard !overflow else { throw RelaySourceReducerError.conversationBootstrapCapacity }
      additionalBytes = next
    }
    let (nextBytes, byteOverflow) = publishedBootstrapBytes.addingReportingOverflow(
      additionalBytes
    )
    guard !byteOverflow, nextBytes <= Self.maximumPublishedBootstrapBytes else {
      throw RelaySourceReducerError.conversationBootstrapCapacity
    }
    return nextBytes
  }
}

private func cursorIsBefore(
  _ lhs: RuntimeStreamCursorV1,
  _ rhs: RuntimeStreamCursorV1
) -> Bool {
  switch (lhs, rhs) {
  case (.beforeFirst, .beforeFirst): false
  case (.beforeFirst, .at): true
  case (.at, .beforeFirst): false
  case (.at(let lhs), .at(let rhs)): lhs < rhs
  }
}
