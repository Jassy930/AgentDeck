import AgentDeckCore
import Foundation
import Observation

enum WorkbenchModelError: Error, Equatable, Sendable {
  case unknownConversation(RuntimeConversationID)
  case catalogUnavailable
  case synchronizationAlreadyInProgress
  case unexpectedSynchronizedReply
  case synchronizationTargetConflict
  case synchronizationGenerationMismatch(
    expected: RuntimeStreamGeneration,
    actual: RuntimeStreamGeneration
  )
  case synchronizationCursorMismatch(
    expected: RuntimeStreamCursorV1,
    actual: RuntimeStreamCursorV1
  )
  case liveStreamDuringSynchronization
  case unexpectedTransferPart
  case conversationContextUnavailable(RuntimeConversationID)
  case draftAlreadyInFlight
  case draftContextMissing
  case draftConversationMismatch(
    expected: RuntimeConversationID,
    actual: RuntimeConversationID
  )
  case draftConversationNotSynchronized(RuntimeConversationID)
}

enum WorkbenchRuntimeAction: Equatable, Sendable {
  case drainNextPrompt(
    conversationID: RuntimeConversationID,
    prompt: String,
    idempotencyKey: RuntimeIdempotencyKey
  )
}

struct WorkbenchConversationDraftContext: Sendable {
  let agentKind: AgentKind
  let cwd: URL
  let createdAt: Date
  let startIdempotencyKey: RuntimeIdempotencyKey
  fileprivate(set) var conversationID: RuntimeConversationID?
}

/// Runtime v2 App model 的 typed registry 与 MainActor ingress owner。
///
/// Canonical cursor/items/approval ledger 始终由每个 `ThreadRuntimeModel` 内的
/// `RuntimeConversationState` 持有；Workbench 只负责 typed selection、catalog、同步 barrier
/// staging 与跨 conversation 路由。同步 payload 在 SyncComplete 前绝不写入 presentation。
@MainActor
@Observable
final class WorkbenchModel {
  private(set) var runtimes: [RuntimeConversationID: ThreadRuntimeModel] = [:]
  private(set) var selectedConversationID: RuntimeConversationID?
  private(set) var catalog: RuntimeCatalogModel?
  private(set) var inFlightDraftContext: WorkbenchConversationDraftContext?

  private var pendingSynchronization: PendingSynchronization?

  var selectedRuntime: ThreadRuntimeModel? {
    guard let selectedConversationID else { return nil }
    return runtimes[selectedConversationID]
  }

  var runtimeList: [ThreadRuntimeModel] {
    runtimes.values.sorted { lhs, rhs in
      let lhsSelected = lhs.conversationID == selectedConversationID
      let rhsSelected = rhs.conversationID == selectedConversationID
      if lhsSelected != rhsSelected { return lhsSelected }
      if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt > rhs.updatedAt }
      return lhs.conversationID.rawValue < rhs.conversationID.rawValue
    }
  }

  var catalogEntries: [RuntimeConversationEntryV2] {
    catalog?.entries ?? []
  }

  var catalogCursor: RuntimeStreamCursorV1? {
    catalog?.cursor
  }

  func runtime(
    conversationID: RuntimeConversationID
  ) -> ThreadRuntimeModel? {
    runtimes[conversationID]
  }

  func catalogEntry(
    conversationID: RuntimeConversationID
  ) -> RuntimeConversationEntryV2? {
    catalog?.entries.first { $0.conversationID == conversationID }
  }

  func selectConversation(_ conversationID: RuntimeConversationID) throws {
    guard let runtime = runtimes[conversationID] else {
      throw WorkbenchModelError.unknownConversation(conversationID)
    }
    selectedConversationID = conversationID
    runtime.unreadEventCount = 0
  }

  func clearSelection() {
    selectedConversationID = nil
  }

  /// 初始 catalog pagination 必须完整收齐后才替换；canonical catalog model 先验证全部页。
  func installCatalog(snapshotPages: [RuntimeCatalogSnapshotV2]) throws {
    let nextCatalog = try RuntimeCatalogModel(snapshotPages: snapshotPages)
    try reconcileCatalogPresentation(nextCatalog)
    catalog = nextCatalog
  }

  /// 新 conversation ID 尚未知时只保存 presentation context，不创建 provisional runtime。
  func beginConversationStart(
    _ draft: RuntimeConversationDraft,
    createdAt: Date = .now
  ) throws {
    guard inFlightDraftContext == nil else {
      throw WorkbenchModelError.draftAlreadyInFlight
    }
    inFlightDraftContext = WorkbenchConversationDraftContext(
      agentKind: draft.agentKind,
      cwd: URL(fileURLWithPath: draft.cwd),
      createdAt: createdAt,
      startIdempotencyKey: draft.idempotencyKeys.start,
      conversationID: nil
    )
  }

  /// Coordinator 在 synchronized replies 已发布后返回最终 start result；这里只校验同一
  /// canonical ID、完成选择，并清理短暂 draft context。
  func completeConversationStart(
    _ result: AppRuntimeConversationStartResult
  ) throws {
    guard let context = inFlightDraftContext else {
      throw WorkbenchModelError.draftContextMissing
    }
    if let inferred = context.conversationID, inferred != result.conversationID {
      throw WorkbenchModelError.draftConversationMismatch(
        expected: inferred,
        actual: result.conversationID
      )
    }
    guard let runtime = runtimes[result.conversationID] else {
      throw WorkbenchModelError.draftConversationNotSynchronized(result.conversationID)
    }
    guard
      case .conversation(let terminalID, let terminalCursor) =
        result.synchronization.terminal.innerCursor,
      terminalID == result.conversationID,
      Self.cursor(runtime.cursor, isAtOrAfter: terminalCursor)
    else {
      throw WorkbenchModelError.draftConversationNotSynchronized(result.conversationID)
    }

    if result.promptReceipt == nil, runtime.phase == .starting {
      runtime.phase = .ready
    }
    inFlightDraftContext = nil
    selectedConversationID = result.conversationID
    runtime.unreadEventCount = 0
  }

  /// Start request 失败时只丢弃临时 context；已经由 daemon 同步出的 canonical runtime 不删除。
  func cancelConversationStart() {
    inFlightDraftContext = nil
  }

  /// 连接换代时丢弃旧 wire 尚未到达 SyncComplete 的纯 staging；canonical model 未被修改。
  func cancelPendingSynchronization() {
    pendingSynchronization = nil
  }

  /// Coordinator 的唯一 MainActor handler。返回的 drain action 仍携 exact conversation ID，
  /// 上层不得在 selection 变化后重新推断目标。
  @discardableResult
  func ingest(_ inbound: AppRuntimeInbound) throws -> WorkbenchRuntimeAction? {
    switch inbound {
    case .synchronizedReply(let reply):
      do {
        return try ingestSynchronizedReply(reply)
      } catch {
        pendingSynchronization = nil
        throw error
      }
    case .stream(let frame):
      guard pendingSynchronization == nil else {
        throw WorkbenchModelError.liveStreamDuringSynchronization
      }
      return try ingestLive(frame)
    }
  }

  /// Approval card 创建时捕获的五元 canonical binding 是唯一目标；selection 不参与路由，
  /// pending ledger 也不会在 receipt/event 前被乐观删除。
  func approvalDecisionIntent(
    for pending: PendingActionRequest,
    decision: ActionDecisionKind,
    persist: Bool
  ) throws -> RuntimeApprovalDecisionIntent {
    guard let runtime = runtimes[pending.conversationID] else {
      throw WorkbenchModelError.unknownConversation(pending.conversationID)
    }
    return try runtime.approvalDecisionIntent(
      for: pending,
      decision: decision,
      persist: persist
    )
  }

  private func ingestSynchronizedReply(
    _ reply: RuntimeReplyV2
  ) throws -> WorkbenchRuntimeAction? {
    var stage = pendingSynchronization ?? PendingSynchronization()
    switch reply {
    case .subscription(.subscribed(let generation)):
      guard stage.subscriptionGeneration == nil,
        stage.target == nil,
        stage.conversationPayloads.isEmpty,
        stage.catalogBackfills.isEmpty
      else {
        throw WorkbenchModelError.synchronizationAlreadyInProgress
      }
      stage.subscriptionGeneration = generation
      pendingSynchronization = stage
      return nil
    case .subscription(.unsubscribed):
      throw WorkbenchModelError.unexpectedSynchronizedReply
    case .snapshot(let snapshot):
      try stage.bind(.conversation(snapshot.conversationID))
      stage.conversationPayloads.append(.snapshot(snapshot))
      pendingSynchronization = stage
      return nil
    case .backfill(let backfill):
      switch backfill {
      case .catalog:
        try stage.bind(.catalog)
        stage.catalogBackfills.append(backfill)
      case .conversation(let conversationID, _, _, _):
        try stage.bind(.conversation(conversationID))
        stage.conversationPayloads.append(.backfill(backfill))
      }
      pendingSynchronization = stage
      return nil
    case .syncComplete(let terminal):
      if let subscribed = stage.subscriptionGeneration,
        subscribed != terminal.streamGeneration
      {
        throw WorkbenchModelError.synchronizationGenerationMismatch(
          expected: subscribed,
          actual: terminal.streamGeneration
        )
      }
      switch terminal.innerCursor {
      case .catalog(let cursor):
        try stage.bind(.catalog)
        try commitCatalogSynchronization(stage, terminalCursor: cursor)
        pendingSynchronization = nil
        return nil
      case .conversation(let conversationID, let cursor):
        try stage.bind(.conversation(conversationID))
        let action = try commitConversationSynchronization(
          stage,
          conversationID: conversationID,
          terminalCursor: cursor
        )
        pendingSynchronization = nil
        return action
      }
    default:
      throw WorkbenchModelError.unexpectedSynchronizedReply
    }
  }

  private func commitConversationSynchronization(
    _ stage: PendingSynchronization,
    conversationID: RuntimeConversationID,
    terminalCursor: RuntimeStreamCursorV1
  ) throws -> WorkbenchRuntimeAction? {
    let existing = runtimes[conversationID]
    let candidate: ThreadRuntimeModel
    var inferredDraft: WorkbenchConversationDraftContext?

    if let existing {
      candidate = existing
    } else if let entry = catalogEntry(conversationID: conversationID) {
      candidate = try ThreadRuntimeModel(catalogEntry: entry)
    } else if var context = inFlightDraftContext {
      if let inferred = context.conversationID, inferred != conversationID {
        throw WorkbenchModelError.draftConversationMismatch(
          expected: inferred,
          actual: conversationID
        )
      }
      context.conversationID = conversationID
      inferredDraft = context
      candidate = try ThreadRuntimeModel(
        conversationID: conversationID,
        agentKind: context.agentKind,
        cwd: context.cwd,
        createdAt: context.createdAt,
        initialPhase: .starting
      )
    } else {
      throw WorkbenchModelError.conversationContextUnavailable(conversationID)
    }

    let runtimeAction = try candidate.applySynchronization(
      stage.conversationPayloads,
      terminalCursor: terminalCursor
    )
    if existing == nil { runtimes[conversationID] = candidate }
    if let inferredDraft { inFlightDraftContext = inferredDraft }
    switch runtimeAction {
    case .drainNextPrompt(let prompt, let idempotencyKey):
      return .drainNextPrompt(
        conversationID: conversationID,
        prompt: prompt,
        idempotencyKey: idempotencyKey
      )
    case nil:
      return nil
    }
  }

  private func commitCatalogSynchronization(
    _ stage: PendingSynchronization,
    terminalCursor: RuntimeStreamCursorV1
  ) throws {
    guard var nextCatalog = catalog else {
      throw WorkbenchModelError.catalogUnavailable
    }
    for backfill in stage.catalogBackfills {
      guard case .catalog(let range, let deltas) = backfill else {
        throw WorkbenchModelError.synchronizationTargetConflict
      }
      guard range.after == nextCatalog.cursor else {
        throw WorkbenchModelError.synchronizationCursorMismatch(
          expected: nextCatalog.cursor,
          actual: range.after
        )
      }
      for delta in deltas {
        nextCatalog = try nextCatalog.reducing(delta)
      }
      guard nextCatalog.cursor == range.through else {
        throw WorkbenchModelError.synchronizationCursorMismatch(
          expected: range.through,
          actual: nextCatalog.cursor
        )
      }
    }
    guard nextCatalog.cursor == terminalCursor else {
      throw WorkbenchModelError.synchronizationCursorMismatch(
        expected: terminalCursor,
        actual: nextCatalog.cursor
      )
    }
    try reconcileCatalogPresentation(nextCatalog)
    catalog = nextCatalog
  }

  private func ingestLive(
    _ frame: LocalRuntimeStreamFrame
  ) throws -> WorkbenchRuntimeAction? {
    switch frame.item {
    case .event(let event):
      guard let runtime = runtimes[event.conversationID] else {
        throw WorkbenchModelError.unknownConversation(event.conversationID)
      }
      let action = try runtime.apply(event)
      if selectedConversationID == event.conversationID {
        runtime.unreadEventCount = 0
      }
      switch action {
      case .drainNextPrompt(let prompt, let idempotencyKey):
        return .drainNextPrompt(
          conversationID: event.conversationID,
          prompt: prompt,
          idempotencyKey: idempotencyKey
        )
      case nil:
        return nil
      }
    case .catalogDelta(let delta):
      guard let catalog else {
        throw WorkbenchModelError.catalogUnavailable
      }
      let nextCatalog = try catalog.reducing(delta)
      try reconcileCatalogPresentation(nextCatalog)
      self.catalog = nextCatalog
      return nil
    case .transferPart:
      throw WorkbenchModelError.unexpectedTransferPart
    }
  }

  private func reconcileCatalogPresentation(
    _ model: RuntimeCatalogModel
  ) throws {
    let entries = model.entries
    let activeConversationIDs = Set(entries.map(\.conversationID))
    // Catalog Removed 淘汰已由 catalog 认证过的 presentation；尚未收到首次
    // Catalog Upsert 的 canonical draft runtime 以 nil entryRevision 明确保留。
    let removedConversationIDs = runtimes.compactMap { element -> RuntimeConversationID? in
      let (conversationID, runtime) = element
      guard runtime.entryRevision != nil,
        !activeConversationIDs.contains(conversationID)
      else {
        return nil
      }
      return conversationID
    }
    for entry in entries {
      try runtimes[entry.conversationID]?.validateCatalogEntry(entry)
    }

    var additions: [RuntimeConversationID: ThreadRuntimeModel] = [:]
    for entry in entries where runtimes[entry.conversationID] == nil {
      additions[entry.conversationID] = try ThreadRuntimeModel(catalogEntry: entry)
    }

    for entry in entries {
      if let existing = runtimes[entry.conversationID] {
        try existing.applyCatalogEntry(entry)
      } else if additions[entry.conversationID] == nil {
        // Runtime registry 只在 MainActor 上修改；这里的分支代表内部原子 reconcile 漂移。
        preconditionFailure("catalog addition disappeared before commit")
      }
    }
    for (conversationID, runtime) in additions {
      runtimes[conversationID] = runtime
    }
    for conversationID in removedConversationIDs {
      runtimes.removeValue(forKey: conversationID)
      if selectedConversationID == conversationID {
        selectedConversationID = nil
      }
    }
  }

  /// `SyncComplete` 之后 daemon 可立即发布这个新 conversation 的 live event；因此
  /// `completeConversationStart` 读回时 runtime cursor 可以已经越过同步 terminal，
  /// 但绝不能落后。cursor 的单调与 exact-next 仍由 canonical reducer 保证。
  private static func cursor(
    _ actual: RuntimeStreamCursorV1,
    isAtOrAfter expected: RuntimeStreamCursorV1
  ) -> Bool {
    switch (actual, expected) {
    case (_, .beforeFirst):
      true
    case (.beforeFirst, .at):
      false
    case (.at(let actualValue), .at(let expectedValue)):
      actualValue >= expectedValue
    }
  }
}

private struct PendingSynchronization {
  fileprivate enum Target: Equatable {
    case catalog
    case conversation(RuntimeConversationID)
  }

  var subscriptionGeneration: RuntimeStreamGeneration?
  var target: Target?
  var conversationPayloads: [RuntimeConversationSynchronizationPayload] = []
  var catalogBackfills: [RuntimeBackfillChunkV2] = []

  mutating func bind(_ target: Target) throws {
    if let current = self.target, current != target {
      throw WorkbenchModelError.synchronizationTargetConflict
    }
    self.target = target
  }
}
