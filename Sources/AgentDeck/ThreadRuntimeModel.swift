import AgentDeckCore
import Foundation
import Observation

enum RuntimeAction: Equatable, Sendable {
  case drainNextPrompt(prompt: String, idempotencyKey: RuntimeIdempotencyKey)
}

private struct QueuedRuntimePrompt: Sendable {
  let prompt: String
  let idempotencyKey: RuntimeIdempotencyKey
}

enum ThreadRuntimeModelError: Error, Equatable, Sendable {
  case catalogConversationMismatch(
    expected: RuntimeConversationID,
    actual: RuntimeConversationID
  )
  case catalogAgentMismatch(expected: AgentKind, actual: AgentKind)
  case catalogEntryRevisionRegressed(current: UInt64, actual: UInt64)
  case catalogEntryRevisionConflict(UInt64)
  case stateAgentMismatch(expected: AgentKind, actual: AgentKind)
  case synchronizationCursorMismatch(
    expected: RuntimeStreamCursorV1,
    actual: RuntimeStreamCursorV1
  )
  case invalidSynchronizationPayloadSequence
  case approvalNoLongerPending(RuntimeApprovalID)
  case approvalBindingMismatch(RuntimeApprovalID)
}

/// UI 使用的 approval presentation，同时保留 daemon 签发的完整 canonical binding。
struct PendingActionRequest: Identifiable, Equatable, Sendable {
  let conversationID: RuntimeConversationID
  let turnID: RuntimeTurnID
  let commandID: RuntimeCommandID
  let approvalID: RuntimeApprovalID
  let requestID: String
  let actionKind: ActionKind
  let summary: String
  let vendor: ActionRequestVendor

  var id: RuntimeApprovalID { approvalID }
  var requestId: String { requestID }

  init(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    commandID: RuntimeCommandID,
    approvalID: RuntimeApprovalID,
    requestID: String,
    actionKind: ActionKind,
    summary: String,
    vendor: ActionRequestVendor
  ) {
    self.conversationID = conversationID
    self.turnID = turnID
    self.commandID = commandID
    self.approvalID = approvalID
    self.requestID = requestID
    self.actionKind = actionKind
    self.summary = summary
    self.vendor = vendor
  }

  fileprivate init(
    conversationID: RuntimeConversationID,
    pending: RuntimeConversationPendingApproval
  ) {
    self.init(
      conversationID: conversationID,
      turnID: pending.turnID,
      commandID: pending.commandID,
      approvalID: pending.approvalID,
      requestID: pending.requestID,
      actionKind: pending.request.kind,
      summary: pending.request.summary,
      vendor: Self.presentationVendor(pending.request.vendor)
    )
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.conversationID == rhs.conversationID
      && lhs.turnID == rhs.turnID
      && lhs.commandID == rhs.commandID
      && lhs.approvalID == rhs.approvalID
      && lhs.requestID == rhs.requestID
      && lhs.actionKind == rhs.actionKind
      && lhs.summary == rhs.summary
      && presentationVendorsExactlyMatch(lhs.vendor, rhs.vendor)
  }

  private static func presentationVendor(
    _ vendor: RuntimeActionRequestVendorV1
  ) -> ActionRequestVendor {
    switch vendor {
    case .codex(let approvalPolicy, let sandbox, let canPersist):
      .codex(
        approvalPolicyAtDecision: approvalPolicy,
        sandboxAtDecision: sandbox,
        canPersist: canPersist
      )
    case .claudeCode(let permissionMode, let toolName):
      .claudeCode(
        permissionModeAtDecision: permissionMode,
        toolName: toolName
      )
    }
  }

  private static func presentationVendorsExactlyMatch(
    _ lhs: ActionRequestVendor,
    _ rhs: ActionRequestVendor
  ) -> Bool {
    switch (lhs, rhs) {
    case (
      .codex(let lhsPolicy, let lhsSandbox, let lhsPersist),
      .codex(let rhsPolicy, let rhsSandbox, let rhsPersist)
    ):
      lhsPolicy == rhsPolicy
        && lhsSandbox == rhsSandbox
        && lhsPersist == rhsPersist
    case (
      .claudeCode(let lhsMode, let lhsTool),
      .claudeCode(let rhsMode, let rhsTool)
    ):
      lhsMode == rhsMode && lhsTool == rhsTool
    default:
      false
    }
  }
}

/// Workbench 交给 `AppRuntimeCoordinator.resolveApproval` 的 exact typed input。
struct RuntimeApprovalDecisionIntent: Sendable {
  let conversationID: RuntimeConversationID
  let turnID: RuntimeTurnID
  let commandID: RuntimeCommandID
  let approvalID: RuntimeApprovalID
  let decision: RuntimeActionDecisionV1
}

/// Coordinator reply sequence 去除 transport terminal 后的 conversation-only payload。
enum RuntimeConversationSynchronizationPayload: Sendable {
  case snapshot(ConversationSnapshotV2)
  case backfill(RuntimeBackfillChunkV2)
}

/// Runtime v2 conversation 的 MainActor presentation adapter。
///
/// `RuntimeConversationState` 唯一拥有 cursor、canonical identity 与 approval ledger；本类型
/// 只缓存 UIItem presentation、catalog metadata 与 UI-only queue/unread/phase。任何 reducer
/// 失败都不会更新 presentation 或时间戳。
@MainActor
@Observable
final class ThreadRuntimeModel {
  private static let largeDeferredContentThreshold = 16 * 1_024

  let conversationID: RuntimeConversationID
  let agentKind: AgentKind
  private(set) var title: String?
  private(set) var cwd: URL?
  private(set) var archived = false
  private(set) var entryRevision: UInt64?
  var phase: SessionModel.Phase
  private(set) var items: [UIItem] = []
  private var queuedPromptEntries: [QueuedRuntimePrompt] = []
  var queuedPrompts: [String] {
    queuedPromptEntries.map(\.prompt)
  }
  private(set) var errorMessage: String?
  var warningMessage: String?
  var unreadEventCount = 0
  let createdAt: Date
  private(set) var updatedAt: Date

  private var conversationState: RuntimeConversationState
  private var itemIndexByID: [String: Int] = [:]
  private var lastCatalogEntry: RuntimeConversationEntryV2?
  private var queuedPromptDispatchInFlight: RuntimeIdempotencyKey?
  private var canonicalErrorMessage: String?
  private var operationErrorMessage: String?

  var cursor: RuntimeStreamCursorV1 { conversationState.cursorState.cursor }
  var runtimeCapabilities: RuntimeSessionCapabilitiesV1? { conversationState.capabilities }
  var configurationState: RuntimeConversationConfigurationStateV2? {
    conversationState.configurationState
  }

  /// 现有 AppKit controls 的 compatibility presentation；SSOT 仍是 runtimeCapabilities。
  var capabilities: SessionCapabilities? {
    runtimeCapabilities.map(Self.presentationCapabilities)
  }

  var claudeCurrentPermissionMode: ClaudeCodePermissionMode? {
    guard
      case .claudeCode(let configuration)? =
        configurationState?.configuration?.vendorControl
    else {
      return nil
    }
    return configuration.permissionMode
  }

  var pendingActionRequests: [PendingActionRequest] {
    conversationState.pendingApprovals.map {
      PendingActionRequest(conversationID: conversationID, pending: $0)
    }
  }

  /// 当前单卡 UI 的兼容入口；ledger 本身可以同时包含多条 approval。
  var pendingActionRequest: PendingActionRequest? { pendingActionRequests.first }

  init(
    conversationID: RuntimeConversationID,
    agentKind: AgentKind,
    cwd: URL?,
    title: String? = nil,
    createdAt: Date = .now,
    initialPhase: SessionModel.Phase = .starting
  ) throws {
    self.conversationID = conversationID
    self.agentKind = agentKind
    self.cwd = cwd
    self.title = title
    phase = initialPhase
    self.createdAt = createdAt
    updatedAt = createdAt
    conversationState = try RuntimeConversationState(conversationID: conversationID)
  }

  convenience init(
    catalogEntry entry: RuntimeConversationEntryV2,
    createdAt: Date? = nil
  ) throws {
    let lastActive = Self.date(millisecondsSinceEpoch: entry.lastActiveMs)
    try self.init(
      conversationID: entry.conversationID,
      agentKind: entry.agentKind,
      cwd: entry.cwd.map { URL(fileURLWithPath: $0) },
      title: entry.title,
      createdAt: createdAt ?? lastActive,
      initialPhase: .ready
    )
    try applyCatalogEntry(entry)
  }

  var displayTitle: String {
    if let title, !title.isEmpty { return title }
    if let project = cwd?.lastPathComponent, !project.isEmpty { return project }
    return conversationID.rawValue
  }

  var statusLabel: String {
    if !queuedPrompts.isEmpty {
      return "\(phase.rawValue) +\(queuedPrompts.count)"
    }
    return phase.rawValue
  }

  func applyCatalogEntry(_ entry: RuntimeConversationEntryV2) throws {
    try validateCatalogEntry(entry)
    if entry.entryRevision == lastCatalogEntry?.entryRevision { return }

    lastCatalogEntry = entry
    title = entry.title
    cwd = entry.cwd.map { URL(fileURLWithPath: $0) }
    archived = entry.archived
    entryRevision = entry.entryRevision
    updatedAt = Self.date(millisecondsSinceEpoch: entry.lastActiveMs)
  }

  /// Catalog reconcile 的纯预验证入口；成功时不得修改 runtime presentation。
  func validateCatalogEntry(_ entry: RuntimeConversationEntryV2) throws {
    guard entry.conversationID == conversationID else {
      throw ThreadRuntimeModelError.catalogConversationMismatch(
        expected: conversationID,
        actual: entry.conversationID
      )
    }
    guard entry.agentKind == agentKind else {
      throw ThreadRuntimeModelError.catalogAgentMismatch(
        expected: agentKind,
        actual: entry.agentKind
      )
    }
    if let current = lastCatalogEntry {
      guard entry.entryRevision >= current.entryRevision else {
        throw ThreadRuntimeModelError.catalogEntryRevisionRegressed(
          current: current.entryRevision,
          actual: entry.entryRevision
        )
      }
      if entry.entryRevision == current.entryRevision {
        guard Self.catalogEntriesExactlyMatch(current, entry) else {
          throw ThreadRuntimeModelError.catalogEntryRevisionConflict(entry.entryRevision)
        }
        return
      }
    }
  }

  /// 完整 snapshot 原子替换 canonical state 与 UI presentation。
  func apply(_ snapshot: ConversationSnapshotV2) throws {
    var nextState = conversationState
    try nextState.apply(snapshot)
    try validateAgentKind(in: nextState)
    let nextItems = Self.presentationItems(from: nextState.items, deferLargeContent: true)

    conversationState = nextState
    items = nextItems
    itemIndexByID = Self.indexByItemID(nextItems)
    setCanonicalError(nextState.failure?.value.message)
    refreshPhase(preservingStarting: true)
    markUpdated()
  }

  /// 完整 backfill 先在值副本归约，成功后一次性替换 presentation。
  func apply(_ backfill: RuntimeBackfillChunkV2) throws {
    var nextState = conversationState
    try nextState.apply(backfill)
    try validateAgentKind(in: nextState)
    let nextItems = Self.presentationItems(from: nextState.items, deferLargeContent: true)

    conversationState = nextState
    items = nextItems
    itemIndexByID = Self.indexByItemID(nextItems)
    setCanonicalError(nextState.failure?.value.message)
    refreshPhase(preservingStarting: true)
    markUpdated()
  }

  /// 一个 Subscribe/Backfill barrier 的全部 payload 必须连同 terminal cursor 原子提交。
  /// 逐条 reply 不得提前污染当前 UI；SyncComplete 本身仍由 coordinator 验证和拥有。
  @discardableResult
  func applySynchronization(
    _ payloads: [RuntimeConversationSynchronizationPayload],
    terminalCursor: RuntimeStreamCursorV1
  ) throws -> RuntimeAction? {
    guard Self.isValidSynchronizationSequence(payloads) else {
      throw ThreadRuntimeModelError.invalidSynchronizationPayloadSequence
    }
    var nextState = conversationState
    for payload in payloads {
      switch payload {
      case .snapshot(let snapshot):
        try nextState.apply(snapshot)
      case .backfill(let backfill):
        try nextState.apply(backfill)
      }
    }
    try validateAgentKind(in: nextState)
    guard nextState.cursorState.cursor == terminalCursor else {
      throw ThreadRuntimeModelError.synchronizationCursorMismatch(
        expected: terminalCursor,
        actual: nextState.cursorState.cursor
      )
    }
    let nextItems = Self.presentationItems(from: nextState.items, deferLargeContent: true)

    conversationState = nextState
    items = nextItems
    itemIndexByID = Self.indexByItemID(nextItems)
    setCanonicalError(nextState.failure?.value.message)
    refreshPhase(preservingStarting: true)
    markUpdated()
    return prepareQueueDispatchIfPossible()
  }

  /// exact-next live event；item event 只替换对应 UI slot，保留其他 slot 已 materialize 的 buffer。
  @discardableResult
  func apply(_ event: RuntimeEventV2) throws -> RuntimeAction? {
    var nextState = conversationState
    try nextState.apply(event)
    try validateAgentKind(in: nextState)

    var nextItems = items
    var nextIndex = itemIndexByID
    if case .item = event.body {
      guard let itemID = event.itemID else {
        preconditionFailure("RuntimeConversationState accepted item event without itemID")
      }
      let canonicalItems = nextState.items
      if let index = nextIndex[itemID.rawValue] {
        guard canonicalItems.indices.contains(index) else {
          preconditionFailure("Thread presentation index drifted from canonical state")
        }
        nextItems[index] = Self.presentationItem(
          canonicalItems[index],
          deferLargeContent: false
        )
      } else {
        guard let canonicalItem = canonicalItems.last,
          canonicalItem.id == itemID.rawValue
        else {
          preconditionFailure("new canonical item was not appended to state")
        }
        nextIndex[itemID.rawValue] = nextItems.count
        nextItems.append(
          Self.presentationItem(canonicalItem, deferLargeContent: false)
        )
      }
    }

    conversationState = nextState
    items = nextItems
    itemIndexByID = nextIndex
    unreadEventCount += 1
    setCanonicalError(nextState.failure?.value.message)
    refreshPhase(preservingStarting: true)
    markUpdated()

    switch event.body {
    case .turnCompleted, .turnInterrupted:
      return prepareQueueDispatchIfPossible()
    default:
      return nil
    }
  }

  func canonicalIdentity(
    for itemID: RuntimeItemID
  ) -> RuntimeCanonicalItemIdentity? {
    conversationState.identity(for: itemID)
  }

  /// Composer 文本先进入 model-owned queue，再尝试派发队首。队首在 daemon command
  /// receipt 成功前始终留在队列中；同一 conversation 同时最多派发一个 queued prompt。
  func enqueuePrompt(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey
  ) -> RuntimeAction? {
    queuedPromptEntries.append(
      QueuedRuntimePrompt(prompt: prompt, idempotencyKey: idempotencyKey)
    )
    return prepareQueueDispatchIfPossible()
  }

  /// 只有 command receipt 成功后才永久移除 exact in-flight 队首。
  func acknowledgeQueuedPrompt(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey
  ) -> RuntimeAction? {
    guard queuedPromptDispatchInFlight == idempotencyKey,
      let first = queuedPromptEntries.first,
      first.prompt == prompt,
      first.idempotencyKey == idempotencyKey
    else {
      return nil
    }
    queuedPromptEntries.removeFirst()
    queuedPromptDispatchInFlight = nil
    markUpdated()
    return prepareQueueDispatchIfPossible()
  }

  /// operation/transport/daemon receipt 失败只释放 dispatch slot，不移除队首。
  @discardableResult
  func failQueuedPromptDispatch(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey
  ) -> Bool {
    guard queuedPromptDispatchInFlight == idempotencyKey,
      queuedPromptEntries.first?.prompt == prompt,
      queuedPromptEntries.first?.idempotencyKey == idempotencyKey
    else {
      return false
    }
    queuedPromptDispatchInFlight = nil
    markUpdated()
    return true
  }

  func recordOperationError(_ message: String) {
    operationErrorMessage = message
    refreshDisplayedError()
  }

  /// 根据 UI 已渲染的 exact approval binding 构造 coordinator input；不修改 canonical ledger。
  func approvalDecisionIntent(
    for expected: PendingActionRequest,
    decision: ActionDecisionKind,
    persist: Bool
  ) throws -> RuntimeApprovalDecisionIntent {
    guard
      let pending = conversationState.pendingApprovals.first(where: {
        $0.approvalID == expected.approvalID
      })
    else {
      throw ThreadRuntimeModelError.approvalNoLongerPending(expected.approvalID)
    }
    let current = PendingActionRequest(conversationID: conversationID, pending: pending)
    guard current == expected else {
      throw ThreadRuntimeModelError.approvalBindingMismatch(expected.approvalID)
    }
    return RuntimeApprovalDecisionIntent(
      conversationID: conversationID,
      turnID: pending.turnID,
      commandID: pending.commandID,
      approvalID: pending.approvalID,
      decision: RuntimeActionDecisionV1(
        requestID: pending.requestID,
        decision: decision,
        persist: persist
      )
    )
  }

  /// UIItem 继续使用 String id，但只允许 canonical RuntimeItemID 对应的 slot。
  @discardableResult
  func materializeDeferredContent(
    itemId: String,
    content: SessionModel.DeferredContent
  ) -> Bool {
    let canonicalID = RuntimeItemID(rawValue: itemId)
    guard conversationState.identity(for: canonicalID) != nil,
      let index = itemIndexByID[itemId],
      items.indices.contains(index)
    else {
      return false
    }

    switch content {
    case .output:
      guard items[index].hasDeferredOutputBuffer else { return false }
      items[index].outputBuffer = Self.detachedBuffer(containing: items[index].output)
      items[index].hasDeferredOutputBuffer = false
    case .diff:
      guard items[index].hasDeferredDiffBuffer else { return false }
      items[index].diffBuffer = Self.detachedBuffer(containing: items[index].diff)
      items[index].hasDeferredDiffBuffer = false
    }
    markUpdated()
    return true
  }

  private func validateAgentKind(in state: RuntimeConversationState) throws {
    guard let actual = state.capabilities?.agentKind else { return }
    guard actual == agentKind else {
      throw ThreadRuntimeModelError.stateAgentMismatch(
        expected: agentKind,
        actual: actual
      )
    }
  }

  private func refreshPhase(preservingStarting: Bool) {
    if conversationState.failure != nil {
      phase = .failed
    } else if !conversationState.pendingApprovals.isEmpty {
      phase = .waitingApproval
    } else if conversationState.activeTurn != nil {
      phase = .running
    } else if conversationState.turnTerminal != nil {
      phase = .ready
    } else if !preservingStarting || phase != .starting {
      phase = .ready
    }
  }

  private func prepareQueueDispatchIfPossible() -> RuntimeAction? {
    guard queuedPromptDispatchInFlight == nil,
      let entry = queuedPromptEntries.first,
      phase == .ready
    else {
      return nil
    }
    queuedPromptDispatchInFlight = entry.idempotencyKey
    operationErrorMessage = nil
    refreshDisplayedError()
    return .drainNextPrompt(
      prompt: entry.prompt,
      idempotencyKey: entry.idempotencyKey
    )
  }

  private func markUpdated() {
    updatedAt = .now
  }

  private func setCanonicalError(_ message: String?) {
    canonicalErrorMessage = message
    refreshDisplayedError()
  }

  private func refreshDisplayedError() {
    errorMessage = canonicalErrorMessage ?? operationErrorMessage
  }

  private static func presentationCapabilities(
    _ value: RuntimeSessionCapabilitiesV1
  ) -> SessionCapabilities {
    let vendor: VendorCapabilities
    switch value.vendor {
    case .codex(let sandboxModes, let persistenceSupported, let reasoningEffortLevels):
      vendor = .codex(
        CodexCapabilities(
          sandboxModes: sandboxModes,
          persistenceSupported: persistenceSupported,
          reasoningEffortLevels: reasoningEffortLevels
        )
      )
    case .claudeCode(let permissionModes, let outputStyles, let hooksSupported, let cliVersion):
      vendor = .claudeCode(
        ClaudeCodeCapabilities(
          permissionModes: permissionModes,
          outputStyles: outputStyles,
          hooksSupported: hooksSupported,
          cliVersion: cliVersion
        )
      )
    }
    return SessionCapabilities(
      agentKind: value.agentKind,
      agentVersion: value.agentVersion,
      features: value.features,
      vendor: vendor
    )
  }

  private static func presentationItems(
    from canonical: [UIItem],
    deferLargeContent: Bool
  ) -> [UIItem] {
    canonical.map { presentationItem($0, deferLargeContent: deferLargeContent) }
  }

  private static func presentationItem(
    _ canonical: UIItem,
    deferLargeContent: Bool
  ) -> UIItem {
    var item = canonical
    item.textBuffer = detachedBuffer(containing: canonical.textBuffer.text)
    item.outputBuffer = detachedBuffer(containing: canonical.outputBuffer.text)
    item.diffBuffer = detachedBuffer(containing: canonical.diffBuffer.text)

    if deferLargeContent,
      item.output.utf8.count > largeDeferredContentThreshold
    {
      item.outputBuffer = StreamingTextBuffer()
      item.hasDeferredOutputBuffer = true
    } else {
      item.hasDeferredOutputBuffer = false
    }
    if deferLargeContent,
      item.diff.utf8.count > largeDeferredContentThreshold
    {
      item.diffBuffer = StreamingTextBuffer()
      item.hasDeferredDiffBuffer = true
    } else {
      item.hasDeferredDiffBuffer = false
    }
    return item
  }

  private static func detachedBuffer(containing text: String) -> StreamingTextBuffer {
    let buffer = StreamingTextBuffer()
    buffer.replace(with: text)
    return buffer
  }

  private static func indexByItemID(_ items: [UIItem]) -> [String: Int] {
    var index: [String: Int] = [:]
    index.reserveCapacity(items.count)
    for (offset, item) in items.enumerated() {
      precondition(index.updateValue(offset, forKey: item.id) == nil)
    }
    return index
  }

  private static func isValidSynchronizationSequence(
    _ payloads: [RuntimeConversationSynchronizationPayload]
  ) -> Bool {
    guard let first = payloads.first else { return true }
    switch first {
    case .snapshot:
      return payloads.dropFirst().allSatisfy { payload in
        if case .backfill = payload { return true }
        return false
      }
    case .backfill:
      return payloads.allSatisfy { payload in
        if case .backfill = payload { return true }
        return false
      }
    }
  }

  private static func catalogEntriesExactlyMatch(
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

  private static func date(millisecondsSinceEpoch value: UInt64) -> Date {
    Date(timeIntervalSince1970: TimeInterval(value) / 1_000)
  }
}
