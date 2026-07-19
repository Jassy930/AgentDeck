import AgentDeckCore
import Foundation
import Observation

enum RuntimeAction: Equatable, Sendable {
  case drainNextPrompt(prompt: String, idempotencyKey: RuntimeIdempotencyKey)
}

private struct PendingRuntimePromptAdmission: Sendable {
  let prompt: String
  let idempotencyKey: RuntimeIdempotencyKey
  let expectedConfigurationRevision: UInt64
}

private struct RetryRequiredRuntimePrompt: Sendable {
  let prompt: String
  let reusableIdempotencyKey: RuntimeIdempotencyKey?
  let reusableExpectedConfigurationRevision: UInt64?
}

private struct AcceptedRuntimePrompt: Sendable {
  let prompt: String
  let commandID: RuntimeCommandID
  let queuePosition: UInt32?
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
  private static let maxPendingPromptAdmissionCount = 1
  private static let maxPendingPromptAdmissionBytes =
    maxPendingPromptAdmissionCount * RuntimePromptPayloadV1.maxUTF8Bytes
  private static let promptPayloadLimitWarning =
    "prompt was not sent: payload exceeds the runtime protocol limit"
  private static let promptAdmissionInFlightWarning =
    "prompt was not sent: another daemon admission is still in flight"

  let conversationID: RuntimeConversationID
  let agentKind: AgentKind
  private(set) var title: String?
  private(set) var cwd: URL?
  private(set) var archived = false
  private(set) var entryRevision: UInt64?
  var phase: SessionModel.Phase
  private(set) var items: [UIItem] = []
  private var pendingPromptAdmissionEntries: [PendingRuntimePromptAdmission] = []
  var pendingPromptAdmissions: [String] {
    pendingPromptAdmissionEntries.map(\.prompt)
  }
  private var retryRequiredPromptAdmission: RetryRequiredRuntimePrompt?
  var retryRequiredPrompt: String? { retryRequiredPromptAdmission?.prompt }
  private var acceptedPromptEntries: [AcceptedRuntimePrompt] = []
  var queuedPrompts: [String] {
    acceptedPromptEntries.map(\.prompt)
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
  private var pendingPromptAdmissionBytes = 0
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
      return "\(phase.rawValue) +\(queuedPrompts.count) queued"
    }
    if !pendingPromptAdmissions.isEmpty {
      return "\(phase.rawValue) \(pendingPromptAdmissions.count) sending"
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
    reconcileAcceptedPrompts(with: nextState)
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
    reconcileAcceptedPrompts(with: nextState)
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
    reconcileAcceptedPrompts(with: nextState)
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
    reconcileAcceptedPrompts(with: nextState)
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

  /// Composer 文本只在等待 daemon admission receipt 期间留在有界本地 FIFO；它不是 daemon
  /// 已接受的 canonical queue。首条立即派发，后续 admission 串行化，避免并发 request 反转
  /// daemon commandSeq。count/bytes 任一满载时明确拒绝新文本，不做无界非持久排队。
  func enqueuePrompt(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64? = nil
  ) -> RuntimeAction? {
    let promptBytes = prompt.utf8.count
    guard promptBytes <= RuntimePromptPayloadV1.maxUTF8Bytes else {
      warningMessage = Self.promptPayloadLimitWarning
      return nil
    }
    guard pendingPromptAdmissionEntries.count < Self.maxPendingPromptAdmissionCount,
      pendingPromptAdmissionBytes <= Self.maxPendingPromptAdmissionBytes - promptBytes
    else {
      warningMessage = Self.promptAdmissionInFlightWarning
      return nil
    }
    let entry: PendingRuntimePromptAdmission
    if let retryRequiredPromptAdmission,
      Self.promptBytesEqual(retryRequiredPromptAdmission.prompt, prompt),
      let reusableIdempotencyKey = retryRequiredPromptAdmission.reusableIdempotencyKey,
      let reusableExpectedConfigurationRevision =
        retryRequiredPromptAdmission.reusableExpectedConfigurationRevision
    {
      entry = PendingRuntimePromptAdmission(
        prompt: retryRequiredPromptAdmission.prompt,
        idempotencyKey: reusableIdempotencyKey,
        expectedConfigurationRevision: reusableExpectedConfigurationRevision
      )
    } else {
      entry = PendingRuntimePromptAdmission(
        prompt: prompt,
        idempotencyKey: idempotencyKey,
        expectedConfigurationRevision: expectedConfigurationRevision
          ?? configurationState?.configurationRevision
          ?? 0
      )
    }
    retryRequiredPromptAdmission = nil
    pendingPromptAdmissionEntries.append(
      entry
    )
    pendingPromptAdmissionBytes += promptBytes
    if warningMessage == Self.promptPayloadLimitWarning
      || warningMessage == Self.promptAdmissionInFlightWarning
    {
      warningMessage = nil
    }
    return prepareQueueDispatchIfPossible()
  }

  /// 只有 command receipt 成功后才永久移除 exact in-flight 队首。
  func acknowledgeQueuedPrompt(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey,
    receipt: CommandReceiptV2
  ) -> RuntimeAction? {
    guard queuedPromptDispatchInFlight == idempotencyKey,
      let first = pendingPromptAdmissionEntries.first,
      first.prompt == prompt,
      first.idempotencyKey == idempotencyKey
    else {
      return nil
    }
    let accepted: AcceptedRuntimePrompt?
    switch receipt {
    case .accepted(let commandID, let queuePosition, _):
      accepted = AcceptedRuntimePrompt(
        prompt: prompt,
        commandID: commandID,
        queuePosition: queuePosition
      )
    case .replayed(let commandID, _):
      accepted = AcceptedRuntimePrompt(
        prompt: prompt,
        commandID: commandID,
        queuePosition: nil
      )
    case .failed:
      return nil
    }
    pendingPromptAdmissionEntries.removeFirst()
    pendingPromptAdmissionBytes -= first.prompt.utf8.count
    queuedPromptDispatchInFlight = nil
    let hasCanonicalEvidence =
      accepted.map {
        self.hasCanonicalEvidence(for: $0.commandID, in: conversationState)
      } ?? false
    if let accepted, !hasCanonicalEvidence {
      acceptedPromptEntries.removeAll { $0.commandID == accepted.commandID }
      acceptedPromptEntries.append(accepted)
    }
    if case .replayed = receipt, hasCanonicalEvidence, phase == .starting {
      refreshPhase(preservingStarting: false)
    }
    markUpdated()
    return prepareQueueDispatchIfPossible()
  }

  /// operation/transport/daemon receipt 失败会退出 sending，并只保留一个显式 retry draft。
  /// 后续相同文本 submit 才复用原 key；不同文本是新意图并替换旧 retry draft。
  @discardableResult
  func failQueuedPromptDispatch(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey,
    reuseIdempotencyKey: Bool = true
  ) -> Bool {
    guard queuedPromptDispatchInFlight == idempotencyKey,
      pendingPromptAdmissionEntries.first?.prompt == prompt,
      pendingPromptAdmissionEntries.first?.idempotencyKey == idempotencyKey
    else {
      return false
    }
    let failed = pendingPromptAdmissionEntries.removeFirst()
    pendingPromptAdmissionBytes -= failed.prompt.utf8.count
    queuedPromptDispatchInFlight = nil
    retryRequiredPromptAdmission = RetryRequiredRuntimePrompt(
      prompt: failed.prompt,
      reusableIdempotencyKey: reuseIdempotencyKey ? failed.idempotencyKey : nil,
      reusableExpectedConfigurationRevision: reuseIdempotencyKey
        ? failed.expectedConfigurationRevision
        : nil
    )
    markUpdated()
    return true
  }

  /// 新 conversation 的 Start/Configure/Subscribe 由 coordinator 组合执行，因此没有本地 pending
  /// entry 可供 `acknowledgeQueuedPrompt` 消费。最终 prompt receipt 到达后仍必须投影成与已有
  /// conversation 相同的 queued/canonical replacement 语义。
  func projectBootstrapPromptReceipt(
    _ prompt: String,
    receipt: CommandReceiptV2
  ) {
    let accepted: AcceptedRuntimePrompt
    switch receipt {
    case .accepted(let commandID, let queuePosition, _):
      accepted = AcceptedRuntimePrompt(
        prompt: prompt,
        commandID: commandID,
        queuePosition: queuePosition
      )
    case .replayed(let commandID, _):
      accepted = AcceptedRuntimePrompt(
        prompt: prompt,
        commandID: commandID,
        queuePosition: nil
      )
    case .failed:
      return
    }
    let hasCanonicalEvidence = hasCanonicalEvidence(
      for: accepted.commandID,
      in: conversationState
    )
    if hasCanonicalEvidence {
      if case .replayed = receipt, phase == .starting {
        refreshPhase(preservingStarting: false)
      }
    } else {
      acceptedPromptEntries.removeAll { $0.commandID == accepted.commandID }
      acceptedPromptEntries.append(accepted)
    }
    markUpdated()
  }

  func retainBootstrapPromptForRetry(
    _ prompt: String,
    reusableIdempotencyKey: RuntimeIdempotencyKey?,
    reusableExpectedConfigurationRevision: UInt64?
  ) {
    retryRequiredPromptAdmission = RetryRequiredRuntimePrompt(
      prompt: prompt,
      reusableIdempotencyKey: reusableIdempotencyKey,
      reusableExpectedConfigurationRevision: reusableExpectedConfigurationRevision
    )
    markUpdated()
  }

  func expectedConfigurationRevision(
    for idempotencyKey: RuntimeIdempotencyKey
  ) -> UInt64? {
    pendingPromptAdmissionEntries.first {
      $0.idempotencyKey == idempotencyKey
    }?.expectedConfigurationRevision
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
      let entry = pendingPromptAdmissionEntries.first
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

  private func reconcileAcceptedPrompts(with state: RuntimeConversationState) {
    acceptedPromptEntries.removeAll { hasCanonicalEvidence(for: $0.commandID, in: state) }
  }

  private func hasCanonicalEvidence(
    for commandID: RuntimeCommandID,
    in state: RuntimeConversationState
  ) -> Bool {
    if state.canonicalItemIdentities.contains(where: { $0.commandID == commandID }) {
      return true
    }
    if state.activeTurn?.commandID == commandID || state.failure?.commandID == commandID {
      return true
    }
    switch state.turnTerminal {
    case .completed(_, let terminalCommandID, _),
      .interrupted(_, let terminalCommandID):
      return terminalCommandID == commandID
    case nil:
      return false
    }
  }

  private static func promptBytesEqual(_ lhs: String, _ rhs: String) -> Bool {
    lhs.utf8.elementsEqual(rhs.utf8)
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
