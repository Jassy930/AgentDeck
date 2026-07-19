import AgentDeckCore
import Foundation
import Observation

struct HistoryOpenTiming: Equatable {
  let conversationID: RuntimeConversationID
  let itemCount: Int
  let readMilliseconds: Int
  let applyMilliseconds: Int
  let totalMilliseconds: Int
}

enum SessionRuntimeModelError: Error, Equatable, CustomStringConvertible {
  case agentDescriptionUnavailable(AgentKind)
  case conversationUnavailable(RuntimeConversationID)
  case conversationNotConfigured(RuntimeConversationID)
  case configurationAgentMismatch
  case catalogEntryUnavailable(String)
  case metadataConflict(RuntimeConversationID, currentRevision: UInt64)

  var description: String {
    switch self {
    case .agentDescriptionUnavailable(let kind):
      "daemon did not describe \(kind.rawValue)"
    case .conversationUnavailable(let id):
      "conversation is unavailable: \(id.rawValue)"
    case .conversationNotConfigured(let id):
      "conversation is not configured: \(id.rawValue)"
    case .configurationAgentMismatch:
      "control mutation does not match the conversation agent"
    case .catalogEntryUnavailable(let value):
      "catalog entry is unavailable: \(value)"
    case .metadataConflict(let id, let revision):
      "catalog metadata conflict for \(id.rawValue) at revision \(revision)"
    }
  }
}

/// Runtime v2 App session model。Production 只持有 AppRuntimeCoordinator；不持有、
/// 不创建、也不关闭 legacy DaemonClient。所有 catalog/history/prompt/approval/config/
/// metadata 操作都经 shared-daemon RuntimeEnvelope wire。
@MainActor
@Observable
final class SessionModel {
  enum Phase: String {
    case idle, starting, ready, running, waitingApproval, draining, failed, closed
  }

  enum DeferredContent {
    case output
    case diff
  }

  var cwd: URL?
  var phase: Phase = .idle {
    didSet {
      switch phase {
      case .starting, .running:
        if oldValue != .starting && oldValue != .running { runStartedAt = .now }
      case .ready, .failed, .closed, .idle:
        runStartedAt = nil
      case .waitingApproval, .draining:
        break
      }
      tickIfNeeded()
    }
  }

  private(set) var items: [UIItem] = []
  var errorMessage: String?
  var warningMessage: String?
  var runStartedAt: Date?
  var tickNow: Date = .now

  private(set) var historyThreads: [HistoryThreadSummary] = []
  var historyGroups: [HistoryProjectGroup] { HistoryProjectGroup.group(historyThreads) }
  var historyErrorMessage: String?
  var isLoadingHistory = false
  var openingHistoryConversationID: RuntimeConversationID?
  var lastHistoryOpenTiming: HistoryOpenTiming?
  var historySearchTerm = ""
  var environmentInfo: EnvironmentInfo?
  var selectedHistoryConversationID: RuntimeConversationID?
  var conversationViewportIdentity = "conversation:0"
  var scrollToLatestRequest = 0

  let workbench: WorkbenchModel

  private let coordinator: AppRuntimeCoordinator
  private let inboundBridge: SessionRuntimeInboundBridge
  private var runtimeBootstrapTask: Task<RuntimeAgentDescriptionsV2, Error>?
  private var runtimeBootstrapTaskID: UInt64?
  private var nextRuntimeBootstrapTaskID: UInt64 = 0
  private var runtimeCoordinatorStarted = false
  private(set) var retryableConversationDraft: RuntimeConversationDraft?
  private var didRequestInitialHistoryRefresh = false
  private var historyCurrentProjectOnly = false
  private var catalogSubscribed = false
  private var canonicalTerminalCommandIDs: [RuntimeConversationID: RuntimeCommandID] = [:]
  private var conversationViewportRevision = 0
  private var tickTimer: Timer?
  private var isTornDown = false

  init(runtimeWire: any AppRuntimeWireSession = OSAccountRuntimeWireSession()) {
    let workbench = WorkbenchModel()
    let bridge = SessionRuntimeInboundBridge(workbench: workbench)
    self.workbench = workbench
    inboundBridge = bridge
    coordinator = AppRuntimeCoordinator(wire: runtimeWire) { inbound in
      try await bridge.ingest(inbound)
    }
    bridge.model = self
  }

  var shouldShowReasoningExpanded: Bool {
    selectedPhase == .running || selectedPhase == .starting
  }

  var selectedErrorMessage: String? {
    workbench.selectedRuntime?.errorMessage ?? errorMessage
  }

  var selectedWarningMessage: String? {
    workbench.selectedRuntime?.warningMessage ?? warningMessage
  }

  var selectedActionRequest: PendingActionRequest? {
    workbench.selectedRuntime?.pendingActionRequest
  }

  var queuedPrompts: [String] {
    workbench.selectedRuntime?.queuedPrompts ?? []
  }

  var selectedSidebarConversationID: String? {
    selectedHistoryConversationID?.rawValue ?? workbench.selectedConversationID?.rawValue
  }

  var selectedItems: [UIItem] {
    workbench.selectedRuntime?.items ?? items
  }

  var selectedPhase: Phase {
    workbench.selectedRuntime?.phase ?? phase
  }

  var elapsedSeconds: Int? {
    guard let runStartedAt else { return nil }
    return max(0, Int(tickNow.timeIntervalSince(runStartedAt)))
  }

  var statusText: String {
    let base: String
    switch selectedPhase {
    case .idle: base = "Ready"
    case .starting: base = "Starting…"
    case .ready: base = "Ready"
    case .running: base = "Working…"
    case .waitingApproval: base = "Waiting for your approval"
    case .draining: base = "Finishing up…"
    case .failed: base = "Failed"
    case .closed: base = "Closed"
    }
    if workbench.selectedRuntime == nil,
      let elapsedSeconds,
      phase == .running || phase == .starting
    {
      return "\(base)  \(elapsedSeconds)s"
    }
    return base
  }

  var historyTimingSummary: String {
    guard let timing = lastHistoryOpenTiming else { return "" }
    return
      "history read \(timing.readMilliseconds)ms · apply \(timing.applyMilliseconds)ms · \(timing.itemCount) items"
  }

  func tickIfNeeded() {
    let needsTick = phase == .running || phase == .starting
    if needsTick && tickTimer == nil {
      tickTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
        Task { @MainActor in self?.tickNow = .now }
      }
    } else if !needsTick {
      tickTimer?.invalidate()
      tickTimer = nil
    }
  }

  func chooseCwd(_ url: URL) -> String? {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
      isDirectory.boolValue
    else {
      return "Not a directory: \(url.path)"
    }
    guard FileManager.default.isReadableFile(atPath: url.path) else {
      return "Directory is not readable: \(url.path)"
    }
    cwd = url
    return nil
  }

  /// Input bar：已有 canonical conversation 时发送 prompt；未选择时使用 daemon 描述的
  /// adapter default configuration 创建 Runtime draft。绝不创建 provisional identity。
  func submit(_ prompt: String, agentKind: AgentKind = .codex) {
    guard !isTornDown else { return }
    let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return }
    do {
      _ = try RuntimePromptPayloadV1(rawValue: trimmed)
    } catch {
      recordOperationFailure(
        error,
        conversationID: workbench.selectedRuntime?.conversationID
      )
      return
    }

    if let runtime = workbench.selectedRuntime {
      switch runtime.phase {
      case .idle, .ready:
        dispatch(
          runtime.enqueuePrompt(
            trimmed,
            idempotencyKey: Self.freshIdempotencyKey(prefix: "prompt")
          ),
          runtime: runtime
        )
      case .starting, .running, .waitingApproval, .draining:
        _ = runtime.enqueuePrompt(
          trimmed,
          idempotencyKey: Self.freshIdempotencyKey(prefix: "prompt")
        )
      case .failed, .closed:
        runtime.warningMessage = "conversation is not ready for a prompt"
      }
      return
    }

    guard let cwd else {
      warningMessage = "Choose a project directory before starting a conversation"
      return
    }
    Task { [weak self] in
      guard let self else { return }
      do {
        let descriptions = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        guard descriptions.agents.contains(where: { $0.agentKind == agentKind }) else {
          throw SessionRuntimeModelError.agentDescriptionUnavailable(agentKind)
        }
        let draft = try RuntimeConversationDraft(
          agentKind: agentKind,
          cwd: cwd.path,
          prompt: trimmed,
          agentDescriptions: descriptions
        )
        startConversation(draft)
      } catch {
        recordOperationFailure(error)
      }
    }
  }

  func startConversation(_ requestedDraft: RuntimeConversationDraft) {
    guard !isTornDown else { return }
    let draft: RuntimeConversationDraft
    if let retained = retryableConversationDraft {
      guard Self.draftsHaveSameIntent(retained, requestedDraft) else {
        warningMessage =
          "Previous conversation start has an unknown outcome; retry or resolve it before starting a different conversation"
        return
      }
      draft = retained
    } else {
      draft = requestedDraft
    }

    do {
      try workbench.beginConversationStart(draft)
    } catch WorkbenchModelError.draftAlreadyInFlight {
      warningMessage = "A conversation start is already in progress"
      return
    } catch {
      recordOperationFailure(error)
      return
    }

    selectedHistoryConversationID = nil
    phase = .starting
    errorMessage = nil
    warningMessage = nil
    Task { [weak self] in
      guard let self else { return }
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        let result = try await coordinator.startConversation(draft)
        guard !isTornDown else { return }
        try workbench.completeConversationStart(result)
        errorMessage = nil
        warningMessage = nil
        if retryableConversationDraft?.idempotencyKeys == draft.idempotencyKeys {
          retryableConversationDraft = nil
        }
        cwd = URL(fileURLWithPath: draft.cwd)
        phase = workbench.selectedRuntime?.phase ?? .ready
        refreshHistoryPresentation()
        resetConversationViewport(prefix: "conversation:\(result.conversationID.rawValue)")
      } catch {
        guard !isTornDown else { return }
        workbench.cancelConversationStart()
        retryableConversationDraft = draft
        recordOperationFailure(error)
      }
    }
  }

  /// 显式重试 outcome-unknown start；复用完整 draft 与三把原始 idempotency keys。
  func retryConversationStart() {
    guard !isTornDown else { return }
    guard let retryableConversationDraft else {
      warningMessage = "There is no conversation start awaiting retry"
      return
    }
    startConversation(retryableConversationDraft)
  }

  func setHistoryThreads(_ threads: [HistoryThreadSummary]) {
    // Preview/test compatibility only. Production loadHistory derives this view from Runtime catalog.
    historyThreads = threads
  }

  func shouldAutoRefreshHistoryOnAppear() -> Bool {
    guard !didRequestInitialHistoryRefresh else { return false }
    didRequestInitialHistoryRefresh = true
    return true
  }

  func loadHistoryOnAppear() {
    guard shouldAutoRefreshHistoryOnAppear() else { return }
    loadHistory()
  }

  func loadHistory(currentProjectOnly: Bool = false) {
    guard !isLoadingHistory else { return }
    isLoadingHistory = true
    historyCurrentProjectOnly = currentProjectOnly
    historyErrorMessage = nil

    Task { [weak self] in
      guard let self else { return }
      defer {
        if !isTornDown { isLoadingHistory = false }
      }
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        if catalogSubscribed {
          guard let cursor = workbench.catalogCursor else {
            throw WorkbenchModelError.catalogUnavailable
          }
          _ = try await coordinator.backfillCatalog(after: cursor)
          guard !isTornDown else { return }
        } else {
          let pages = try await coordinator.loadCatalog()
          guard !isTornDown else { return }
          try workbench.installCatalog(snapshotPages: pages)
          guard let cursor = workbench.catalogCursor else {
            throw WorkbenchModelError.catalogUnavailable
          }
          _ = try await coordinator.synchronizeCatalog(cursor: cursor)
          guard !isTornDown else { return }
          catalogSubscribed = true
        }
        refreshHistoryPresentation()
      } catch {
        guard !isTornDown else { return }
        historyErrorMessage = String(describing: error)
      }
    }
  }

  func openHistoryThread(_ thread: HistoryThreadSummary) {
    guard let conversationID = authoritativeConversationID(for: thread.id) else {
      historyErrorMessage = SessionRuntimeModelError.catalogEntryUnavailable(thread.id).description
      return
    }
    openingHistoryConversationID = conversationID
    historyErrorMessage = nil
    lastHistoryOpenTiming = nil
    let startedAt = Date()

    Task { [weak self] in
      guard let self else { return }
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        guard let runtime = workbench.runtime(conversationID: conversationID) else {
          throw SessionRuntimeModelError.conversationUnavailable(conversationID)
        }
        let readStartedAt = Date()
        if runtime.runtimeCapabilities == nil {
          _ = try await coordinator.synchronizeConversation(
            conversationID: conversationID,
            cursor: runtime.cursor
          )
          guard !isTornDown else { return }
        }
        let readFinishedAt = Date()
        try workbench.selectConversation(conversationID)
        openingHistoryConversationID = nil
        selectedHistoryConversationID = conversationID
        cwd = workbench.selectedRuntime?.cwd ?? cwd
        resetConversationViewport(prefix: "history:\(conversationID.rawValue)")
        let appliedAt = Date()
        lastHistoryOpenTiming = HistoryOpenTiming(
          conversationID: conversationID,
          itemCount: workbench.selectedRuntime?.items.count ?? 0,
          readMilliseconds: Self.milliseconds(from: readStartedAt, to: readFinishedAt),
          applyMilliseconds: Self.milliseconds(from: readFinishedAt, to: appliedAt),
          totalMilliseconds: Self.milliseconds(from: startedAt, to: appliedAt)
        )
      } catch {
        guard !isTornDown else { return }
        if openingHistoryConversationID == conversationID {
          openingHistoryConversationID = nil
        }
        historyErrorMessage = String(describing: error)
      }
    }
  }

  func startNewSessionFromCurrentProject() {
    selectedHistoryConversationID = nil
    workbench.clearSelection()
    openingHistoryConversationID = nil
    resetConversationViewport(prefix: "conversation")
    items.removeAll()
    errorMessage = nil
    warningMessage = nil
    phase = cwd == nil ? .idle : .ready
  }

  func startNewSession(inProjectCwd projectCwd: String) {
    cwd = URL(fileURLWithPath: projectCwd)
    startNewSessionFromCurrentProject()
  }

  func archiveHistoryThread(_ thread: HistoryThreadSummary) {
    updateMetadata(for: thread, mutation: .setArchived(archived: true))
  }

  func renameHistoryThread(_ thread: HistoryThreadSummary, name: String) {
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return }
    updateMetadata(for: thread, mutation: .rename(title: trimmed))
  }

  func materializeDeferredContent(itemId: String, content: DeferredContent) {
    _ = workbench.selectedRuntime?.materializeDeferredContent(itemId: itemId, content: content)
  }

  func decidePendingAction(
    _ pending: PendingActionRequest,
    decision: ActionDecisionKind,
    persist: Bool = false
  ) {
    do {
      let intent = try workbench.approvalDecisionIntent(
        for: pending,
        decision: decision,
        persist: persist
      )
      Task { [weak self] in
        guard let self else { return }
        do {
          _ = try await ensureRuntimeStarted()
          guard !isTornDown else { return }
          _ = try await coordinator.resolveApproval(
            conversationID: intent.conversationID,
            turnID: intent.turnID,
            approvalID: intent.approvalID,
            decision: intent.decision
          )
        } catch {
          recordOperationFailure(error, conversationID: intent.conversationID)
        }
      }
    } catch {
      recordOperationFailure(error, conversationID: pending.conversationID)
    }
  }

  func updateConversationConfiguration(
    conversationID: RuntimeConversationID,
    mutation: RuntimeAgentControlMutation
  ) {
    do {
      guard let runtime = workbench.runtime(conversationID: conversationID) else {
        throw SessionRuntimeModelError.conversationUnavailable(conversationID)
      }
      guard let state = runtime.configurationState,
        let current = state.configuration,
        state.configurationRevision > 0
      else {
        throw SessionRuntimeModelError.conversationNotConfigured(conversationID)
      }
      let next = try Self.configuration(applying: mutation, to: current)
      let request = RuntimeConfigureConversationRequestV2(
        conversationID: conversationID,
        idempotencyKey: Self.freshIdempotencyKey(prefix: "configure"),
        expectedConfigurationRevision: state.configurationRevision,
        configuration: next
      )
      Task { [weak self] in
        guard let self else { return }
        do {
          _ = try await ensureRuntimeStarted()
          guard !isTornDown else { return }
          let receipt = try await coordinator.configureConversation(request)
          guard !isTornDown else { return }
          if case .conflict(_, let currentRevision) = receipt {
            runtime.warningMessage =
              "configuration changed at revision \(currentRevision); resyncing"
            _ = try await coordinator.backfillConversation(
              conversationID: conversationID,
              after: runtime.cursor
            )
            guard !isTornDown else { return }
          }
        } catch {
          recordOperationFailure(error, conversationID: conversationID)
        }
      }
    } catch {
      recordOperationFailure(error, conversationID: conversationID)
    }
  }

  func teardown() {
    guard !isTornDown else { return }
    isTornDown = true
    inboundBridge.deactivate()
    tickTimer?.invalidate()
    runtimeBootstrapTask?.cancel()
    runtimeBootstrapTask = nil
    runtimeBootstrapTaskID = nil
    workbench.cancelConversationStart()
    retryableConversationDraft = nil
    canonicalTerminalCommandIDs.removeAll()
    isLoadingHistory = false
    phase = .closed
    Task { [coordinator] in await coordinator.close() }
  }

  fileprivate func didApplyInbound(
    _ inbound: AppRuntimeInbound,
    action: WorkbenchRuntimeAction?
  ) {
    guard !isTornDown else { return }
    observeCanonicalLifecycle(inbound)
    switch inbound {
    case .stream(let frame):
      switch frame.item {
      case .event(let event):
        if case .item = event.body { scrollToLatestRequest += 1 }
      case .catalogDelta:
        refreshHistoryPresentation()
      case .transferPart:
        break
      }
    case .synchronizedReply(.syncComplete):
      refreshHistoryPresentation()
    case .synchronizedReply:
      break
    }

    guard
      case .drainNextPrompt(let conversationID, let prompt, let idempotencyKey) = action
    else { return }
    sendQueuedPrompt(
      prompt,
      idempotencyKey: idempotencyKey,
      conversationID: conversationID
    )
  }

  private func ensureRuntimeStarted() async throws -> RuntimeAgentDescriptionsV2 {
    guard !isTornDown else { throw CancellationError() }
    if let runtimeBootstrapTask, let runtimeBootstrapTaskID {
      return try await awaitRuntimeBootstrap(
        runtimeBootstrapTask,
        taskID: runtimeBootstrapTaskID
      )
    }

    nextRuntimeBootstrapTaskID &+= 1
    let taskID = nextRuntimeBootstrapTaskID
    let task = Task { [weak self] in
      guard let self else { throw CancellationError() }
      guard !isTornDown else { throw CancellationError() }
      if !runtimeCoordinatorStarted {
        try await coordinator.start()
        guard !isTornDown else { throw CancellationError() }
        runtimeCoordinatorStarted = true
      }
      let descriptions = try await coordinator.describeAgents()
      guard !isTornDown else { throw CancellationError() }
      return descriptions
    }
    runtimeBootstrapTask = task
    runtimeBootstrapTaskID = taskID
    return try await awaitRuntimeBootstrap(task, taskID: taskID)
  }

  private func awaitRuntimeBootstrap(
    _ task: Task<RuntimeAgentDescriptionsV2, Error>,
    taskID: UInt64
  ) async throws -> RuntimeAgentDescriptionsV2 {
    do {
      let descriptions = try await task.value
      guard !isTornDown else { throw CancellationError() }
      return descriptions
    } catch {
      // 旧 attempt 的晚到失败不得清掉已经安装的新 task。
      if runtimeBootstrapTaskID == taskID {
        runtimeBootstrapTask = nil
        runtimeBootstrapTaskID = nil
      }
      throw error
    }
  }

  private func dispatch(
    _ action: RuntimeAction?,
    runtime: ThreadRuntimeModel
  ) {
    guard case .drainNextPrompt(let prompt, let idempotencyKey) = action else { return }
    sendQueuedPrompt(
      prompt,
      idempotencyKey: idempotencyKey,
      conversationID: runtime.conversationID
    )
  }

  private func sendQueuedPrompt(
    _ prompt: String,
    idempotencyKey: RuntimeIdempotencyKey,
    conversationID: RuntimeConversationID
  ) {
    do {
      guard let runtime = workbench.runtime(conversationID: conversationID) else {
        throw SessionRuntimeModelError.conversationUnavailable(conversationID)
      }
      guard let revision = runtime.configurationState?.configurationRevision, revision > 0 else {
        throw SessionRuntimeModelError.conversationNotConfigured(conversationID)
      }
      let payload = try RuntimePromptPayloadV1(rawValue: prompt)
      runtime.phase = .starting
      Task { [weak self] in
        guard let self else { return }
        do {
          _ = try await ensureRuntimeStarted()
          guard !isTornDown else { return }
          let receipt = try await coordinator.sendPrompt(
            conversationID: conversationID,
            idempotencyKey: idempotencyKey,
            expectedConfigurationRevision: revision,
            prompt: payload
          )
          guard !isTornDown else { return }
          if case .replayed(let commandID, _) = receipt,
            canonicalTerminalCommandIDs[conversationID] == commandID,
            runtime.phase == .starting
          {
            // 这把 idempotency key 对应的 command 已由 canonical terminal event 收口；
            // 本次仅补取丢失的 receipt，不应把 presentation 永久留在 starting。
            // `.accepted` 或已有 active-turn phase 绝不走这里。
            runtime.phase = .ready
          }
          let nextAction = runtime.acknowledgeQueuedPrompt(
            prompt,
            idempotencyKey: idempotencyKey
          )
          dispatch(nextAction, runtime: runtime)
        } catch {
          guard !isTornDown else { return }
          _ = runtime.failQueuedPromptDispatch(
            prompt,
            idempotencyKey: idempotencyKey
          )
          if runtime.phase == .starting {
            runtime.phase = .ready
          }
          recordOperationFailure(error, conversationID: conversationID)
        }
      }
    } catch {
      guard !isTornDown else { return }
      if let runtime = workbench.runtime(conversationID: conversationID) {
        _ = runtime.failQueuedPromptDispatch(
          prompt,
          idempotencyKey: idempotencyKey
        )
        if runtime.phase == .starting {
          runtime.phase = .ready
        }
      }
      recordOperationFailure(error, conversationID: conversationID)
    }
  }

  private func updateMetadata(
    for thread: HistoryThreadSummary,
    mutation: RuntimeConversationMetadataMutationV2
  ) {
    guard let conversationID = authoritativeConversationID(for: thread.id),
      let entry = workbench.catalogEntry(conversationID: conversationID)
    else {
      historyErrorMessage = SessionRuntimeModelError.catalogEntryUnavailable(thread.id).description
      return
    }
    let request = RuntimeConversationMetadataMutationRequestV2(
      conversationID: conversationID,
      idempotencyKey: Self.freshIdempotencyKey(prefix: "metadata"),
      expectedEntryRevision: entry.entryRevision,
      mutation: mutation
    )

    Task { [weak self] in
      guard let self else { return }
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        let receipt = try await coordinator.updateConversationMetadata(request)
        guard !isTornDown else { return }
        if case .conflict(_, let currentRevision) = receipt {
          throw SessionRuntimeModelError.metadataConflict(
            conversationID,
            currentRevision: currentRevision
          )
        }
        if case .setArchived(true) = mutation,
          selectedHistoryConversationID == conversationID
        {
          startNewSessionFromCurrentProject()
        }
        loadHistory(currentProjectOnly: historyCurrentProjectOnly)
      } catch {
        guard !isTornDown else { return }
        historyErrorMessage = String(describing: error)
      }
    }
  }

  /// 只记录已经由 Workbench canonical reducer 接受的 lifecycle identity。replayed receipt
  /// 只有与同 conversation 的 exact terminal command 匹配时，才可恢复 ready；仅凭旧的
  /// presentation phase 或 `replayed` 标签不足以证明 command 已终结。
  private func observeCanonicalLifecycle(_ inbound: AppRuntimeInbound) {
    switch inbound {
    case .stream(let frame):
      guard case .event(let event) = frame.item else { return }
      observeCanonicalLifecycle(event)
    case .synchronizedReply(.snapshot(let snapshot)):
      canonicalTerminalCommandIDs.removeValue(forKey: snapshot.conversationID)
    case .synchronizedReply(.backfill(let backfill)):
      guard case .conversation(_, _, _, let events) = backfill else { return }
      for event in events {
        observeCanonicalLifecycle(event)
      }
    case .synchronizedReply:
      return
    }
  }

  private func observeCanonicalLifecycle(_ event: RuntimeEventV2) {
    guard let commandID = event.commandID else { return }
    switch event.body {
    case .turnStarted:
      canonicalTerminalCommandIDs.removeValue(forKey: event.conversationID)
    case .turnCompleted, .turnInterrupted:
      canonicalTerminalCommandIDs[event.conversationID] = commandID
    default:
      return
    }
  }

  private func authoritativeConversationID(for rawValue: String) -> RuntimeConversationID? {
    if let entry = workbench.catalogEntries.first(where: {
      $0.conversationID.rawValue == rawValue
    }) {
      return entry.conversationID
    }
    return workbench.runtimeList.first(where: {
      $0.conversationID.rawValue == rawValue && $0.entryRevision == nil
    })?.conversationID
  }

  private func refreshHistoryPresentation() {
    var summaries = workbench.catalogEntries.map(Self.historySummary)
    let catalogIDs = Set(workbench.catalogEntries.map(\.conversationID))
    summaries.append(
      contentsOf: workbench.runtimeList.compactMap { runtime in
        guard runtime.entryRevision == nil, !catalogIDs.contains(runtime.conversationID) else {
          return nil
        }
        return Self.historySummary(runtime)
      })
    if historyCurrentProjectOnly, let cwd {
      summaries = summaries.filter { $0.cwd == cwd.path }
    }
    historyThreads = summaries.sorted { lhs, rhs in
      if lhs.updatedAt != rhs.updatedAt { return lhs.updatedAt > rhs.updatedAt }
      return lhs.id < rhs.id
    }
  }

  private func resetConversationViewport(prefix: String) {
    conversationViewportRevision += 1
    conversationViewportIdentity = "\(prefix):\(conversationViewportRevision)"
  }

  private func recordOperationFailure(
    _ error: Error,
    conversationID: RuntimeConversationID? = nil
  ) {
    guard !isTornDown else { return }
    let message = String(describing: error)
    if let conversationID, let runtime = workbench.runtime(conversationID: conversationID) {
      runtime.recordOperationError(message)
    } else {
      errorMessage = message
      phase = .failed
    }
  }

  private static func configuration(
    applying mutation: RuntimeAgentControlMutation,
    to current: RuntimeConversationConfigurationV2
  ) throws -> RuntimeConversationConfigurationV2 {
    switch (current.vendorControl, mutation) {
    case (.codex(let value), .codexSandbox(let sandbox)):
      return codexConfiguration(from: value, sandbox: sandbox)
    case (.codex(let value), .codexApprovalPolicy(let policy)):
      return codexConfiguration(from: value, approvalPolicy: policy)
    case (.codex(let value), .codexReasoningEffort(let effort)):
      return codexConfiguration(from: value, reasoningEffort: effort)
    case (.claudeCode(let value), .claudeCodePermissionMode(let mode)):
      return try claudeCodeConfiguration(from: value, permissionMode: mode)
    case (.claudeCode(let value), .claudeCodeOutputStyle(let style)):
      return try claudeCodeConfiguration(from: value, outputStyle: style)
    default:
      throw SessionRuntimeModelError.configurationAgentMismatch
    }
  }

  private static func codexConfiguration(
    from current: RuntimeCodexConversationConfigurationV2,
    approvalPolicy: CodexApprovalPolicy? = nil,
    sandbox: CodexSandboxMode? = nil,
    reasoningEffort: CodexReasoningEffort? = nil
  ) -> RuntimeConversationConfigurationV2 {
    RuntimeConversationConfigurationV2(
      vendorControl: .codex(
        RuntimeCodexConversationConfigurationV2(
          approvalPolicy: approvalPolicy ?? current.approvalPolicy,
          sandbox: sandbox ?? current.sandbox,
          reasoningEffort: reasoningEffort ?? current.reasoningEffort
        )
      )
    )
  }

  private static func claudeCodeConfiguration(
    from current: RuntimeClaudeCodeConversationConfigurationV2,
    permissionMode: ClaudeCodePermissionMode? = nil,
    outputStyle: String?? = nil
  ) throws -> RuntimeConversationConfigurationV2 {
    let selectedStyle: String?
    if let outputStyle { selectedStyle = outputStyle } else { selectedStyle = current.outputStyle }
    return RuntimeConversationConfigurationV2(
      vendorControl: .claudeCode(
        try RuntimeClaudeCodeConversationConfigurationV2(
          permissionMode: permissionMode ?? current.permissionMode,
          model: current.model,
          effort: current.effort,
          outputStyle: selectedStyle
        )
      )
    )
  }

  private static func historySummary(
    _ entry: RuntimeConversationEntryV2
  ) -> HistoryThreadSummary {
    HistoryThreadSummary(
      id: entry.conversationID.rawValue,
      name: entry.title,
      preview: entry.title ?? "",
      cwd: entry.cwd ?? "",
      createdAt: Int(entry.lastActiveMs / 1_000),
      updatedAt: Int(entry.lastActiveMs / 1_000),
      status: entry.archived ? "archived" : "ready",
      modelProvider: entry.agentKind == .codex ? "openai" : "anthropic",
      source: entry.agentKind == .codex ? "codex" : "claude_code",
      agentKind: entry.agentKind
    )
  }

  private static func historySummary(
    _ runtime: ThreadRuntimeModel
  ) -> HistoryThreadSummary {
    let prompt = runtime.items.lazy
      .filter { $0.kind == "user" }
      .compactMap { CommandMessageSanitizer.sanitize(userText: $0.text) }
      .first?
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let preview: String
    if let prompt, !prompt.isEmpty {
      preview = prompt
    } else {
      preview = runtime.displayTitle
    }
    return HistoryThreadSummary(
      id: runtime.conversationID.rawValue,
      name: runtime.title,
      preview: preview,
      cwd: runtime.cwd?.path ?? "",
      createdAt: Int(runtime.createdAt.timeIntervalSince1970),
      updatedAt: Int(runtime.updatedAt.timeIntervalSince1970),
      status: runtime.phase.rawValue,
      modelProvider: runtime.agentKind == .codex ? "openai" : "anthropic",
      source: "live",
      agentKind: runtime.agentKind
    )
  }

  private static func freshIdempotencyKey(prefix: String) -> RuntimeIdempotencyKey {
    RuntimeIdempotencyKey(rawValue: "\(prefix):\(UUID().uuidString.lowercased())")
  }

  private static func draftsHaveSameIntent(
    _ lhs: RuntimeConversationDraft,
    _ rhs: RuntimeConversationDraft
  ) -> Bool {
    guard lhs.agentKind == rhs.agentKind,
      lhs.cwd == rhs.cwd,
      lhs.prompt == rhs.prompt
    else {
      return false
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    guard let lhsConfiguration = try? encoder.encode(lhs.configuration),
      let rhsConfiguration = try? encoder.encode(rhs.configuration)
    else {
      return false
    }
    return lhsConfiguration == rhsConfiguration
  }

  private static func milliseconds(from start: Date, to end: Date) -> Int {
    max(0, Int((end.timeIntervalSince(start) * 1_000).rounded()))
  }
}

@MainActor
private final class SessionRuntimeInboundBridge {
  weak var model: SessionModel?
  private let workbench: WorkbenchModel
  private var acceptsInbound = true

  init(workbench: WorkbenchModel) {
    self.workbench = workbench
  }

  func ingest(_ inbound: AppRuntimeInbound) async throws {
    guard acceptsInbound else { return }
    let action = try workbench.ingest(inbound)
    guard acceptsInbound else { return }
    model?.didApplyInbound(inbound, action: action)
  }

  func deactivate() {
    acceptsInbound = false
    model = nil
  }
}
