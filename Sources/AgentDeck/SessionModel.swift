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

private struct ConversationBootstrapAdmission: Sendable {
  let agentKind: AgentKind
  let cwd: String
  let prompt: RuntimePromptPayloadV1?
  let idempotencyKeys: RuntimeConversationIdempotencyKeys

  init(
    agentKind: AgentKind,
    cwd: String,
    prompt: RuntimePromptPayloadV1?,
    idempotencyKeys: RuntimeConversationIdempotencyKeys
  ) {
    self.agentKind = agentKind
    self.cwd = cwd
    self.prompt = prompt
    self.idempotencyKeys = idempotencyKeys
  }

  init(draft: RuntimeConversationDraft) {
    self.init(
      agentKind: draft.agentKind,
      cwd: draft.cwd,
      prompt: draft.prompt,
      idempotencyKeys: draft.idempotencyKeys
    )
  }

  func matches(agentKind: AgentKind, cwd: String, prompt: RuntimePromptPayloadV1) -> Bool {
    guard self.agentKind == agentKind, self.cwd == cwd, let retainedPrompt = self.prompt else {
      return false
    }
    return retainedPrompt.rawValue.utf8.elementsEqual(prompt.rawValue.utf8)
  }
}

enum PromptComposerOwner: Hashable, Sendable {
  case newConversation(cwd: String?)
  case bootstrap(
    agentKind: AgentKind,
    lineageID: UUID
  )
  case conversation(RuntimeConversationID)
}

struct PromptRetryDraft: Equatable, Sendable {
  let owner: PromptComposerOwner
  let prompt: String
}

private enum ConversationStartRetryPolicy: Sendable {
  /// 请求可能已经抵达 daemon；只能逐字节重放冻结的完整 draft。
  case exact
  /// Start 已明确拒绝，旧 payload 未生效；允许用户修正完整 draft 后重新开始。
  case replaceStart
  /// Start 已成功、Configure 明确拒绝；Start identity 必须保持，configuration/prompt 可修正。
  case replaceConfigure
}

private enum MutationRetryIdentityPolicy: Sendable {
  case exactRequired
  case freshAllowed
}

enum SessionRuntimeModelError: Error, Equatable, CustomStringConvertible {
  case agentDescriptionUnavailable(AgentKind)
  case conversationUnavailable(RuntimeConversationID)
  case conversationNotConfigured(RuntimeConversationID)
  case configurationAgentMismatch
  case catalogEntryUnavailable(String)
  case metadataConflict(RuntimeConversationID, currentRevision: UInt64)
  case subscriptionCapacityUnavailable

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
    case .subscriptionCapacityUnavailable:
      "all local Runtime subscription slots are pinned by active conversations"
    }
  }
}

/// Runtime v2 App session model。Production 只持有 AppRuntimeCoordinator；不持有、
/// 不创建、也不关闭 legacy DaemonClient。所有 catalog/history/prompt/approval/config/
/// metadata 操作都经 shared-daemon RuntimeEnvelope wire。
@MainActor
@Observable
final class SessionModel {
  /// 与 daemon P3.6 的 connection-bound hard cap 保持一致；catalog 也占一个 live slot。
  private static let maximumLiveSubscriptionsPerConnection = 64

  private struct RuntimeCoordinatorLease {
    let coordinator: AppRuntimeCoordinator
    let generation: UInt64
  }

  private struct HistoryOpenIntent {
    let generation: UInt64
    let conversationID: RuntimeConversationID
    let startedAt: Date
  }

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

  private var coordinator: AppRuntimeCoordinator?
  private let inboundBridge: SessionRuntimeInboundBridge
  private let runtimeWireFactory: (@MainActor () -> any AppRuntimeWireSession)?
  private var runtimeConnectionGeneration: UInt64 = 0
  private var runtimeConnectionNeedsReplacement = false
  private var runtimeConnectionRequiresSubscriptionRestore = false
  private var runtimeCoordinatorCloseTask: Task<Void, Never>?
  private var runtimeCoordinatorCloseGeneration: UInt64?
  private var runtimeBootstrapTask: Task<RuntimeAgentDescriptionsV2, Error>?
  private var runtimeBootstrapTaskID: UInt64?
  private var nextRuntimeBootstrapTaskID: UInt64 = 0
  private var runtimeCoordinatorStarted = false
  private var conversationStartTask: Task<Void, Never>?
  private var conversationStartTaskID: UInt64?
  private var nextConversationStartTaskID: UInt64 = 0
  private(set) var retryableConversationDraft: RuntimeConversationDraft?
  private var conversationStartRetryPolicy: ConversationStartRetryPolicy?
  private var pendingConversationBootstrapAdmission: ConversationBootstrapAdmission?
  private var retryRequiredConversationBootstrapAdmission: ConversationBootstrapAdmission?
  private var bootstrapComposerLineageID: UUID?
  private var didRequestInitialHistoryRefresh = false
  private var historyCurrentProjectOnly = false
  private var catalogSubscribed = false
  private var wantsCatalogSubscription = false
  private var subscribedConversationIDs: Set<RuntimeConversationID> = []
  private var conversationSubscriptionLastUsed: [RuntimeConversationID: UInt64] = [:]
  private var conversationSubscriptionUseClock: UInt64 = 0
  private var liveSubscriptionAdmissionHeld = false
  private var liveSubscriptionAdmissionWaiters: [CheckedContinuation<Void, Never>] = []
  private var pendingHistoryOpenIntent: HistoryOpenIntent?
  private var historyOpenDrainTask: Task<Void, Never>?
  private var historyOpenIntentGeneration: UInt64 = 0
  private var conversationViewportRevision = 0
  private var tickTimer: Timer?
  private var isTornDown = false

  convenience init() {
    self.init(runtimeWireFactory: { OSAccountRuntimeWireSession() })
  }

  convenience init(runtimeWire: any AppRuntimeWireSession) {
    self.init(runtimeWire: runtimeWire, runtimeWireFactory: nil)
  }

  convenience init(
    runtimeWireFactory: @escaping @MainActor () -> any AppRuntimeWireSession
  ) {
    self.init(runtimeWire: nil, runtimeWireFactory: runtimeWireFactory)
  }

  private init(
    runtimeWire: (any AppRuntimeWireSession)?,
    runtimeWireFactory: (@MainActor () -> any AppRuntimeWireSession)?
  ) {
    let workbench = WorkbenchModel()
    let bridge = SessionRuntimeInboundBridge(workbench: workbench)
    self.workbench = workbench
    inboundBridge = bridge
    self.runtimeWireFactory = runtimeWireFactory
    coordinator = runtimeWire.map {
      Self.makeCoordinator(wire: $0, bridge: bridge, connectionGeneration: 0)
    }
    runtimeConnectionNeedsReplacement = runtimeWire == nil
    bridge.model = self
  }

  var shouldShowReasoningExpanded: Bool {
    selectedPhase == .running || selectedPhase == .starting
  }

  var selectedErrorMessage: String? {
    if retryableConversationDraft != nil
      || retryRequiredConversationBootstrapAdmission != nil
    {
      return errorMessage
    }
    return workbench.selectedRuntime?.errorMessage ?? errorMessage
  }

  var selectedWarningMessage: String? {
    if pendingConversationBootstrapAdmission != nil
      || retryableConversationDraft != nil
      || retryRequiredConversationBootstrapAdmission != nil
    {
      return warningMessage
    }
    return workbench.selectedRuntime?.warningMessage ?? warningMessage
  }

  var selectedActionRequest: PendingActionRequest? {
    workbench.selectedRuntime?.pendingActionRequest
  }

  var queuedPrompts: [String] {
    workbench.selectedRuntime?.queuedPrompts ?? []
  }

  var promptComposerOwner: PromptComposerOwner {
    if let admission = pendingConversationBootstrapAdmission {
      return bootstrapComposerOwner(agentKind: admission.agentKind)
    }
    if let draft = retryableConversationDraft {
      return bootstrapComposerOwner(agentKind: draft.agentKind)
    }
    if let admission = retryRequiredConversationBootstrapAdmission {
      return bootstrapComposerOwner(agentKind: admission.agentKind)
    }
    if let conversationID = workbench.selectedConversationID {
      return .conversation(conversationID)
    }
    return .newConversation(cwd: cwd?.standardizedFileURL.path)
  }

  var retryRequiredPromptDraft: PromptRetryDraft? {
    if pendingConversationBootstrapAdmission == nil {
      if let draft = retryableConversationDraft, let prompt = draft.prompt?.rawValue {
        return PromptRetryDraft(
          owner: bootstrapComposerOwner(agentKind: draft.agentKind),
          prompt: prompt
        )
      }
      if let admission = retryRequiredConversationBootstrapAdmission,
        let prompt = admission.prompt?.rawValue
      {
        return PromptRetryDraft(
          owner: bootstrapComposerOwner(agentKind: admission.agentKind),
          prompt: prompt
        )
      }
    }
    if let runtime = workbench.selectedRuntime,
      let prompt = runtime.retryRequiredPrompt
    {
      return PromptRetryDraft(
        owner: .conversation(runtime.conversationID),
        prompt: prompt
      )
    }
    return nil
  }

  var sendingPrompts: [String] {
    if let prompt = pendingConversationBootstrapAdmission?.prompt {
      return [prompt.rawValue]
    }
    if let runtime = workbench.selectedRuntime {
      return runtime.pendingPromptAdmissions
    }
    return []
  }

  var isConversationBootstrapAdmissionInFlight: Bool {
    pendingConversationBootstrapAdmission != nil
  }

  var isComposerAdmissionInFlight: Bool {
    if pendingConversationBootstrapAdmission != nil { return true }
    return !(workbench.selectedRuntime?.pendingPromptAdmissions.isEmpty ?? true)
  }

  var canRetryPromptlessConversationStart: Bool {
    guard !isTornDown, pendingConversationBootstrapAdmission == nil else { return false }
    if let draft = retryableConversationDraft { return draft.prompt == nil }
    if let admission = retryRequiredConversationBootstrapAdmission {
      return admission.prompt == nil
    }
    return false
  }

  var canRetryConversationStart: Bool {
    guard !isTornDown, pendingConversationBootstrapAdmission == nil else { return false }
    if let draft = retryableConversationDraft {
      return draft.prompt == nil || conversationStartRetryPolicy == .exact
    }
    return retryRequiredConversationBootstrapAdmission != nil
  }

  var retryRequiredPrompt: String? {
    retryRequiredPromptDraft?.prompt
  }

  var selectedSidebarConversationID: String? {
    selectedHistoryConversationID?.rawValue ?? workbench.selectedConversationID?.rawValue
  }

  var selectedItems: [UIItem] {
    workbench.selectedRuntime?.items ?? items
  }

  var selectedPhase: Phase {
    if pendingConversationBootstrapAdmission != nil
      || retryableConversationDraft != nil
      || retryRequiredConversationBootstrapAdmission != nil
    {
      return phase
    }
    return workbench.selectedRuntime?.phase ?? phase
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
  @discardableResult
  func submit(
    _ prompt: String,
    agentKind: AgentKind? = nil,
    expectedComposerOwner: PromptComposerOwner? = nil
  ) -> Bool {
    guard !isTornDown else { return false }
    if let expectedComposerOwner, expectedComposerOwner != promptComposerOwner {
      warningMessage = "The composer target changed; review the restored draft before sending"
      return false
    }
    let requestedAgentKind = agentKind ?? promptComposerAgentKind
    guard !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      return false
    }
    let payload: RuntimePromptPayloadV1
    do {
      payload = try RuntimePromptPayloadV1(rawValue: prompt)
    } catch {
      recordOperationFailure(
        error,
        conversationID: workbench.selectedRuntime?.conversationID
      )
      return false
    }

    guard pendingConversationBootstrapAdmission == nil else {
      warningMessage = "A conversation prompt admission is already in progress"
      return false
    }

    if let retained = retryableConversationDraft {
      guard let cwd else {
        warningMessage = "Choose a project directory before starting a conversation"
        return false
      }
      switch conversationStartRetryPolicy ?? .exact {
      case .exact:
        guard retained.agentKind == requestedAgentKind,
          retained.cwd == cwd.path,
          let retainedPrompt = retained.prompt,
          retainedPrompt.rawValue.utf8.elementsEqual(payload.rawValue.utf8)
        else {
          warningMessage =
            "Previous conversation start has an unknown outcome; retry the exact draft before starting a different conversation"
          return false
        }
        return startConversation(
          retained,
          preservingBootstrapComposerLineage: true
        )
      case .replaceStart:
        if retained.agentKind == requestedAgentKind {
          do {
            return startConversation(
              try retained.replacingIntent(
                cwd: cwd.path,
                prompt: payload.rawValue,
                idempotencyKeys: .fresh()
              ),
              preservingBootstrapComposerLineage: true
            )
          } catch {
            recordOperationFailure(error)
            return false
          }
        }
        let admission = ConversationBootstrapAdmission(
          agentKind: requestedAgentKind,
          cwd: cwd.path,
          prompt: payload,
          idempotencyKeys: .fresh()
        )
        beginConversationBootstrap(
          admission,
          preservingBootstrapComposerLineage: true
        )
        return true
      case .replaceConfigure:
        guard retained.agentKind == requestedAgentKind, retained.cwd == cwd.path else {
          warningMessage =
            "The previous Start succeeded; Configure retry must keep the original agent and project directory"
          return false
        }
        do {
          return startConversation(
            try retained.replacingIntent(
              cwd: retained.cwd,
              prompt: payload.rawValue,
              idempotencyKeys: .fresh()
            ),
            preservingBootstrapComposerLineage: true
          )
        } catch {
          recordOperationFailure(error)
          return false
        }
      }
    }

    if let runtime = workbench.selectedRuntime {
      guard let revision = runtime.configurationState?.configurationRevision,
        revision > 0
      else {
        recordOperationFailure(
          SessionRuntimeModelError.conversationNotConfigured(runtime.conversationID),
          conversationID: runtime.conversationID
        )
        return false
      }
      switch runtime.phase {
      case .idle, .ready:
        let action = runtime.enqueuePrompt(
          prompt,
          idempotencyKey: Self.freshIdempotencyKey(prefix: "prompt"),
          expectedConfigurationRevision: revision
        )
        dispatch(action, runtime: runtime)
        return action != nil
      case .starting, .running, .waitingApproval, .draining:
        let action = runtime.enqueuePrompt(
          prompt,
          idempotencyKey: Self.freshIdempotencyKey(prefix: "prompt"),
          expectedConfigurationRevision: revision
        )
        dispatch(action, runtime: runtime)
        return action != nil
      case .failed, .closed:
        runtime.warningMessage = "conversation is not ready for a prompt"
        return false
      }
    }

    guard let cwd else {
      warningMessage = "Choose a project directory before starting a conversation"
      return false
    }
    let admission: ConversationBootstrapAdmission
    let preservesBootstrapComposerLineage: Bool
    if let retry = retryRequiredConversationBootstrapAdmission,
      retry.matches(agentKind: requestedAgentKind, cwd: cwd.path, prompt: payload)
    {
      admission = retry
      preservesBootstrapComposerLineage = true
    } else {
      admission = ConversationBootstrapAdmission(
        agentKind: requestedAgentKind,
        cwd: cwd.path,
        prompt: payload,
        idempotencyKeys: .fresh()
      )
      preservesBootstrapComposerLineage = false
    }
    beginConversationBootstrap(
      admission,
      preservingBootstrapComposerLineage: preservesBootstrapComposerLineage
    )
    return true
  }

  @discardableResult
  func startConversation(_ requestedDraft: RuntimeConversationDraft) -> Bool {
    startConversation(
      requestedDraft,
      preservingBootstrapComposerLineage: false
    )
  }

  @discardableResult
  private func startConversation(
    _ requestedDraft: RuntimeConversationDraft,
    preservingBootstrapComposerLineage: Bool
  ) -> Bool {
    guard !isTornDown else { return false }
    let draft: RuntimeConversationDraft
    if let retained = retryableConversationDraft {
      switch conversationStartRetryPolicy ?? .exact {
      case .exact:
        guard Self.draftsHaveSameIntent(retained, requestedDraft) else {
          warningMessage =
            "Previous conversation start has an unknown outcome; retry the exact draft before starting a different conversation"
          return false
        }
        draft = retained
      case .replaceStart:
        draft = requestedDraft
      case .replaceConfigure:
        guard retained.agentKind == requestedDraft.agentKind,
          retained.cwd == requestedDraft.cwd
        else {
          warningMessage =
            "The previous Start succeeded; Configure retry must keep the original agent and project directory"
          return false
        }
        do {
          draft = try requestedDraft.replacingIdempotencyKeys(
            RuntimeConversationIdempotencyKeys(
              start: retained.idempotencyKeys.start,
              configure: requestedDraft.idempotencyKeys.configure,
              prompt: requestedDraft.idempotencyKeys.prompt
            )
          )
        } catch {
          recordOperationFailure(error)
          return false
        }
      }
    } else {
      draft = requestedDraft
    }

    if let pendingConversationBootstrapAdmission,
      pendingConversationBootstrapAdmission.idempotencyKeys != draft.idempotencyKeys
    {
      warningMessage = "A conversation start is already in progress"
      return false
    }
    guard workbench.inFlightDraftContext == nil else {
      warningMessage = "A conversation start is already in progress"
      return false
    }
    let previousBootstrapComposerLineageID = bootstrapComposerLineageID
    bootstrapComposerLineageID =
      preservingBootstrapComposerLineage
      ? (bootstrapComposerLineageID ?? UUID())
      : UUID()
    pendingConversationBootstrapAdmission = ConversationBootstrapAdmission(draft: draft)
    retryRequiredConversationBootstrapAdmission = nil
    invalidateHistoryOpenIntent()

    do {
      try workbench.beginConversationStart(draft)
    } catch WorkbenchModelError.draftAlreadyInFlight {
      clearPendingConversationAdmission(matching: draft.idempotencyKeys)
      bootstrapComposerLineageID = previousBootstrapComposerLineageID
      warningMessage = "A conversation start is already in progress"
      return false
    } catch {
      clearPendingConversationAdmission(matching: draft.idempotencyKeys)
      bootstrapComposerLineageID = previousBootstrapComposerLineageID
      recordOperationFailure(error)
      return false
    }

    selectedHistoryConversationID = nil
    workbench.clearSelection()
    phase = .starting
    errorMessage = nil
    warningMessage = nil
    nextConversationStartTaskID &+= 1
    let taskID = nextConversationStartTaskID
    let task = Task { [weak self] in
      guard let self else { return }
      defer { finishConversationStartTask(taskID: taskID) }
      var operationLease: RuntimeCoordinatorLease?
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        let lease = try currentRuntimeCoordinatorLease()
        operationLease = lease
        let result = try await withLiveSubscriptionAdmission {
          try await makeRoomForLiveSubscription(
            requiredConversationID: nil,
            using: lease
          )
          try requireCurrentRuntimeCoordinator(lease)
          do {
            let result = try await lease.coordinator.startConversation(draft)
            try requireCurrentRuntimeCoordinator(lease)
            subscribedConversationIDs.insert(result.conversationID)
            touchConversationSubscription(result.conversationID)
            return result
          } catch let failure as AppRuntimeConversationStartFailure {
            if case .prompt = failure.stage, let partialResult = failure.partialResult {
              try requireCurrentRuntimeCoordinator(lease)
              subscribedConversationIDs.insert(partialResult.conversationID)
              touchConversationSubscription(partialResult.conversationID)
            }
            throw failure
          }
        }
        try workbench.completeConversationStart(result)
        if let runtime = workbench.runtime(conversationID: result.conversationID) {
          switch result.configurationReceipt {
          case .applied, .replayed:
            if let prompt = draft.prompt?.rawValue,
              let receipt = result.promptReceipt
            {
              runtime.projectBootstrapPromptReceipt(prompt, receipt: receipt)
            }
          case .conflict(_, let currentRevision):
            if let prompt = draft.prompt?.rawValue {
              runtime.retainBootstrapPromptForRetry(
                prompt,
                reusableIdempotencyKey: nil,
                reusableExpectedConfigurationRevision: nil
              )
            }
            runtime.warningMessage =
              "configuration changed at revision \(currentRevision); current daemon configuration was synchronized, review it before retrying the prompt"
          case .failed:
            preconditionFailure("coordinator must unwrap failed configuration receipt")
          }
        }
        clearPendingConversationAdmission(matching: draft.idempotencyKeys)
        errorMessage = nil
        warningMessage = nil
        retryableConversationDraft = nil
        conversationStartRetryPolicy = nil
        bootstrapComposerLineageID = nil
        cwd = URL(fileURLWithPath: draft.cwd)
        phase = workbench.selectedRuntime?.phase ?? .ready
        refreshHistoryPresentation()
        resetConversationViewport(prefix: "conversation:\(result.conversationID.rawValue)")
      } catch let failure as AppRuntimeConversationStartFailure {
        guard !isTornDown,
          pendingConversationBootstrapAdmission?.idempotencyKeys == draft.idempotencyKeys
        else { return }
        if case .prompt = failure.stage, let partialResult = failure.partialResult {
          do {
            if let operationLease { try requireCurrentRuntimeCoordinator(operationLease) }
            try recoverConversationAfterPromptFailure(
              failure,
              partialResult: partialResult,
              draft: draft
            )
            await invalidateRuntimeConnectionIfNeeded(
              after: failure.underlying,
              failedCoordinator: operationLease
            )
            return
          } catch {
            workbench.cancelConversationStart()
            clearPendingConversationAdmission(matching: draft.idempotencyKeys)
            retryableConversationDraft = draft
            conversationStartRetryPolicy = .exact
            await invalidateRuntimeConnectionIfNeeded(
              after: failure.underlying,
              failedCoordinator: operationLease
            )
            recordOperationFailure(error)
            return
          }
        }
        workbench.cancelConversationStart()
        clearPendingConversationAdmission(matching: draft.idempotencyKeys)
        do {
          retryableConversationDraft = try Self.retryDraft(
            after: failure,
            original: draft
          )
          conversationStartRetryPolicy = Self.retryPolicy(after: failure)
          recordOperationFailure(failure.underlying)
        } catch {
          retryableConversationDraft = draft
          conversationStartRetryPolicy = .exact
          recordOperationFailure(error)
        }
        await invalidateRuntimeConnectionIfNeeded(
          after: failure.underlying,
          failedCoordinator: operationLease
        )
      } catch {
        guard !isTornDown,
          pendingConversationBootstrapAdmission?.idempotencyKeys == draft.idempotencyKeys
        else { return }
        workbench.cancelConversationStart()
        clearPendingConversationAdmission(matching: draft.idempotencyKeys)
        retryableConversationDraft = draft
        conversationStartRetryPolicy = .exact
        await invalidateRuntimeConnectionIfNeeded(
          after: error,
          failedCoordinator: operationLease
        )
        recordOperationFailure(error)
      }
    }
    conversationStartTask = task
    conversationStartTaskID = taskID
    return true
  }

  /// 显式重试 outcome-unknown start；复用完整 draft 与三把原始 idempotency keys。
  func retryConversationStart() {
    guard !isTornDown else { return }
    if let retryableConversationDraft {
      _ = startConversation(
        retryableConversationDraft,
        preservingBootstrapComposerLineage: true
      )
      return
    }
    if let admission = retryRequiredConversationBootstrapAdmission {
      beginConversationBootstrap(
        admission,
        preservingBootstrapComposerLineage: true
      )
      return
    }
    warningMessage = "There is no conversation start awaiting retry"
  }

  func recordComposerDraftCacheDrop(_ message: String) {
    if let runtime = workbench.selectedRuntime {
      runtime.warningMessage = message
    } else {
      warningMessage = message
    }
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
    wantsCatalogSubscription = true
    historyCurrentProjectOnly = currentProjectOnly
    historyErrorMessage = nil

    Task { [weak self] in
      guard let self else { return }
      var operationLease: RuntimeCoordinatorLease?
      defer {
        if !isTornDown { isLoadingHistory = false }
      }
      do {
        _ = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        let lease = try currentRuntimeCoordinatorLease()
        operationLease = lease
        if catalogSubscribed {
          guard let cursor = workbench.catalogCursor else {
            throw WorkbenchModelError.catalogUnavailable
          }
          _ = try await lease.coordinator.backfillCatalog(after: cursor)
          try requireCurrentRuntimeCoordinator(lease)
        } else {
          let pages = try await lease.coordinator.loadCatalog()
          try requireCurrentRuntimeCoordinator(lease)
          try workbench.installCatalog(snapshotPages: pages)
          guard let cursor = workbench.catalogCursor else {
            throw WorkbenchModelError.catalogUnavailable
          }
          try await synchronizeCatalogIfNeeded(cursor: cursor, using: lease)
          guard !isTornDown else { return }
          catalogSubscribed = true
        }
        refreshHistoryPresentation()
      } catch {
        guard runtimeFailureBelongsToCurrentGeneration(operationLease) else { return }
        await invalidateRuntimeConnectionIfNeeded(
          after: error,
          failedCoordinator: operationLease
        )
        historyErrorMessage = String(describing: error)
      }
    }
  }

  func openHistoryThread(_ thread: HistoryThreadSummary) {
    guard !hasBootstrapConversationIntent else {
      historyErrorMessage =
        "Finish or retry the pending conversation start before opening history"
      return
    }
    let historyIntentGeneration = beginHistoryOpenIntent()
    guard let conversationID = authoritativeConversationID(for: thread.id) else {
      historyErrorMessage = SessionRuntimeModelError.catalogEntryUnavailable(thread.id).description
      return
    }
    openingHistoryConversationID = conversationID
    historyErrorMessage = nil
    lastHistoryOpenTiming = nil
    pendingHistoryOpenIntent = HistoryOpenIntent(
      generation: historyIntentGeneration,
      conversationID: conversationID,
      startedAt: .now
    )
    guard historyOpenDrainTask == nil else { return }
    historyOpenDrainTask = Task { [weak self] in
      await self?.drainHistoryOpenIntents()
    }
  }

  private func drainHistoryOpenIntents() async {
    defer { historyOpenDrainTask = nil }
    while !isTornDown, let intent = pendingHistoryOpenIntent {
      pendingHistoryOpenIntent = nil
      await performHistoryOpen(intent)
    }
  }

  private func performHistoryOpen(_ intent: HistoryOpenIntent) async {
    var operationLease: RuntimeCoordinatorLease?
    do {
      _ = try await ensureRuntimeStarted(
        requiredConversationID: intent.conversationID
      )
      guard !isTornDown else { return }
      guard let runtime = workbench.runtime(conversationID: intent.conversationID) else {
        throw SessionRuntimeModelError.conversationUnavailable(intent.conversationID)
      }
      let lease = try currentRuntimeCoordinatorLease()
      operationLease = lease
      let readStartedAt = Date()
      try await synchronizeConversationIfNeeded(runtime, using: lease)
      try requireCurrentRuntimeCoordinator(lease)
      let readFinishedAt = Date()
      guard isCurrentHistoryOpenIntent(intent.generation) else { return }
      try workbench.selectConversation(intent.conversationID)
      openingHistoryConversationID = nil
      selectedHistoryConversationID = intent.conversationID
      cwd = workbench.selectedRuntime?.cwd ?? cwd
      resetConversationViewport(prefix: "history:\(intent.conversationID.rawValue)")
      let appliedAt = Date()
      lastHistoryOpenTiming = HistoryOpenTiming(
        conversationID: intent.conversationID,
        itemCount: workbench.selectedRuntime?.items.count ?? 0,
        readMilliseconds: Self.milliseconds(from: readStartedAt, to: readFinishedAt),
        applyMilliseconds: Self.milliseconds(from: readFinishedAt, to: appliedAt),
        totalMilliseconds: Self.milliseconds(from: intent.startedAt, to: appliedAt)
      )
    } catch {
      let failureBelongsToCurrentGeneration =
        runtimeFailureBelongsToCurrentGeneration(operationLease)
      if failureBelongsToCurrentGeneration {
        await invalidateRuntimeConnectionIfNeeded(
          after: error,
          failedCoordinator: operationLease
        )
      }
      guard isCurrentHistoryOpenIntent(intent.generation) else { return }
      openingHistoryConversationID = nil
      historyErrorMessage = String(describing: error)
    }
  }

  func startNewSessionFromCurrentProject() {
    guard !hasBootstrapConversationIntent else {
      warningMessage =
        "Finish or retry the pending conversation start before starting another session"
      return
    }
    invalidateHistoryOpenIntent()
    selectedHistoryConversationID = nil
    workbench.clearSelection()
    resetConversationViewport(prefix: "conversation")
    items.removeAll()
    errorMessage = nil
    warningMessage = nil
    phase = cwd == nil ? .idle : .ready
  }

  func startNewSession(inProjectCwd projectCwd: String) {
    guard !hasBootstrapConversationIntent else {
      warningMessage =
        "Finish or retry the pending conversation start before changing projects"
      return
    }
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
        var operationLease: RuntimeCoordinatorLease?
        do {
          _ = try await ensureRuntimeStarted(
            requiredConversationID: intent.conversationID
          )
          guard !isTornDown else { return }
          let lease = try currentRuntimeCoordinatorLease()
          operationLease = lease
          if let runtime = workbench.runtime(conversationID: intent.conversationID) {
            try await synchronizeConversationIfNeeded(
              runtime,
              using: lease
            )
          }
          _ = try await lease.coordinator.resolveApproval(
            conversationID: intent.conversationID,
            turnID: intent.turnID,
            approvalID: intent.approvalID,
            decision: intent.decision
          )
          try requireCurrentRuntimeCoordinator(lease)
        } catch {
          guard runtimeFailureBelongsToCurrentGeneration(operationLease) else { return }
          await invalidateRuntimeConnectionIfNeeded(
            after: error,
            failedCoordinator: operationLease
          )
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
        var operationLease: RuntimeCoordinatorLease?
        do {
          _ = try await ensureRuntimeStarted(
            requiredConversationID: conversationID
          )
          guard !isTornDown else { return }
          let lease = try currentRuntimeCoordinatorLease()
          operationLease = lease
          try await synchronizeConversationIfNeeded(
            runtime,
            using: lease
          )
          let receipt = try await lease.coordinator.configureConversation(request)
          try requireCurrentRuntimeCoordinator(lease)
          if case .conflict(_, let currentRevision) = receipt {
            runtime.warningMessage =
              "configuration changed at revision \(currentRevision); resyncing"
            _ = try await lease.coordinator.backfillConversation(
              conversationID: conversationID,
              after: runtime.cursor
            )
            try requireCurrentRuntimeCoordinator(lease)
          }
        } catch {
          guard runtimeFailureBelongsToCurrentGeneration(operationLease) else { return }
          await invalidateRuntimeConnectionIfNeeded(
            after: error,
            failedCoordinator: operationLease
          )
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
    conversationStartTask?.cancel()
    conversationStartTask = nil
    conversationStartTaskID = nil
    historyOpenDrainTask?.cancel()
    historyOpenDrainTask = nil
    pendingHistoryOpenIntent = nil
    workbench.cancelConversationStart()
    pendingConversationBootstrapAdmission = nil
    retryRequiredConversationBootstrapAdmission = nil
    retryableConversationDraft = nil
    conversationStartRetryPolicy = nil
    bootstrapComposerLineageID = nil
    catalogSubscribed = false
    subscribedConversationIDs.removeAll()
    conversationSubscriptionLastUsed.removeAll()
    workbench.cancelPendingSynchronization()
    isLoadingHistory = false
    phase = .closed
    let activeCoordinator = coordinator
    coordinator = nil
    Task { await activeCoordinator?.close() }
  }

  fileprivate func didApplyInbound(
    _ inbound: AppRuntimeInbound,
    action: WorkbenchRuntimeAction?
  ) {
    guard !isTornDown else { return }
    switch inbound {
    case .stream(let frame):
      switch frame.item {
      case .event(let event):
        if case .item = event.body { scrollToLatestRequest += 1 }
      case .catalogDelta:
        refreshHistoryPresentation()
      case .transferPart:
        break
      case .pairingPending:
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

  private static func makeCoordinator(
    wire: any AppRuntimeWireSession,
    bridge: SessionRuntimeInboundBridge,
    connectionGeneration: UInt64
  ) -> AppRuntimeCoordinator {
    AppRuntimeCoordinator(
      wire: wire,
      inboundHandler: { inbound in
        try await bridge.ingest(
          inbound,
          connectionGeneration: connectionGeneration
        )
      },
      terminationHandler: {
        bridge.connectionTerminated(connectionGeneration: connectionGeneration)
      }
    )
  }

  private func installFreshRuntimeCoordinatorIfNeeded() async throws {
    while true {
      if let closeTask = runtimeCoordinatorCloseTask,
        let closeGeneration = runtimeCoordinatorCloseGeneration
      {
        await closeTask.value
        if runtimeCoordinatorCloseGeneration == closeGeneration {
          runtimeCoordinatorCloseTask = nil
          runtimeCoordinatorCloseGeneration = nil
        }
        continue
      }
      guard !isTornDown else { throw CancellationError() }
      guard let activeCoordinator = coordinator else { break }
      let activeGeneration = runtimeConnectionGeneration
      let requiresFreshConnection = await activeCoordinator.requiresFreshConnection()
      guard !isTornDown else { throw CancellationError() }
      guard coordinator === activeCoordinator,
        runtimeConnectionGeneration == activeGeneration
      else {
        continue
      }
      guard requiresFreshConnection else { return }

      runtimeConnectionGeneration &+= 1
      inboundBridge.activate(connectionGeneration: runtimeConnectionGeneration)
      coordinator = nil
      runtimeConnectionNeedsReplacement = true
      runtimeConnectionRequiresSubscriptionRestore = true
      runtimeCoordinatorStarted = false
      runtimeBootstrapTask?.cancel()
      runtimeBootstrapTask = nil
      runtimeBootstrapTaskID = nil
      catalogSubscribed = false
      subscribedConversationIDs.removeAll()
      conversationSubscriptionLastUsed.removeAll()
      workbench.cancelPendingSynchronization()

      let closeTask = Task { await activeCoordinator.close() }
      runtimeCoordinatorCloseTask = closeTask
      runtimeCoordinatorCloseGeneration = activeGeneration
    }
    guard !isTornDown else { throw CancellationError() }
    guard coordinator == nil || runtimeConnectionNeedsReplacement else { return }
    guard let runtimeWireFactory else {
      throw AppRuntimeCoordinatorError.closed
    }

    runtimeConnectionGeneration &+= 1
    let generation = runtimeConnectionGeneration
    let freshCoordinator = Self.makeCoordinator(
      wire: runtimeWireFactory(),
      bridge: inboundBridge,
      connectionGeneration: generation
    )
    inboundBridge.activate(connectionGeneration: generation)
    coordinator = freshCoordinator
    runtimeConnectionNeedsReplacement = false
  }

  private func currentRuntimeCoordinatorLease() throws -> RuntimeCoordinatorLease {
    guard !isTornDown, !runtimeConnectionNeedsReplacement, let coordinator else {
      throw AppRuntimeCoordinatorError.closed
    }
    return RuntimeCoordinatorLease(
      coordinator: coordinator,
      generation: runtimeConnectionGeneration
    )
  }

  private func requireCurrentRuntimeCoordinator(_ lease: RuntimeCoordinatorLease) throws {
    guard !isTornDown, !runtimeConnectionNeedsReplacement,
      runtimeConnectionGeneration == lease.generation,
      coordinator === lease.coordinator
    else {
      throw AppRuntimeCoordinatorError.closed
    }
  }

  private func runtimeFailureBelongsToCurrentGeneration(
    _ lease: RuntimeCoordinatorLease?
  ) -> Bool {
    guard !isTornDown else { return false }
    guard let lease else { return true }
    return runtimeConnectionGeneration == lease.generation
      && coordinator === lease.coordinator
  }

  private func invalidateRuntimeConnectionIfNeeded(
    after error: Error,
    failedCoordinator lease: RuntimeCoordinatorLease?
  ) async {
    guard runtimeWireFactory != nil, let lease else { return }
    let coordinatorClosed = await lease.coordinator.requiresFreshConnection()
    guard coordinatorClosed || Self.requiresFreshRuntimeConnection(after: error),
      runtimeConnectionGeneration == lease.generation,
      coordinator === lease.coordinator
    else { return }

    runtimeConnectionGeneration &+= 1
    inboundBridge.activate(connectionGeneration: runtimeConnectionGeneration)
    coordinator = nil
    runtimeConnectionNeedsReplacement = true
    runtimeConnectionRequiresSubscriptionRestore = true
    runtimeCoordinatorStarted = false
    runtimeBootstrapTask?.cancel()
    runtimeBootstrapTask = nil
    runtimeBootstrapTaskID = nil
    catalogSubscribed = false
    subscribedConversationIDs.removeAll()
    conversationSubscriptionLastUsed.removeAll()
    workbench.cancelPendingSynchronization()

    let closeTask = Task { await lease.coordinator.close() }
    runtimeCoordinatorCloseTask = closeTask
    runtimeCoordinatorCloseGeneration = lease.generation
    await closeTask.value
  }

  /// Stream pump 的异常终止只在旧 wire 的真实 close barrier 完成后到达这里。
  /// 不热循环建连接；只原子废弃旧 generation，让下一次用户操作直接创建 fresh wire。
  fileprivate func runtimeConnectionTerminated(connectionGeneration: UInt64) {
    guard !isTornDown, runtimeWireFactory != nil,
      runtimeConnectionGeneration == connectionGeneration,
      coordinator != nil
    else { return }

    runtimeConnectionGeneration &+= 1
    inboundBridge.activate(connectionGeneration: runtimeConnectionGeneration)
    coordinator = nil
    runtimeConnectionNeedsReplacement = true
    runtimeConnectionRequiresSubscriptionRestore = true
    runtimeCoordinatorStarted = false
    runtimeBootstrapTask?.cancel()
    runtimeBootstrapTask = nil
    runtimeBootstrapTaskID = nil
    catalogSubscribed = false
    subscribedConversationIDs.removeAll()
    conversationSubscriptionLastUsed.removeAll()
    workbench.cancelPendingSynchronization()
    let message = "Local daemon connection closed; the next action will reconnect"
    if let runtime = workbench.selectedRuntime {
      runtime.warningMessage = message
    } else {
      warningMessage = message
    }
  }

  private func restoreRequiredSubscriptions(
    using lease: RuntimeCoordinatorLease,
    requiredConversationID: RuntimeConversationID?
  ) async throws {
    if wantsCatalogSubscription, let cursor = workbench.catalogCursor {
      try await synchronizeCatalogIfNeeded(cursor: cursor, using: lease)
    }
    var conversationIDs: [RuntimeConversationID] = []
    if let selectedConversationID = workbench.selectedConversationID {
      conversationIDs.append(selectedConversationID)
    }
    if let requiredConversationID,
      !conversationIDs.contains(requiredConversationID)
    {
      conversationIDs.append(requiredConversationID)
    }
    for conversationID in conversationIDs {
      guard let runtime = workbench.runtime(conversationID: conversationID) else { continue }
      try await synchronizeConversationIfNeeded(runtime, using: lease)
    }
  }

  private func synchronizeCatalogIfNeeded(
    cursor: RuntimeStreamCursorV1,
    using lease: RuntimeCoordinatorLease
  ) async throws {
    guard !catalogSubscribed else { return }
    try await withLiveSubscriptionAdmission {
      guard !catalogSubscribed else { return }
      try await makeRoomForLiveSubscription(
        requiredConversationID: nil,
        using: lease
      )
      try requireCurrentRuntimeCoordinator(lease)
      _ = try await lease.coordinator.synchronizeCatalog(cursor: cursor)
      try requireCurrentRuntimeCoordinator(lease)
      catalogSubscribed = true
    }
  }

  private func synchronizeConversationIfNeeded(
    _ runtime: ThreadRuntimeModel,
    using lease: RuntimeCoordinatorLease
  ) async throws {
    let conversationID = runtime.conversationID
    if subscribedConversationIDs.contains(conversationID) {
      touchConversationSubscription(conversationID)
      return
    }
    try await withLiveSubscriptionAdmission {
      if subscribedConversationIDs.contains(conversationID) {
        touchConversationSubscription(conversationID)
        return
      }
      try await makeRoomForLiveSubscription(
        requiredConversationID: conversationID,
        using: lease
      )
      try requireCurrentRuntimeCoordinator(lease)
      _ = try await lease.coordinator.synchronizeConversation(
        conversationID: conversationID,
        cursor: runtime.cursor
      )
      try requireCurrentRuntimeCoordinator(lease)
      subscribedConversationIDs.insert(conversationID)
      touchConversationSubscription(conversationID)
    }
  }

  private func makeRoomForLiveSubscription(
    requiredConversationID: RuntimeConversationID?,
    using lease: RuntimeCoordinatorLease
  ) async throws {
    let liveCount = subscribedConversationIDs.count + (catalogSubscribed ? 1 : 0)
    guard liveCount >= Self.maximumLiveSubscriptionsPerConnection else { return }

    let selectedConversationID = workbench.selectedConversationID
    let victim =
      subscribedConversationIDs.filter { conversationID in
        guard conversationID != requiredConversationID,
          conversationID != selectedConversationID
        else { return false }
        guard let runtime = workbench.runtime(conversationID: conversationID) else {
          return true
        }
        guard runtime.pendingPromptAdmissions.isEmpty,
          runtime.pendingActionRequest == nil
        else { return false }
        switch runtime.phase {
        case .idle, .ready, .failed, .closed:
          return true
        case .starting, .running, .waitingApproval, .draining:
          return false
        }
      }
      .min { lhs, rhs in
        let lhsUse = conversationSubscriptionLastUsed[lhs] ?? 0
        let rhsUse = conversationSubscriptionLastUsed[rhs] ?? 0
        if lhsUse != rhsUse { return lhsUse < rhsUse }
        return lhs.rawValue < rhs.rawValue
      }

    guard let victim else {
      throw SessionRuntimeModelError.subscriptionCapacityUnavailable
    }
    try requireCurrentRuntimeCoordinator(lease)
    try await lease.coordinator.unsubscribeConversation(victim)
    try requireCurrentRuntimeCoordinator(lease)
    subscribedConversationIDs.remove(victim)
    conversationSubscriptionLastUsed.removeValue(forKey: victim)
  }

  private func touchConversationSubscription(_ conversationID: RuntimeConversationID) {
    conversationSubscriptionUseClock &+= 1
    conversationSubscriptionLastUsed[conversationID] = conversationSubscriptionUseClock
  }

  /// daemon 的 64-slot 上界要求“必要腾槽 + 会产生 Subscribe 的操作 + 本地记账”不可重入。
  /// FIFO admission 同时覆盖 catalog、conversation 与 Start 内嵌 Subscribe。
  private func withLiveSubscriptionAdmission<T>(
    _ operation: () async throws -> T
  ) async throws -> T {
    await acquireLiveSubscriptionAdmission()
    defer { releaseLiveSubscriptionAdmission() }
    guard !isTornDown, !Task.isCancelled else { throw CancellationError() }
    return try await operation()
  }

  private func acquireLiveSubscriptionAdmission() async {
    guard liveSubscriptionAdmissionHeld else {
      liveSubscriptionAdmissionHeld = true
      return
    }
    await withCheckedContinuation { continuation in
      liveSubscriptionAdmissionWaiters.append(continuation)
    }
  }

  private func releaseLiveSubscriptionAdmission() {
    guard !liveSubscriptionAdmissionWaiters.isEmpty else {
      liveSubscriptionAdmissionHeld = false
      return
    }
    liveSubscriptionAdmissionWaiters.removeFirst().resume()
  }

  private func ensureRuntimeStarted(
    requiredConversationID: RuntimeConversationID? = nil
  ) async throws -> RuntimeAgentDescriptionsV2 {
    guard !isTornDown else { throw CancellationError() }
    try await installFreshRuntimeCoordinatorIfNeeded()
    let lease = try currentRuntimeCoordinatorLease()
    if let runtimeBootstrapTask, let runtimeBootstrapTaskID {
      return try await awaitRuntimeBootstrap(
        runtimeBootstrapTask,
        taskID: runtimeBootstrapTaskID,
        lease: lease
      )
    }

    nextRuntimeBootstrapTaskID &+= 1
    let taskID = nextRuntimeBootstrapTaskID
    let task = Task { [weak self] in
      guard let self else { throw CancellationError() }
      guard !isTornDown else { throw CancellationError() }
      if !runtimeCoordinatorStarted {
        try await lease.coordinator.start()
        try requireCurrentRuntimeCoordinator(lease)
        runtimeCoordinatorStarted = true
      }
      let descriptions = try await lease.coordinator.describeAgents()
      try requireCurrentRuntimeCoordinator(lease)
      if runtimeConnectionRequiresSubscriptionRestore {
        try await restoreRequiredSubscriptions(
          using: lease,
          requiredConversationID: requiredConversationID
        )
        try requireCurrentRuntimeCoordinator(lease)
        runtimeConnectionRequiresSubscriptionRestore = false
      }
      try requireCurrentRuntimeCoordinator(lease)
      return descriptions
    }
    runtimeBootstrapTask = task
    runtimeBootstrapTaskID = taskID
    return try await awaitRuntimeBootstrap(task, taskID: taskID, lease: lease)
  }

  private func beginConversationBootstrap(
    _ admission: ConversationBootstrapAdmission,
    preservingBootstrapComposerLineage: Bool = false
  ) {
    precondition(pendingConversationBootstrapAdmission == nil)
    if !preservingBootstrapComposerLineage || bootstrapComposerLineageID == nil {
      bootstrapComposerLineageID = UUID()
    }
    pendingConversationBootstrapAdmission = admission
    retryRequiredConversationBootstrapAdmission = nil
    invalidateHistoryOpenIntent()
    phase = .starting
    errorMessage = nil
    warningMessage = nil

    Task { [weak self] in
      guard let self else { return }
      do {
        let descriptions = try await ensureRuntimeStarted()
        guard !isTornDown else { return }
        let draft = try RuntimeConversationDraft(
          agentKind: admission.agentKind,
          cwd: admission.cwd,
          prompt: admission.prompt?.rawValue,
          agentDescriptions: descriptions,
          idempotencyKeys: admission.idempotencyKeys
        )
        guard
          pendingConversationBootstrapAdmission?.idempotencyKeys
            == admission.idempotencyKeys
        else { return }
        guard
          startConversation(
            draft,
            preservingBootstrapComposerLineage: true
          )
        else {
          throw WorkbenchModelError.draftAlreadyInFlight
        }
      } catch {
        guard !isTornDown,
          pendingConversationBootstrapAdmission?.idempotencyKeys
            == admission.idempotencyKeys
        else { return }
        pendingConversationBootstrapAdmission = nil
        retryRequiredConversationBootstrapAdmission = admission
        recordOperationFailure(error)
      }
    }
  }

  private func finishConversationStartTask(taskID: UInt64) {
    guard conversationStartTaskID == taskID else { return }
    conversationStartTask = nil
    conversationStartTaskID = nil
  }

  private func recoverConversationAfterPromptFailure(
    _ failure: AppRuntimeConversationStartFailure,
    partialResult: AppRuntimeConversationStartResult,
    draft: RuntimeConversationDraft
  ) throws {
    try workbench.completeConversationStart(partialResult)
    guard let prompt = draft.prompt?.rawValue,
      let runtime = workbench.runtime(conversationID: partialResult.conversationID)
    else {
      throw SessionRuntimeModelError.conversationUnavailable(partialResult.conversationID)
    }
    runtime.retainBootstrapPromptForRetry(
      prompt,
      reusableIdempotencyKey: Self.promptFailureRequiresExactRetry(failure.underlying)
        ? draft.idempotencyKeys.prompt
        : nil,
      reusableExpectedConfigurationRevision: Self.promptFailureRequiresExactRetry(
        failure.underlying
      )
        ? Self.configurationRevision(from: partialResult.configurationReceipt)
        : nil
    )
    clearPendingConversationAdmission(matching: draft.idempotencyKeys)
    retryableConversationDraft = nil
    conversationStartRetryPolicy = nil
    bootstrapComposerLineageID = nil
    errorMessage = nil
    warningMessage = nil
    cwd = URL(fileURLWithPath: draft.cwd)
    phase = runtime.phase
    refreshHistoryPresentation()
    resetConversationViewport(prefix: "conversation:\(partialResult.conversationID.rawValue)")
    recordOperationFailure(
      failure.underlying,
      conversationID: partialResult.conversationID
    )
  }

  private static func retryDraft(
    after failure: AppRuntimeConversationStartFailure,
    original: RuntimeConversationDraft
  ) throws -> RuntimeConversationDraft {
    guard !promptFailureRequiresExactRetry(failure.underlying) else {
      return original
    }
    let originalKeys = original.idempotencyKeys
    let replacementKeys: RuntimeConversationIdempotencyKeys
    switch failure.stage {
    case .start:
      replacementKeys = .fresh()
    case .configure:
      replacementKeys = RuntimeConversationIdempotencyKeys(
        start: originalKeys.start,
        configure: freshIdempotencyKey(prefix: "configure"),
        prompt: originalKeys.prompt
      )
    case .synchronize:
      return original
    case .prompt:
      replacementKeys = RuntimeConversationIdempotencyKeys(
        start: originalKeys.start,
        configure: originalKeys.configure,
        prompt: freshIdempotencyKey(prefix: "prompt")
      )
    }
    return try original.replacingIdempotencyKeys(replacementKeys)
  }

  private static func retryPolicy(
    after failure: AppRuntimeConversationStartFailure
  ) -> ConversationStartRetryPolicy {
    guard !promptFailureRequiresExactRetry(failure.underlying) else {
      return .exact
    }
    switch failure.stage {
    case .start:
      return .replaceStart
    case .configure:
      return .replaceConfigure
    case .synchronize, .prompt:
      return .exact
    }
  }

  private func clearPendingConversationAdmission(
    matching idempotencyKeys: RuntimeConversationIdempotencyKeys
  ) {
    guard pendingConversationBootstrapAdmission?.idempotencyKeys == idempotencyKeys else {
      return
    }
    pendingConversationBootstrapAdmission = nil
  }

  private func awaitRuntimeBootstrap(
    _ task: Task<RuntimeAgentDescriptionsV2, Error>,
    taskID: UInt64,
    lease: RuntimeCoordinatorLease
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
      await invalidateRuntimeConnectionIfNeeded(
        after: error,
        failedCoordinator: lease
      )
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
    guard let runtime = workbench.runtime(conversationID: conversationID) else {
      recordOperationFailure(
        SessionRuntimeModelError.conversationUnavailable(conversationID),
        conversationID: conversationID
      )
      return
    }
    let phaseBeforeAdmission = runtime.phase
    let presentsAdmissionAsStarting =
      phaseBeforeAdmission == .idle || phaseBeforeAdmission == .ready
    let restoresReadyOnFailure = presentsAdmissionAsStarting

    do {
      guard let revision = runtime.expectedConfigurationRevision(for: idempotencyKey), revision > 0
      else {
        throw SessionRuntimeModelError.conversationNotConfigured(conversationID)
      }
      let payload = try RuntimePromptPayloadV1(rawValue: prompt)
      if presentsAdmissionAsStarting {
        runtime.phase = .starting
      }
      Task { [weak self] in
        guard let self else { return }
        var operationLease: RuntimeCoordinatorLease?
        do {
          _ = try await ensureRuntimeStarted(
            requiredConversationID: conversationID
          )
          guard !isTornDown else { return }
          let lease = try currentRuntimeCoordinatorLease()
          operationLease = lease
          try await synchronizeConversationIfNeeded(runtime, using: lease)
          let receipt = try await lease.coordinator.sendPrompt(
            conversationID: conversationID,
            idempotencyKey: idempotencyKey,
            expectedConfigurationRevision: revision,
            prompt: payload
          )
          try requireCurrentRuntimeCoordinator(lease)
          let nextAction = runtime.acknowledgeQueuedPrompt(
            prompt,
            idempotencyKey: idempotencyKey,
            receipt: receipt
          )
          dispatch(nextAction, runtime: runtime)
        } catch {
          let failureBelongsToCurrentGeneration =
            runtimeFailureBelongsToCurrentGeneration(operationLease)
          if failureBelongsToCurrentGeneration {
            await invalidateRuntimeConnectionIfNeeded(
              after: error,
              failedCoordinator: operationLease
            )
          }
          guard !isTornDown else { return }
          _ = runtime.failQueuedPromptDispatch(
            prompt,
            idempotencyKey: idempotencyKey,
            reuseIdempotencyKey: Self.promptFailureRequiresExactRetry(error)
          )
          if restoresReadyOnFailure, runtime.phase == .starting {
            runtime.phase = .ready
          }
          if failureBelongsToCurrentGeneration {
            recordOperationFailure(error, conversationID: conversationID)
          }
        }
      }
    } catch {
      guard !isTornDown else { return }
      _ = runtime.failQueuedPromptDispatch(
        prompt,
        idempotencyKey: idempotencyKey,
        reuseIdempotencyKey: false
      )
      if restoresReadyOnFailure, runtime.phase == .starting {
        runtime.phase = .ready
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
      var operationLease: RuntimeCoordinatorLease?
      do {
        _ = try await ensureRuntimeStarted(
          requiredConversationID: conversationID
        )
        guard !isTornDown else { return }
        let lease = try currentRuntimeCoordinatorLease()
        operationLease = lease
        let receipt = try await lease.coordinator.updateConversationMetadata(request)
        try requireCurrentRuntimeCoordinator(lease)
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
        guard runtimeFailureBelongsToCurrentGeneration(operationLease) else { return }
        await invalidateRuntimeConnectionIfNeeded(
          after: error,
          failedCoordinator: operationLease
        )
        guard !isTornDown else { return }
        historyErrorMessage = String(describing: error)
      }
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

  /// 未知错误默认保留 exact identity；只有有协议证据保证 pre-COMMIT 拒绝的 code 才允许 fresh。
  private static func promptFailureRequiresExactRetry(_ error: Error) -> Bool {
    retryIdentityPolicy(after: error) == .exactRequired
  }

  private static func retryIdentityPolicy(
    after error: Error
  ) -> MutationRetryIdentityPolicy {
    if error is RuntimeEnvelopeClientFailure { return .exactRequired }
    guard let coordinatorError = error as? AppRuntimeCoordinatorError else {
      return .exactRequired
    }
    switch coordinatorError {
    case .daemonFailure(let code, _, _):
      return daemonFailureAllowsFreshIdentity(code)
        ? .freshAllowed
        : .exactRequired
    case .notStarted,
      .alreadyStarted,
      .operationInProgress,
      .configurationConflict:
      return .freshAllowed
    case .unexpectedReply,
      .receiptConversationMismatch,
      .receiptApprovalMismatch,
      .receiptConfigurationRevisionMismatch,
      .closed,
      .missingSubscriptionReceipt,
      .unexpectedUnsubscribeReceipt,
      .subscriptionGenerationMismatch,
      .synchronizationTargetMismatch,
      .missingSynchronizationTerminal,
      .replyAfterSynchronizationTerminal,
      .synchronizationReplyLimitExceeded,
      .catalogPageLimitExceeded,
      .catalogPageCursorCycle:
      return .exactRequired
    }
  }

  private static func daemonFailureAllowsFreshIdentity(_ code: String) -> Bool {
    switch code {
    case "daemon.command.idempotency_conflict",
      "daemon.command.queue_full",
      "daemon.payload.item_too_large",
      "daemon.conversation.not_found",
      "daemon.conversation.configuration_required",
      "daemon.conversation.configuration_conflict",
      "daemon.runtime.invalid_request",
      "daemon.runtime.protocol_mismatch",
      "daemon.runtime.feature_unavailable",
      "daemon.runtime.not_ready",
      "daemon.runtime.recovery_blocked",
      "daemon.runtime.disk_low",
      "daemon.runtime.store_full",
      "daemon.runtime.store_busy",
      "daemon.runtime.recovering",
      "daemon.authorization.revoked",
      "daemon.authorization.permission_denied":
      return true
    default:
      // store_unavailable/actor_unavailable/connection/read/unknown code 可能折叠
      // after-COMMIT reply loss；保守 exact retry 由 daemon durable ledger 裁决。
      return false
    }
  }

  private static func requiresFreshRuntimeConnection(after error: Error) -> Bool {
    if error is RuntimeEnvelopeClientFailure { return true }
    guard let coordinatorError = error as? AppRuntimeCoordinatorError else { return false }
    switch coordinatorError {
    case .closed,
      .unexpectedReply,
      .receiptConversationMismatch,
      .receiptApprovalMismatch,
      .receiptConfigurationRevisionMismatch:
      return true
    case .notStarted,
      .alreadyStarted,
      .operationInProgress,
      .daemonFailure,
      .configurationConflict,
      .missingSubscriptionReceipt,
      .unexpectedUnsubscribeReceipt,
      .subscriptionGenerationMismatch,
      .synchronizationTargetMismatch,
      .missingSynchronizationTerminal,
      .replyAfterSynchronizationTerminal,
      .synchronizationReplyLimitExceeded,
      .catalogPageLimitExceeded,
      .catalogPageCursorCycle:
      return false
    }
  }

  private var hasBootstrapConversationIntent: Bool {
    pendingConversationBootstrapAdmission != nil
      || retryableConversationDraft != nil
      || retryRequiredConversationBootstrapAdmission != nil
  }

  private var promptComposerAgentKind: AgentKind {
    if let admission = pendingConversationBootstrapAdmission {
      return admission.agentKind
    }
    if let draft = retryableConversationDraft {
      return draft.agentKind
    }
    if let admission = retryRequiredConversationBootstrapAdmission {
      return admission.agentKind
    }
    return workbench.selectedRuntime?.agentKind ?? .codex
  }

  private func bootstrapComposerOwner(
    agentKind: AgentKind
  ) -> PromptComposerOwner {
    guard let bootstrapComposerLineageID else {
      preconditionFailure("bootstrap composer state requires a logical lineage")
    }
    return .bootstrap(
      agentKind: agentKind,
      lineageID: bootstrapComposerLineageID
    )
  }

  @discardableResult
  private func beginHistoryOpenIntent() -> UInt64 {
    historyOpenIntentGeneration &+= 1
    pendingHistoryOpenIntent = nil
    openingHistoryConversationID = nil
    return historyOpenIntentGeneration
  }

  private func invalidateHistoryOpenIntent() {
    historyOpenIntentGeneration &+= 1
    pendingHistoryOpenIntent = nil
    openingHistoryConversationID = nil
  }

  private func isCurrentHistoryOpenIntent(_ generation: UInt64) -> Bool {
    !isTornDown && historyOpenIntentGeneration == generation
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
    guard lhs.agentKind == rhs.agentKind, lhs.cwd == rhs.cwd else {
      return false
    }
    switch (lhs.prompt, rhs.prompt) {
    case (nil, nil):
      break
    case (.some(let lhsPrompt), .some(let rhsPrompt)):
      guard lhsPrompt.rawValue.utf8.elementsEqual(rhsPrompt.rawValue.utf8) else {
        return false
      }
    default:
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

  private static func configurationRevision(
    from receipt: RuntimeConfigurationReceiptV2
  ) -> UInt64? {
    switch receipt {
    case .applied(_, let revision), .replayed(_, let revision):
      return revision
    case .conflict, .failed:
      return nil
    }
  }

  private static func milliseconds(from start: Date, to end: Date) -> Int {
    max(0, Int((end.timeIntervalSince(start) * 1_000).rounded()))
  }
}

@MainActor
final class SessionRuntimeInboundBridge {
  weak var model: SessionModel?
  private let workbench: WorkbenchModel
  private var acceptsInbound = true
  private var activeConnectionGeneration: UInt64 = 0

  init(workbench: WorkbenchModel) {
    self.workbench = workbench
  }

  func ingest(
    _ inbound: AppRuntimeInbound,
    connectionGeneration: UInt64
  ) async throws {
    guard acceptsInbound, connectionGeneration == activeConnectionGeneration else { return }
    let action = try workbench.ingest(inbound)
    guard acceptsInbound, connectionGeneration == activeConnectionGeneration else { return }
    model?.didApplyInbound(inbound, action: action)
  }

  func connectionTerminated(connectionGeneration: UInt64) {
    guard acceptsInbound, connectionGeneration == activeConnectionGeneration else { return }
    model?.runtimeConnectionTerminated(connectionGeneration: connectionGeneration)
  }

  func activate(connectionGeneration: UInt64) {
    activeConnectionGeneration = connectionGeneration
  }

  func deactivate() {
    acceptsInbound = false
    model = nil
  }
}
