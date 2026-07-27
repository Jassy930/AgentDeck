import AgentDeckCore
import AgentDeckSessionSource
import Foundation

enum PromptSubmissionState: Equatable {
  case idle
  case sending(idempotencyKey: UUID)
  case queued(commandID: RuntimeCommandID, queuePosition: UInt32?)
  case failed(message: String)
}

enum ApprovalState: Equatable {
  case none
  case pending
  case submitting(ActionDecisionKind)
  case applied(ActionDecisionKind)
  case alreadyHandled(
    decision: ActionDecisionKind,
    deliveryState: ApprovalDeliveryStateV1
  )
  case submissionFailed(ActionDecisionKind)
  case deliveryFailed(ActionDecisionKind)
  case expired(ActionDecisionKind?)
}

@MainActor
final class SessionDetailViewModel {
  private struct PendingPrompt {
    let idempotencyKey: UUID
    let text: String
    var commandID: RuntimeCommandID?
    var queuePosition: UInt32?
  }

  private struct ApprovalContext {
    let turnID: RuntimeTurnID
    let commandID: RuntimeCommandID
    let approvalID: RuntimeApprovalID
    let request: RuntimeActionRequestV1
  }

  private struct ApprovalOperation {
    enum Kind: Equatable {
      case resolve
      case retryDelivery
    }

    let token: UUID
    let approvalID: RuntimeApprovalID
    let decision: ActionDecisionKind
    let kind: Kind
    let idempotencyKey: UUID?
    let canonicalTransitionCountAtStart: UInt64
    let canonicalEventFence: UInt64?
  }

  private struct ApprovalReceiptObservation {
    let approvalID: RuntimeApprovalID
    let decision: ActionDecisionKind?
    let deliveryState: ApprovalDeliveryStateV1
    let wasAlreadyHandled: Bool
    let canonicalTransitionCountAtStart: UInt64
    let canonicalEventFence: UInt64?
    var canonicalCaughtUp: Bool
  }

  private struct RetiredApprovalOperation {
    let operation: ApprovalOperation
    let canonicalDecision: ActionDecisionKind?
    let canonicalDeliveryState: ApprovalDeliveryStateV1
  }

  private struct ApprovalSnapshotFloor {
    let approvalID: RuntimeApprovalID
    let decision: ActionDecisionKind?
    let deliveryState: ApprovalDeliveryStateV1
  }

  private struct CanonicalApprovalResolutionEvent {
    let approvalID: RuntimeApprovalID
    let eventSeq: UInt64
  }

  private let source: any SessionSource
  let conversationID: String
  private(set) var rows: [ConversationDisplayRow] = []
  private(set) var pendingApproval: RuntimeActionRequestV1?
  private(set) var approvalState: ApprovalState = .none
  private(set) var promptState: PromptSubmissionState = .idle
  private(set) var draftText = ""
  private(set) var errorText: String?
  private(set) var isStreaming = false
  private(set) var connectionState: SessionConnectionState = .connecting
  var onUpdate: (() -> Void)?

  private var conversationState: RuntimeConversationState
  private var pendingPrompt: PendingPrompt?
  private var retryablePrompt: PendingPrompt?
  private var approvalContext: ApprovalContext?
  private var selectedApprovalDecision: ActionDecisionKind?
  private var locallySubmittedApprovalDecision: ActionDecisionKind?
  private var approvalWasAlreadyHandled = false
  private var canonicalApprovalDecision: ActionDecisionKind?
  private var canonicalApprovalDeliveryState: ApprovalDeliveryStateV1?
  private var approvalReceiptObservation: ApprovalReceiptObservation?
  private var approvalSnapshotFloor: ApprovalSnapshotFloor?
  private var lastCanonicalApprovalResolutionEvent: CanonicalApprovalResolutionEvent?
  private var canonicalApprovalTransitionCount: UInt64 = 0
  private var lastCanonicalDeliveryFailureTransition: UInt64?
  private var lastCanonicalDeliveryFailureEventSeq: UInt64?
  private var retryableApprovalSubmission: ApprovalOperation?
  private(set) var isTerminal = false
  private var observationTask: Task<Void, Never>?
  private var promptTask: Task<Void, Never>?
  private var promptTaskKey: UUID?
  private var approvalTask: Task<Void, Never>?
  private var approvalOperation: ApprovalOperation?
  private var retiredApprovalOperations: [UUID: RetiredApprovalOperation] = [:]
  private(set) var approvalResponseGeneration: UInt64 = 0

  private static let maxRetiredApprovalOperations = 32

  init(source: any SessionSource, conversationID: String) {
    precondition(!conversationID.isEmpty, "conversationID 不能为空")
    self.source = source
    self.conversationID = conversationID
    conversationState = try! RuntimeConversationState(
      conversationID: RuntimeConversationID(rawValue: conversationID)
    )
  }

  func start() {
    guard !isTerminal, observationTask == nil else { return }
    let source = source
    let conversationID = conversationID
    observationTask = Task { [weak self, source, conversationID] in
      let stream = await source.conversation(conversationID: conversationID)
      for await update in stream {
        guard !Task.isCancelled, let self else { break }
        handle(update)
      }
      guard let self else { return }
      observationTask = nil
    }
  }

  func updateDraft(_ text: String) {
    draftText = text
  }

  func sendPrompt(_ text: String) {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !isTerminal, !trimmed.isEmpty, pendingPrompt == nil, promptTask == nil else {
      return
    }

    draftText = text
    errorText = nil
    let idempotencyKey: UUID
    if let retryablePrompt, retryablePrompt.text == trimmed {
      idempotencyKey = retryablePrompt.idempotencyKey
    } else {
      idempotencyKey = UUID()
    }
    retryablePrompt = nil
    pendingPrompt = PendingPrompt(
      idempotencyKey: idempotencyKey,
      text: trimmed,
      commandID: nil,
      queuePosition: nil
    )
    promptState = .sending(idempotencyKey: idempotencyKey)
    isStreaming = true
    rebuildRows()
    onUpdate?()

    let source = source
    let conversationID = conversationID
    promptTaskKey = idempotencyKey
    promptTask = Task { [weak self, source, conversationID] in
      do {
        let receipt = try await source.sendPrompt(
          conversationID: conversationID,
          text: trimmed,
          idempotencyKey: idempotencyKey
        )
        guard let self else { return }
        finishPromptTask(idempotencyKey: idempotencyKey)
        handleCommandReceipt(receipt, idempotencyKey: idempotencyKey)
      } catch {
        guard let self else { return }
        finishPromptTask(idempotencyKey: idempotencyKey)
        failPrompt(error, idempotencyKey: idempotencyKey)
      }
    }
  }

  func resolveApproval(approve: Bool) {
    guard !isTerminal,
      approvalOperation == nil,
      approvalState == .pending,
      let context = approvalContext
    else { return }
    let decision: ActionDecisionKind = approve ? .approve : .deny
    let idempotencyKey = UUID()
    let operation = ApprovalOperation(
      token: UUID(),
      approvalID: context.approvalID,
      decision: decision,
      kind: .resolve,
      idempotencyKey: idempotencyKey,
      canonicalTransitionCountAtStart: canonicalApprovalTransitionCount,
      canonicalEventFence: currentCanonicalEventSequence()
    )
    retryableApprovalSubmission = nil
    approvalOperation = operation
    selectedApprovalDecision = decision
    locallySubmittedApprovalDecision = decision
    approvalWasAlreadyHandled = false
    approvalState = .submitting(decision)
    errorText = nil
    onUpdate?()
    launchApprovalResolution(context: context, operation: operation)
  }

  private func launchApprovalResolution(
    context: ApprovalContext,
    operation: ApprovalOperation
  ) {
    guard let idempotencyKey = operation.idempotencyKey else {
      preconditionFailure("approval resolve 必须绑定 idempotency key")
    }
    let source = source
    let conversationID = conversationID
    approvalTask = Task { [weak self, source, conversationID] in
      do {
        let receipt = try await source.resolveApproval(
          conversationID: conversationID,
          turnID: context.turnID.rawValue,
          approvalID: context.approvalID.rawValue,
          decision: operation.decision,
          idempotencyKey: idempotencyKey
        )
        guard let self else { return }
        handleApprovalReceipt(
          receipt,
          submittedDecision: operation.decision,
          expectedApprovalID: context.approvalID,
          operationToken: operation.token
        )
        approvalResponseGeneration &+= 1
      } catch {
        guard let self else { return }
        handleApprovalFailure(error, operation: operation)
        approvalResponseGeneration &+= 1
      }
      guard let self else { return }
      finishApprovalOperation(operation.token)
    }
  }

  func retryApprovalDelivery() {
    guard !isTerminal,
      approvalOperation == nil,
      let context = approvalContext
    else { return }

    if case .submissionFailed = approvalState,
      let retryable = retryableApprovalSubmission,
      retryable.approvalID == context.approvalID,
      retryable.kind == .resolve,
      retryable.idempotencyKey != nil
    {
      let operation = ApprovalOperation(
        token: UUID(),
        approvalID: retryable.approvalID,
        decision: retryable.decision,
        kind: .resolve,
        idempotencyKey: retryable.idempotencyKey,
        canonicalTransitionCountAtStart: canonicalApprovalTransitionCount,
        canonicalEventFence: currentCanonicalEventSequence()
      )
      approvalOperation = operation
      selectedApprovalDecision = operation.decision
      approvalState = .submitting(operation.decision)
      errorText = nil
      onUpdate?()
      launchApprovalResolution(context: context, operation: operation)
      return
    }

    let decision: ActionDecisionKind
    switch approvalState {
    case .deliveryFailed(let winner):
      decision = winner
    case .alreadyHandled(let winner, .deliveryFailed):
      decision = winner
    default:
      return
    }
    guard let failureEventSeq = lastCanonicalDeliveryFailureEventSeq,
      let currentEventSeq = currentCanonicalEventSequence(),
      currentEventSeq >= failureEventSeq
    else {
      errorText = "等待审批投递失败状态同步后再重试"
      onUpdate?()
      return
    }

    let operation = ApprovalOperation(
      token: UUID(),
      approvalID: context.approvalID,
      decision: decision,
      kind: .retryDelivery,
      idempotencyKey: nil,
      canonicalTransitionCountAtStart: canonicalApprovalTransitionCount,
      canonicalEventFence: currentCanonicalEventSequence()
    )
    approvalOperation = operation
    selectedApprovalDecision = decision
    approvalState = .submitting(decision)
    errorText = nil
    onUpdate?()
    let source = source
    let conversationID = conversationID
    approvalTask = Task { [weak self, source, conversationID] in
      do {
        let receipt = try await source.retryApprovalDelivery(
          conversationID: conversationID,
          approvalID: context.approvalID.rawValue
        )
        guard let self else { return }
        handleApprovalReceipt(
          receipt,
          submittedDecision: decision,
          expectedApprovalID: context.approvalID,
          operationToken: operation.token
        )
        approvalResponseGeneration &+= 1
      } catch {
        guard let self else { return }
        handleApprovalFailure(error, operation: operation)
        approvalResponseGeneration &+= 1
      }
      guard let self else { return }
      finishApprovalOperation(operation.token)
    }
  }

  private func handle(_ update: ConversationUpdate) {
    guard !isTerminal else { return }
    do {
      switch update {
      case .snapshot(let snapshot):
        let wasRecoveringFromLag: Bool
        if case .lagged = connectionState {
          wasRecoveringFromLag = true
        } else {
          wasRecoveringFromLag = false
        }
        try conversationState.apply(snapshot)
        prepareApprovalProjectionForSnapshot()
        synchronizeConversationProjection()
        if wasRecoveringFromLag, !isTerminal {
          handleConnectionState(.connected)
        }
      case .event(let event):
        try conversationState.apply(event)
        handleEventLifecycle(event)
        synchronizeConversationProjection()
      case .commandState(let receipt):
        handleCommandStatus(receipt)
      case .connectionState(let state):
        handleConnectionState(state)
      }
    } catch {
      enterTerminal(
        .securityError,
        message: "会话事件校验失败：\(error)"
      )
    }
    rebuildRows()
    onUpdate?()
  }

  private func synchronizeConversationProjection() {
    if let resolution = conversationState.lastApprovalResolution,
      approvalContext?.approvalID == resolution.approvalID
    {
      guard approvalContext?.turnID == resolution.turnID,
        approvalContext?.commandID == resolution.commandID,
        resolution.requestID == nil
          || approvalContext?.request.requestID == resolution.requestID
      else {
        enterTerminal(
          .securityError,
          message: "恢复后的审批结果身份与既有证据不匹配"
        )
        return
      }
      applyCanonicalApprovalResolution(resolution)
      guard !isTerminal else { return }
    }

    if let context = approvalContext,
      let turnTerminal = conversationState.turnTerminal
    {
      let terminalTurnMatchesContext: Bool
      let terminalCommandID: RuntimeCommandID
      switch turnTerminal {
      case .completed(
        let turnID, let commandID,
        summary: _
      ),
        .interrupted(let turnID, let commandID):
        terminalTurnMatchesContext = turnID == context.turnID
        terminalCommandID = commandID
      case .failed(
        let turnID, let commandID,
        failure: _
      ):
        terminalTurnMatchesContext = turnID == nil || turnID == context.turnID
        terminalCommandID = commandID
      }
      guard terminalTurnMatchesContext,
        context.commandID == terminalCommandID,
        approvalProjectionIsTerminalForTurnAdvance
      else {
        enterTerminal(
          .securityError,
          message: "turn 终态与本地审批证据不一致"
        )
        return
      }
    }

    if let context = approvalContext,
      let activeTurn = conversationState.activeTurn,
      activeTurn.turnID != context.turnID
        || activeTurn.commandID != context.commandID,
      conversationState.pendingApproval?.approvalID != context.approvalID,
      conversationState.lastApprovalResolution?.approvalID != context.approvalID
    {
      guard approvalOperation == nil else {
        enterTerminal(
          .securityError,
          message: "新 turn 到达时旧审批操作仍在途"
        )
        return
      }
      guard approvalProjectionIsTerminalForTurnAdvance else {
        enterTerminal(
          .securityError,
          message: "新 turn 到达时旧审批仍处于非终态"
        )
        return
      }
      clearApprovalProjectionForTurnAdvance()
    }

    if let pending = conversationState.pendingApproval {
      if let context = approvalContext,
        context.approvalID == pending.approvalID
      {
        guard context.turnID == pending.turnID,
          context.commandID == pending.commandID,
          context.request.requestID == pending.requestID
        else {
          enterTerminal(
            .securityError,
            message: "恢复后的审批身份与既有证据不匹配"
          )
          return
        }
        pendingApproval = pending.request
      } else {
        if let context = approvalContext,
          context.turnID == pending.turnID,
          context.commandID == pending.commandID,
          !approvalProjectionIsTerminalForTurnAdvance,
          conversationState.lastApprovalResolution?.approvalID != context.approvalID
        {
          enterTerminal(
            .securityError,
            message: "恢复后的未决审批被外来 approval 身份替换"
          )
          return
        }
        if let resolution = conversationState.lastApprovalResolution,
          resolution.approvalID == approvalOperation?.approvalID
        {
          retireApprovalOperation(for: resolution)
          guard !isTerminal else { return }
        } else {
          invalidateApprovalOperation()
        }
        approvalContext = ApprovalContext(
          turnID: pending.turnID,
          commandID: pending.commandID,
          approvalID: pending.approvalID,
          request: pending.request
        )
        pendingApproval = pending.request
        selectedApprovalDecision = nil
        locallySubmittedApprovalDecision = nil
        approvalWasAlreadyHandled = false
        canonicalApprovalDecision = nil
        canonicalApprovalDeliveryState = nil
        approvalReceiptObservation = nil
        approvalSnapshotFloor = nil
        lastCanonicalApprovalResolutionEvent = nil
        canonicalApprovalTransitionCount = 0
        lastCanonicalDeliveryFailureTransition = nil
        lastCanonicalDeliveryFailureEventSeq = nil
        retryableApprovalSubmission = nil
        approvalState = .pending
      }
    }
    if let failure = conversationState.failure {
      errorText = failure.value.message
      if failure.commandID != nil {
        isStreaming = false
      }
    }
    reconcilePendingPromptWithCanonicalEvidence()
  }

  private var approvalProjectionIsTerminalForTurnAdvance: Bool {
    switch approvalState {
    case .applied, .expired:
      return true
    case .alreadyHandled(_, let deliveryState):
      return deliveryState == .applied || deliveryState == .expired
    case .none, .pending, .submitting, .submissionFailed, .deliveryFailed:
      return false
    }
  }

  private func clearApprovalProjectionForTurnAdvance() {
    approvalContext = nil
    pendingApproval = nil
    selectedApprovalDecision = nil
    locallySubmittedApprovalDecision = nil
    approvalWasAlreadyHandled = false
    canonicalApprovalDecision = nil
    canonicalApprovalDeliveryState = nil
    approvalReceiptObservation = nil
    approvalSnapshotFloor = nil
    lastCanonicalApprovalResolutionEvent = nil
    canonicalApprovalTransitionCount = 0
    lastCanonicalDeliveryFailureTransition = nil
    lastCanonicalDeliveryFailureEventSeq = nil
    retryableApprovalSubmission = nil
    approvalState = .none
  }

  /// Snapshot 只开启新的 canonical generation；receipt、在途 operation 与既有审批身份
  /// 属于同一长期 observation 的本地证据，不能被 recovery barrier 清空。
  private func prepareApprovalProjectionForSnapshot() {
    if approvalSnapshotFloor == nil {
      approvalSnapshotFloor = currentApprovalSnapshotFloor()
    }
    if let receipt = approvalReceiptObservation {
      approvalReceiptObservation = ApprovalReceiptObservation(
        approvalID: receipt.approvalID,
        decision: receipt.decision,
        deliveryState: receipt.deliveryState,
        wasAlreadyHandled: receipt.wasAlreadyHandled,
        canonicalTransitionCountAtStart: canonicalApprovalTransitionCount,
        canonicalEventFence: receipt.canonicalEventFence,
        canonicalCaughtUp: false
      )
    }
    canonicalApprovalDecision = nil
    canonicalApprovalDeliveryState = nil
    lastCanonicalApprovalResolutionEvent = nil
    lastCanonicalDeliveryFailureTransition = nil
  }

  private func currentApprovalSnapshotFloor() -> ApprovalSnapshotFloor? {
    guard let context = approvalContext else { return nil }
    let evidence: (ActionDecisionKind?, ApprovalDeliveryStateV1)?
    switch approvalState {
    case .applied(let decision):
      evidence = (decision, .applied)
    case .alreadyHandled(let decision, let deliveryState):
      evidence = (decision, deliveryState)
    case .deliveryFailed(let decision):
      evidence = (decision, .deliveryFailed)
    case .expired(let decision):
      evidence = (decision, .expired)
    case .submitting:
      if let deliveryState = canonicalApprovalDeliveryState {
        evidence = (canonicalApprovalDecision ?? selectedApprovalDecision, deliveryState)
      } else {
        evidence = nil
      }
    case .none, .pending, .submissionFailed:
      evidence = nil
    }
    guard let evidence else { return nil }
    return ApprovalSnapshotFloor(
      approvalID: context.approvalID,
      decision: evidence.0,
      deliveryState: evidence.1
    )
  }

  private func applyCanonicalApprovalResolution(
    _ resolution: RuntimeConversationApprovalResolution
  ) {
    let canonicalEventSeq: UInt64?
    if lastCanonicalApprovalResolutionEvent?.approvalID == resolution.approvalID {
      canonicalEventSeq = lastCanonicalApprovalResolutionEvent?.eventSeq
    } else {
      canonicalEventSeq = nil
    }
    if let canonicalEventSeq,
      let failureEventSeq = lastCanonicalDeliveryFailureEventSeq,
      canonicalEventSeq <= failureEventSeq,
      resolution.deliveryState == .applied
        || resolution.deliveryState == .expired
    {
      enterTerminal(
        .securityError,
        message: "审批 canonical 在同一游标发生分叉"
      )
      return
    }
    if let receipt = approvalReceiptObservation,
      receipt.approvalID == resolution.approvalID,
      receipt.decision != resolution.decision
    {
      enterTerminal(
        .securityError,
        message: "审批 canonical 与回执的赢家不一致"
      )
      return
    }
    if let floor = approvalSnapshotFloor,
      floor.approvalID == resolution.approvalID,
      floor.decision != resolution.decision
    {
      enterTerminal(
        .securityError,
        message: "审批 canonical 与恢复前证据的赢家不一致"
      )
      return
    }

    let isNewTransition =
      canonicalApprovalDecision != resolution.decision
      || canonicalApprovalDeliveryState != resolution.deliveryState
    if isNewTransition {
      canonicalApprovalTransitionCount &+= 1
      if resolution.deliveryState == .deliveryFailed {
        lastCanonicalDeliveryFailureTransition = canonicalApprovalTransitionCount
      }
    }
    switch resolution.deliveryState {
    case .deliveryFailed:
      if let canonicalEventSeq,
        canonicalEventSeq >= (lastCanonicalDeliveryFailureEventSeq ?? 0)
      {
        lastCanonicalDeliveryFailureEventSeq = canonicalEventSeq
      }
    case .applied, .expired:
      if let canonicalEventSeq,
        let failureEventSeq = lastCanonicalDeliveryFailureEventSeq,
        canonicalEventSeq > failureEventSeq
      {
        lastCanonicalDeliveryFailureEventSeq = nil
      }
    case .claimed, .applying:
      break
    }
    if let decision = resolution.decision {
      if let expectedDecision = selectedApprovalDecision
        ?? locallySubmittedApprovalDecision
      {
        if expectedDecision != decision {
          approvalWasAlreadyHandled = true
        }
      } else {
        approvalWasAlreadyHandled = true
      }
    }
    if let decision = resolution.decision {
      selectedApprovalDecision = decision
    }
    canonicalApprovalDecision = resolution.decision
    canonicalApprovalDeliveryState = resolution.deliveryState
    retryableApprovalSubmission = nil
    updateReceiptCatchUpAgainstCanonical()
    updateSnapshotFloorAgainstCanonical(resolution)
    applyEffectiveApprovalDeliveryState()
    switch resolution.deliveryState {
    case .claimed, .applying:
      break
    case .applied, .deliveryFailed, .expired:
      if shouldRetireApprovalOperation(
        approvalID: resolution.approvalID,
        canonicalEventSeq: canonicalEventSeq
      ) {
        retireApprovalOperation(for: resolution)
      }
    }
  }

  private func updateSnapshotFloorAgainstCanonical(
    _ resolution: RuntimeConversationApprovalResolution
  ) {
    guard let floor = approvalSnapshotFloor,
      floor.approvalID == resolution.approvalID
    else { return }

    let canonicalCoversFloor: Bool
    switch floor.deliveryState {
    case .claimed:
      canonicalCoversFloor = true
    case .applying:
      canonicalCoversFloor = resolution.deliveryState != .claimed
    case .applied:
      canonicalCoversFloor = resolution.deliveryState == .applied
    case .deliveryFailed:
      canonicalCoversFloor =
        resolution.deliveryState == .deliveryFailed
        || (resolution.deliveryState == .applying
          && approvalOperation?.kind == .retryDelivery
          && canonicalResolutionEventIsAfterFence(
            approvalOperation?.canonicalEventFence,
            approvalID: resolution.approvalID
          ))
        || resolution.deliveryState == .applied
        || resolution.deliveryState == .expired
    case .expired:
      canonicalCoversFloor = resolution.deliveryState == .expired
    }
    if canonicalCoversFloor {
      approvalSnapshotFloor = nil
    }
  }

  private func updateReceiptCatchUpAgainstCanonical() {
    guard var receipt = approvalReceiptObservation,
      !receipt.canonicalCaughtUp,
      receipt.approvalID == approvalContext?.approvalID,
      let canonicalState = canonicalApprovalDeliveryState
    else { return }

    let canonicalAdvancedDuringOperation = canonicalResolutionEventIsAfterFence(
      receipt.canonicalEventFence,
      approvalID: receipt.approvalID
    )
    let currentStateCoversReceipt: Bool
    switch receipt.deliveryState {
    case .claimed:
      currentStateCoversReceipt = canonicalAdvancedDuringOperation
    case .applying:
      currentStateCoversReceipt =
        canonicalState != .claimed
        && canonicalAdvancedDuringOperation
    case .applied:
      currentStateCoversReceipt =
        canonicalState == .applied && canonicalAdvancedDuringOperation
    case .deliveryFailed:
      currentStateCoversReceipt =
        (canonicalState == .deliveryFailed && canonicalAdvancedDuringOperation)
        || ((canonicalState == .applied || canonicalState == .expired)
          && canonicalAdvancedDuringOperation)
    case .expired:
      currentStateCoversReceipt =
        canonicalState == .expired && canonicalAdvancedDuringOperation
    }
    if currentStateCoversReceipt {
      receipt.canonicalCaughtUp = true
      approvalReceiptObservation = receipt
    }
  }

  private func applyEffectiveApprovalDeliveryState() {
    if let floor = approvalSnapshotFloor,
      floor.approvalID == approvalContext?.approvalID
    {
      applyApprovalDeliveryState(
        floor.deliveryState,
        decision: floor.decision
      )
      return
    }
    if let receipt = approvalReceiptObservation,
      !receipt.canonicalCaughtUp
    {
      applyApprovalDeliveryState(
        receipt.deliveryState,
        decision: receipt.decision
      )
      return
    }
    let decision =
      canonicalApprovalDecision
      ?? approvalReceiptObservation?.decision
      ?? selectedApprovalDecision
    let deliveryState: ApprovalDeliveryStateV1?
    deliveryState =
      canonicalApprovalDeliveryState
      ?? approvalReceiptObservation?.deliveryState
    guard let deliveryState else { return }
    applyApprovalDeliveryState(deliveryState, decision: decision)
  }

  private func applyApprovalDeliveryState(
    _ deliveryState: ApprovalDeliveryStateV1,
    decision: ActionDecisionKind?
  ) {
    if approvalWasAlreadyHandled, let decision {
      approvalState = .alreadyHandled(
        decision: decision,
        deliveryState: deliveryState
      )
      return
    }
    switch deliveryState {
    case .claimed, .applying:
      if let decision { approvalState = .submitting(decision) }
    case .applied:
      if let decision { approvalState = .applied(decision) }
    case .deliveryFailed:
      if let decision { approvalState = .deliveryFailed(decision) }
    case .expired:
      approvalState = .expired(decision)
    }
  }

  private func handleEventLifecycle(_ event: RuntimeEventV2) {
    switch event.body {
    case .turnStarted:
      isStreaming = true
    case .turnCompleted, .turnInterrupted:
      isStreaming = false
    case .error:
      if event.commandID != nil {
        isStreaming = false
      }
    case .approvalResolved(_, let approvalID, _, _):
      lastCanonicalApprovalResolutionEvent = CanonicalApprovalResolutionEvent(
        approvalID: approvalID,
        eventSeq: event.eventSeq
      )
    case .capabilities, .configurationChanged, .vendorPanelEvent, .item,
      .actionRequest:
      break
    }
  }

  private func handleCommandReceipt(
    _ receipt: CommandReceipt,
    idempotencyKey: UUID
  ) {
    guard var prompt = pendingPrompt, prompt.idempotencyKey == idempotencyKey else {
      return
    }
    switch receipt {
    case .accepted(let commandID, let queuePosition, _):
      retryablePrompt = nil
      prompt.commandID = commandID
      prompt.queuePosition = queuePosition
      pendingPrompt = prompt
      promptState = .queued(commandID: commandID, queuePosition: queuePosition)
      draftText = ""
      reconcilePendingPromptWithCanonicalEvidence()
    case .replayed(let commandID, _):
      retryablePrompt = nil
      prompt.commandID = commandID
      pendingPrompt = prompt
      promptState = .queued(commandID: commandID, queuePosition: nil)
      draftText = ""
      reconcilePendingPromptWithCanonicalEvidence()
    case .failed(let failure):
      retryablePrompt = nil
      pendingPrompt = nil
      promptState = .failed(message: failure.message)
      errorText = failure.message
      isStreaming = false
    }
    rebuildRows()
    onUpdate?()
  }

  private func failPrompt(_ error: any Error, idempotencyKey: UUID) {
    guard let prompt = pendingPrompt, prompt.idempotencyKey == idempotencyKey else { return }
    if enterTerminalIfRequired(error) {
      rebuildRows()
      onUpdate?()
      return
    }
    let message = sourceFailureMessage(error)
    if let failure = error as? SessionSourceFailure,
      failure.code == .transportUnavailable
    {
      retryablePrompt = prompt
    } else {
      retryablePrompt = nil
    }
    pendingPrompt = nil
    promptState = .failed(message: message)
    errorText = message
    isStreaming = false
    rebuildRows()
    onUpdate?()
  }

  private func finishPromptTask(idempotencyKey: UUID) {
    guard promptTaskKey == idempotencyKey else { return }
    promptTaskKey = nil
    promptTask = nil
  }

  private func reconcilePendingPromptWithCanonicalEvidence() {
    guard let prompt = pendingPrompt, let commandID = prompt.commandID else { return }
    let canonicalUserArrived = zip(
      conversationState.canonicalItemIdentities,
      conversationState.items
    ).contains { identity, item in
      identity.commandID == commandID && item.kind == "user"
    }
    if canonicalUserArrived {
      pendingPrompt = nil
      promptState = .idle
      return
    }

    guard let terminal = conversationState.turnTerminal else { return }
    switch terminal {
    case .failed(_, let terminalCommandID, let failure):
      guard terminalCommandID == commandID else { return }
      retryablePrompt = nil
      pendingPrompt = nil
      draftText = prompt.text
      promptState = .failed(message: failure.message)
      errorText = failure.message
      isStreaming = false
    case .completed(_, let terminalCommandID, _),
      .interrupted(_, let terminalCommandID):
      guard terminalCommandID == commandID else { return }
      pendingPrompt = nil
      promptState = .idle
    }
  }

  private func handleCommandStatus(_ receipt: CommandStatusReceiptV2) {
    guard receipt.conversationID.rawValue == conversationID else {
      enterTerminal(.securityError, message: "命令状态属于另一会话")
      return
    }
    let pendingCommandID = pendingPrompt?.commandID
    let activeCommandID = conversationState.activeTurn?.commandID
    guard receipt.commandID == pendingCommandID || receipt.commandID == activeCommandID else {
      return
    }
    switch receipt.status {
    case .accepted, .started:
      isStreaming = true
    case .completed:
      isStreaming = false
    case .failed, .interrupted, .expired, .canceled, .revokedBeforeStart:
      isStreaming = false
      errorText = "命令状态：\(receipt.status.rawValue)"
      if let prompt = pendingPrompt, prompt.commandID == receipt.commandID {
        pendingPrompt = nil
        draftText = prompt.text
        promptState = .failed(message: errorText ?? "命令失败")
      }
    }
  }

  private func handleConnectionState(_ state: SessionConnectionState) {
    connectionState = state
    switch state {
    case .connecting:
      break
    case .connected:
      let connectionErrors: Set<String> = [
        "Relay 不可达", "机器离线", "正在重连", "事件流落后，正在重新同步",
      ]
      if let errorText, connectionErrors.contains(errorText) {
        self.errorText = nil
      }
    case .relayUnavailable:
      errorText = "Relay 不可达"
    case .machineOffline:
      errorText = "机器离线"
    case .reconnecting:
      errorText = "正在重连"
    case .lagged:
      errorText = "事件流落后，正在重新同步"
    case .revoked:
      enterTerminal(.revoked, message: "授权已撤销")
    case .incompatible:
      enterTerminal(.incompatible, message: "版本不兼容")
    case .securityError:
      enterTerminal(.securityError, message: "安全校验失败")
    }
  }

  private func enterTerminal(
    _ state: SessionConnectionState,
    message: String
  ) {
    isTerminal = true
    connectionState = state
    errorText = message
    isStreaming = false
    observationTask?.cancel()
    promptTask?.cancel()
    promptTask = nil
    promptTaskKey = nil
    if let prompt = pendingPrompt {
      draftText = prompt.text
      promptState = .failed(message: message)
    }
    pendingPrompt = nil
    retryablePrompt = nil
    invalidateApprovalOperation()
    retiredApprovalOperations.removeAll(keepingCapacity: false)
    retryableApprovalSubmission = nil
    approvalSnapshotFloor = nil
    lastCanonicalApprovalResolutionEvent = nil
    lastCanonicalDeliveryFailureEventSeq = nil
    approvalContext = nil
    pendingApproval = nil
    approvalState = .none
  }

  private func handleApprovalReceipt(
    _ receipt: ApprovalReceipt,
    submittedDecision: ActionDecisionKind,
    expectedApprovalID: RuntimeApprovalID,
    operationToken: UUID
  ) {
    let activeOperation = approvalOperation.flatMap { operation in
      operation.token == operationToken ? operation : nil
    }
    let retiredOperation = retiredApprovalOperations[operationToken]
    guard let operation = activeOperation ?? retiredOperation?.operation,
      operation.approvalID == expectedApprovalID
    else { return }

    let actualApprovalID: RuntimeApprovalID
    let receiptDecision: ActionDecisionKind?
    let receiptDeliveryState: ApprovalDeliveryStateV1
    let wasAlreadyHandled: Bool
    switch receipt {
    case .claimed(let approvalID):
      actualApprovalID = approvalID
      receiptDecision = submittedDecision
      receiptDeliveryState = .claimed
      wasAlreadyHandled = false
    case .applied(let approvalID):
      actualApprovalID = approvalID
      receiptDecision = submittedDecision
      receiptDeliveryState = .applied
      wasAlreadyHandled = false
    case .alreadyHandled(let approvalID, let decision, let state):
      actualApprovalID = approvalID
      receiptDecision = decision
      receiptDeliveryState = state
      wasAlreadyHandled = true
    case .deliveryFailed(let approvalID):
      actualApprovalID = approvalID
      receiptDecision = submittedDecision
      receiptDeliveryState = .deliveryFailed
      wasAlreadyHandled = false
    case .expired(let approvalID):
      actualApprovalID = approvalID
      receiptDecision = nil
      receiptDeliveryState = .expired
      wasAlreadyHandled = false
    }
    guard actualApprovalID == expectedApprovalID else {
      enterTerminal(.securityError, message: "审批回执身份不匹配")
      rebuildRows()
      onUpdate?()
      return
    }

    if let retiredOperation {
      if retiredOperation.canonicalDecision != receiptDecision {
        enterTerminal(
          .securityError,
          message: "迟到审批回执与 canonical 赢家不一致"
        )
        rebuildRows()
        onUpdate?()
        return
      }
      if !approvalDeliveryEvidenceIsCompatible(
        retiredOperation.canonicalDeliveryState,
        receiptDeliveryState,
        operationKind: retiredOperation.operation.kind
      ) {
        enterTerminal(
          .securityError,
          message: "迟到审批回执与 canonical 投递终态互斥"
        )
        rebuildRows()
        onUpdate?()
      }
      return
    }

    guard approvalContext?.approvalID == expectedApprovalID else { return }

    if canonicalApprovalDeliveryState != nil,
      canonicalApprovalDecision != receiptDecision
    {
      enterTerminal(
        .securityError,
        message: "审批 canonical 与回执的赢家不一致"
      )
      rebuildRows()
      onUpdate?()
      return
    }
    if let floor = approvalSnapshotFloor,
      floor.approvalID == expectedApprovalID,
      floor.decision != receiptDecision
    {
      enterTerminal(
        .securityError,
        message: "审批回执与恢复前证据的赢家不一致"
      )
      rebuildRows()
      onUpdate?()
      return
    }

    selectedApprovalDecision = receiptDecision
    retryableApprovalSubmission = nil
    if wasAlreadyHandled, operation.kind == .resolve {
      approvalWasAlreadyHandled = true
    }
    approvalReceiptObservation = ApprovalReceiptObservation(
      approvalID: expectedApprovalID,
      decision: receiptDecision,
      deliveryState: receiptDeliveryState,
      wasAlreadyHandled: wasAlreadyHandled,
      canonicalTransitionCountAtStart: operation.canonicalTransitionCountAtStart,
      canonicalEventFence: operation.canonicalEventFence,
      canonicalCaughtUp: false
    )
    advanceSnapshotFloor(
      approvalID: expectedApprovalID,
      decision: receiptDecision,
      deliveryState: receiptDeliveryState,
      operationKind: operation.kind
    )
    updateReceiptCatchUpAgainstCanonical()
    applyEffectiveApprovalDeliveryState()
    onUpdate?()
  }

  private func advanceSnapshotFloor(
    approvalID: RuntimeApprovalID,
    decision: ActionDecisionKind?,
    deliveryState: ApprovalDeliveryStateV1,
    operationKind: ApprovalOperation.Kind
  ) {
    guard let floor = approvalSnapshotFloor,
      floor.approvalID == approvalID
    else { return }

    if approvalDeliveryTransitionIsAllowed(
      from: floor.deliveryState,
      to: deliveryState,
      operationKind: operationKind
    ) {
      approvalSnapshotFloor = ApprovalSnapshotFloor(
        approvalID: approvalID,
        decision: decision,
        deliveryState: deliveryState
      )
    }
  }

  private func approvalDeliveryTransitionIsAllowed(
    from current: ApprovalDeliveryStateV1,
    to next: ApprovalDeliveryStateV1,
    operationKind: ApprovalOperation.Kind
  ) -> Bool {
    switch (current, next) {
    case (let current, let next) where current == next:
      return true
    case (.claimed, .applying),
      (.claimed, .applied),
      (.claimed, .deliveryFailed),
      (.claimed, .expired),
      (.applying, .applied),
      (.applying, .deliveryFailed),
      (.applying, .expired),
      (.deliveryFailed, .applied),
      (.deliveryFailed, .expired):
      return true
    case (.deliveryFailed, .applying):
      return operationKind == .retryDelivery
    default:
      return false
    }
  }

  private func approvalDeliveryEvidenceIsCompatible(
    _ canonical: ApprovalDeliveryStateV1,
    _ receipt: ApprovalDeliveryStateV1,
    operationKind: ApprovalOperation.Kind
  ) -> Bool {
    approvalDeliveryTransitionIsAllowed(
      from: canonical,
      to: receipt,
      operationKind: operationKind
    )
      || approvalDeliveryTransitionIsAllowed(
        from: receipt,
        to: canonical,
        operationKind: operationKind
      )
  }

  private func handleApprovalFailure(
    _ error: any Error,
    operation: ApprovalOperation
  ) {
    if enterTerminalIfRequired(error) {
      rebuildRows()
      onUpdate?()
      return
    }
    if retiredApprovalOperations[operation.token] != nil { return }
    guard approvalOperation?.token == operation.token,
      approvalContext?.approvalID == operation.approvalID
    else { return }
    if operation.kind == .retryDelivery {
      retryableApprovalSubmission = nil
      selectedApprovalDecision = operation.decision
      approvalState = .deliveryFailed(operation.decision)
      errorText = sourceFailureMessage(error)
      onUpdate?()
      return
    }
    if canonicalApprovalDeliveryState != nil {
      retryableApprovalSubmission = nil
      applyEffectiveApprovalDeliveryState()
      errorText = sourceFailureMessage(error)
      onUpdate?()
      return
    }
    switch operation.kind {
    case .resolve:
      if let failure = error as? SessionSourceFailure,
        failure.code == .transportUnavailable
      {
        retryableApprovalSubmission = operation
        approvalState = .submissionFailed(operation.decision)
      } else {
        retryableApprovalSubmission = nil
        selectedApprovalDecision = nil
        locallySubmittedApprovalDecision = nil
        approvalWasAlreadyHandled = false
        approvalState = .pending
      }
    case .retryDelivery:
      preconditionFailure("retry delivery failure 已在前置分支处理")
    }
    errorText = sourceFailureMessage(error)
    onUpdate?()
  }

  private func finishApprovalOperation(_ token: UUID) {
    if approvalOperation?.token == token {
      approvalOperation = nil
      approvalTask = nil
      return
    }
    retiredApprovalOperations.removeValue(forKey: token)
  }

  private func shouldRetireApprovalOperation(
    approvalID: RuntimeApprovalID,
    canonicalEventSeq: UInt64?
  ) -> Bool {
    guard let operation = approvalOperation,
      operation.approvalID == approvalID
    else { return false }
    guard operation.kind == .retryDelivery else { return true }
    guard let canonicalEventSeq else { return false }
    guard let fence = operation.canonicalEventFence else { return true }
    return canonicalEventSeq > fence
  }

  private func retireApprovalOperation(
    for resolution: RuntimeConversationApprovalResolution
  ) {
    guard let operation = approvalOperation,
      operation.approvalID == resolution.approvalID
    else { return }
    guard
      retiredApprovalOperations.count
        < Self.maxRetiredApprovalOperations
    else {
      enterTerminal(
        .securityError,
        message: "审批回执校验队列超过安全上限"
      )
      return
    }
    approvalTask?.cancel()
    approvalTask = nil
    approvalOperation = nil
    retiredApprovalOperations[operation.token] = RetiredApprovalOperation(
      operation: operation,
      canonicalDecision: resolution.decision,
      canonicalDeliveryState: resolution.deliveryState
    )
  }

  private func invalidateApprovalOperation() {
    approvalTask?.cancel()
    approvalTask = nil
    approvalOperation = nil
  }

  private func currentCanonicalEventSequence() -> UInt64? {
    switch conversationState.cursorState.cursor {
    case .beforeFirst:
      return nil
    case .at(let eventSeq):
      return eventSeq
    }
  }

  private func canonicalResolutionEventIsAfterFence(
    _ fence: UInt64?,
    approvalID: RuntimeApprovalID
  ) -> Bool {
    guard let event = lastCanonicalApprovalResolutionEvent,
      event.approvalID == approvalID
    else { return false }
    guard let fence else { return true }
    return event.eventSeq > fence
  }

  private func rebuildRows() {
    var items = conversationState.items
    if let prompt = pendingPrompt {
      let lifecycle: String
      switch promptState {
      case .sending:
        lifecycle = "sending"
      case .queued:
        lifecycle = "queued"
      case .idle, .failed:
        lifecycle = "sending"
      }
      var item = UIItem(
        id: "local-prompt-\(prompt.idempotencyKey.uuidString.lowercased())",
        lifecycle: lifecycle,
        kind: "user",
        text: prompt.text
      )
      item.textBuffer.replace(with: prompt.text)
      item.hasNonWhitespaceText = true
      items.append(item)
    }
    rows = ConversationDisplayRowBuilder.rows(
      from: makeConversationTurns(from: items)
    )
  }

  private func sourceFailureMessage(_ error: any Error) -> String {
    guard let failure = error as? SessionSourceFailure else {
      return error.localizedDescription
    }
    if let message = failure.message { return message }
    return switch failure.code {
    case .transportUnavailable: "Relay 不可达"
    case .machineOffline: "机器离线"
    case .revoked: "授权已撤销"
    case .incompatible: "版本不兼容"
    case .securityError: "安全校验失败"
    case .invalidPairInvite: "配对邀请无效"
    case .pairInviteExpired: "配对邀请已过期"
    case .commandRejected: "命令被拒绝"
    case .storageUnavailable: "本地存储不可用"
    case .unknown: "未知错误"
    }
  }

  @discardableResult
  private func enterTerminalIfRequired(_ error: any Error) -> Bool {
    guard let failure = error as? SessionSourceFailure else { return false }
    let state: SessionConnectionState
    switch failure.code {
    case .revoked:
      state = .revoked
    case .incompatible:
      state = .incompatible
    case .securityError:
      state = .securityError
    case .transportUnavailable, .machineOffline, .invalidPairInvite,
      .pairInviteExpired, .commandRejected, .storageUnavailable, .unknown:
      return false
    }
    enterTerminal(state, message: sourceFailureMessage(error))
    return true
  }

  deinit {
    observationTask?.cancel()
    promptTask?.cancel()
    approvalTask?.cancel()
  }
}
