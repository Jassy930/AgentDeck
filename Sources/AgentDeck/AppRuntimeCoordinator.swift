import AgentDeckCore
import Foundation

/// App runtime orchestration 依赖的最小 wire seam。Production 只由
/// `LocalRuntimeWireSession` 实现；测试 fake 不需要建立 UDS。
protocol AppRuntimeWireSession: Sendable {
  func start() async throws
  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2
  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence
  func nextStream() async throws -> LocalRuntimeStreamFrame
  func close() async
}

protocol AppRuntimeWireReplySequence: Sendable {
  func next() async throws -> RuntimeReplyV2?
  func cancel() async
}

extension LocalRuntimeWireSession: AppRuntimeWireSession {
  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    try await beginSynchronizedRequest(request)
  }
}
extension LocalRuntimeReplySequence: AppRuntimeWireReplySequence {}

/// 所有 daemon→App 的持续输入共用一个 MainActor consumer。Coordinator 每次都等待
/// consumer 返回后才读取下一项，不建立第二个无界队列。
enum AppRuntimeInbound: Sendable {
  case synchronizedReply(RuntimeReplyV2)
  case stream(LocalRuntimeStreamFrame)
}

typealias AppRuntimeInboundHandler =
  @MainActor @Sendable (AppRuntimeInbound) async throws -> Void

typealias AppRuntimeTerminationHandler = @MainActor @Sendable () async -> Void

enum AppRuntimeOperation: String, Equatable, Sendable {
  case describeAgents
  case catalog
  case startConversation
  case configureConversation
  case unsubscribe
  case subscribe
  case backfill
  case sendPrompt
  case resolveApproval
  case updateConversationMetadata
}

enum AppRuntimeReplyKind: String, Equatable, Sendable {
  case hello
  case agents
  case configuration
  case conversationMetadata
  case stageUpgrade
  case command
  case commandStatus
  case conversationStart
  case cancellation
  case approval
  case revocation
  case subscription
  case catalog
  case snapshot
  case backfill
  case syncComplete
  case transferPart
  case pairInvite
  case pendingPairings
  case pairing
  case machineRemoteStatus
  case failure
}

enum AppRuntimeCoordinatorError: Error, Equatable, Sendable {
  case notStarted
  case alreadyStarted
  case closed
  case operationInProgress
  case unexpectedReply(
    operation: AppRuntimeOperation,
    expected: AppRuntimeReplyKind,
    actual: AppRuntimeReplyKind
  )
  case daemonFailure(code: String, message: String, diagnosticRef: String?)
  case receiptConversationMismatch(
    operation: AppRuntimeOperation,
    expected: RuntimeConversationID,
    actual: RuntimeConversationID
  )
  case receiptApprovalMismatch(
    expected: RuntimeApprovalID,
    actual: RuntimeApprovalID
  )
  case receiptConfigurationRevisionMismatch(expected: UInt64, actual: UInt64)
  case configurationConflict(
    conversationID: RuntimeConversationID,
    currentRevision: UInt64
  )
  case missingSubscriptionReceipt
  case unexpectedUnsubscribeReceipt
  case subscriptionGenerationMismatch(
    expected: RuntimeStreamGeneration,
    actual: RuntimeStreamGeneration
  )
  case synchronizationTargetMismatch
  case missingSynchronizationTerminal
  case replyAfterSynchronizationTerminal
  case synchronizationReplyLimitExceeded
  case catalogPageLimitExceeded
  case catalogPageCursorCycle(RuntimeCatalogPageCursor)
  case catalogPageCursorMismatch(
    expected: RuntimeCatalogPageCursor?,
    actual: RuntimeCatalogPageCursor?
  )
}

struct AppRuntimeSynchronizationResult: Sendable {
  let replies: [RuntimeReplyV2]
  let terminal: RuntimeSyncCompleteV1
}

struct AppRuntimeConversationStartResult: Sendable {
  let conversationID: RuntimeConversationID
  let configurationReceipt: RuntimeConfigurationReceiptV2
  let synchronization: AppRuntimeSynchronizationResult
  let promptReceipt: CommandReceiptV2?
}

enum AppRuntimeConversationStartStage: Equatable, Sendable {
  case start
  case configure
  case synchronize
  case prompt
}

struct AppRuntimeConversationStartFailure: Error, @unchecked Sendable {
  let stage: AppRuntimeConversationStartStage
  let underlying: any Error
  let partialResult: AppRuntimeConversationStartResult?
}

/// Runtime v2 的 App-level sequencing owner。
///
/// - 只有这个 actor 调用 `nextStream()`；
/// - Subscribe/Backfill 在 actor reentrancy 期间保持单飞，messageId 相关的 unary control 可并行；
/// - Subscribe/Backfill 的 snapshot/backfill/terminal 全部消费后才开放 stream gate；
/// - close 只关闭当前 wire，不发送 daemon shutdown 或隐式 unsubscribe。
actor AppRuntimeCoordinator {
  private static let maximumCatalogPages = 128
  private static let maximumSynchronizationReplies = 4_096

  private enum State: Equatable {
    case idle
    case starting
    case running
    case closing
    case closed
  }

  private enum SynchronizationTarget: Equatable {
    case catalog
    case conversation(RuntimeConversationID)
  }

  private let wire: any AppRuntimeWireSession
  private let inboundHandler: AppRuntimeInboundHandler
  private let terminationHandler: AppRuntimeTerminationHandler
  private var state = State.idle
  private var lifecycleGeneration: UInt64 = 0
  private var synchronizationOperationActive = false
  private var synchronizationActive = false
  private var streamGateWaiter: CheckedContinuation<Void, Never>?
  private var streamPump: Task<Void, Never>?
  private var wireCloseTask: Task<Void, Never>?
  private var firstStreamFailure: (any Error)?
  private var didNotifyUnexpectedTermination = false

  init(
    wire: any AppRuntimeWireSession,
    inboundHandler: @escaping AppRuntimeInboundHandler,
    terminationHandler: @escaping AppRuntimeTerminationHandler = {}
  ) {
    self.wire = wire
    self.inboundHandler = inboundHandler
    self.terminationHandler = terminationHandler
  }

  func start() async throws {
    switch state {
    case .idle:
      lifecycleGeneration &+= 1
      state = .starting
    case .starting, .running:
      throw AppRuntimeCoordinatorError.alreadyStarted
    case .closing, .closed:
      throw AppRuntimeCoordinatorError.closed
    }

    do {
      try await wire.start()
    } catch {
      if state == .starting {
        state = .idle
        throw error
      }
      await finishClosing()
      throw AppRuntimeCoordinatorError.closed
    }
    guard state == .starting else {
      await finishClosing()
      throw AppRuntimeCoordinatorError.closed
    }
    state = .running
    streamPump = Task { [weak self] in
      await self?.runStreamPump()
    }
  }

  func describeAgents() async throws -> RuntimeAgentDescriptionsV2 {
    try requireRunning()
    let reply = try await request(.describeAgents)
    guard case .agents(let agents) = reply else {
      throw unexpected(
        operation: .describeAgents,
        expected: .agents,
        actual: reply
      )
    }
    return agents
  }

  /// 读取一个固定 barrier 的完整 Catalog pagination。页数与每页大小都有硬上界，
  /// repeated cursor 在发起重复请求前 fail-close。
  func loadCatalog() async throws -> [RuntimeCatalogSnapshotV2] {
    try requireRunning()

    var pages: [RuntimeCatalogSnapshotV2] = []
    pages.reserveCapacity(4)
    var pageCursor: RuntimeCatalogPageCursor?
    var seenCursors: Set<String> = []

    while pages.count < Self.maximumCatalogPages {
      let reply = try await request(.catalog(pageCursor: pageCursor))
      guard case .catalog(let page) = reply else {
        throw unexpected(operation: .catalog, expected: .catalog, actual: reply)
      }
      guard page.currentPageCursor == pageCursor else {
        throw AppRuntimeCoordinatorError.catalogPageCursorMismatch(
          expected: pageCursor,
          actual: page.currentPageCursor
        )
      }
      pages.append(page)
      guard let next = page.nextPageCursor else { return pages }
      guard seenCursors.insert(next.rawValue).inserted else {
        throw AppRuntimeCoordinatorError.catalogPageCursorCycle(next)
      }
      pageCursor = next
    }
    throw AppRuntimeCoordinatorError.catalogPageLimitExceeded
  }

  /// 新会话的不可分割 App 顺序：Start → Configure(rev0) → Subscribe →
  /// snapshot/backfill/SyncComplete → optional SendPrompt。
  func startConversation(
    _ draft: RuntimeConversationDraft
  ) async throws -> AppRuntimeConversationStartResult {
    do {
      try beginSynchronizationOperation()
    } catch {
      throw AppRuntimeConversationStartFailure(
        stage: .start,
        underlying: error,
        partialResult: nil
      )
    }
    defer { endSynchronizationOperation() }

    let startReply: RuntimeReplyV2
    do {
      startReply = try await request(draft.startRequest)
    } catch {
      throw AppRuntimeConversationStartFailure(
        stage: .start,
        underlying: error,
        partialResult: nil
      )
    }
    guard case .conversationStart(let startReceipt) = startReply else {
      throw AppRuntimeConversationStartFailure(
        stage: .start,
        underlying: unexpected(
          operation: .startConversation,
          expected: .conversationStart,
          actual: startReply
        ),
        partialResult: nil
      )
    }
    let conversationID = startReceipt.conversationID
    let configurationReceipt: RuntimeConfigurationReceiptV2
    do {
      configurationReceipt = try await configureUnchecked(
        draft.configureRequest(conversationID: conversationID)
      )
    } catch {
      throw AppRuntimeConversationStartFailure(
        stage: .configure,
        underlying: error,
        partialResult: nil
      )
    }
    switch configurationReceipt {
    case .applied, .replayed, .conflict:
      break
    case .failed:
      preconditionFailure("configureUnchecked must unwrap daemon Failure")
    }

    let synchronization: AppRuntimeSynchronizationResult
    do {
      synchronization = try await synchronizeUnchecked(
        draft.subscribeRequest(conversationID: conversationID),
        operation: .subscribe,
        target: .conversation(conversationID),
        requiresSubscription: true
      )
    } catch {
      throw AppRuntimeConversationStartFailure(
        stage: .synchronize,
        underlying: error,
        partialResult: nil
      )
    }

    let promptReceipt: CommandReceiptV2?
    if case .conflict = configurationReceipt {
      promptReceipt = nil
    } else {
      do {
        if let promptRequest = try draft.sendPromptRequest(
          conversationID: conversationID,
          configurationReceipt: configurationReceipt
        ) {
          promptReceipt = try await sendPromptUnchecked(promptRequest)
        } else {
          promptReceipt = nil
        }
      } catch {
        throw AppRuntimeConversationStartFailure(
          stage: .prompt,
          underlying: error,
          partialResult: AppRuntimeConversationStartResult(
            conversationID: conversationID,
            configurationReceipt: configurationReceipt,
            synchronization: synchronization,
            promptReceipt: nil
          )
        )
      }
    }
    return AppRuntimeConversationStartResult(
      conversationID: conversationID,
      configurationReceipt: configurationReceipt,
      synchronization: synchronization,
      promptReceipt: promptReceipt
    )
  }

  /// 已有 conversation 从给定 cursor 建立同步 barrier。daemon 可选择 Snapshot、
  /// Backfill 或直接 SyncComplete；所有项都在返回前依序转发给 MainActor。
  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    try beginSynchronizationOperation()
    defer { endSynchronizationOperation() }
    return try await synchronizeUnchecked(
      .subscribe(
        innerCursor: .conversation(
          conversationID: conversationID,
          cursor: cursor
        )
      ),
      operation: .subscribe,
      target: .conversation(conversationID),
      requiresSubscription: true
    )
  }

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    try beginSynchronizationOperation()
    defer { endSynchronizationOperation() }
    return try await synchronizeUnchecked(
      .backfill(.conversation(conversationID: conversationID, after: cursor)),
      operation: .backfill,
      target: .conversation(conversationID),
      requiresSubscription: false
    )
  }

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    try beginSynchronizationOperation()
    defer { endSynchronizationOperation() }
    return try await synchronizeUnchecked(
      .subscribe(innerCursor: .catalog(cursor: cursor)),
      operation: .subscribe,
      target: .catalog,
      requiresSubscription: true
    )
  }

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    try beginSynchronizationOperation()
    defer { endSynchronizationOperation() }
    return try await synchronizeUnchecked(
      .backfill(.catalog(after: cursor)),
      operation: .backfill,
      target: .catalog,
      requiresSubscription: false
    )
  }

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2
  ) async throws -> RuntimeConfigurationReceiptV2 {
    try requireRunning()
    return try await configureUnchecked(.configureConversation(configuration))
  }

  /// 释放当前 connection 上一个 conversation live subscription。只有 daemon 的
  /// 精确 `Unsubscribed` ACK 到达后，调用方才可以从本地 live-slot 账本移除目标。
  func unsubscribeConversation(
    _ conversationID: RuntimeConversationID
  ) async throws {
    try requireRunning()
    let reply = try await request(
      .unsubscribe(target: .conversation(conversationID: conversationID))
    )
    guard case .subscription(.unsubscribed) = reply else {
      throw unexpected(
        operation: .unsubscribe,
        expected: .subscription,
        actual: reply
      )
    }
  }

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1
  ) async throws -> CommandReceiptV2 {
    try requireRunning()
    return try await sendPromptUnchecked(
      .sendPrompt(
        conversationID: conversationID,
        idempotencyKey: idempotencyKey,
        expectedConfigurationRevision: expectedConfigurationRevision,
        prompt: prompt
      )
    )
  }

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1
  ) async throws -> ApprovalReceiptV1 {
    try requireRunning()
    let reply = try await request(
      .resolveApproval(
        conversationID: conversationID,
        turnID: turnID,
        approvalID: approvalID,
        decision: decision
      )
    )
    guard case .approval(let receipt) = reply else {
      throw unexpected(operation: .resolveApproval, expected: .approval, actual: reply)
    }
    let actual = Self.approvalID(from: receipt)
    guard actual == approvalID else {
      throw AppRuntimeCoordinatorError.receiptApprovalMismatch(
        expected: approvalID,
        actual: actual
      )
    }
    return receipt
  }

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2
  ) async throws -> RuntimeConversationMetadataReceiptV2 {
    try requireRunning()
    let reply = try await request(.updateConversationMetadata(mutation))
    guard case .conversationMetadata(let receipt) = reply else {
      throw unexpected(
        operation: .updateConversationMetadata,
        expected: .conversationMetadata,
        actual: reply
      )
    }
    try validateMetadataReceipt(receipt, expected: mutation.conversationID)
    return receipt
  }

  func streamFailure() -> (any Error)? {
    firstStreamFailure
  }

  func requiresFreshConnection() -> Bool {
    state == .closing || state == .closed
  }

  func close() async {
    switch state {
    case .closed:
      return
    case .closing:
      await finishClosing()
      return
    case .idle, .starting, .running:
      lifecycleGeneration &+= 1
      state = .closing
    }
    synchronizationActive = false
    streamGateWaiter?.resume()
    streamGateWaiter = nil
    streamPump?.cancel()
    streamPump = nil
    await finishClosing()
  }

  private func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    let generation = try runningGeneration()
    try Task.checkCancellation()
    let reply = try await wire.request(request)
    try requireRunning(generation: generation)
    try Task.checkCancellation()
    if case .failure(let failure) = reply {
      throw Self.daemonFailure(failure)
    }
    return reply
  }

  private func configureUnchecked(
    _ request: RuntimeRequestV2
  ) async throws -> RuntimeConfigurationReceiptV2 {
    guard case .configureConversation(let configuration) = request else {
      preconditionFailure("configureUnchecked requires ConfigureConversation")
    }
    let reply = try await self.request(request)
    guard case .configuration(let receipt) = reply else {
      throw unexpected(
        operation: .configureConversation,
        expected: .configuration,
        actual: reply
      )
    }
    try validateConfigurationReceipt(receipt, expected: configuration.conversationID)
    return receipt
  }

  private func sendPromptUnchecked(
    _ request: RuntimeRequestV2
  ) async throws -> CommandReceiptV2 {
    guard case .sendPrompt(_, _, let expectedRevision, _) = request else {
      preconditionFailure("sendPromptUnchecked requires SendPrompt")
    }
    let reply = try await self.request(request)
    guard case .command(let receipt) = reply else {
      throw unexpected(operation: .sendPrompt, expected: .command, actual: reply)
    }
    let actualRevision: UInt64
    switch receipt {
    case .accepted(_, _, let revision), .replayed(_, let revision):
      actualRevision = revision
    case .failed(let failure):
      throw Self.daemonFailure(failure)
    }
    guard actualRevision == expectedRevision else {
      throw AppRuntimeCoordinatorError.receiptConfigurationRevisionMismatch(
        expected: expectedRevision,
        actual: actualRevision
      )
    }
    return receipt
  }

  private func synchronizeUnchecked(
    _ request: RuntimeRequestV2,
    operation: AppRuntimeOperation,
    target: SynchronizationTarget,
    requiresSubscription: Bool
  ) async throws -> AppRuntimeSynchronizationResult {
    let generation = try runningGeneration()
    try Task.checkCancellation()
    guard synchronizationOperationActive, !synchronizationActive else {
      throw AppRuntimeCoordinatorError.operationInProgress
    }
    synchronizationActive = true
    defer { finishSynchronization() }

    var activeSequence: (any AppRuntimeWireReplySequence)?
    do {
      let sequence = try await wire.beginAppSynchronizedRequest(request)
      try requireRunning(generation: generation)
      try Task.checkCancellation()
      activeSequence = sequence
      var replies: [RuntimeReplyV2] = []
      replies.reserveCapacity(4)
      var subscriptionGeneration: RuntimeStreamGeneration?
      var terminal: RuntimeSyncCompleteV1?

      while let reply = try await sequence.next() {
        try requireRunning(generation: generation)
        try Task.checkCancellation()
        guard terminal == nil else {
          throw AppRuntimeCoordinatorError.replyAfterSynchronizationTerminal
        }
        guard replies.count < Self.maximumSynchronizationReplies else {
          throw AppRuntimeCoordinatorError.synchronizationReplyLimitExceeded
        }
        switch reply {
        case .failure(let failure):
          throw Self.daemonFailure(failure)
        case .subscription(.subscribed(let generation)):
          guard requiresSubscription, subscriptionGeneration == nil, replies.isEmpty else {
            throw unexpected(
              operation: operation,
              expected: .syncComplete,
              actual: reply
            )
          }
          subscriptionGeneration = generation
        case .subscription(.unsubscribed):
          throw AppRuntimeCoordinatorError.unexpectedUnsubscribeReceipt
        case .snapshot(let snapshot):
          guard case .conversation(let conversationID) = target,
            snapshot.conversationID == conversationID
          else {
            throw AppRuntimeCoordinatorError.synchronizationTargetMismatch
          }
        case .backfill(let chunk):
          guard Self.backfill(chunk, matches: target) else {
            throw AppRuntimeCoordinatorError.synchronizationTargetMismatch
          }
        case .syncComplete(let sync):
          guard Self.innerCursor(sync.innerCursor, matches: target) else {
            throw AppRuntimeCoordinatorError.synchronizationTargetMismatch
          }
          if let subscriptionGeneration,
            subscriptionGeneration != sync.streamGeneration
          {
            throw AppRuntimeCoordinatorError.subscriptionGenerationMismatch(
              expected: subscriptionGeneration,
              actual: sync.streamGeneration
            )
          }
          terminal = sync
        default:
          throw unexpected(
            operation: operation,
            expected: .syncComplete,
            actual: reply
          )
        }
        replies.append(reply)
      }
      try requireRunning(generation: generation)
      try Task.checkCancellation()

      if requiresSubscription, subscriptionGeneration == nil {
        throw AppRuntimeCoordinatorError.missingSubscriptionReceipt
      }
      guard let terminal else {
        throw AppRuntimeCoordinatorError.missingSynchronizationTerminal
      }

      // 只有完整 sequence 已读到 nil 且 terminal 全部验证后才发布。整个 publish
      // 期间 synchronizationActive 仍为 true，因此 live stream 最多在 pump 内持有一帧。
      for reply in replies {
        try await inboundHandler(.synchronizedReply(reply))
        try requireRunning(generation: generation)
        try Task.checkCancellation()
      }
      return AppRuntimeSynchronizationResult(replies: replies, terminal: terminal)
    } catch {
      if let activeSequence { await activeSequence.cancel() }
      await failSynchronizationClosed()
      throw error
    }
  }

  private func validateConfigurationReceipt(
    _ receipt: RuntimeConfigurationReceiptV2,
    expected: RuntimeConversationID
  ) throws {
    let actual: RuntimeConversationID
    switch receipt {
    case .applied(let conversationID, _),
      .replayed(let conversationID, _),
      .conflict(let conversationID, _):
      actual = conversationID
    case .failed(let failure):
      throw Self.daemonFailure(failure)
    }
    guard actual == expected else {
      throw AppRuntimeCoordinatorError.receiptConversationMismatch(
        operation: .configureConversation,
        expected: expected,
        actual: actual
      )
    }
  }

  private func validateMetadataReceipt(
    _ receipt: RuntimeConversationMetadataReceiptV2,
    expected: RuntimeConversationID
  ) throws {
    let actual: RuntimeConversationID
    switch receipt {
    case .applied(let conversationID, _),
      .replayed(let conversationID, _),
      .conflict(let conversationID, _):
      actual = conversationID
    case .failed(let failure):
      throw Self.daemonFailure(failure)
    }
    guard actual == expected else {
      throw AppRuntimeCoordinatorError.receiptConversationMismatch(
        operation: .updateConversationMetadata,
        expected: expected,
        actual: actual
      )
    }
  }

  private func beginSynchronizationOperation() throws {
    try requireRunning()
    guard !synchronizationOperationActive else {
      throw AppRuntimeCoordinatorError.operationInProgress
    }
    synchronizationOperationActive = true
  }

  private func endSynchronizationOperation() {
    synchronizationOperationActive = false
  }

  private func requireRunning() throws {
    switch state {
    case .running:
      return
    case .idle, .starting:
      throw AppRuntimeCoordinatorError.notStarted
    case .closing, .closed:
      throw AppRuntimeCoordinatorError.closed
    }
  }

  private func runningGeneration() throws -> UInt64 {
    try requireRunning()
    return lifecycleGeneration
  }

  private func requireRunning(generation: UInt64) throws {
    guard state == .running, lifecycleGeneration == generation else {
      throw AppRuntimeCoordinatorError.closed
    }
  }

  /// 同步序列或 MainActor publish 失败后不能继续把 live stream 叠加到不完整投影。
  /// 这里只 close 当前 client wire；不发送 daemon shutdown/unsubscribe。
  private func failSynchronizationClosed() async {
    switch state {
    case .running:
      lifecycleGeneration &+= 1
      state = .closing
      streamPump?.cancel()
      streamPump = nil
    case .closing:
      break
    case .idle, .starting, .closed:
      return
    }
    await finishClosing()
  }

  private func finishSynchronization() {
    synchronizationActive = false
    streamGateWaiter?.resume()
    streamGateWaiter = nil
  }

  private func waitForSynchronizationGate() async {
    guard synchronizationActive, state == .running else { return }
    await withCheckedContinuation { continuation in
      precondition(streamGateWaiter == nil)
      streamGateWaiter = continuation
    }
  }

  private func runStreamPump() async {
    while !Task.isCancelled {
      await waitForSynchronizationGate()
      guard state == .running, !Task.isCancelled else { return }
      do {
        let frame = try await wire.nextStream()
        await waitForSynchronizationGate()
        guard state == .running, !Task.isCancelled else { return }
        try await inboundHandler(.stream(frame))
      } catch {
        guard state == .running, !Task.isCancelled else { return }
        if firstStreamFailure == nil { firstStreamFailure = error }
        state = .closing
        synchronizationActive = false
        streamGateWaiter?.resume()
        streamGateWaiter = nil
        await finishClosing()
        await notifyUnexpectedTerminationIfNeeded()
        return
      }
    }
  }

  private func notifyUnexpectedTerminationIfNeeded() async {
    guard !didNotifyUnexpectedTermination else { return }
    didNotifyUnexpectedTermination = true
    await terminationHandler()
  }

  private func finishClosing() async {
    let task: Task<Void, Never>
    if let wireCloseTask {
      task = wireCloseTask
    } else {
      let wire = wire
      task = Task { await wire.close() }
      wireCloseTask = task
    }
    await task.value
    state = .closed
  }

  private func unexpected(
    operation: AppRuntimeOperation,
    expected: AppRuntimeReplyKind,
    actual: RuntimeReplyV2
  ) -> AppRuntimeCoordinatorError {
    .unexpectedReply(
      operation: operation,
      expected: expected,
      actual: Self.kind(of: actual)
    )
  }

  private static func daemonFailure(
    _ failure: RuntimeFailureV1
  ) -> AppRuntimeCoordinatorError {
    .daemonFailure(
      code: failure.code,
      message: failure.message,
      diagnosticRef: failure.diagnosticRef
    )
  }

  private static func approvalID(from receipt: ApprovalReceiptV1) -> RuntimeApprovalID {
    switch receipt {
    case .claimed(let approvalID),
      .applied(let approvalID),
      .deliveryFailed(let approvalID),
      .expired(let approvalID),
      .alreadyHandled(let approvalID, _, _):
      approvalID
    }
  }

  private static func innerCursor(
    _ cursor: RuntimeInnerCursorV1,
    matches target: SynchronizationTarget
  ) -> Bool {
    switch (cursor, target) {
    case (.catalog, .catalog):
      true
    case (.conversation(let actual, _), .conversation(let expected)):
      actual == expected
    default:
      false
    }
  }

  private static func backfill(
    _ chunk: RuntimeBackfillChunkV2,
    matches target: SynchronizationTarget
  ) -> Bool {
    switch (chunk, target) {
    case (.catalog, .catalog):
      true
    case (.conversation(let actual, _, _, _), .conversation(let expected)):
      actual == expected
    default:
      false
    }
  }

  private static func kind(of reply: RuntimeReplyV2) -> AppRuntimeReplyKind {
    switch reply {
    case .hello: .hello
    case .agents: .agents
    case .configuration: .configuration
    case .conversationMetadata: .conversationMetadata
    case .stageUpgrade: .stageUpgrade
    case .command: .command
    case .commandStatus: .commandStatus
    case .conversationStart: .conversationStart
    case .cancellation: .cancellation
    case .approval: .approval
    case .revocation: .revocation
    case .subscription: .subscription
    case .catalog: .catalog
    case .snapshot: .snapshot
    case .backfill: .backfill
    case .syncComplete: .syncComplete
    case .transferPart: .transferPart
    case .pairInvite: .pairInvite
    case .pendingPairings: .pendingPairings
    case .pairing: .pairing
    case .machineRemoteStatus: .machineRemoteStatus
    case .failure: .failure
    }
  }
}
