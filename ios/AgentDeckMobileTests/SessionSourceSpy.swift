import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

actor SessionSourceSpy: SessionSource {
  struct PromptCall: Sendable {
    let conversationID: String
    let text: String
    let idempotencyKey: UUID
  }

  struct ApprovalCall: Sendable {
    let conversationID: String
    let turnID: String
    let approvalID: String
    let decision: ActionDecisionKind
    let idempotencyKey: UUID
  }

  enum CommandBehavior: Sendable {
    case immediate(CommandReceipt)
    case failure(SessionSourceFailure)
    case suspended
  }

  enum ApprovalBehavior: Sendable {
    case immediate(ApprovalReceipt)
    case failure(SessionSourceFailure)
    case suspended
  }

  enum PairInviteInspectionBehavior: Sendable {
    case immediate(PairingPreview)
    case failure(SessionSourceFailure)
    case suspended
  }

  enum PairingBehavior: Sendable {
    case finished([PairingProgress])
    case failure(SessionSourceFailure)
    case suspended
    case suspendedBeforeStream
  }

  enum RevocationBehavior: Sendable {
    case immediate(RevocationReceipt)
    case failure(SessionSourceFailure)
    case suspended
  }

  private struct PendingApprovalContinuation {
    let approvalID: String
    let continuation: CheckedContinuation<ApprovalReceipt, any Error>
  }

  private struct PendingInspectionContinuation {
    let encodedInvite: String
    let continuation: CheckedContinuation<PairingPreview, any Error>
  }

  private struct PendingPairingContinuation {
    let encodedInvite: String
    let continuation:
      CheckedContinuation<AsyncThrowingStream<PairingProgress, any Error>, any Error>
  }

  private struct PendingRevocationContinuation {
    let machineID: String
    let continuation: CheckedContinuation<RevocationReceipt, any Error>
  }

  private var machineContinuation: AsyncStream<ResourceState<[MachineSummary]>>.Continuation?
  private var conversationListContinuation:
    AsyncStream<ResourceState<[ConversationSummary]>>.Continuation?
  private var conversationContinuation: AsyncStream<ConversationUpdate>.Continuation?
  private var inboxContinuation: AsyncStream<ResourceState<[InboxItem]>>.Continuation?

  private var machineSubscriptions = 0
  private var conversationListSubscriptions = 0
  private var conversationSubscriptions = 0
  private var inboxSubscriptions = 0
  private var machineTerminations = 0
  private var conversationListTerminations = 0
  private var conversationTerminations = 0
  private var inboxTerminations = 0
  private var promptCalls: [PromptCall] = []
  private var approvalCalls: [ApprovalCall] = []
  private var retryApprovalIDs: [String] = []
  private var inspectionCalls: [String] = []
  private var pairingCalls: [String] = []
  private var revocationCalls: [String] = []
  private var pairingTerminations = 0
  private var shutdowns = 0
  private var shutdownSuspended = false
  private var shutdownContinuation: CheckedContinuation<Void, Never>?

  private var commandBehavior: CommandBehavior = .immediate(
    .accepted(
      commandID: RuntimeCommandID(rawValue: "command-default"),
      queuePosition: 0,
      configurationRevision: 1
    )
  )
  private var approvalBehavior: ApprovalBehavior = .immediate(
    .applied(RuntimeApprovalID(rawValue: "approval-default"))
  )
  private var retryBehavior: ApprovalBehavior = .immediate(
    .applied(RuntimeApprovalID(rawValue: "approval-default"))
  )
  private var inspectionBehavior: PairInviteInspectionBehavior = .failure(
    SessionSourceFailure(code: .invalidPairInvite)
  )
  private var pairingBehavior: PairingBehavior = .failure(
    SessionSourceFailure(code: .invalidPairInvite)
  )
  private var revocationBehavior: RevocationBehavior = .failure(
    SessionSourceFailure(code: .unknown)
  )
  private var pendingCommand: CheckedContinuation<CommandReceipt, any Error>?
  private var pendingApprovals: [PendingApprovalContinuation] = []
  private var pendingRetry: CheckedContinuation<ApprovalReceipt, any Error>?
  private var pendingInspections: [PendingInspectionContinuation] = []
  private var pendingPairings: [PendingPairingContinuation] = []
  private var pairingContinuations: [AsyncThrowingStream<PairingProgress, any Error>.Continuation] =
    []
  private var pendingRevocations: [PendingRevocationContinuation] = []

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    machineSubscriptions += 1
    let pair = AsyncStream<ResourceState<[MachineSummary]>>.makeStream(
      bufferingPolicy: .bufferingNewest(1)
    )
    machineContinuation = pair.continuation
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.recordMachineTermination() }
    }
    return pair.stream
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    _ = machineID
    conversationListSubscriptions += 1
    let pair = AsyncStream<ResourceState<[ConversationSummary]>>.makeStream(
      bufferingPolicy: .bufferingNewest(1)
    )
    conversationListContinuation = pair.continuation
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.recordConversationListTermination() }
    }
    return pair.stream
  }

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
    _ = conversationID
    conversationSubscriptions += 1
    let pair = AsyncStream<ConversationUpdate>.makeStream(
      bufferingPolicy: .bufferingNewest(512)
    )
    conversationContinuation = pair.continuation
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.recordConversationTermination() }
    }
    return pair.stream
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    inboxSubscriptions += 1
    let pair = AsyncStream<ResourceState<[InboxItem]>>.makeStream(
      bufferingPolicy: .bufferingNewest(1)
    )
    inboxContinuation = pair.continuation
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.recordInboxTermination() }
    }
    return pair.stream
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    inspectionCalls.append(encoded)
    switch inspectionBehavior {
    case .immediate(let preview):
      return preview
    case .failure(let error):
      throw error
    case .suspended:
      return try await withCheckedThrowingContinuation { continuation in
        pendingInspections.append(
          PendingInspectionContinuation(
            encodedInvite: encoded,
            continuation: continuation
          )
        )
      }
    }
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, any Error> {
    pairingCalls.append(encodedInvite)
    if case .suspendedBeforeStream = pairingBehavior {
      return try await withCheckedThrowingContinuation { continuation in
        pendingPairings.append(
          PendingPairingContinuation(
            encodedInvite: encodedInvite,
            continuation: continuation
          )
        )
      }
    }
    return makePairingStream(behavior: pairingBehavior)
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    revocationCalls.append(machineID)
    switch revocationBehavior {
    case .immediate(let receipt):
      return receipt
    case .failure(let error):
      throw error
    case .suspended:
      return try await withCheckedThrowingContinuation { continuation in
        pendingRevocations.append(
          PendingRevocationContinuation(
            machineID: machineID,
            continuation: continuation
          )
        )
      }
    }
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    promptCalls.append(
      PromptCall(
        conversationID: conversationID,
        text: text,
        idempotencyKey: idempotencyKey
      )
    )
    switch commandBehavior {
    case .immediate(let receipt):
      return receipt
    case .failure(let error):
      throw error
    case .suspended:
      return try await withCheckedThrowingContinuation { continuation in
        pendingCommand = continuation
      }
    }
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    approvalCalls.append(
      ApprovalCall(
        conversationID: conversationID,
        turnID: turnID,
        approvalID: approvalID,
        decision: decision,
        idempotencyKey: idempotencyKey
      )
    )
    switch approvalBehavior {
    case .immediate(let receipt):
      return receipt
    case .failure(let error):
      throw error
    case .suspended:
      return try await withCheckedThrowingContinuation { continuation in
        pendingApprovals.append(
          PendingApprovalContinuation(
            approvalID: approvalID,
            continuation: continuation
          )
        )
      }
    }
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    _ = conversationID
    retryApprovalIDs.append(approvalID)
    switch retryBehavior {
    case .immediate(let receipt):
      return receipt
    case .failure(let error):
      throw error
    case .suspended:
      return try await withCheckedThrowingContinuation { continuation in
        pendingRetry = continuation
      }
    }
  }

  func emitMachines(_ state: ResourceState<[MachineSummary]>) {
    machineContinuation?.yield(state)
  }

  func emitConversations(_ state: ResourceState<[ConversationSummary]>) {
    conversationListContinuation?.yield(state)
  }

  func emitConversation(_ update: ConversationUpdate) {
    conversationContinuation?.yield(update)
  }

  func emitInbox(_ state: ResourceState<[InboxItem]>) {
    inboxContinuation?.yield(state)
  }

  func setCommandBehavior(_ behavior: CommandBehavior) {
    commandBehavior = behavior
  }

  func setApprovalBehavior(_ behavior: ApprovalBehavior) {
    approvalBehavior = behavior
  }

  func setRetryBehavior(_ behavior: ApprovalBehavior) {
    retryBehavior = behavior
  }

  func setInspectionBehavior(_ behavior: PairInviteInspectionBehavior) {
    inspectionBehavior = behavior
  }

  func setPairingBehavior(_ behavior: PairingBehavior) {
    pairingBehavior = behavior
  }

  func setRevocationBehavior(_ behavior: RevocationBehavior) {
    revocationBehavior = behavior
  }

  func completeCommand(with receipt: CommandReceipt) {
    pendingCommand?.resume(returning: receipt)
    pendingCommand = nil
  }

  func completeApproval(with receipt: ApprovalReceipt) {
    guard !pendingApprovals.isEmpty else { return }
    pendingApprovals.removeFirst().continuation.resume(returning: receipt)
  }

  func failApproval(with error: any Error) {
    guard !pendingApprovals.isEmpty else { return }
    pendingApprovals.removeFirst().continuation.resume(throwing: error)
  }

  func completeApproval(
    approvalID: String,
    with receipt: ApprovalReceipt
  ) {
    guard
      let index = pendingApprovals.firstIndex(where: {
        $0.approvalID == approvalID
      })
    else { return }
    pendingApprovals.remove(at: index).continuation.resume(returning: receipt)
  }

  func completeRetry(with receipt: ApprovalReceipt) {
    pendingRetry?.resume(returning: receipt)
    pendingRetry = nil
  }

  func failRetry(with error: any Error) {
    pendingRetry?.resume(throwing: error)
    pendingRetry = nil
  }

  func completeInspection(
    encodedInvite: String,
    with preview: PairingPreview
  ) {
    guard
      let index = pendingInspections.firstIndex(where: {
        $0.encodedInvite == encodedInvite
      })
    else { return }
    pendingInspections.remove(at: index).continuation.resume(returning: preview)
  }

  func failInspection(
    encodedInvite: String,
    with error: any Error
  ) {
    guard
      let index = pendingInspections.firstIndex(where: {
        $0.encodedInvite == encodedInvite
      })
    else { return }
    pendingInspections.remove(at: index).continuation.resume(throwing: error)
  }

  func completePairingBeforeStream(encodedInvite: String) {
    guard
      let index = pendingPairings.firstIndex(where: {
        $0.encodedInvite == encodedInvite
      })
    else { return }
    let pending = pendingPairings.remove(at: index)
    pending.continuation.resume(
      returning: makePairingStream(behavior: .suspended)
    )
  }

  func failPairingBeforeStream(
    encodedInvite: String,
    with error: any Error
  ) {
    guard
      let index = pendingPairings.firstIndex(where: {
        $0.encodedInvite == encodedInvite
      })
    else { return }
    pendingPairings.remove(at: index).continuation.resume(throwing: error)
  }

  func emitPairing(_ progress: PairingProgress) {
    pairingContinuations.first?.yield(progress)
  }

  func finishPairing() {
    guard !pairingContinuations.isEmpty else { return }
    pairingContinuations.removeFirst().finish()
  }

  func failPairing(with error: any Error) {
    guard !pairingContinuations.isEmpty else { return }
    pairingContinuations.removeFirst().finish(throwing: error)
  }

  func completeRevocation(
    machineID: String,
    with receipt: RevocationReceipt
  ) {
    guard
      let index = pendingRevocations.firstIndex(where: {
        $0.machineID == machineID
      })
    else { return }
    pendingRevocations.remove(at: index).continuation.resume(returning: receipt)
  }

  func shutdown() async {
    shutdowns += 1
    for continuation in pairingContinuations {
      continuation.finish()
    }
    pairingContinuations.removeAll(keepingCapacity: false)
    if shutdownSuspended {
      await withCheckedContinuation { continuation in
        shutdownContinuation = continuation
      }
    }
  }

  func suspendShutdown() {
    shutdownSuspended = true
  }

  func releaseShutdown() {
    shutdownSuspended = false
    shutdownContinuation?.resume()
    shutdownContinuation = nil
  }

  func machineSubscriptionCount() -> Int { machineSubscriptions }
  func conversationListSubscriptionCount() -> Int { conversationListSubscriptions }
  func conversationSubscriptionCount() -> Int { conversationSubscriptions }
  func inboxSubscriptionCount() -> Int { inboxSubscriptions }
  func machineTerminationCount() -> Int { machineTerminations }
  func conversationListTerminationCount() -> Int { conversationListTerminations }
  func conversationTerminationCount() -> Int { conversationTerminations }
  func inboxTerminationCount() -> Int { inboxTerminations }
  func recordedPromptCalls() -> [PromptCall] { promptCalls }
  func recordedApprovalCalls() -> [ApprovalCall] { approvalCalls }
  func recordedRetryApprovalIDs() -> [String] { retryApprovalIDs }
  func recordedInspectionCalls() -> [String] { inspectionCalls }
  func recordedPairingCalls() -> [String] { pairingCalls }
  func recordedRevocationCalls() -> [String] { revocationCalls }
  func pairingTerminationCount() -> Int { pairingTerminations }
  func shutdownCount() -> Int { shutdowns }

  func waitForMachineSubscriptions(_ count: Int) async {
    await waitUntil("machine subscriptions >= \(count)") {
      machineSubscriptions >= count
    }
  }

  func waitForConversationListSubscriptions(_ count: Int) async {
    await waitUntil("conversation-list subscriptions >= \(count)") {
      conversationListSubscriptions >= count
    }
  }

  func waitForConversationSubscriptions(_ count: Int) async {
    await waitUntil("conversation subscriptions >= \(count)") {
      conversationSubscriptions >= count
    }
  }

  func waitForInboxSubscriptions(_ count: Int) async {
    await waitUntil("inbox subscriptions >= \(count)") {
      inboxSubscriptions >= count
    }
  }

  func waitForPromptCalls(_ count: Int) async {
    await waitUntil("prompt calls >= \(count)") {
      promptCalls.count >= count
    }
  }

  func waitForApprovalCalls(_ count: Int) async {
    await waitUntil("approval calls >= \(count)") {
      approvalCalls.count >= count
    }
  }

  func waitForRetryCalls(_ count: Int) async {
    await waitUntil("approval retry calls >= \(count)") {
      retryApprovalIDs.count >= count
    }
  }

  func waitForInspectionCalls(_ count: Int) async {
    await waitUntil("pair invite inspection calls >= \(count)") {
      inspectionCalls.count >= count
    }
  }

  func waitForPairingCalls(_ count: Int) async {
    await waitUntil("pairing calls >= \(count)") {
      pairingCalls.count >= count
    }
  }

  func waitForRevocationCalls(_ count: Int) async {
    await waitUntil("revocation calls >= \(count)") {
      revocationCalls.count >= count
    }
  }

  func waitForPairingTerminations(_ count: Int) async {
    await waitUntil("pairing terminations >= \(count)") {
      pairingTerminations >= count
    }
  }

  func waitForShutdowns(_ count: Int) async {
    await waitUntil("shutdowns >= \(count)") {
      shutdowns >= count
    }
  }

  func waitForConversationTerminations(_ count: Int) async {
    await waitUntil("conversation terminations >= \(count)") {
      conversationTerminations >= count
    }
  }

  func waitForMachineTerminations(_ count: Int) async {
    await waitUntil("machine terminations >= \(count)") {
      machineTerminations >= count
    }
  }

  func waitForConversationListTerminations(_ count: Int) async {
    await waitUntil("conversation-list terminations >= \(count)") {
      conversationListTerminations >= count
    }
  }

  func waitForInboxTerminations(_ count: Int) async {
    await waitUntil("inbox terminations >= \(count)") {
      inboxTerminations >= count
    }
  }

  private func waitUntil(
    _ description: String,
    timeout: Duration = .seconds(2),
    predicate: () -> Bool
  ) async {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    while clock.now < deadline {
      if predicate() { return }
      try? await Task.sleep(for: .milliseconds(1))
    }
    XCTFail("等待 \(description) 超时")
  }

  private func recordMachineTermination() { machineTerminations += 1 }
  private func recordConversationListTermination() { conversationListTerminations += 1 }
  private func recordConversationTermination() { conversationTerminations += 1 }
  private func recordInboxTermination() { inboxTerminations += 1 }

  private func recordPairingTermination() { pairingTerminations += 1 }

  private func installPairingContinuation(
    _ continuation: AsyncThrowingStream<PairingProgress, any Error>.Continuation,
    behavior: PairingBehavior
  ) {
    switch behavior {
    case .finished(let progress):
      for value in progress {
        continuation.yield(value)
      }
      continuation.finish()
    case .failure(let error):
      continuation.finish(throwing: error)
    case .suspended:
      pairingContinuations.append(continuation)
    case .suspendedBeforeStream:
      XCTFail("suspendedBeforeStream 必须在创建 stream 前处理")
      continuation.finish()
    }
  }

  private func makePairingStream(
    behavior: PairingBehavior
  ) -> AsyncThrowingStream<PairingProgress, any Error> {
    let pair = AsyncThrowingStream<PairingProgress, any Error>.makeStream(
      bufferingPolicy: .bufferingNewest(4)
    )
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.recordPairingTermination() }
    }
    installPairingContinuation(pair.continuation, behavior: behavior)
    return pair.stream
  }
}

enum SessionSourceTestValues {
  static func snapshot(
    conversationID: String,
    baseEventCursor: Any = "beforeFirst"
  ) throws -> ConversationSnapshotV2 {
    try decode(
      ConversationSnapshotV2.self,
      [
        "conversationId": conversationID,
        "baseEventCursor": baseEventCursor,
        "configurationState": [
          "configurationRevision": 0,
          "configuration": NSNull(),
        ],
        "items": [
          [
            "kind": "capabilities",
            "commandId": NSNull(),
            "itemId": NSNull(),
            "entityId": NSNull(),
            "capabilities": [
              "agentKind": "codex",
              "agentVersion": "fixture",
              "features": ["approval"],
              "vendor": [
                "agentKind": "codex",
                "sandboxModes": [],
                "persistenceSupported": false,
                "reasoningEffortLevels": [],
              ],
            ],
          ]
        ],
      ]
    )
  }

  static func turnStarted(
    conversationID: String,
    commandID: String,
    turnID: String,
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: RuntimeCommandID(rawValue: commandID),
      itemID: nil,
      entityID: nil,
      body: .turnStarted(turnID: RuntimeTurnID(rawValue: turnID))
    )
  }

  static func userMessage(
    conversationID: String,
    commandID: String,
    itemID: String = "item-user",
    text: String,
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: RuntimeCommandID(rawValue: commandID),
      itemID: RuntimeItemID(rawValue: itemID),
      entityID: RuntimeEntityID(rawValue: "entity-\(itemID)"),
      body: .item(
        .userMessage(text: text, meta: RuntimeAgentItemMetaV1())
      )
    )
  }

  static func actionRequest(
    conversationID: String,
    commandID: String,
    turnID: String,
    approvalID: String,
    requestID: String = "request-1",
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    let request = try decode(
      RuntimeActionRequestV1.self,
      [
        "requestId": requestID,
        "kind": "executeCommand",
        "summary": "uv run alembic upgrade head",
        "vendor": [
          "agentKind": "codex",
          "approvalPolicyAtDecision": "on-request",
          "sandboxAtDecision": "workspace-write",
          "canPersist": true,
        ],
      ]
    )
    return try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: RuntimeCommandID(rawValue: commandID),
      itemID: nil,
      entityID: nil,
      body: .actionRequest(
        turnID: RuntimeTurnID(rawValue: turnID),
        approvalID: RuntimeApprovalID(rawValue: approvalID),
        request: request
      )
    )
  }

  static func approvalResolved(
    conversationID: String,
    commandID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind?,
    state: ApprovalDeliveryStateV1,
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: RuntimeCommandID(rawValue: commandID),
      itemID: nil,
      entityID: nil,
      body: .approvalResolved(
        turnID: RuntimeTurnID(rawValue: turnID),
        approvalID: RuntimeApprovalID(rawValue: approvalID),
        decision: decision,
        state: state
      )
    )
  }

  static func turnCompleted(
    conversationID: String,
    commandID: String,
    turnID: String,
    eventSeq: UInt64
  ) throws -> RuntimeEventV2 {
    let summary = try decode(
      RuntimeTurnSummaryV1.self,
      [
        "totalInputTokens": 1,
        "totalOutputTokens": 1,
        "elapsedMs": 1,
      ]
    )
    return try RuntimeEventV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      eventID: RuntimeEventID(rawValue: "event-\(eventSeq)"),
      eventSeq: eventSeq,
      commandID: RuntimeCommandID(rawValue: commandID),
      itemID: nil,
      entityID: nil,
      body: .turnCompleted(
        turnID: RuntimeTurnID(rawValue: turnID),
        summary: summary
      )
    )
  }

  static func commandStatus(
    conversationID: String,
    commandID: String,
    status: CommandStatusV1,
    turnID: String? = nil
  ) -> CommandStatusReceiptV2 {
    CommandStatusReceiptV2(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      commandID: RuntimeCommandID(rawValue: commandID),
      configurationRevision: 1,
      status: status,
      turnID: turnID.map(RuntimeTurnID.init(rawValue:))
    )
  }

  private static func decode<T: Decodable>(_ type: T.Type, _ object: Any) throws -> T {
    let data = try JSONSerialization.data(
      withJSONObject: object,
      options: [.sortedKeys, .fragmentsAllowed]
    )
    return try JSONDecoder().decode(type, from: data)
  }
}

@MainActor
func waitForMainActorState(
  timeout: Duration = .seconds(2),
  _ predicate: () -> Bool
) async {
  let clock = ContinuousClock()
  let deadline = clock.now.advanced(by: timeout)
  while clock.now < deadline {
    if predicate() { return }
    try? await Task.sleep(for: .milliseconds(1))
  }
  XCTFail("等待 MainActor 状态超时")
}
