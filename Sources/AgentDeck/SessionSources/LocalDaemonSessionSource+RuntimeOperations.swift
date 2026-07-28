import AgentDeckCore
import AgentDeckSessionSource
import Foundation

extension LocalDaemonSessionSource {
  // MARK: - Shared SessionSource operations

  func inspectPairInvite(_: String) async throws -> PairingPreview {
    throw unsupportedLocalFacade("pair invite inspection belongs to the Relay client")
  }

  func pair(_: String) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    throw unsupportedLocalFacade("remote pairing belongs to the Relay client")
  }

  func revokeSelf(machineID _: String) async throws -> RevocationReceipt {
    throw unsupportedLocalFacade("the host local scope is not a paired remote device")
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    let state = try requireConversationState(conversationID)
    guard let revision = state.configurationState?.configurationRevision, revision > 0 else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let payload: RuntimePromptPayloadV1
    do {
      payload = try RuntimePromptPayloadV1(rawValue: text)
    } catch {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let lease = try await ensureStarted().lease
    let receipt = try await requireCoordinator(lease).sendPrompt(
      conversationID: RuntimeConversationID(rawValue: conversationID),
      idempotencyKey: RuntimeIdempotencyKey(rawValue: idempotencyKey.uuidString.lowercased()),
      expectedConfigurationRevision: revision,
      prompt: payload
    )
    try requireCurrent(lease)
    return receipt
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey _: UUID
  ) async throws -> ApprovalReceipt {
    let state = try requireConversationState(conversationID)
    guard
      let pending = state.pendingApprovals.first(where: {
        $0.approvalID.rawValue == approvalID && $0.turnID.rawValue == turnID
      })
    else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let lease = try await ensureStarted().lease
    let receipt = try await requireCoordinator(lease).resolveApproval(
      conversationID: state.conversationID,
      turnID: pending.turnID,
      approvalID: pending.approvalID,
      decision: RuntimeActionDecisionV1(
        requestID: pending.requestID,
        decision: decision,
        persist: false
      )
    )
    try requireCurrent(lease)
    return receipt
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    let state = try requireConversationState(conversationID)
    let lease = try await ensureStarted().lease
    let receipt = try await requireCoordinator(lease).retryApprovalDelivery(
      conversationID: state.conversationID,
      approvalID: RuntimeApprovalID(rawValue: approvalID)
    )
    try requireCurrent(lease)
    return receipt
  }

  // MARK: - Runtime administration

  // 确定性 component/source 测试便利面。`SessionModel` 不使用这些 overload，
  // 它必须先取 opaque lease，并在每个跨 actor 操作前后做 exact-generation 核对。
  func describeAgents() async throws -> RuntimeAgentDescriptionsV2 {
    let lease = try await connectionLease()
    return try await describeAgents(using: lease)
  }

  func startConversation(
    _ draft: RuntimeConversationDraft
  ) async throws -> AppRuntimeConversationStartResult {
    let lease = try await connectionLease()
    return try await startConversation(draft, using: lease)
  }

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2
  ) async throws -> RuntimeConfigurationReceiptV2 {
    let lease = try await connectionLease()
    return try await configureConversation(configuration, using: lease)
  }

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2
  ) async throws -> RuntimeConversationMetadataReceiptV2 {
    let lease = try await connectionLease()
    return try await updateConversationMetadata(mutation, using: lease)
  }

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1
  ) async throws -> ApprovalReceiptV1 {
    let lease = try await connectionLease()
    return try await resolveApproval(
      conversationID: conversationID,
      turnID: turnID,
      approvalID: approvalID,
      decision: decision,
      using: lease
    )
  }

  func describeAgents(
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeAgentDescriptionsV2 {
    try await ensureStarted(using: lease).descriptions
  }

  func startConversation(
    _ draft: RuntimeConversationDraft,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeConversationStartResult {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let result = try await requireCoordinator(lease).startConversation(draft)
    try requireCurrent(lease)
    return result
  }

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConfigurationReceiptV2 {
    _ = try await ensureStarted(using: lease)
    let receipt = try await requireCoordinator(lease).configureConversation(configuration)
    try requireCurrent(lease)
    return receipt
  }

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConversationMetadataReceiptV2 {
    _ = try await ensureStarted(using: lease)
    let receipt = try await requireCoordinator(lease).updateConversationMetadata(mutation)
    try requireCurrent(lease)
    return receipt
  }

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> ApprovalReceiptV1 {
    _ = try await ensureStarted(using: lease)
    let receipt = try await requireCoordinator(lease).resolveApproval(
      conversationID: conversationID,
      turnID: turnID,
      approvalID: approvalID,
      decision: decision
    )
    try requireCurrent(lease)
    return receipt
  }

  // MARK: - Existing SessionModel operation surface

  func loadCatalog() async throws -> [RuntimeCatalogSnapshotV2] {
    let lease = try await connectionLease()
    return try await loadCatalog(using: lease)
  }

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    let lease = try await connectionLease()
    return try await synchronizeCatalog(cursor: cursor, using: lease)
  }

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    let lease = try await connectionLease()
    return try await backfillCatalog(after: cursor, using: lease)
  }

  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    let lease = try await connectionLease()
    return try await synchronizeConversation(
      conversationID: conversationID,
      cursor: cursor,
      using: lease
    )
  }

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1
  ) async throws -> AppRuntimeSynchronizationResult {
    let lease = try await connectionLease()
    return try await backfillConversation(
      conversationID: conversationID,
      after: cursor,
      using: lease
    )
  }

  func unsubscribeConversation(_ conversationID: RuntimeConversationID) async throws {
    let lease = try await connectionLease()
    try await unsubscribeConversation(conversationID, using: lease)
  }

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1
  ) async throws -> CommandReceiptV2 {
    let lease = try await connectionLease()
    return try await sendPrompt(
      conversationID: conversationID,
      idempotencyKey: idempotencyKey,
      expectedConfigurationRevision: expectedConfigurationRevision,
      prompt: prompt,
      using: lease
    )
  }

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let result = try await requireCoordinator(lease).synchronizeCatalog(cursor: cursor)
    try requireCurrent(lease)
    return result
  }

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let result = try await requireCoordinator(lease).backfillCatalog(after: cursor)
    try requireCurrent(lease)
    return result
  }

  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let result = try await requireCoordinator(lease).synchronizeConversation(
      conversationID: conversationID,
      cursor: cursor
    )
    try requireCurrent(lease)
    return result
  }

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let result = try await requireCoordinator(lease).backfillConversation(
      conversationID: conversationID,
      after: cursor
    )
    try requireCurrent(lease)
    return result
  }

  func unsubscribeConversation(
    _ conversationID: RuntimeConversationID,
    using lease: LocalConversationConnectionLease
  ) async throws {
    try requireCurrent(lease)
    try await requireCoordinator(lease).unsubscribeConversation(conversationID)
    try requireCurrent(lease)
  }

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> CommandReceiptV2 {
    _ = try await ensureStarted(using: lease)
    let receipt = try await requireCoordinator(lease).sendPrompt(
      conversationID: conversationID,
      idempotencyKey: idempotencyKey,
      expectedConfigurationRevision: expectedConfigurationRevision,
      prompt: prompt
    )
    try requireCurrent(lease)
    return receipt
  }
}
