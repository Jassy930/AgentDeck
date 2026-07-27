import AgentDeckCore
import AgentDeckSessionSource
import Foundation

/// 单台 MachineConnection 对 production Runtime command facade 暴露的最小 typed seam。
/// endpoint 自己拥有 active transport generation、DeviceRequestSigner、correlation waiter
/// 与 generation teardown；Source/facade 不接触 raw key 或 arbitrary sealed bytes。
protocol MachineRuntimeRequestEndpoint: Sendable {
  var machineID: String { get }

  func expectedGrantSerial() async throws -> UInt64

  func beginSubscription(
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) async throws

  func endSubscription(
    target: RuntimeSubscriptionTargetV1,
    requestID: RuntimeMessageID
  ) async throws

  func sendDirectedRequest(
    _ envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract
  ) async throws -> RuntimeReplyV2
}

protocol RelayPairingCommandHandling: Sendable {
  func shutdown() async
  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview
  func pair(_ encodedInvite: String) async throws -> AsyncThrowingStream<PairingProgress, Error>
}

private struct MissingRelayPairingCommandHandler: RelayPairingCommandHandling {
  func shutdown() async {}

  func inspectPairInvite(_: String) async throws -> PairingPreview {
    throw SessionSourceFailure(code: .commandRejected)
  }

  func pair(_: String) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    throw SessionSourceFailure(code: .commandRejected)
  }
}

typealias RelayRuntimeMessageIDGenerator = @Sendable () -> RuntimeMessageID

/// P5.4 production Runtime command/subscription facade。
///
/// 这里固定业务 DTO、messageId 与 exact reply contract；active generation 原子发送、
/// outcome-unknown retry、StreamBinding durable install 与 waiter lifecycle 留在 endpoint，
/// 从而不会把 Source actor 变成第二个 transport owner。
struct RelayRuntimeCommandClient: RelaySessionSourceCommandClient {
  private let endpoints: [String: any MachineRuntimeRequestEndpoint]
  private let pairing: any RelayPairingCommandHandling
  private let messageIDGenerator: RelayRuntimeMessageIDGenerator

  init(
    endpoints: [String: any MachineRuntimeRequestEndpoint],
    pairing: any RelayPairingCommandHandling = MissingRelayPairingCommandHandler(),
    messageIDGenerator: @escaping RelayRuntimeMessageIDGenerator = {
      RuntimeMessageID(rawValue: "relay-request-\(UUID().uuidString.lowercased())")
    }
  ) throws {
    for (machineID, endpoint) in endpoints {
      guard !machineID.isEmpty,
        machineID.utf8.count <= 8 * 1_024,
        endpoint.machineID == machineID
      else {
        throw SessionSourceFailure(code: .securityError)
      }
    }
    self.endpoints = endpoints
    self.pairing = pairing
    self.messageIDGenerator = messageIDGenerator
  }

  func shutdown() async {
    await pairing.shutdown()
  }

  func subscribe(
    machineID: String,
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) async throws {
    let endpoint = try endpoint(for: machineID)
    try Self.validate(requestID)
    try Self.validate(target)
    if case .at(UInt64.max) = after {
      throw SessionSourceFailure(code: .securityError)
    }
    try await endpoint.beginSubscription(
      target: target,
      after: after,
      requestID: requestID
    )
  }

  func unsubscribe(
    machineID: String,
    target: RuntimeSubscriptionTargetV1
  ) async throws {
    let endpoint = try endpoint(for: machineID)
    try Self.validate(target)
    let requestID = messageIDGenerator()
    try Self.validate(requestID)
    try await endpoint.endSubscription(
      target: target,
      requestID: requestID
    )
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    try await pairing.inspectPairInvite(encoded)
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    try await pairing.pair(encodedInvite)
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    let endpoint = try endpoint(for: machineID)
    let grantSerial = try await endpoint.expectedGrantSerial()
    guard grantSerial > 0 else {
      throw SessionSourceFailure(code: .securityError)
    }
    let reply = try await endpoint.sendDirectedRequest(
      try makeEnvelope(request: .revoke(target: .selfDevice)),
      contract: .revocation(expectedGrantSerial: grantSerial)
    )
    switch reply {
    case .revocation(.committed(let committed)):
      guard committed.rawValue == grantSerial else {
        throw SessionSourceFailure(code: .securityError)
      }
      return .committed(committed)
    case .revocation(.failed(let failure)):
      return .failed(failure)
    case .failure(let failure):
      throw Self.commandFailure(failure)
    case .hello, .agents, .configuration, .conversationMetadata, .stageUpgrade,
      .command, .commandStatus, .conversationStart, .cancellation, .approval,
      .subscription, .catalog, .snapshot, .backfill, .syncComplete, .transferPart,
      .pairInvite, .pendingPairings, .pairing, .machineRemoteStatus:
      throw SessionSourceFailure(code: .securityError)
    }
  }

  func sendPrompt(
    machineID: String,
    conversationID: String,
    text: String,
    idempotencyKey: UUID,
    expectedConfigurationRevision: UInt64
  ) async throws -> CommandReceipt {
    let endpoint = try endpoint(for: machineID)
    guard expectedConfigurationRevision > 0 else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let runtimeConversationID = try Self.runtimeConversationID(conversationID)
    let envelope = try makeEnvelope(
      messageID: Self.idempotentMessageID(prefix: "relay-command", idempotencyKey),
      request: .sendPrompt(
        conversationID: runtimeConversationID,
        idempotencyKey: RuntimeIdempotencyKey(
          rawValue: idempotencyKey.uuidString.lowercased()
        ),
        expectedConfigurationRevision: expectedConfigurationRevision,
        prompt: RuntimePromptPayloadV1(rawValue: text)
      )
    )
    let reply = try await endpoint.sendDirectedRequest(
      envelope,
      contract: .command(
        expectedConfigurationRevision: expectedConfigurationRevision
      )
    )
    switch reply {
    case .command(
      .accepted(let commandID, let queuePosition, let configurationRevision)
    ):
      guard configurationRevision == expectedConfigurationRevision else {
        throw SessionSourceFailure(code: .securityError)
      }
      return .accepted(
        commandID: commandID,
        queuePosition: queuePosition,
        configurationRevision: configurationRevision
      )
    case .command(.replayed(let commandID, let configurationRevision)):
      guard configurationRevision == expectedConfigurationRevision else {
        throw SessionSourceFailure(code: .securityError)
      }
      return .replayed(
        commandID: commandID,
        configurationRevision: configurationRevision
      )
    case .command(.failed(let failure)):
      return .failed(failure)
    case .failure(let failure):
      throw Self.commandFailure(failure)
    case .hello, .agents, .configuration, .conversationMetadata, .stageUpgrade,
      .commandStatus, .conversationStart, .cancellation, .approval, .revocation,
      .subscription, .catalog, .snapshot, .backfill, .syncComplete, .transferPart,
      .pairInvite, .pendingPairings, .pairing, .machineRemoteStatus:
      throw SessionSourceFailure(code: .securityError)
    }
  }

  func resolveApproval(
    machineID: String,
    conversationID: String,
    turnID: String,
    approvalID: String,
    requestID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    let endpoint = try endpoint(for: machineID)
    let runtimeApprovalID = try Self.runtimeApprovalID(approvalID)
    guard !turnID.isEmpty, turnID.utf8.count <= 8 * 1_024,
      !requestID.isEmpty, requestID.utf8.count <= 8 * 1_024
    else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let envelope = try makeEnvelope(
      messageID: Self.idempotentMessageID(prefix: "relay-approval", idempotencyKey),
      request: .resolveApproval(
        conversationID: try Self.runtimeConversationID(conversationID),
        turnID: RuntimeTurnID(rawValue: turnID),
        approvalID: runtimeApprovalID,
        decision: RuntimeActionDecisionV1(
          requestID: requestID,
          decision: decision,
          persist: false
        )
      )
    )
    let reply = try await endpoint.sendDirectedRequest(
      envelope,
      contract: .approval(expectedApprovalID: runtimeApprovalID, isRetry: false)
    )
    return try Self.approvalReceipt(
      reply,
      expectedApprovalID: runtimeApprovalID,
      isRetry: false
    )
  }

  func retryApprovalDelivery(
    machineID: String,
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    let endpoint = try endpoint(for: machineID)
    let runtimeApprovalID = try Self.runtimeApprovalID(approvalID)
    let envelope = try makeEnvelope(
      request: .retryApproval(
        conversationID: try Self.runtimeConversationID(conversationID),
        approvalID: runtimeApprovalID
      )
    )
    let reply = try await endpoint.sendDirectedRequest(
      envelope,
      contract: .approval(expectedApprovalID: runtimeApprovalID, isRetry: true)
    )
    return try Self.approvalReceipt(
      reply,
      expectedApprovalID: runtimeApprovalID,
      isRetry: true
    )
  }

  private func endpoint(
    for machineID: String
  ) throws -> any MachineRuntimeRequestEndpoint {
    guard let endpoint = endpoints[machineID] else {
      throw SessionSourceFailure(code: .machineOffline)
    }
    return endpoint
  }

  private func makeEnvelope(
    messageID: RuntimeMessageID? = nil,
    request: RuntimeRequestV2
  ) throws -> RuntimeEnvelopeV2 {
    let resolvedMessageID = messageID ?? messageIDGenerator()
    try Self.validate(resolvedMessageID)
    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: resolvedMessageID,
      body: .request(request)
    )
    _ = try RuntimeWireCodec.encode(envelope)
    return envelope
  }

  private static func validate(_ messageID: RuntimeMessageID) throws {
    guard !messageID.rawValue.isEmpty,
      messageID.rawValue.utf8.count <= RuntimeMessageIDKind.maximumWireUTF8Bytes!
    else {
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private static func validate(_ target: RuntimeSubscriptionTargetV1) throws {
    if case .conversation(let conversationID) = target {
      _ = try runtimeConversationID(conversationID.rawValue)
    }
  }

  private static func runtimeConversationID(
    _ value: String
  ) throws -> RuntimeConversationID {
    guard !value.isEmpty, value.utf8.count <= 8 * 1_024 else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    return RuntimeConversationID(rawValue: value)
  }

  private static func runtimeApprovalID(
    _ value: String
  ) throws -> RuntimeApprovalID {
    guard !value.isEmpty, value.utf8.count <= 8 * 1_024 else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    return RuntimeApprovalID(rawValue: value)
  }

  private static func idempotentMessageID(
    prefix: String,
    _ key: UUID
  ) -> RuntimeMessageID {
    RuntimeMessageID(rawValue: "\(prefix)-\(key.uuidString.lowercased())")
  }

  private static func approvalReceipt(
    _ reply: RuntimeReplyV2,
    expectedApprovalID: RuntimeApprovalID,
    isRetry: Bool
  ) throws -> ApprovalReceipt {
    switch reply {
    case .approval(let receipt):
      guard approvalID(receipt) == expectedApprovalID,
        !isRetry || retryApprovalReceiptIsAllowed(receipt)
      else {
        throw SessionSourceFailure(code: .securityError)
      }
      return receipt
    case .failure(let failure):
      throw commandFailure(failure)
    case .hello, .agents, .configuration, .conversationMetadata, .stageUpgrade,
      .command, .commandStatus, .conversationStart, .cancellation, .revocation,
      .subscription, .catalog, .snapshot, .backfill, .syncComplete, .transferPart,
      .pairInvite, .pendingPairings, .pairing, .machineRemoteStatus:
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private static func approvalID(
    _ receipt: ApprovalReceiptV1
  ) -> RuntimeApprovalID {
    switch receipt {
    case .claimed(let approvalID), .applied(let approvalID),
      .alreadyHandled(let approvalID, _, _), .deliveryFailed(let approvalID),
      .expired(let approvalID):
      return approvalID
    }
  }

  private static func retryApprovalReceiptIsAllowed(
    _ receipt: ApprovalReceiptV1
  ) -> Bool {
    switch receipt {
    case .applied, .deliveryFailed, .expired:
      return true
    case .alreadyHandled(_, _, let state):
      return state == .claimed || state == .applying || state == .expired
    case .claimed:
      return false
    }
  }

  private static func commandFailure(_ failure: RuntimeFailureV1) -> SessionSourceFailure {
    SessionSourceFailure(
      code: .commandRejected,
      message: failure.message,
      diagnosticReference: failure.diagnosticRef
    )
  }
}
