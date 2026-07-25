import AgentDeckCore
import Foundation

public protocol SessionSource: Sendable {
  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>>

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>>

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate>

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>>

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error>

  func revokeSelf(machineID: String) async throws -> RevocationReceipt

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt
}
