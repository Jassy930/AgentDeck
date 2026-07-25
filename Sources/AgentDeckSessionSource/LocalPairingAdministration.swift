import AgentDeckCore
import Foundation

public protocol LocalPairingAdministration: Sendable {
  func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>>

  func confirmPairing(id: String) async throws -> PairingAdministrationReceipt

  func cancelPairing(id: String) async throws -> PairingAdministrationReceipt
}
