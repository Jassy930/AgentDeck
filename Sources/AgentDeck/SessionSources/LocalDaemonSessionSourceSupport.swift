import AgentDeckCore
import AgentDeckSessionSource
import Foundation

// 这些 module-internal nested support types 只服务于 LocalDaemonSessionSource 的跨文件实现。
extension LocalDaemonSessionSource {
  struct LocalResolvedPairingTombstone: Sendable {
    let expiresAtMs: UInt64
  }

  struct LocalDaemonConnection {
    let lease: LocalConversationConnectionLease
    let coordinator: AppRuntimeCoordinator
    let activationTask: Task<Void, Never>
    var started: Bool
    var descriptions: RuntimeAgentDescriptionsV2?
  }

  struct LocalDaemonConnectionOpening {
    let id: UUID
    let task: Task<any AppRuntimeWireSession, Error>
  }

  struct LocalDaemonStartOperation {
    let generation: UInt64
    let task: Task<RuntimeAgentDescriptionsV2, Error>
  }

  struct LocalDaemonSynchronizationWaiter {
    let id: UUID
    let continuation: CheckedContinuation<Bool, Never>
  }

  struct LocalConversationObservation {
    let id: UUID
    let broadcaster: BoundedBroadcaster<ConversationUpdate>
    let generation: BoundedBroadcastGeneration
    var task: Task<LocalConversationConnectionLease?, Never>?
  }

  struct LocalConversationAdmission {
    let id: UUID
    let broadcaster: BoundedBroadcaster<ConversationUpdate>
    let generation: BoundedBroadcastGeneration
  }

  struct LocalConversationRetirement {
    let id: UUID
    let task: Task<Void, Never>
  }

  struct LocalCatalogSynchronizationStage {
    var subscriptionGeneration: RuntimeStreamGeneration?
    var conversationID: RuntimeConversationID?
    var catalogSnapshots: [RuntimeCatalogSnapshotV2] = []
    var snapshot: ConversationSnapshotV2?
    var conversationBackfills: [RuntimeBackfillChunkV2] = []
    var catalogBackfills: [RuntimeBackfillChunkV2] = []
    var commandStatuses: [CommandStatusReceiptV2] = []
  }

  typealias WireFactory = @Sendable () async throws -> any AppRuntimeWireSession
  typealias MachineIdentityLoader = @Sendable () throws -> String
  typealias ConnectionActivationHandler = @Sendable (UInt64) async -> Void
  typealias InboundHandler = @Sendable (AppRuntimeInbound, UInt64) async throws -> Void
  typealias TerminationHandler = @Sendable (UInt64, SessionSourceFailure) async -> Void
  typealias NowMilliseconds = @Sendable () -> UInt64
  typealias ConversationAdmissionHook = @Sendable () async -> Void
  typealias SynchronizationPostGrantHook = @Sendable () async -> Void

  static let maximumResourceObservers = 8
  static let maximumConversationObservations = 64
  static let resourceBufferCapacity = 2
  static let conversationBufferCapacity = 512
  static let maximumResolvedPairingTombstones = 64
}
