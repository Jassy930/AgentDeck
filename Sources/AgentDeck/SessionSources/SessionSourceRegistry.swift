import AgentDeckCore
import AgentDeckSessionSource
import Foundation

/// App 内部使用的机器路由键。本机不是字符串哨兵，remote 与 fixture 也不共享命名空间。
enum MachineScope: Hashable, Sendable {
  case local
  case remote(machineID: String)
  case fixture(id: String)

  fileprivate func validate() throws {
    switch self {
    case .local:
      return
    case .remote(let machineID):
      guard !machineID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw SessionSourceRegistryError.invalidRemoteMachineID
      }
    case .fixture(let id):
      guard !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw SessionSourceRegistryError.invalidFixtureID
      }
    }
  }
}

/// 只有本机 UDS source 才能提供的 conversation 管理面。
///
/// 普通 UI 继续只消费 `SessionSource`；需要本机管理能力的 composition/controller 必须
/// 显式取得该 capability，不能 downcast concrete source。
protocol LocalConversationAdministration: Sendable {
  func connectionLease() async throws -> LocalConversationConnectionLease

  func requireCurrentConnection(
    _ lease: LocalConversationConnectionLease
  ) async throws

  func requiresFreshConnection(
    _ lease: LocalConversationConnectionLease
  ) async -> Bool

  @discardableResult
  func invalidateConnection(
    _ lease: LocalConversationConnectionLease,
    reason: LocalConversationConnectionInvalidationReason
  ) async -> Bool

  func describeAgents(
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeAgentDescriptionsV2

  func startConversation(
    _ draft: RuntimeConversationDraft,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeConversationStartResult

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConfigurationReceiptV2

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConversationMetadataReceiptV2

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> ApprovalReceiptV1

  func loadCatalog(
    using lease: LocalConversationConnectionLease
  ) async throws -> [RuntimeCatalogSnapshotV2]

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult

  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult

  func unsubscribeConversation(
    _ conversationID: RuntimeConversationID,
    using lease: LocalConversationConnectionLease
  ) async throws

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> CommandReceiptV2
}

/// Registry/composition 独占的 source 生命周期 owner。
///
/// Handle 故意不暴露该接口，避免任意 UI consumer 关闭共享 source。`shutdown` 先阻止
/// 新工作，`join` 再等待该 generation 的 owner tasks 全部退出。
protocol SessionSourceLifecycle: SessionSource {
  func shutdown() async
  func join() async
}

struct SessionSourceCapabilities: Sendable {
  let localPairingAdministration: (any LocalPairingAdministration)?
  let localConversationAdministration: (any LocalConversationAdministration)?

  init(
    localPairingAdministration: (any LocalPairingAdministration)? = nil,
    localConversationAdministration: (any LocalConversationAdministration)? = nil
  ) {
    self.localPairingAdministration = localPairingAdministration
    self.localConversationAdministration = localConversationAdministration
  }
}

/// UI/model 可保存的最小路由结果；不包含 lifecycle，也不依赖 concrete source 类型。
struct SessionSourceHandle: Sendable {
  let scope: MachineScope
  let source: any SessionSource
  let localPairingAdministration: (any LocalPairingAdministration)?
  let localConversationAdministration: (any LocalConversationAdministration)?

  fileprivate init(registration: SessionSourceRegistration) {
    scope = registration.scope
    source = registration.source
    localPairingAdministration = registration.capabilities.localPairingAdministration
    localConversationAdministration = registration.capabilities.localConversationAdministration
  }
}

/// Composition/factory 交给 registry 的完整 owner record。
///
/// `source`、typed capabilities 与 lifecycle 显式分栏，避免通过 concrete downcast 猜能力，
/// 同时让 registry 成为唯一 teardown owner。
struct SessionSourceRegistration: Sendable {
  let scope: MachineScope
  let source: any SessionSource
  let capabilities: SessionSourceCapabilities
  fileprivate let lifecycle: any SessionSourceLifecycle

  init(
    scope: MachineScope,
    source: any SessionSource,
    capabilities: SessionSourceCapabilities,
    lifecycle: any SessionSourceLifecycle
  ) throws {
    try scope.validate()
    switch scope {
    case .local:
      guard capabilities.localPairingAdministration != nil,
        capabilities.localConversationAdministration != nil
      else {
        throw SessionSourceRegistryError.localCapabilitiesRequired
      }
    case .remote, .fixture:
      guard capabilities.localPairingAdministration == nil,
        capabilities.localConversationAdministration == nil
      else {
        throw SessionSourceRegistryError.localCapabilitiesForbidden(scope: scope)
      }
    }

    self.scope = scope
    self.source = source
    self.capabilities = capabilities
    self.lifecycle = lifecycle
  }

  fileprivate var handle: SessionSourceHandle {
    SessionSourceHandle(registration: self)
  }
}

enum SessionSourceRegistryError: Error, Equatable, Sendable {
  case invalidRemoteMachineID
  case invalidFixtureID
  case localCapabilitiesRequired
  case localCapabilitiesForbidden(scope: MachineScope)
  case localRegistrationRequired(actual: MachineScope)
  case fixtureRegistrationRequired(actual: MachineScope)
  case registrationScopeMismatch(expected: MachineScope, actual: MachineScope)
  case fixtureAlreadyRegistered(id: String)
  case unknownFixture(id: String)
  case unknownRemote(machineID: String)
  case shutDown
}

typealias RemoteSessionSourceFactory =
  @Sendable (_ machineID: String) async throws -> SessionSourceRegistration

/// local 固定、remote 按 machine ID 单飞缓存、fixture 显式注册的 source registry。
actor SessionSourceRegistry {
  private enum State: Sendable {
    case running
    case shuttingDown
    case shutDown
  }

  private struct RemoteOpening: Sendable {
    let generation: UUID
    let task: Task<SessionSourceRegistration, Error>
    let signal: RemoteOpeningSignal
    let completionTask: Task<Void, Never>
  }

  private enum RemoteOpeningWaitOutcome: Sendable {
    case completed(
      Result<SessionSourceRegistration, Error>,
      suppressFailureForReplacementWaiter: Bool
    )
    case cancelled
  }

  /// `Task.result` 本身不会因为 waiter 被取消而提前返回。每个 waiter 因此通过
  /// 独立 continuation 等待 shared factory；取消只解除该 waiter，factory 仍由
  /// registry generation 持有，并在 invalidate/shutdown 时统一取消、收口。
  private actor RemoteOpeningSignal {
    private struct Waiter {
      let suppressFailureForReplacementWaiter: Bool
      let continuation: CheckedContinuation<RemoteOpeningWaitOutcome, Never>
    }

    private var result: Result<SessionSourceRegistration, Error>?
    private var waiters: [UUID: Waiter] = [:]
    private var cancelledWaiters: Set<UUID> = []
    private var hasCancelledWaiter = false

    func wait(id: UUID) async -> RemoteOpeningWaitOutcome {
      if cancelledWaiters.remove(id) != nil { return .cancelled }
      if let result {
        return .completed(
          result,
          suppressFailureForReplacementWaiter: hasCancelledWaiter
        )
      }
      let suppressFailureForReplacementWaiter = hasCancelledWaiter
      return await withCheckedContinuation { continuation in
        waiters[id] = Waiter(
          suppressFailureForReplacementWaiter: suppressFailureForReplacementWaiter,
          continuation: continuation
        )
      }
    }

    func cancel(id: UUID) {
      guard result == nil else { return }
      hasCancelledWaiter = true
      if let waiter = waiters.removeValue(forKey: id) {
        waiter.continuation.resume(returning: .cancelled)
      } else {
        // onCancel 可能先于 operation 注册 continuation；保留有界的一次性 tombstone。
        cancelledWaiters.insert(id)
      }
    }

    func resolve(_ result: Result<SessionSourceRegistration, Error>) {
      guard self.result == nil else { return }
      self.result = result
      let pending = Array(waiters.values)
      waiters.removeAll(keepingCapacity: false)
      cancelledWaiters.removeAll(keepingCapacity: false)
      for waiter in pending {
        waiter.continuation.resume(
          returning: .completed(
            result,
            suppressFailureForReplacementWaiter: waiter.suppressFailureForReplacementWaiter
          )
        )
      }
    }
  }

  private struct RemoteReady: Sendable {
    let generation: UUID
    let registration: SessionSourceRegistration
  }

  private struct RemoteInvalidation: Sendable {
    let generation: UUID
    let task: Task<Void, Never>
  }

  private enum RemoteSlot: Sendable {
    case opening(RemoteOpening)
    case ready(RemoteReady)
    case invalidating(RemoteInvalidation)
  }

  private struct ShutdownOperation: Sendable {
    let id: UUID
    let task: Task<Void, Never>
  }

  private let local: SessionSourceRegistration
  private let remoteFactory: RemoteSessionSourceFactory
  private var fixtures: [String: SessionSourceRegistration] = [:]
  private var remoteSlots: [String: RemoteSlot] = [:]
  private var remoteGenerations: [String: UUID] = [:]
  private var state = State.running
  private var shutdownOperation: ShutdownOperation?

  init(
    local: SessionSourceRegistration,
    remoteFactory: @escaping RemoteSessionSourceFactory
  ) throws {
    guard local.scope == .local else {
      throw SessionSourceRegistryError.localRegistrationRequired(actual: local.scope)
    }
    self.local = local
    self.remoteFactory = remoteFactory
  }

  /// Fixture 必须由 preview/test composition 显式注册；不允许覆盖而泄漏旧 lifecycle。
  func registerFixture(_ registration: SessionSourceRegistration) throws {
    try requireRunning()
    try registration.scope.validate()
    guard case .fixture(let id) = registration.scope else {
      throw SessionSourceRegistryError.fixtureRegistrationRequired(actual: registration.scope)
    }
    guard fixtures[id] == nil else {
      throw SessionSourceRegistryError.fixtureAlreadyRegistered(id: id)
    }
    fixtures[id] = registration
  }

  func open(_ scope: MachineScope) async throws -> SessionSourceHandle {
    try Task.checkCancellation()
    try scope.validate()
    try requireRunning()

    switch scope {
    case .local:
      return local.handle
    case .fixture(let id):
      guard let registration = fixtures[id] else {
        throw SessionSourceRegistryError.unknownFixture(id: id)
      }
      return registration.handle
    case .remote(let machineID):
      return try await openRemote(machineID: machineID)
    }
  }

  /// 先把旧 generation 从可见 cache 隔离，再完整 shutdown/join；同 ID 的新 open
  /// 只能越过该 barrier 后 cold-open。generation token 使旧 factory completion 无法 ABA 回填。
  func invalidateRemote(machineID: String) async throws {
    let scope = MachineScope.remote(machineID: machineID)
    try scope.validate()
    try requireRunning()

    let invalidation: RemoteInvalidation
    switch remoteSlots[machineID] {
    case .none:
      throw SessionSourceRegistryError.unknownRemote(machineID: machineID)
    case .invalidating(let existing):
      invalidation = existing
    case .opening(let opening):
      let generation = UUID()
      remoteGenerations[machineID] = generation
      opening.task.cancel()
      let task = Task {
        if case .success(let registration) = await opening.task.result {
          await Self.shutdownAndJoin(registration.lifecycle)
        }
        await opening.completionTask.value
      }
      invalidation = RemoteInvalidation(generation: generation, task: task)
      remoteSlots[machineID] = .invalidating(invalidation)
    case .ready(let ready):
      let generation = UUID()
      remoteGenerations[machineID] = generation
      let task = Task {
        await Self.shutdownAndJoin(ready.registration.lifecycle)
      }
      invalidation = RemoteInvalidation(generation: generation, task: task)
      remoteSlots[machineID] = .invalidating(invalidation)
    }

    await invalidation.task.value
    finishInvalidation(machineID: machineID, generation: invalidation.generation)
  }

  /// 阻止所有新 open，等待 factory/invalidation 收敛，然后关闭并 join registry
  /// 拥有的 local、remote 与 fixture lifecycle。并发 shutdown 共享同一 barrier。
  func shutdown() async {
    let operation: ShutdownOperation
    switch state {
    case .running:
      state = .shuttingDown
      let id = UUID()
      let local = local
      let fixtures = Array(fixtures.values)
      let remoteSlots = Array(remoteSlots.values)
      self.fixtures.removeAll(keepingCapacity: false)
      self.remoteSlots.removeAll(keepingCapacity: false)

      let task = Task {
        await Self.shutdownRegistryOwners(
          local: local,
          fixtures: fixtures,
          remoteSlots: remoteSlots
        )
      }
      operation = ShutdownOperation(id: id, task: task)
      shutdownOperation = operation
    case .shuttingDown:
      guard let existing = shutdownOperation else {
        preconditionFailure("shuttingDown 必须持有 shutdown operation")
      }
      operation = existing
    case .shutDown:
      return
    }

    await operation.task.value
    if shutdownOperation?.id == operation.id {
      shutdownOperation = nil
      state = .shutDown
    }
  }

  private func openRemote(machineID: String) async throws -> SessionSourceHandle {
    while true {
      try Task.checkCancellation()
      try requireRunning()

      switch remoteSlots[machineID] {
      case .ready(let ready):
        guard remoteGenerations[machineID] == ready.generation else {
          remoteSlots.removeValue(forKey: machineID)
          continue
        }
        return ready.registration.handle

      case .invalidating(let invalidation):
        await invalidation.task.value
        finishInvalidation(machineID: machineID, generation: invalidation.generation)
        continue

      case .opening(let opening):
        let waiterID = UUID()
        let outcome = await withTaskCancellationHandler {
          await opening.signal.wait(id: waiterID)
        } onCancel: {
          Task { await opening.signal.cancel(id: waiterID) }
        }
        guard
          case .completed(
            let result,
            let suppressFailureForReplacementWaiter
          ) = outcome
        else {
          throw CancellationError()
        }
        try requireRunning()

        // invalidate 已切换 generation 时，旧 waiter 只能重走新 generation，不能返回旧 handle。
        guard remoteGenerations[machineID] == opening.generation else {
          try Task.checkCancellation()
          continue
        }

        switch result {
        case .success(let registration):
          switch remoteSlots[machineID] {
          case .opening(let current) where current.generation == opening.generation:
            remoteSlots[machineID] = .ready(
              RemoteReady(generation: opening.generation, registration: registration)
            )
          case .ready(let current) where current.generation == opening.generation:
            try Task.checkCancellation()
            return current.registration.handle
          default:
            continue
          }
          try Task.checkCancellation()
          return registration.handle

        case .failure(let error):
          if case .opening(let current) = remoteSlots[machineID],
            current.generation == opening.generation
          {
            remoteSlots.removeValue(forKey: machineID)
          }
          if suppressFailureForReplacementWaiter {
            try Task.checkCancellation()
            continue
          }
          // factory failure 不是 cache：即使当前唯一 waiter 已取消，也要先按 exact
          // generation 清掉失败 slot，再把 cancellation 传播给该 waiter。否则下一次
          // 显式 retry 只会重放旧失败，必须第三次 open 才真正 cold-open。
          try Task.checkCancellation()
          throw error
        }

      case .none:
        // 每次 cold-open 都必须 mint 新 generation。失败后的旧 waiter 可能晚于 retry
        // 恢复；若复用旧 token，它会把新 opening 误认成自己的 slot 并删除（ABA）。
        let generation = UUID()
        remoteGenerations[machineID] = generation
        let expectedScope = MachineScope.remote(machineID: machineID)
        let factory = remoteFactory
        let task = Task<SessionSourceRegistration, Error> {
          let registration = try await factory(machineID)
          guard registration.scope == expectedScope else {
            await Self.shutdownAndJoin(registration.lifecycle)
            throw SessionSourceRegistryError.registrationScopeMismatch(
              expected: expectedScope,
              actual: registration.scope
            )
          }
          return registration
        }
        let signal = RemoteOpeningSignal()
        let completionTask = Task { [weak self] in
          let result = await task.result
          await signal.resolve(result)
          if case .failure = result {
            await self?.finishFailedOpening(
              machineID: machineID,
              generation: generation
            )
          }
        }
        remoteSlots[machineID] = .opening(
          RemoteOpening(
            generation: generation,
            task: task,
            signal: signal,
            completionTask: completionTask
          )
        )
      }
    }
  }

  private func finishInvalidation(machineID: String, generation: UUID) {
    guard case .invalidating(let current) = remoteSlots[machineID],
      current.generation == generation
    else { return }
    remoteSlots.removeValue(forKey: machineID)
  }

  private func finishFailedOpening(machineID: String, generation: UUID) {
    guard case .opening(let current) = remoteSlots[machineID],
      current.generation == generation
    else { return }
    remoteSlots.removeValue(forKey: machineID)
  }

  private func requireRunning() throws {
    guard state == .running else {
      throw SessionSourceRegistryError.shutDown
    }
  }

  private static func shutdownAndJoin(_ lifecycle: any SessionSourceLifecycle) async {
    await lifecycle.shutdown()
    await lifecycle.join()
  }

  private static func shutdownRegistryOwners(
    local: SessionSourceRegistration,
    fixtures: [SessionSourceRegistration],
    remoteSlots: [RemoteSlot]
  ) async {
    var lifecycles: [any SessionSourceLifecycle] = [local.lifecycle]
    lifecycles.append(contentsOf: fixtures.map(\.lifecycle))
    var openings: [RemoteOpening] = []
    var invalidations: [Task<Void, Never>] = []

    for slot in remoteSlots {
      switch slot {
      case .ready(let ready):
        lifecycles.append(ready.registration.lifecycle)
      case .opening(let opening):
        openings.append(opening)
      case .invalidating(let invalidation):
        invalidations.append(invalidation.task)
      }
    }

    // 先并发通知全部已知 owner 停止接新工作。opening 也各自等待 factory，返回后立即
    // shutdown；某个 owner 或 factory 卡住不能让其它已知 WSS/UDS 继续保持 live。
    let knownShutdowns = lifecycles.map { lifecycle in
      Task { await lifecycle.shutdown() }
    }
    for opening in openings {
      opening.task.cancel()
    }
    let openingShutdowns = openings.map { opening in
      Task<(any SessionSourceLifecycle)?, Never> {
        guard case .success(let registration) = await opening.task.result else {
          await opening.completionTask.value
          return nil
        }
        await registration.lifecycle.shutdown()
        await opening.completionTask.value
        return registration.lifecycle
      }
    }
    let invalidationWaiters = invalidations.map { invalidation in
      Task { await invalidation.value }
    }

    for shutdown in knownShutdowns {
      await shutdown.value
    }
    for shutdown in openingShutdowns {
      if let lifecycle = await shutdown.value {
        lifecycles.append(lifecycle)
      }
    }
    for invalidation in invalidationWaiters {
      await invalidation.value
    }

    // 全部 owner 都收到 shutdown 后才并发 join。
    let joins = lifecycles.map { lifecycle in
      Task { await lifecycle.join() }
    }
    for join in joins {
      await join.value
    }
  }
}
