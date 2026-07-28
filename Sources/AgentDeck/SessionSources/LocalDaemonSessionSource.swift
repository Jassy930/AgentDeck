import AgentDeckCore
import AgentDeckSessionSource
import Foundation

/// 一次本机 Runtime connection 的不可伪造租约。`SessionModel` 只能回传
/// source mint 出的 token；coordinator 始终留在 `LocalDaemonSessionSource` actor 内。
struct LocalConversationConnectionLease: Hashable, Sendable {
  let generation: UInt64
  fileprivate let token: UUID
}

enum LocalConversationConnectionInvalidationReason: Sendable {
  case coordinatorClosed
  case transportOrProtocolFault
  case failure(SessionSourceFailure)
}

/// macOS 本机唯一 Runtime v5 / UDS owner。
///
/// - `SessionModel` 的本机管理操作与共享 `SessionSource` facade 复用同一 coordinator；
/// - source replacement 只轮换内部 connection generation，不产生第二个 UDS owner；
/// - 所有资源流有界，conversation 每个 ID 只允许一个 observer；
/// - shutdown 只关闭本 client fd/pump，绝不向 daemon 发送 shutdown。
actor LocalDaemonSessionSource:
  SessionSourceLifecycle,
  LocalPairingAdministration,
  LocalConversationAdministration
{
  private let wireFactory: WireFactory?
  private var initialWire: (any AppRuntimeWireSession)?
  private let machineIdentityLoader: MachineIdentityLoader
  private let machineName: String
  private let connectionActivation: ConnectionActivationHandler
  private let downstreamInbound: InboundHandler
  private let downstreamTermination: TerminationHandler
  private let nowMilliseconds: NowMilliseconds
  private let conversationAdmissionHook: ConversationAdmissionHook?
  private let synchronizationPostGrantHook: SynchronizationPostGrantHook?

  private var connection: LocalDaemonConnection?
  private var connectionOpening: LocalDaemonConnectionOpening?
  private var connectionGeneration: UInt64 = 0
  private var connectionStartOperation: LocalDaemonStartOperation?
  private var connectionCloseTask: Task<Void, Never>?
  private var connectionCloseGeneration: UInt64?
  private var didShutdown = false
  private var shutdownComplete = false
  private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

  /// `AppRuntimeCoordinator` 的 synchronized request 是单飞协议。source 在它外层
  /// 提供 FIFO gate，让 catalog/conversation bootstrap 与本机 Start 不会因 actor
  /// reentrancy 撞出 `operationInProgress`。
  private var synchronizationTurnActive = false
  private var synchronizationTurnWaiters: [LocalDaemonSynchronizationWaiter] = []

  private var localMachineID: String?
  private var catalogModel: RuntimeCatalogModel?
  private var catalogSubscriptionReady = false
  private var synchronizationStage: LocalCatalogSynchronizationStage?
  private var conversationStates: [String: RuntimeConversationState] = [:]
  private var latestConversationSnapshots: [String: ConversationSnapshotV2] = [:]
  private var pendingPairingValues: [String: RuntimePendingPairingV4] = [:]
  private var pendingPairingLiveRevision: UInt64 = 0
  private var pendingPairingLiveRevisions: [String: UInt64] = [:]
  private var resolvedPairingTombstones: [String: LocalResolvedPairingTombstone] = [:]
  private var fatalFailure: SessionSourceFailure?
  private var resourceRevision: UInt64 = 0
  private var debugConversationOverflowCount = 0

  private var machineObservers: [UUID: AsyncStream<ResourceState<[MachineSummary]>>.Continuation] =
    [:]
  private var catalogObservers:
    [UUID: AsyncStream<ResourceState<[ConversationSummary]>>.Continuation] = [:]
  private var inboxObservers: [UUID: AsyncStream<ResourceState<[InboxItem]>>.Continuation] = [:]
  private var pairingObservers: [UUID: AsyncStream<ResourceState<[PendingPairing]>>.Continuation] =
    [:]
  private var conversationAdmissions: [String: LocalConversationAdmission] = [:]
  private var conversationObservations: [String: LocalConversationObservation] = [:]
  private var conversationRetirements: [String: LocalConversationRetirement] = [:]
  private var conversationRetirementWaiterCount = 0
  private var catalogBootstrapTask: Task<Void, Never>?
  private var machineBootstrapTask: Task<Void, Never>?
  private var pairingBootstrapTask: Task<Void, Never>?

  init(
    installation: LocalClientInstallation,
    machineName: String = Host.current().localizedName ?? "This Mac",
    connectionActivation: @escaping ConnectionActivationHandler,
    inboundHandler: @escaping InboundHandler = { _, _ in },
    terminationHandler: @escaping TerminationHandler = { _, _ in },
    conversationAdmissionHook: ConversationAdmissionHook? = nil,
    synchronizationPostGrantHook: SynchronizationPostGrantHook? = nil
  ) {
    wireFactory = { LocalRuntimeWireSession(installation: installation) }
    initialWire = nil
    machineIdentityLoader = {
      try installation.loadOrCreate().rawValue
    }
    self.machineName = machineName
    self.connectionActivation = connectionActivation
    downstreamInbound = inboundHandler
    downstreamTermination = terminationHandler
    nowMilliseconds = {
      UInt64(max(1, Date().timeIntervalSince1970 * 1_000))
    }
    self.conversationAdmissionHook = conversationAdmissionHook
    self.synchronizationPostGrantHook = synchronizationPostGrantHook
  }

  /// 确定性的 component/test seam。Production composition 不接受任意 pathname 或
  /// machine identity；注入 wire 默认只可消费一次，避免测试无意证明可重连。
  init(
    runtimeWire: any AppRuntimeWireSession,
    machineID: String,
    machineName: String = "Test Mac",
    connectionActivation: @escaping ConnectionActivationHandler = { _ in },
    inboundHandler: @escaping InboundHandler = { _, _ in },
    terminationHandler: @escaping TerminationHandler = { _, _ in },
    nowMilliseconds: @escaping NowMilliseconds = { 0 },
    conversationAdmissionHook: ConversationAdmissionHook? = nil,
    synchronizationPostGrantHook: SynchronizationPostGrantHook? = nil
  ) {
    wireFactory = nil
    initialWire = runtimeWire
    machineIdentityLoader = { machineID }
    self.machineName = machineName
    self.connectionActivation = connectionActivation
    downstreamInbound = inboundHandler
    downstreamTermination = terminationHandler
    self.nowMilliseconds = nowMilliseconds
    self.conversationAdmissionHook = conversationAdmissionHook
    self.synchronizationPostGrantHook = synchronizationPostGrantHook
  }

  init(
    runtimeWireFactory: @escaping WireFactory,
    machineID: String,
    machineName: String = "Test Mac",
    connectionActivation: @escaping ConnectionActivationHandler = { _ in },
    inboundHandler: @escaping InboundHandler = { _, _ in },
    terminationHandler: @escaping TerminationHandler = { _, _ in },
    nowMilliseconds: @escaping NowMilliseconds = { 0 },
    conversationAdmissionHook: ConversationAdmissionHook? = nil,
    synchronizationPostGrantHook: SynchronizationPostGrantHook? = nil
  ) {
    wireFactory = runtimeWireFactory
    initialWire = nil
    machineIdentityLoader = { machineID }
    self.machineName = machineName
    self.connectionActivation = connectionActivation
    downstreamInbound = inboundHandler
    downstreamTermination = terminationHandler
    self.nowMilliseconds = nowMilliseconds
    self.conversationAdmissionHook = conversationAdmissionHook
    self.synchronizationPostGrantHook = synchronizationPostGrantHook
  }

  // MARK: - Connection ownership

  func connectionLease() async throws -> LocalConversationConnectionLease {
    while true {
      if let fatalFailure { throw fatalFailure }
      try await installConnectionIfNeeded()
      guard !didShutdown, let current = connection else {
        throw AppRuntimeCoordinatorError.closed
      }
      await current.activationTask.value
      try requireCurrent(current.lease)
      if await current.coordinator.requiresFreshConnection() {
        _ = await invalidateConnection(
          current.lease,
          reason: .coordinatorClosed
        )
        continue
      }
      return current.lease
    }
  }

  func ensureStarted() async throws -> (
    lease: LocalConversationConnectionLease,
    descriptions: RuntimeAgentDescriptionsV2,
    openedFreshConnection: Bool
  ) {
    let lease = try await connectionLease()
    return try await ensureStarted(using: lease)
  }

  func ensureStarted(
    using lease: LocalConversationConnectionLease
  ) async throws -> (
    lease: LocalConversationConnectionLease,
    descriptions: RuntimeAgentDescriptionsV2,
    openedFreshConnection: Bool
  ) {
    while true {
      try requireCurrent(lease)
      guard let coordinator = coordinator(for: lease) else {
        throw AppRuntimeCoordinatorError.closed
      }
      if await coordinator.requiresFreshConnection() {
        _ = await invalidateConnection(lease, reason: .coordinatorClosed)
        throw AppRuntimeCoordinatorError.closed
      }
      if let descriptions = connection?.descriptions {
        return (lease, descriptions, false)
      }

      let operation: LocalDaemonStartOperation
      let openedFreshConnection: Bool
      if let current = connectionStartOperation,
        current.generation == lease.generation
      {
        operation = current
        openedFreshConnection = false
      } else {
        let needsStart = connection?.started != true
        let task = Task<RuntimeAgentDescriptionsV2, Error> {
          if needsStart {
            try await coordinator.start()
            self.markConnectionStarted(lease)
          }
          return try await coordinator.describeAgents()
        }
        operation = LocalDaemonStartOperation(generation: lease.generation, task: task)
        connectionStartOperation = operation
        openedFreshConnection = needsStart
      }

      do {
        let descriptions = try await operation.task.value
        try requireCurrent(lease)
        guard connectionStartOperation?.generation == lease.generation else {
          continue
        }
        connectionStartOperation = nil
        connection?.descriptions = descriptions
        if localMachineID == nil {
          let identity = try machineIdentityLoader()
          guard !identity.isEmpty else {
            throw SessionSourceFailure(code: .securityError)
          }
          localMachineID = identity
        }
        publishMachinesConnected()
        return (lease, descriptions, openedFreshConnection)
      } catch {
        if connectionStartOperation?.generation == lease.generation {
          connectionStartOperation = nil
        }
        throw error
      }
    }
  }

  func requireCurrent(_ lease: LocalConversationConnectionLease) throws {
    guard !didShutdown,
      connection?.lease.generation == lease.generation,
      connection?.lease.token == lease.token
    else {
      throw AppRuntimeCoordinatorError.closed
    }
  }

  private func isCurrent(_ lease: LocalConversationConnectionLease?) -> Bool {
    guard !didShutdown, let lease else { return lease == nil && connection == nil }
    return connection?.lease.generation == lease.generation
      && connection?.lease.token == lease.token
  }

  func requireCurrentConnection(
    _ lease: LocalConversationConnectionLease
  ) async throws {
    try requireCurrent(lease)
  }

  func requiresFreshConnection(_ lease: LocalConversationConnectionLease) async -> Bool {
    guard isCurrent(lease) else { return true }
    guard let coordinator = coordinator(for: lease) else { return true }
    return await coordinator.requiresFreshConnection()
  }

  private func coordinator(
    for lease: LocalConversationConnectionLease
  ) -> AppRuntimeCoordinator? {
    guard connection?.lease == lease else { return nil }
    return connection?.coordinator
  }

  private func markConnectionStarted(_ lease: LocalConversationConnectionLease) {
    guard connection?.lease == lease else { return }
    connection?.started = true
  }

  func requireCoordinator(
    _ lease: LocalConversationConnectionLease
  ) throws -> AppRuntimeCoordinator {
    try requireCurrent(lease)
    guard let coordinator = coordinator(for: lease) else {
      throw AppRuntimeCoordinatorError.closed
    }
    return coordinator
  }

  func acquireSynchronizationTurn() async throws {
    try Task.checkCancellation()
    guard !didShutdown else { throw AppRuntimeCoordinatorError.closed }
    if !synchronizationTurnActive {
      synchronizationTurnActive = true
      return
    }
    let waiterID = UUID()
    let granted = await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        if Task.isCancelled || didShutdown {
          continuation.resume(returning: false)
        } else {
          synchronizationTurnWaiters.append(
            LocalDaemonSynchronizationWaiter(
              id: waiterID,
              continuation: continuation
            )
          )
        }
      }
    } onCancel: {
      Task { await self.cancelSynchronizationWaiter(waiterID) }
    }
    guard granted else {
      if didShutdown { throw AppRuntimeCoordinatorError.closed }
      throw CancellationError()
    }
    await synchronizationPostGrantHook?()
    do {
      try Task.checkCancellation()
      guard !didShutdown else { throw AppRuntimeCoordinatorError.closed }
    } catch {
      releaseSynchronizationTurn()
      throw error
    }
  }

  func releaseSynchronizationTurn() {
    guard synchronizationTurnActive else { return }
    if synchronizationTurnWaiters.isEmpty {
      synchronizationTurnActive = false
    } else {
      synchronizationTurnWaiters.removeFirst().continuation.resume(returning: true)
    }
  }

  private func cancelSynchronizationWaiter(_ id: UUID) {
    guard let index = synchronizationTurnWaiters.firstIndex(where: { $0.id == id }) else {
      return
    }
    synchronizationTurnWaiters.remove(at: index).continuation.resume(returning: false)
  }

  @discardableResult
  func invalidateConnection(
    _ lease: LocalConversationConnectionLease,
    reason: LocalConversationConnectionInvalidationReason
  ) async -> Bool {
    guard connection?.lease.generation == lease.generation,
      connection?.lease.token == lease.token,
      let coordinator = connection?.coordinator
    else { return false }
    let exactFailure = await coordinator.streamFailure()
    guard connection?.lease == lease else { return false }
    let failure =
      exactFailure.map { Self.publicFailure($0) }
      ?? Self.failure(for: reason)
    connection = nil
    connectionStartOperation?.task.cancel()
    connectionStartOperation = nil
    synchronizationStage = nil
    catalogSubscriptionReady = false
    let task = Task { await coordinator.close() }
    connectionCloseTask = task
    connectionCloseGeneration = lease.generation
    await task.value
    if connectionCloseGeneration == lease.generation {
      connectionCloseTask = nil
      connectionCloseGeneration = nil
    }
    await publishConnectionFailure(failure)
    await downstreamTermination(lease.generation, failure)
    return true
  }

  /// 旧 component test seam；production/model 使用带 typed reason 的 capability API。
  func invalidate(_ lease: LocalConversationConnectionLease) async {
    _ = await invalidateConnection(lease, reason: .transportOrProtocolFault)
  }

  func shutdown() async {
    if didShutdown {
      await waitForShutdownCompletion()
      return
    }
    didShutdown = true
    let opening = connectionOpening
    connectionOpening = nil
    opening?.task.cancel()
    connectionStartOperation?.task.cancel()
    let startTask = connectionStartOperation?.task
    connectionStartOperation = nil
    let catalogTask = catalogBootstrapTask
    catalogBootstrapTask?.cancel()
    catalogBootstrapTask = nil
    let pairingTask = pairingBootstrapTask
    pairingBootstrapTask?.cancel()
    pairingBootstrapTask = nil
    let machineTask = machineBootstrapTask
    machineBootstrapTask?.cancel()
    machineBootstrapTask = nil
    let activeAdmissions = Array(conversationAdmissions.values)
    let activeObservations = Array(conversationObservations.values)
    conversationAdmissions.removeAll(keepingCapacity: false)
    conversationObservations.removeAll(keepingCapacity: false)
    for admission in activeAdmissions { await admission.broadcaster.finish() }
    for observation in activeObservations { await observation.broadcaster.finish() }
    let turnWaiters = synchronizationTurnWaiters
    synchronizationTurnWaiters.removeAll(keepingCapacity: false)
    synchronizationTurnActive = false
    for waiter in turnWaiters { waiter.continuation.resume(returning: false) }
    let priorCloseTask = connectionCloseTask
    let active = connection
    connection = nil
    if let active {
      await active.activationTask.value
      let task = Task { await active.coordinator.close() }
      connectionCloseTask = task
      connectionCloseGeneration = active.lease.generation
      await task.value
    }
    if let opening,
      case .success(let wire) = await opening.task.result
    {
      await wire.close()
    }
    await priorCloseTask?.value
    _ = await startTask?.result
    await catalogTask?.value
    await pairingTask?.value
    await machineTask?.value
    for observation in activeObservations { _ = await observation.task?.value }
    let retirementTasks = Array(conversationRetirements.values)
    for retirement in retirementTasks { await retirement.task.value }
    conversationRetirements.removeAll(keepingCapacity: false)
    await finishAllStreams()
    shutdownComplete = true
    let waiters = shutdownWaiters
    shutdownWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
  }

  func join() async {
    await shutdown()
  }

  private func waitForShutdownCompletion() async {
    if shutdownComplete { return }
    await withCheckedContinuation { continuation in
      shutdownWaiters.append(continuation)
    }
  }

  private func installConnectionIfNeeded() async throws {
    if let fatalFailure { throw fatalFailure }
    while let task = connectionCloseTask {
      let generation = connectionCloseGeneration
      await task.value
      if connectionCloseGeneration == generation {
        connectionCloseTask = nil
        connectionCloseGeneration = nil
      }
    }
    if let fatalFailure { throw fatalFailure }
    guard !didShutdown else { throw AppRuntimeCoordinatorError.closed }
    if let connection {
      await connection.activationTask.value
      try requireCurrent(connection.lease)
      return
    }

    let opening: LocalDaemonConnectionOpening
    if let current = connectionOpening {
      opening = current
    } else {
      let task: Task<any AppRuntimeWireSession, Error>
      if let initialWire {
        self.initialWire = nil
        task = Task { initialWire }
      } else if let wireFactory {
        task = Task { try await wireFactory() }
      } else {
        throw AppRuntimeCoordinatorError.closed
      }
      opening = LocalDaemonConnectionOpening(id: UUID(), task: task)
      connectionOpening = opening
    }

    let result = await opening.task.result
    let ownsOpeningResult = connectionOpening?.id == opening.id
    if ownsOpeningResult {
      connectionOpening = nil
    }
    let wire = try result.get()
    guard !didShutdown else {
      // shutdown 先取走 opening 时由 shutdown owner 关闭该 wire；否则由当前
      // completion owner 收口，保证 async factory 产物只 close 一次。
      if ownsOpeningResult { await wire.close() }
      throw AppRuntimeCoordinatorError.closed
    }
    if let connection {
      // 并发 waiter 共用同一 opening；第一个 waiter 已安装后，后续 waiter
      // 只等待该 generation 的 activation barrier，不能关闭共享 wire。
      await connection.activationTask.value
      try requireCurrent(connection.lease)
      return
    }

    connectionGeneration &+= 1
    guard connectionGeneration != 0 else {
      didShutdown = true
      await wire.close()
      throw SessionSourceFailure(code: .securityError)
    }
    let generation = connectionGeneration
    let lease = LocalConversationConnectionLease(generation: generation, token: UUID())
    let source = self
    let coordinator = AppRuntimeCoordinator(
      wire: wire,
      inboundHandler: { inbound in
        try await source.forward(inbound, generation: generation)
      },
      terminationHandler: {
        await source.connectionTerminated(generation: generation)
      }
    )
    let activationTask = Task {
      await source.connectionActivation(generation)
    }
    connection = LocalDaemonConnection(
      lease: lease,
      coordinator: coordinator,
      activationTask: activationTask,
      started: false,
      descriptions: nil
    )
    await activationTask.value
    try requireCurrent(lease)
  }

  private func forward(_ inbound: AppRuntimeInbound, generation: UInt64) async throws {
    guard connection?.lease.generation == generation, !didShutdown else { return }
    // 旧 App model canonical reducer 先验证；本 source projection 只在它成功后发布。
    try await downstreamInbound(inbound, generation)
    guard connection?.lease.generation == generation, !didShutdown else { return }
    try await ingest(inbound)
  }

  private func connectionTerminated(generation: UInt64) async {
    guard let active = connection, active.lease.generation == generation else { return }
    let failure = Self.publicFailure(await active.coordinator.streamFailure())
    guard connection?.lease == active.lease else { return }
    connection = nil
    synchronizationStage = nil
    catalogSubscriptionReady = false
    await publishConnectionFailure(failure)
    await downstreamTermination(generation, failure)
  }

  @discardableResult
  private func invalidateCurrentConnectionIfNeeded(
    after error: any Error
  ) async -> Bool {
    let failure = Self.publicFailure(error)
    guard Self.requiresConnectionInvalidation(failure) else { return false }
    if fatalFailure != nil { return true }
    guard let lease = connection?.lease else {
      await publishConnectionFailure(failure)
      return true
    }
    return await invalidateConnection(lease, reason: .failure(failure))
  }

  // MARK: - Shared SessionSource

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    if let fatalFailure {
      return terminalResourceStream(.failed(error: fatalFailure, retryable: false))
    }
    guard !didShutdown, machineObservers.count < Self.maximumResourceObservers else {
      return terminalResourceStream(
        .failed(
          error: SessionSourceFailure(code: didShutdown ? .transportUnavailable : .securityError),
          retryable: !didShutdown
        ))
    }
    let id = UUID()
    let pair = AsyncStream<ResourceState<[MachineSummary]>>.makeStream(
      bufferingPolicy: .bufferingNewest(Self.resourceBufferCapacity)
    )
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeMachineObserver(id) }
    }
    machineObservers[id] = pair.continuation
    pair.continuation.yield(.loading(previous: currentMachines()))
    startMachineBootstrapIfNeeded()
    return pair.stream
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    do {
      _ = try await ensureStarted()
      guard machineID == localMachineID else {
        return terminalResourceStream(
          .failed(
            error: SessionSourceFailure(code: .machineOffline),
            retryable: false
          ))
      }
    } catch {
      let failure = Self.publicFailure(error)
      return terminalResourceStream(
        .failed(
          error: failure,
          retryable: Self.isRetryable(failure)
        ))
    }
    guard catalogObservers.count < Self.maximumResourceObservers else {
      return terminalResourceStream(
        .failed(
          error: SessionSourceFailure(code: .securityError),
          retryable: false
        ))
    }
    let id = UUID()
    let pair = AsyncStream<ResourceState<[ConversationSummary]>>.makeStream(
      bufferingPolicy: .bufferingNewest(Self.resourceBufferCapacity)
    )
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeCatalogObserver(id) }
    }
    catalogObservers[id] = pair.continuation
    if let catalogModel, catalogSubscriptionReady {
      pair.continuation.yield(
        .ready(value: conversationSummaries(catalogModel), revision: nextResourceRevision())
      )
    } else {
      pair.continuation.yield(
        .loading(previous: catalogModel.map(conversationSummaries))
      )
    }
    startCatalogBootstrapIfNeeded()
    return pair.stream
  }

  func conversation(
    conversationID: String
  ) async -> AsyncStream<ConversationUpdate> {
    if let fatalFailure {
      return terminalConversationStream(connectionState(for: fatalFailure))
    }
    guard !conversationID.isEmpty, !didShutdown else {
      return terminalConversationStream(.machineOffline)
    }
    while let retirement = conversationRetirements[conversationID] {
      conversationRetirementWaiterCount += 1
      await retirement.task.value
      conversationRetirementWaiterCount -= 1
      guard !didShutdown, !Task.isCancelled else {
        return terminalConversationStream(.machineOffline)
      }
    }
    guard !didShutdown,
      !Task.isCancelled,
      conversationAdmissions[conversationID] == nil,
      conversationObservations[conversationID] == nil,
      conversationRetirements[conversationID] == nil,
      conversationAdmissions.count + conversationObservations.count
        + conversationRetirements.count
        < Self.maximumConversationObservations
    else {
      return terminalConversationStream(.lagged(reason: .snapshotRequired))
    }

    let id = UUID()
    let generation = BoundedBroadcastGeneration()
    let broadcaster = BoundedBroadcaster<ConversationUpdate>(
      capacity: Self.conversationBufferCapacity,
      overflowStrategy: .invalidateGeneration,
      generation: generation,
      maximumObservers: 1
    )
    // 在第一次跨 actor await 前占住 exact ID、全局容量与 provisional broadcaster；
    // 否则同 ID 并发 open 或 65 路 admission 都能越过 actor reentrancy 的 guard，
    // shutdown 也无法关闭尚未登记的 owner。
    conversationAdmissions[conversationID] = LocalConversationAdmission(
      id: id,
      broadcaster: broadcaster,
      generation: generation
    )
    await conversationAdmissionHook?()
    guard
      let stream = await broadcaster.streamIfAvailable(
        onTermination: { [weak self] in
          Task {
            await self?.conversationObserverDidTerminate(
              conversationID: conversationID,
              observationID: id
            )
          }
        }
      )
    else {
      if conversationAdmissions[conversationID]?.id == id {
        conversationAdmissions.removeValue(forKey: conversationID)
      }
      return terminalConversationStream(
        didShutdown ? .machineOffline : .lagged(reason: .snapshotRequired)
      )
    }
    guard !didShutdown,
      !Task.isCancelled,
      conversationAdmissions[conversationID]?.id == id,
      conversationObservations[conversationID] == nil,
      conversationRetirements[conversationID] == nil
    else {
      if conversationAdmissions[conversationID]?.id == id {
        conversationAdmissions.removeValue(forKey: conversationID)
      }
      await broadcaster.finish()
      return terminalConversationStream(.machineOffline)
    }
    conversationAdmissions.removeValue(forKey: conversationID)
    conversationObservations[conversationID] = LocalConversationObservation(
      id: id,
      broadcaster: broadcaster,
      generation: generation,
      task: nil
    )
    _ = await broadcaster.publish(
      .connectionState(.connecting),
      on: generation
    )
    let task = Task<LocalConversationConnectionLease?, Never> { [weak self] in
      guard let self else { return nil }
      return await self.bootstrapConversation(conversationID, observationID: id)
    }
    conversationObservations[conversationID]?.task = task
    return stream
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    if let fatalFailure {
      return terminalResourceStream(.failed(error: fatalFailure, retryable: false))
    }
    guard !didShutdown, inboxObservers.count < Self.maximumResourceObservers else {
      return terminalResourceStream(
        .failed(
          error: SessionSourceFailure(code: didShutdown ? .transportUnavailable : .securityError),
          retryable: !didShutdown
        ))
    }
    let id = UUID()
    let pair = AsyncStream<ResourceState<[InboxItem]>>.makeStream(
      bufferingPolicy: .bufferingNewest(Self.resourceBufferCapacity)
    )
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeInboxObserver(id) }
    }
    inboxObservers[id] = pair.continuation
    pair.continuation.yield(.ready(value: inboxValues(), revision: resourceRevision))
    return pair.stream
  }

  // MARK: - Local-only administration

  func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>> {
    if let fatalFailure {
      return terminalResourceStream(.failed(error: fatalFailure, retryable: false))
    }
    guard !didShutdown, pairingObservers.count < Self.maximumResourceObservers else {
      return terminalResourceStream(
        .failed(
          error: SessionSourceFailure(code: didShutdown ? .transportUnavailable : .securityError),
          retryable: !didShutdown
        ))
    }
    let id = UUID()
    let pair = AsyncStream<ResourceState<[PendingPairing]>>.makeStream(
      bufferingPolicy: .bufferingNewest(Self.resourceBufferCapacity)
    )
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removePairingObserver(id) }
    }
    pairingObservers[id] = pair.continuation
    pair.continuation.yield(.loading(previous: sortedPendingPairings()))
    startPairingBootstrapIfNeeded()
    return pair.stream
  }

  func confirmPairing(id: String) async throws -> PairingAdministrationReceipt {
    try await pairingDecision(id: id, confirm: true)
  }

  func cancelPairing(id: String) async throws -> PairingAdministrationReceipt {
    try await pairingDecision(id: id, confirm: false)
  }

  func loadCatalog(
    using lease: LocalConversationConnectionLease
  ) async throws -> [RuntimeCatalogSnapshotV2] {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    _ = try await ensureStarted(using: lease)
    try Task.checkCancellation()
    let pages = try await requireCoordinator(lease).loadCatalog()
    try requireCurrent(lease)
    // SessionModel 与 SessionSource facade 共用这一条 coordinator ingress；因此 read path
    // 也必须先给 source projection 安装同一份 canonical baseline。否则随后 Subscribe 的
    // SyncComplete 会因为 source 缺 catalogModel 而被误判为 security failure。这里只安装
    // baseline，仍要等 Subscribe/Backfill 的完整 terminal 才能发布 ready catalog。
    catalogModel = try RuntimeCatalogModel(snapshotPages: pages)
    catalogSubscriptionReady = false
    return pages
  }

  // MARK: - Projection / publication

  private func ingest(_ inbound: AppRuntimeInbound) async throws {
    switch inbound {
    case .synchronizedReply(let reply):
      try await ingestSynchronized(reply)
    case .stream(let frame):
      try await ingestLive(frame.item)
    }
  }

  private func ingestSynchronized(_ reply: RuntimeReplyV2) async throws {
    var stage = synchronizationStage ?? LocalCatalogSynchronizationStage()
    switch reply {
    case .subscription(.subscribed(let generation)):
      guard stage.subscriptionGeneration == nil else {
        throw SessionSourceFailure(code: .securityError)
      }
      stage.subscriptionGeneration = generation
      synchronizationStage = stage
    case .catalog(let page):
      guard stage.conversationID == nil, stage.snapshot == nil,
        stage.conversationBackfills.isEmpty, stage.catalogBackfills.isEmpty
      else {
        throw SessionSourceFailure(code: .securityError)
      }
      stage.catalogSnapshots.append(page)
      synchronizationStage = stage
    case .snapshot(let snapshot):
      guard stage.catalogSnapshots.isEmpty, stage.snapshot == nil,
        stage.catalogBackfills.isEmpty,
        stage.conversationBackfills.isEmpty
      else {
        throw SessionSourceFailure(code: .securityError)
      }
      stage.conversationID = snapshot.conversationID
      stage.snapshot = snapshot
      synchronizationStage = stage
    case .backfill(let backfill):
      switch backfill {
      case .catalog:
        guard stage.snapshot == nil, stage.conversationID == nil,
          stage.conversationBackfills.isEmpty
        else {
          throw SessionSourceFailure(code: .securityError)
        }
        stage.catalogBackfills.append(backfill)
      case .conversation(let conversationID, _, _, _):
        guard stage.catalogSnapshots.isEmpty, stage.catalogBackfills.isEmpty else {
          throw SessionSourceFailure(code: .securityError)
        }
        if let expected = stage.conversationID, expected != conversationID {
          throw SessionSourceFailure(code: .securityError)
        }
        stage.conversationID = conversationID
        stage.conversationBackfills.append(backfill)
      }
      synchronizationStage = stage
    case .commandStatus(let status):
      stage.commandStatuses.append(status)
      synchronizationStage = stage
    case .syncComplete(let terminal):
      try await commitSynchronization(stage, terminal: terminal)
      synchronizationStage = nil
    case .failure(let failure):
      synchronizationStage = nil
      throw SessionSourceFailure(
        code: .commandRejected,
        message: failure.message,
        diagnosticReference: failure.diagnosticRef
      )
    default:
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private func commitSynchronization(
    _ stage: LocalCatalogSynchronizationStage,
    terminal: RuntimeSyncCompleteV1
  ) async throws {
    switch terminal.innerCursor {
    case .catalog(let terminalCursor):
      guard stage.conversationID == nil, stage.snapshot == nil,
        stage.conversationBackfills.isEmpty
      else { throw SessionSourceFailure(code: .securityError) }
      var model: RuntimeCatalogModel
      if stage.catalogSnapshots.isEmpty {
        guard let existing = catalogModel else {
          throw SessionSourceFailure(code: .securityError)
        }
        model = existing
      } else {
        model = try RuntimeCatalogModel(snapshotPages: stage.catalogSnapshots)
      }
      for backfill in stage.catalogBackfills {
        guard case .catalog(_, let deltas) = backfill else {
          throw SessionSourceFailure(code: .securityError)
        }
        for delta in deltas { model = try model.reducing(delta) }
      }
      guard model.cursor == terminalCursor else {
        throw SessionSourceFailure(code: .securityError)
      }
      catalogModel = model
      if stage.subscriptionGeneration != nil {
        catalogSubscriptionReady = true
      }
      if catalogSubscriptionReady {
        publishCatalog(model)
      }
    case .conversation(let conversationID, let terminalCursor):
      guard stage.catalogSnapshots.isEmpty, stage.catalogBackfills.isEmpty,
        stage.conversationID == nil || stage.conversationID == conversationID
      else { throw SessionSourceFailure(code: .securityError) }
      let existing = conversationStates[conversationID.rawValue]
      if stage.subscriptionGeneration != nil, existing == nil, stage.snapshot == nil {
        // 首次 Subscribe(BeforeFirst) 即使是空 conversation 也必须携带只含
        // capabilities 的 snapshot；直接 terminal 不能伪造一个无 baseline 的 state。
        throw SessionSourceFailure(code: .securityError)
      }
      var state = try RuntimeConversationState(conversationID: conversationID)
      if let snapshot = stage.snapshot {
        try state.apply(snapshot)
      } else if let existing {
        state = existing
      }
      for backfill in stage.conversationBackfills { try state.apply(backfill) }
      guard state.cursorState.cursor == terminalCursor else {
        throw SessionSourceFailure(code: .securityError)
      }
      conversationStates[conversationID.rawValue] = state
      if let snapshot = stage.snapshot {
        latestConversationSnapshots[conversationID.rawValue] = snapshot
        await publishConversation(.snapshot(snapshot), conversationID: conversationID.rawValue)
      }
      for backfill in stage.conversationBackfills {
        if case .conversation(_, _, _, let events) = backfill {
          for event in events {
            await publishConversation(.event(event), conversationID: conversationID.rawValue)
          }
        }
      }
      for status in stage.commandStatuses where status.conversationID == conversationID {
        await publishConversation(.commandState(status), conversationID: conversationID.rawValue)
      }
      publishDerivedConversationResources()
    }
  }

  private func ingestLive(_ item: RuntimeStreamItemV2) async throws {
    switch item {
    case .event(let event):
      guard var state = conversationStates[event.conversationID.rawValue] else {
        throw SessionSourceFailure(code: .securityError)
      }
      try state.apply(event)
      conversationStates[event.conversationID.rawValue] = state
      await publishConversation(.event(event), conversationID: event.conversationID.rawValue)
      publishDerivedConversationResources()
    case .catalogDelta(let delta):
      guard let catalogModel else { throw SessionSourceFailure(code: .securityError) }
      let next = try catalogModel.reducing(delta)
      self.catalogModel = next
      publishCatalog(next)
    case .pairingPending(let pending):
      guard try shouldPublishPendingPairing(pending) else { return }
      guard pendingPairingLiveRevision < UInt64.max else {
        throw SessionSourceFailure(code: .securityError)
      }
      pendingPairingLiveRevision += 1
      pendingPairingValues[pending.pairingID.rawValue] = pending
      pendingPairingLiveRevisions[pending.pairingID.rawValue] = pendingPairingLiveRevision
      publishPendingPairings()
    case .transferPart:
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private func startMachineBootstrapIfNeeded() {
    guard machineBootstrapTask == nil, !didShutdown else { return }
    machineBootstrapTask = Task { [weak self] in
      guard let self else { return }
      await self.bootstrapMachines()
      await self.finishMachineBootstrap()
    }
  }

  private func bootstrapMachines() async {
    do {
      try Task.checkCancellation()
      _ = try await ensureStarted()
      try Task.checkCancellation()
    } catch {
      if !Task.isCancelled,
        !(await invalidateCurrentConnectionIfNeeded(after: error))
      {
        await publishConnectionFailure(Self.publicFailure(error))
      }
    }
  }

  private func finishMachineBootstrap() {
    machineBootstrapTask = nil
  }

  private func startCatalogBootstrapIfNeeded() {
    guard !catalogSubscriptionReady, catalogBootstrapTask == nil else { return }
    catalogBootstrapTask = Task { [weak self] in
      guard let self else { return }
      do {
        try await self.bootstrapCatalog()
      } catch {
        await self.markCatalogSubscriptionUnavailable()
        if !(await self.invalidateCurrentConnectionIfNeeded(after: error)) {
          await self.publishCatalogFailure(error)
        }
      }
      await self.finishCatalogBootstrap()
    }
  }

  private func finishCatalogBootstrap() {
    catalogBootstrapTask = nil
  }

  private func markCatalogSubscriptionUnavailable() {
    catalogSubscriptionReady = false
  }

  private func bootstrapCatalog() async throws {
    try await acquireSynchronizationTurn()
    defer { releaseSynchronizationTurn() }
    let lease = try await ensureStarted().lease
    try Task.checkCancellation()
    let pages = try await requireCoordinator(lease).loadCatalog()
    try requireCurrent(lease)
    let model = try RuntimeCatalogModel(snapshotPages: pages)
    catalogModel = model
    guard let cursor = pages.first?.baseCatalogCursor else {
      throw SessionSourceFailure(code: .securityError)
    }
    _ = try await requireCoordinator(lease).synchronizeCatalog(cursor: cursor)
    try requireCurrent(lease)
  }

  private func bootstrapConversation(
    _ id: String,
    observationID: UUID
  ) async -> LocalConversationConnectionLease? {
    do {
      try await acquireSynchronizationTurn()
      defer { releaseSynchronizationTurn() }
      guard conversationObservations[id]?.id == observationID else { return nil }
      let lease = try await ensureStarted().lease
      guard conversationObservations[id]?.id == observationID else { return nil }
      try Task.checkCancellation()
      _ = try await requireCoordinator(lease).synchronizeConversation(
        conversationID: RuntimeConversationID(rawValue: id),
        cursor: .beforeFirst
      )
      try requireCurrent(lease)
      guard conversationObservations[id]?.id == observationID else { return lease }
      await publishConversation(.connectionState(.connected), conversationID: id)
      return lease
    } catch {
      guard conversationObservations[id]?.id == observationID else { return nil }
      if !(await invalidateCurrentConnectionIfNeeded(after: error)) {
        await publishConversation(
          .connectionState(connectionState(for: error)),
          conversationID: id
        )
      }
      return nil
    }
  }

  private func conversationObserverDidTerminate(
    conversationID: String,
    observationID: UUID
  ) async {
    guard let observation = conversationObservations[conversationID],
      observation.id == observationID
    else { return }
    let retirementID = UUID()
    let bootstrapTask = observation.task
    let source = self
    let task = Task {
      await observation.broadcaster.finish()
      if let lease = await bootstrapTask?.value {
        await source.unsubscribeRetiredConversation(
          RuntimeConversationID(rawValue: conversationID),
          lease: lease
        )
      }
      await source.finishConversationRetirement(
        conversationID,
        retirementID: retirementID
      )
    }
    // active removal 与 retirement registration 必须在同一 actor turn 完成；任何 await
    // 之前先安装 barrier，避免新 generation 从空窗进入。
    conversationRetirements[conversationID] = LocalConversationRetirement(
      id: retirementID,
      task: task
    )
    conversationObservations.removeValue(forKey: conversationID)
  }

  private func unsubscribeRetiredConversation(
    _ conversationID: RuntimeConversationID,
    lease: LocalConversationConnectionLease
  ) async {
    guard !didShutdown, isCurrent(lease) else { return }
    do {
      try await requireCoordinator(lease).unsubscribeConversation(conversationID)
      try requireCurrent(lease)
    } catch {
      if let coordinator = coordinator(for: lease),
        await coordinator.requiresFreshConnection()
      {
        _ = await invalidateConnection(lease, reason: .coordinatorClosed)
      }
    }
  }

  private func finishConversationRetirement(
    _ conversationID: String,
    retirementID: UUID
  ) {
    guard conversationRetirements[conversationID]?.id == retirementID else { return }
    conversationStates.removeValue(forKey: conversationID)
    latestConversationSnapshots.removeValue(forKey: conversationID)
    conversationRetirements.removeValue(forKey: conversationID)
    publishDerivedConversationResources()
  }

  private func startPairingBootstrapIfNeeded() {
    guard pairingBootstrapTask == nil else { return }
    pairingBootstrapTask = Task { [weak self] in
      guard let self else { return }
      do {
        let baselineRevision = await self.currentPendingPairingLiveRevision()
        let started = try await self.ensureStarted()
        let values = try await requireCoordinator(started.lease).listPendingPairings()
        try await self.installPendingPairings(
          values,
          baselineLiveRevision: baselineRevision,
          lease: started.lease
        )
      } catch {
        if !(await self.invalidateCurrentConnectionIfNeeded(after: error)) {
          await self.publishPairingFailure(error)
        }
      }
      await self.finishPairingBootstrap()
    }
  }

  private func installPendingPairings(
    _ values: [RuntimePendingPairingV4],
    baselineLiveRevision: UInt64,
    lease: LocalConversationConnectionLease
  ) throws {
    try requireCurrent(lease)
    var indexed: [String: RuntimePendingPairingV4] = [:]
    for value in values {
      guard try shouldPublishPendingPairing(value) else { continue }
      guard indexed.updateValue(value, forKey: value.pairingID.rawValue) == nil else {
        throw SessionSourceFailure(code: .securityError)
      }
    }
    if pendingPairingLiveRevision == baselineLiveRevision {
      pendingPairingValues = indexed
      pendingPairingLiveRevisions.removeAll(keepingCapacity: true)
    } else {
      for (id, revision) in pendingPairingLiveRevisions
      where revision > baselineLiveRevision {
        guard let live = pendingPairingValues[id] else {
          throw SessionSourceFailure(code: .securityError)
        }
        indexed[id] = live
      }
      pendingPairingValues = indexed
      pendingPairingLiveRevisions = pendingPairingLiveRevisions.filter {
        $0.value > baselineLiveRevision
      }
    }
    publishPendingPairings()
  }

  private func currentPendingPairingLiveRevision() -> UInt64 {
    pendingPairingLiveRevision
  }

  /// confirm/cancel receipt 与已经从 wire 读出、但仍阻塞在 downstream reducer 的
  /// `PairingPending` 可以跨 actor 交错。resolved tombstone 在原 request expiry 前
  /// 拒绝该迟到帧；相同 ID 携带不同 expiry 视为 identity reuse 并 fail-close。
  private func shouldPublishPendingPairing(
    _ pending: RuntimePendingPairingV4
  ) throws -> Bool {
    let now = nowMilliseconds()
    pruneResolvedPairingTombstones(nowMilliseconds: now)
    guard pending.expiresAtMs > now else { return false }
    guard let tombstone = resolvedPairingTombstones[pending.pairingID.rawValue] else {
      return true
    }
    guard tombstone.expiresAtMs == pending.expiresAtMs else {
      throw SessionSourceFailure(code: .securityError)
    }
    return false
  }

  private func recordResolvedPairing(
    id: String,
    expiresAtMs: UInt64
  ) throws {
    let now = nowMilliseconds()
    pruneResolvedPairingTombstones(nowMilliseconds: now)
    guard expiresAtMs > now else { return }
    if let existing = resolvedPairingTombstones[id] {
      guard existing.expiresAtMs == expiresAtMs else {
        throw SessionSourceFailure(code: .securityError)
      }
      return
    }
    guard resolvedPairingTombstones.count < Self.maximumResolvedPairingTombstones else {
      throw SessionSourceFailure(code: .securityError)
    }
    resolvedPairingTombstones[id] = LocalResolvedPairingTombstone(
      expiresAtMs: expiresAtMs
    )
  }

  private func pruneResolvedPairingTombstones(nowMilliseconds: UInt64) {
    resolvedPairingTombstones = resolvedPairingTombstones.filter {
      $0.value.expiresAtMs > nowMilliseconds
    }
  }

  private func finishPairingBootstrap() {
    pairingBootstrapTask = nil
  }

  private func pairingDecision(
    id: String,
    confirm: Bool
  ) async throws -> PairingAdministrationReceipt {
    await pairingBootstrapTask?.value
    guard let pending = pendingPairingValues[id] else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    let pairingID = RuntimePairingID(rawValue: id)
    let lease = try await ensureStarted().lease
    let coordinator = try requireCoordinator(lease)
    let receipt =
      try await
      (confirm
      ? coordinator.confirmPairing(pairingID)
      : coordinator.cancelPairing(pairingID))
    try requireCurrent(lease)
    do {
      try recordResolvedPairing(
        id: id,
        expiresAtMs: pending.expiresAtMs
      )
    } catch {
      _ = await invalidateConnection(
        lease,
        reason: .failure(Self.publicFailure(error))
      )
      throw error
    }
    pendingPairingValues.removeValue(forKey: id)
    pendingPairingLiveRevisions.removeValue(forKey: id)
    publishPendingPairings()
    return receipt
  }

  func requireConversationState(_ id: String) throws -> RuntimeConversationState {
    guard let state = conversationStates[id] else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    return state
  }

  private func publishMachinesConnected() {
    guard !didShutdown else { return }
    let state = ResourceState<[MachineSummary]>.ready(
      value: currentMachines() ?? [],
      revision: nextResourceRevision()
    )
    for continuation in machineObservers.values { continuation.yield(state) }
  }

  private func publishConnectionFailure(_ reportedFailure: SessionSourceFailure) async {
    guard !didShutdown else { return }
    let failure: SessionSourceFailure
    if let fatalFailure {
      failure = fatalFailure
    } else {
      failure = reportedFailure
      if failure.code == .securityError { fatalFailure = failure }
    }
    let retryable = Self.isRetryable(failure)
    let state = ResourceState<[MachineSummary]>.failed(
      error: failure,
      retryable: retryable
    )
    for continuation in machineObservers.values { continuation.yield(state) }
    publishCatalogFailure(failure)
    pendingPairingValues.removeAll(keepingCapacity: true)
    pendingPairingLiveRevisions.removeAll(keepingCapacity: true)
    publishPairingFailure(failure)
    let connectionState = connectionState(for: failure)
    for id in Array(conversationObservations.keys) {
      await publishConversation(.connectionState(connectionState), conversationID: id)
      conversationStates.removeValue(forKey: id)
      if let observation = conversationObservations[id] {
        await conversationObserverDidTerminate(
          conversationID: id,
          observationID: observation.id
        )
      }
    }
  }

  private func publishCatalog(_ model: RuntimeCatalogModel) {
    let state = ResourceState<[ConversationSummary]>.ready(
      value: conversationSummaries(model),
      revision: nextResourceRevision()
    )
    for continuation in catalogObservers.values { continuation.yield(state) }
  }

  private func publishCatalogFailure(_ error: (any Error)?) {
    publishCatalogFailure(Self.publicFailure(error))
  }

  private func publishCatalogFailure(_ failure: SessionSourceFailure) {
    let state = ResourceState<[ConversationSummary]>.failed(
      error: failure,
      retryable: Self.isRetryable(failure)
    )
    for continuation in catalogObservers.values { continuation.yield(state) }
  }

  private func publishConversation(
    _ update: ConversationUpdate,
    conversationID: String
  ) async {
    guard let observation = conversationObservations[conversationID] else { return }
    switch await observation.broadcaster.publish(update, on: observation.generation) {
    case .published:
      return
    case .overflow:
      debugConversationOverflowCount += 1
      // 自有有界队列会先原子清空旧 generation，再把 lag marker 作为唯一
      // 可见断点；不能用 AsyncStream bufferingNewest 追加 marker，否则消费者
      // 会先看到不连续事件后缀并误判 securityError。
      _ = await observation.broadcaster.finish(
        delivering: .connectionState(.lagged(reason: .bufferDropped))
      )
      await conversationObserverDidTerminate(
        conversationID: conversationID,
        observationID: observation.id
      )
    case .finished, .staleGeneration, .awaitingBarrier, .invalidState, .replacedOldest:
      await conversationObserverDidTerminate(
        conversationID: conversationID,
        observationID: observation.id
      )
    }
  }

  private func publishInbox() {
    let state = ResourceState<[InboxItem]>.ready(
      value: inboxValues(),
      revision: nextResourceRevision()
    )
    for continuation in inboxObservers.values { continuation.yield(state) }
  }

  private func publishDerivedConversationResources() {
    if connection?.descriptions != nil {
      publishMachinesConnected()
    }
    if catalogSubscriptionReady, let catalogModel {
      publishCatalog(catalogModel)
    }
    publishInbox()
  }

  private func publishPendingPairings() {
    let state = ResourceState<[PendingPairing]>.ready(
      value: sortedPendingPairings(),
      revision: nextResourceRevision()
    )
    for continuation in pairingObservers.values { continuation.yield(state) }
  }

  private func publishPairingFailure(_ error: any Error) {
    publishPairingFailure(Self.publicFailure(error))
  }

  private func publishPairingFailure(_ failure: SessionSourceFailure) {
    let state = ResourceState<[PendingPairing]>.failed(
      error: failure,
      retryable: Self.isRetryable(failure)
    )
    for continuation in pairingObservers.values { continuation.yield(state) }
  }

  private func currentMachines() -> [MachineSummary]? {
    guard let localMachineID else { return nil }
    return [
      MachineSummary(
        id: localMachineID,
        name: machineName,
        connectionState: connection?.descriptions == nil ? .connecting : .connected,
        lastHeartbeat: nil,
        activeConversationCount: conversationStates.values.filter {
          $0.activeTurn != nil
        }.count,
        pendingApprovalCount: conversationStates.values.reduce(0) {
          $0 + $1.pendingApprovals.count
        }
      )
    ]
  }

  private func conversationSummaries(_ model: RuntimeCatalogModel) -> [ConversationSummary] {
    let machineID = localMachineID ?? ""
    return model.entries.map { entry in
      ConversationSummary(
        id: entry.conversationID.rawValue,
        machineID: machineID,
        title: entry.title ?? entry.conversationID.rawValue,
        cwd: entry.cwd ?? "",
        agentKind: entry.agentKind,
        group: conversationGroup(
          for: conversationStates[entry.conversationID.rawValue]
        ),
        lastActiveMs: entry.lastActiveMs,
        archived: entry.archived,
        revision: entry.entryRevision
      )
    }
  }

  private func conversationGroup(
    for state: RuntimeConversationState?
  ) -> ConversationGroup {
    guard let state else { return .recent }
    if !state.pendingApprovals.isEmpty { return .waitingApproval }
    if state.activeTurn != nil { return .active }
    return .recent
  }

  private func inboxValues() -> [InboxItem] {
    let machineID = localMachineID ?? ""
    var values: [InboxItem] = []
    for (conversationID, state) in conversationStates {
      for pending in state.pendingApprovals {
        values.append(
          InboxItem(
            id: "\(machineID)/\(conversationID)/\(pending.approvalID.rawValue)",
            conversationID: conversationID,
            machineID: machineID,
            kind: .waitingApproval,
            title: "Approval required"
          )
        )
      }
      if state.failure != nil {
        values.append(
          InboxItem(
            id: "\(machineID)/\(conversationID)/failed",
            conversationID: conversationID,
            machineID: machineID,
            kind: .failed,
            title: "Conversation failed"
          )
        )
      }
    }
    return values.sorted { $0.id < $1.id }
  }

  private func sortedPendingPairings() -> [RuntimePendingPairingV4] {
    pendingPairingValues.values.sorted {
      if $0.requestedAtMs != $1.requestedAtMs { return $0.requestedAtMs < $1.requestedAtMs }
      return $0.pairingID.rawValue < $1.pairingID.rawValue
    }
  }

  private func nextResourceRevision() -> UInt64 {
    resourceRevision &+= 1
    if resourceRevision == 0 { resourceRevision = 1 }
    return resourceRevision
  }

  private func removeMachineObserver(_ id: UUID) { machineObservers.removeValue(forKey: id) }
  private func removeCatalogObserver(_ id: UUID) { catalogObservers.removeValue(forKey: id) }
  private func removeInboxObserver(_ id: UUID) { inboxObservers.removeValue(forKey: id) }
  private func removePairingObserver(_ id: UUID) { pairingObservers.removeValue(forKey: id) }

  private func finishAllStreams() async {
    for continuation in machineObservers.values { continuation.finish() }
    for continuation in catalogObservers.values { continuation.finish() }
    for continuation in inboxObservers.values { continuation.finish() }
    for continuation in pairingObservers.values { continuation.finish() }
    for observation in conversationObservations.values {
      await observation.broadcaster.finish()
    }
    machineObservers.removeAll(keepingCapacity: false)
    catalogObservers.removeAll(keepingCapacity: false)
    inboxObservers.removeAll(keepingCapacity: false)
    pairingObservers.removeAll(keepingCapacity: false)
    conversationAdmissions.removeAll(keepingCapacity: false)
    conversationObservations.removeAll(keepingCapacity: false)
  }

  private func terminalResourceStream<Value: Sendable>(
    _ state: ResourceState<Value>
  ) -> AsyncStream<ResourceState<Value>> {
    AsyncStream { continuation in
      continuation.yield(state)
      continuation.finish()
    }
  }

  private func terminalConversationStream(
    _ state: SessionConnectionState
  ) -> AsyncStream<ConversationUpdate> {
    AsyncStream { continuation in
      continuation.yield(.connectionState(state))
      continuation.finish()
    }
  }

  func debugConversationObservationCount() -> Int {
    conversationObservations.count
  }

  func debugConversationOwnerCount() -> Int {
    conversationAdmissions.count + conversationObservations.count + conversationRetirements.count
  }

  func debugConversationRetirementCount() -> Int {
    conversationRetirements.count
  }

  func debugConversationRetirementWaiterCount() -> Int {
    conversationRetirementWaiterCount
  }

  func debugConversationOverflowEvents() -> Int {
    debugConversationOverflowCount
  }

  func debugSynchronizationWaiterCount() -> Int {
    synchronizationTurnWaiters.count
  }

  func debugSynchronizationTurnActive() -> Bool {
    synchronizationTurnActive
  }

  func debugConversationHasCapabilities(_ conversationID: String) -> Bool {
    conversationStates[conversationID]?.capabilities != nil
  }

  func debugPendingPairingCount() -> Int { pendingPairingValues.count }

  func debugResolvedPairingTombstoneCount() -> Int {
    resolvedPairingTombstones.count
  }

  func debugFatalFailure() -> SessionSourceFailure? { fatalFailure }

  func debugDidShutdown() -> Bool { didShutdown }

  func debugShutdownWaiterCount() -> Int { shutdownWaiters.count }
}
