import AgentDeckCore
import AgentDeckRelayClient
import AgentDeckSessionSource
import Foundation

/// macOS production App 的 SessionSource composition root。
///
/// - local source 与 `SessionModel` 由同一个 production binding 构造，因此进程内只有
///   一个 UDS/coordinator owner；
/// - remote source 共用同一 installation namespace 与 `PairedMachineStore`，但每台
///   machine 都 cold-open 独立的 `RelaySessionSource(.machine(id))`；
/// - registry 独占所有 source lifecycle，model/controller 只保存 handle/capability。
@MainActor
final class AppSessionSourceComposition {
  typealias RemoteLifecycleFactory =
    @Sendable (_ machineID: String, _ store: PairedMachineStore) async throws
    -> any SessionSourceLifecycle

  let model: SessionModel
  let localSource: LocalDaemonSessionSource
  let registry: SessionSourceRegistry
  let selectedMachineScope: SelectedMachineScopeGenerationOwner

  var localPairingAdministration: (any LocalPairingAdministration)? { localSource }

  // registry 的 remote factory 也会强持有 provider；composition 再显式持有，令
  // shared-store ownership 在对象图中可见，而不是只藏在 escaping closure 内。
  private let pairedMachineStoreProvider: MacOSPairedMachineStoreProvider

  private init(
    model: SessionModel,
    localSource: LocalDaemonSessionSource,
    registry: SessionSourceRegistry,
    selectedMachineScope: SelectedMachineScopeGenerationOwner,
    pairedMachineStoreProvider: MacOSPairedMachineStoreProvider
  ) {
    self.model = model
    self.localSource = localSource
    self.registry = registry
    self.selectedMachineScope = selectedMachineScope
    self.pairedMachineStoreProvider = pairedMachineStoreProvider
  }

  static func production() throws -> AppSessionSourceComposition {
    try production(
      installation: LocalClientInstallation.forOSAccount(),
      remoteLifecycleFactory: makeProductionRemoteLifecycle
    )
  }

  /// 确定性的 composition test seam。调用方只能替换 remote lifecycle factory；
  /// local binding、installation namespace、registry capability matrix 均仍走 production 路径。
  static func production(
    installation: LocalClientInstallation,
    remoteLifecycleFactory: @escaping RemoteLifecycleFactory
  ) throws -> AppSessionSourceComposition {
    let binding = SessionModel.makeProductionLocalBinding(installation: installation)
    let localRegistration = try SessionSourceRegistration(
      scope: .local,
      source: binding.source,
      capabilities: SessionSourceCapabilities(
        localPairingAdministration: binding.source,
        localConversationAdministration: binding.source
      ),
      lifecycle: binding.source
    )
    let storeProvider = MacOSPairedMachineStoreProvider(installation: installation)
    let registry = try SessionSourceRegistry(
      local: localRegistration,
      remoteFactory: { machineID in
        let store = try await storeProvider.sharedStore()
        let lifecycle = try await remoteLifecycleFactory(machineID, store)
        return try SessionSourceRegistration(
          scope: .remote(machineID: machineID),
          source: lifecycle,
          capabilities: SessionSourceCapabilities(),
          lifecycle: lifecycle
        )
      }
    )
    let selectedMachineScope = SelectedMachineScopeGenerationOwner(registry: registry)
    return AppSessionSourceComposition(
      model: binding.model,
      localSource: binding.source,
      registry: registry,
      selectedMachineScope: selectedMachineScope,
      pairedMachineStoreProvider: storeProvider
    )
  }

  /// AppDelegate 使用的确定性 teardown 入口。先同步关闭 model admission 并 cancel
  /// operation，再取消 scope observations、由 registry shutdown/join 全部 UDS/WSS
  /// owner；source close 解开在途 I/O 后，最后等待 model operation barrier。
  func shutdown() async {
    model.teardown()
    await selectedMachineScope.shutdown()
    await registry.shutdown()
    await model.shutdown()
  }

  private static func makeProductionRemoteLifecycle(
    machineID: String,
    store: PairedMachineStore
  ) async throws -> any SessionSourceLifecycle {
    let relaySource = try await RelaySessionSource.open(
      scope: .machine(machineID),
      pairedMachineStore: store
    )
    return RelaySessionSourceLifecycleAdapter(source: relaySource)
  }
}

/// installation record 与 remote Keychain/file-state 使用同一个 macOS App namespace。
/// provider 首次 remote open 才触发 `loadOrCreate()`，保持 App/model 构造零文件副作用。
private actor MacOSPairedMachineStoreProvider {
  private let installation: LocalClientInstallation
  private var cachedStore: PairedMachineStore?

  init(installation: LocalClientInstallation) {
    self.installation = installation
  }

  func sharedStore() throws -> PairedMachineStore {
    if let cachedStore { return cachedStore }

    let installationValue = try installation.loadOrCreate().rawValue
    guard let installationID = UUID(uuidString: installationValue) else {
      throw SessionSourceFailure(code: .storageUnavailable)
    }
    let store = PairedMachineStore(
      keyStore: AppleKeychainStore(),
      stateRootURL: installation.recordPath.deletingLastPathComponent(),
      clientKind: .macOSApp,
      installationID: installationID
    )
    cachedStore = store
    return store
  }
}

/// 避免给外部 module 的 actor 增加 retroactive lifecycle conformance；adapter 只做
/// `SessionSource` 透传，并把已经完整 join 内部任务的 `shutdown()` 复用为 join barrier。
private struct RelaySessionSourceLifecycleAdapter: SessionSourceLifecycle, Sendable {
  let source: RelaySessionSource

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    await source.machines()
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    await source.conversations(machineID: machineID)
  }

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
    await source.conversation(conversationID: conversationID)
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    await source.inbox()
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    try await source.inspectPairInvite(encoded)
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    try await source.pair(encodedInvite)
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    try await source.revokeSelf(machineID: machineID)
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    try await source.sendPrompt(
      conversationID: conversationID,
      text: text,
      idempotencyKey: idempotencyKey
    )
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    try await source.resolveApproval(
      conversationID: conversationID,
      turnID: turnID,
      approvalID: approvalID,
      decision: decision,
      idempotencyKey: idempotencyKey
    )
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    try await source.retryApprovalDelivery(
      conversationID: conversationID,
      approvalID: approvalID
    )
  }

  func shutdown() async {
    await source.shutdown()
  }

  func join() async {
    await source.shutdown()
  }
}

struct MachineScopeObservationContext: Equatable, Sendable {
  let scope: MachineScope
  let generation: UInt64
}

struct SelectedMachineScope: Sendable {
  let context: MachineScopeObservationContext
  let handle: SessionSourceHandle
}

enum SelectedMachineScopeError: Error, Equatable, Sendable {
  case noSelection
  case catalogMachineMismatch(expected: String, actual: String)
  case observationAlreadyActive
  case generationExhausted
  case shutDown
}

private enum MachineScopeObservationTaskContext {
  @TaskLocal static var observationID: UUID?
}

/// selected machine scope 的 consumer-generation owner。
///
/// Registry 拥有 source/WSS/UDS lifecycle；本 actor 只拥有当前 selection 的 catalog、
/// conversation 与 inbox consumer tasks。切 scope 时先换代，使迟到值立即失效，再
/// cancel + join 全部非调用方旧 task，最后才 open 新 handle；handler 重入时，其所属
/// task 延迟到 switch operation 离开 cancellation handler 后取消，避免自等待/自取消。
actor SelectedMachineScopeGenerationOwner {
  typealias SelectionPostOperationHook = @Sendable () async -> Void
  typealias CatalogHandler =
    @Sendable (MachineScopeObservationContext, ResourceState<[ConversationSummary]>) async -> Void
  typealias ConversationHandler =
    @Sendable (MachineScopeObservationContext, ConversationUpdate) async -> Void
  typealias InboxHandler =
    @Sendable (MachineScopeObservationContext, ResourceState<[InboxItem]>) async -> Void

  private enum ObservationKind: Sendable {
    case catalog
    case conversation
    case inbox
  }

  private struct OwnedObservation: Sendable {
    let id: UUID
    let task: Task<Void, Never>
  }

  private struct ObservationTasks: Sendable {
    var catalog: OwnedObservation?
    var conversation: OwnedObservation?
    var inbox: OwnedObservation?

    var all: [OwnedObservation] {
      [catalog, conversation, inbox].compactMap { $0 }
    }
  }

  private struct SwitchWaiter {
    let id: UUID
    let continuation: CheckedContinuation<Bool, Never>
  }

  private struct SwitchOperation: Sendable {
    let id: UUID
    let task: Task<SelectedMachineScope, Error>
  }

  private let registry: SessionSourceRegistry
  /// 只供 deterministic lifecycle test 锁住 operation success 与外层 shutdown guard
  /// 之间的窗口；production composition 固定为 nil，不新增 reentrancy point。
  private let selectionPostOperationHook: SelectionPostOperationHook?
  private var current: SelectedMachineScope?
  private var observationTasks = ObservationTasks()
  private var retiredObservationTasks: [UUID: OwnedObservation] = [:]
  private var nextGeneration: UInt64 = 0
  private var isShutDown = false
  private var switchTurnActive = false
  private var switchWaiters: [SwitchWaiter] = []
  private var activeSwitchOperation: SwitchOperation?
  private var shutdownOperation: Task<Void, Never>?

  init(
    registry: SessionSourceRegistry,
    selectionPostOperationHook: SelectionPostOperationHook? = nil
  ) {
    self.registry = registry
    self.selectionPostOperationHook = selectionPostOperationHook
  }

  func selection() -> SelectedMachineScope? {
    current
  }

  @discardableResult
  func select(_ scope: MachineScope) async throws -> SelectedMachineScope {
    let callerObservationID = MachineScopeObservationTaskContext.observationID
    try await acquireSwitchTurn()
    let operation = SwitchOperation(
      id: UUID(),
      task: Task { [self] in
        try await replaceSelection(
          with: scope,
          excludingObservationID: callerObservationID
        )
      }
    )
    activeSwitchOperation = operation
    do {
      let selection = try await withTaskCancellationHandler {
        try await operation.task.value
      } onCancel: {
        operation.task.cancel()
      }
      cancelRetiredObservation(callerObservationID)
      if let selectionPostOperationHook {
        await selectionPostOperationHook()
      }
      guard !isShutDown else { throw SelectedMachineScopeError.shutDown }
      finishSwitchOperation(operation.id)
      return selection
    } catch {
      cancelRetiredObservation(callerObservationID)
      finishSwitchOperation(operation.id)
      throw error
    }
  }

  func observeCatalog(
    machineID: String,
    handler: @escaping CatalogHandler
  ) throws {
    let selection = try requireSelection()
    if case .remote(let expected) = selection.context.scope, expected != machineID {
      throw SelectedMachineScopeError.catalogMachineMismatch(
        expected: expected,
        actual: machineID
      )
    }
    guard observationTasks.catalog == nil else {
      throw SelectedMachineScopeError.observationAlreadyActive
    }

    let id = UUID()
    let context = selection.context
    let source = selection.handle.source
    let task = Task { [weak self] in
      await MachineScopeObservationTaskContext.$observationID.withValue(id) {
        let stream = await source.conversations(machineID: machineID)
        for await state in stream {
          guard !Task.isCancelled else { break }
          await self?.publishCatalog(state, context: context, handler: handler)
        }
        await self?.finishObservation(.catalog, id: id, context: context)
      }
    }
    observationTasks.catalog = OwnedObservation(id: id, task: task)
  }

  func observeConversation(
    conversationID: String,
    handler: @escaping ConversationHandler
  ) throws {
    let selection = try requireSelection()
    guard observationTasks.conversation == nil else {
      throw SelectedMachineScopeError.observationAlreadyActive
    }

    let id = UUID()
    let context = selection.context
    let source = selection.handle.source
    let task = Task { [weak self] in
      await MachineScopeObservationTaskContext.$observationID.withValue(id) {
        let stream = await source.conversation(conversationID: conversationID)
        for await update in stream {
          guard !Task.isCancelled else { break }
          await self?.publishConversation(update, context: context, handler: handler)
        }
        await self?.finishObservation(.conversation, id: id, context: context)
      }
    }
    observationTasks.conversation = OwnedObservation(id: id, task: task)
  }

  func observeInbox(handler: @escaping InboxHandler) throws {
    let selection = try requireSelection()
    guard observationTasks.inbox == nil else {
      throw SelectedMachineScopeError.observationAlreadyActive
    }

    let id = UUID()
    let context = selection.context
    let source = selection.handle.source
    let task = Task { [weak self] in
      await MachineScopeObservationTaskContext.$observationID.withValue(id) {
        let stream = await source.inbox()
        for await state in stream {
          guard !Task.isCancelled else { break }
          await self?.publishInbox(state, context: context, handler: handler)
        }
        await self?.finishObservation(.inbox, id: id, context: context)
      }
    }
    observationTasks.inbox = OwnedObservation(id: id, task: task)
  }

  func shutdown() async {
    let callerObservationID = MachineScopeObservationTaskContext.observationID
    if let shutdownOperation {
      // observation handler 不能等待包含自身的既有 barrier；state 已在首次调用时
      // 同步失效，当前 callback 返回后由该 barrier 完成最终 join。
      guard callerObservationID == nil else { return }
      await shutdownOperation.value
      return
    }

    isShutDown = true
    _ = advanceGeneration()
    current = nil

    // shutdown 不进入 switch FIFO：先抢占 active registry.open，并立即拒绝所有
    // 尚未取得 turn 的 selection。否则卡住的 remote factory 会让 AppKit 永久停在
    // terminateLater，registry 也永远等不到随后负责取消 factory 的 shutdown。
    let activeSwitch = activeSwitchOperation
    activeSwitch?.task.cancel()
    cancelAllSwitchWaiters()

    let observations = takeObservationsForCancellation(excluding: nil)
    let operation = Task {
      if let activeSwitch {
        _ = await activeSwitch.task.result
      }
      for observation in observations {
        await observation.task.value
      }
    }
    shutdownOperation = operation
    // reentrant shutdown 已同步完成 generation/state invalidation，但不能在当前
    // callback 内等待包含自身的完整 barrier，否则会形成 task 自等待。
    guard callerObservationID == nil else { return }
    await operation.value
  }

  private func replaceSelection(
    with scope: MachineScope,
    excludingObservationID: UUID?
  ) async throws -> SelectedMachineScope {
    guard !isShutDown else { throw SelectedMachineScopeError.shutDown }
    guard let generation = advanceGeneration() else {
      isShutDown = true
      throw SelectedMachineScopeError.generationExhausted
    }
    current = nil
    await cancelAndJoinObservations(excluding: excludingObservationID)
    let handle = try await registry.open(scope)
    guard !isShutDown else { throw SelectedMachineScopeError.shutDown }
    let selection = SelectedMachineScope(
      context: MachineScopeObservationContext(scope: scope, generation: generation),
      handle: handle
    )
    current = selection
    return selection
  }

  private func requireSelection() throws -> SelectedMachineScope {
    guard !isShutDown else { throw SelectedMachineScopeError.shutDown }
    guard let current else { throw SelectedMachineScopeError.noSelection }
    return current
  }

  private func advanceGeneration() -> UInt64? {
    nextGeneration &+= 1
    return nextGeneration == 0 ? nil : nextGeneration
  }

  private func cancelAndJoinObservations(excluding observationID: UUID?) async {
    let tasks = takeObservationsForCancellation(excluding: observationID)
    for owned in tasks { await owned.task.value }
  }

  /// 先从 active slots 隔离全部 observation，并取消需要 join 的 task。若切 scope
  /// 是由某个 handler 重入触发，则该 handler 所属 task 不能加入当前 join 集合；
  /// 它会留在 retired 集合中，待 operation 返回后取消并由 callback 自行清理，或
  /// 由后续外部 lifecycle barrier 回收。
  private func takeObservationsForCancellation(
    excluding observationID: UUID?
  ) -> [OwnedObservation] {
    let tasks = observationTasks.all + retiredObservationTasks.values
    observationTasks = ObservationTasks()
    retiredObservationTasks.removeAll(keepingCapacity: false)

    var tasksToJoin: [OwnedObservation] = []
    for owned in tasks {
      if owned.id == observationID {
        // 当前 task 正在 `select()` 的 cancellation handler 内等待 switch operation；
        // 此处若立即 cancel，会反向取消该 operation。先隔离并失效 generation，待
        // operation 离开 cancellation handler 后再 cancel，让 callback 安全 unwind。
        retiredObservationTasks[owned.id] = owned
      } else {
        owned.task.cancel()
        tasksToJoin.append(owned)
      }
    }
    return tasksToJoin
  }

  private func cancelRetiredObservation(_ id: UUID?) {
    guard let id, let observation = retiredObservationTasks[id] else { return }
    observation.task.cancel()
  }

  private func publishCatalog(
    _ state: ResourceState<[ConversationSummary]>,
    context: MachineScopeObservationContext,
    handler: CatalogHandler
  ) async {
    guard current?.context == context, !isShutDown else { return }
    await handler(context, state)
  }

  private func publishConversation(
    _ update: ConversationUpdate,
    context: MachineScopeObservationContext,
    handler: ConversationHandler
  ) async {
    guard current?.context == context, !isShutDown else { return }
    await handler(context, update)
  }

  private func publishInbox(
    _ state: ResourceState<[InboxItem]>,
    context: MachineScopeObservationContext,
    handler: InboxHandler
  ) async {
    guard current?.context == context, !isShutDown else { return }
    await handler(context, state)
  }

  private func finishObservation(
    _ kind: ObservationKind,
    id: UUID,
    context: MachineScopeObservationContext
  ) {
    retiredObservationTasks.removeValue(forKey: id)
    guard current?.context == context else { return }
    switch kind {
    case .catalog:
      if observationTasks.catalog?.id == id { observationTasks.catalog = nil }
    case .conversation:
      if observationTasks.conversation?.id == id { observationTasks.conversation = nil }
    case .inbox:
      if observationTasks.inbox?.id == id { observationTasks.inbox = nil }
    }
  }

  private func acquireSwitchTurn() async throws {
    try Task.checkCancellation()
    guard !switchTurnActive else {
      let id = UUID()
      let granted = await withTaskCancellationHandler {
        await withCheckedContinuation { continuation in
          if Task.isCancelled {
            continuation.resume(returning: false)
          } else {
            switchWaiters.append(SwitchWaiter(id: id, continuation: continuation))
          }
        }
      } onCancel: {
        Task { await self.cancelSwitchWaiter(id) }
      }
      guard granted else { throw CancellationError() }
      do {
        try Task.checkCancellation()
      } catch {
        releaseSwitchTurn()
        throw error
      }
      return
    }
    switchTurnActive = true
  }

  private func releaseSwitchTurn() {
    guard switchTurnActive else { return }
    if switchWaiters.isEmpty {
      switchTurnActive = false
    } else {
      switchWaiters.removeFirst().continuation.resume(returning: true)
    }
  }

  private func finishSwitchOperation(_ id: UUID) {
    guard activeSwitchOperation?.id == id else { return }
    activeSwitchOperation = nil
    releaseSwitchTurn()
  }

  private func cancelAllSwitchWaiters() {
    let waiters = switchWaiters
    switchWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.continuation.resume(returning: false)
    }
  }

  private func cancelSwitchWaiter(_ id: UUID) {
    guard let index = switchWaiters.firstIndex(where: { $0.id == id }) else { return }
    switchWaiters.remove(at: index).continuation.resume(returning: false)
  }
}
