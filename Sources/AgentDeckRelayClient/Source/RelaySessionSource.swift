import AgentDeckCore
import AgentDeckSessionSource
import Foundation

public enum RelaySourceScope: Sendable {
  case allPairedMachines
  case machine(String)
}

/// RelaySessionSource 的出站 command/subscription seam。注入实现负责 Runtime encode、
/// DeviceRequestSigner、request correlation 与 exact retry；Source 只提供已验证 reducer baseline。
/// Pairing 由同一 PairedMachineStore namespace 的 production handler 独立拥有。
public protocol RelaySessionSourceCommandClient: Sendable {
  func shutdown() async

  func subscribe(
    machineID: String,
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) async throws

  func unsubscribe(
    machineID: String,
    target: RuntimeSubscriptionTargetV1
  ) async throws

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview
  func pair(_ encodedInvite: String) async throws -> AsyncThrowingStream<PairingProgress, Error>
  func revokeSelf(machineID: String) async throws -> RevocationReceipt

  func sendPrompt(
    machineID: String,
    conversationID: String,
    text: String,
    idempotencyKey: UUID,
    expectedConfigurationRevision: UInt64
  ) async throws -> CommandReceipt

  func resolveApproval(
    machineID: String,
    conversationID: String,
    turnID: String,
    approvalID: String,
    requestID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt

  func retryApprovalDelivery(
    machineID: String,
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt
}

struct CatalogSnapshotAccumulator: Sendable {
  static let maximumPages = 128
  static let maximumEntries = 10_000
  static let maximumBytes = 64 * 1_024 * 1_024

  let maximumPages: Int
  let maximumEntries: Int
  let maximumBytes: Int
  private(set) var pages: [RuntimeCatalogSnapshotV2] = []
  private(set) var entryCount = 0
  private(set) var encodedBytes = 0

  init(
    maximumPages: Int = Self.maximumPages,
    maximumEntries: Int = Self.maximumEntries,
    maximumBytes: Int = Self.maximumBytes
  ) {
    precondition(maximumPages > 0 && maximumPages <= Self.maximumPages)
    precondition(maximumEntries > 0 && maximumEntries <= Self.maximumEntries)
    precondition(maximumBytes > 0 && maximumBytes <= Self.maximumBytes)
    self.maximumPages = maximumPages
    self.maximumEntries = maximumEntries
    self.maximumBytes = maximumBytes
  }

  mutating func append(_ page: RuntimeCatalogSnapshotV2) throws {
    let pageBytes = try canonicalBytes(page).count
    let (nextEntryCount, entryOverflow) = entryCount.addingReportingOverflow(page.entries.count)
    let (nextEncodedBytes, byteOverflow) = encodedBytes.addingReportingOverflow(pageBytes)
    guard !entryOverflow, !byteOverflow,
      pages.count < maximumPages,
      nextEntryCount <= maximumEntries,
      nextEncodedBytes <= maximumBytes
    else {
      throw RelaySourceReducerError.catalogCapacity
    }
    pages.append(page)
    entryCount = nextEntryCount
    encodedBytes = nextEncodedBytes
  }
}

private struct CatalogBootstrap: Sendable {
  let requestID: RuntimeMessageID
  var generation: RuntimeStreamGeneration?
  var snapshot = CatalogSnapshotAccumulator()
  var stagedReducer: CatalogReducer?
  var backfillStarted = false
}

private struct CatalogActiveSubscription: Sendable {
  let requestID: RuntimeMessageID
  let generation: RuntimeStreamGeneration
}

private struct BroadcastChannel<Element: Sendable>: Sendable {
  let broadcaster: BoundedBroadcaster<Element>
  let generation: BoundedBroadcastGeneration
}

private struct ConversationObservation: Sendable {
  let machineID: String
  let broadcaster: BoundedBroadcaster<ConversationUpdate>
  var broadcastGeneration: BoundedBroadcastGeneration
  var resume: RelayConversationResumeCoordinator
  var subscriptionRequestID: RuntimeMessageID
  var observerIDs: Set<UUID>
  var awaitingBroadcastBarrier = false
  /// 任何跨 actor await 前后的 observation CAS。commit 返回后如果 token 已变化，
  /// 旧 scratch 只能放弃发布并触发 fresh snapshot，不能覆盖新 subscription 或复活 teardown。
  var stateToken = UUID()
}

protocol RelayMachineConnectionOwner:
  MachineConnectionUpdateSource,
  MachineRuntimeRequestEndpoint
{}

extension MachineConnection: RelayMachineConnectionOwner {}

protocol RelayMachineConnectionAssemblyProvider: Sendable {
  func listMachines() async throws -> [PairedMachine]
  func openStartedConnection(machineID: String) async throws -> any RelayMachineConnectionOwner
}

private actor PairedStoreMachineConnectionAssemblyProvider:
  RelayMachineConnectionAssemblyProvider
{
  private let store: PairedMachineStore
  private var recordsByID: [String: StoredPairedMachineRecordV1] = [:]

  init(store: PairedMachineStore) {
    self.store = store
  }

  func listMachines() async throws -> [PairedMachine] {
    let records = try await store.list()
    var next: [String: StoredPairedMachineRecordV1] = [:]
    for record in records {
      guard next.updateValue(record, forKey: record.machineID) == nil else {
        throw SessionSourceFailure(code: .securityError)
      }
    }
    recordsByID = next
    return records.map(\.pairedMachine)
  }

  func openStartedConnection(
    machineID: String
  ) async throws -> any RelayMachineConnectionOwner {
    guard let record = recordsByID[machineID] else {
      throw SessionSourceFailure(code: .machineOffline)
    }
    guard
      let material = try await store.openConnectionMaterial(
        rootFingerprint: record.machineRootFingerprint,
        machineRoute: record.machineRoute
      )
    else {
      throw SessionSourceFailure(code: .storageUnavailable)
    }
    let connection = try await MachineConnection.open(material: material)
    await connection.start()
    return connection
  }
}

/// iOS/远程 macOS 共用的 Relay SessionSource facade/reducer composition。
///
/// 该 actor 只消费 `MachineConnectionUpdate.delivery(VerifiedRuntimeDelivery)`；任何
/// raw frame/RuntimeEnvelope 都在类型边界之外。Catalog/Conversation bootstrap 在
/// SyncComplete 前只写 staged reducer，资源流 newest(1)，conversation 固定 512。
public actor RelaySessionSource: SessionSource {
  /// 与 daemon/Relay live-subscription cap 对齐。internal initializer 只允许测试
  /// 使用更低 seam，production composition 不能放大这些固定上界。
  static let maximumConversationObservationsPerMachine = 64
  static let maximumConversationObservations = 4_096
  static let maximumObserversPerConversation = 1

  private let scope: RelaySourceScope
  private let commandClient: any RelaySessionSourceCommandClient
  private let machinesByID: [String: PairedMachine]
  private let connections: [String: any MachineConnectionUpdateSource]
  private let conversationObservationLimit: Int
  private let conversationObservationPerMachineLimit: Int

  private let machineBroadcaster: BoundedBroadcaster<ResourceState<[MachineSummary]>>
  private let machineGeneration: BoundedBroadcastGeneration
  private let inboxBroadcaster: BoundedBroadcaster<ResourceState<[InboxItem]>>
  private let inboxGeneration: BoundedBroadcastGeneration

  private var catalogChannels: [String: BroadcastChannel<ResourceState<[ConversationSummary]>>] =
    [:]
  private var conversationObservations: [String: ConversationObservation] = [:]
  /// 最后 observer 退出后，target-scoped unsubscribe 返回前继续占住 exact conversation。
  /// value 保留 machineID，使 fatal readback 与 per-machine observation cap 在 retirement
  /// 窗口内仍然准确；同 target 不能在旧 retirement 的跨 actor await 中 ABA 重建。
  private var conversationRetirements: [String: String] = [:]
  private var connectionStates: [String: SessionConnectionState] = [:]
  /// transport generation 不能单独标识 production reconnect（每轮 fresh transport 可从
  /// 1 重新计数）；业务门禁必须绑定 connectionID + generation 的完整 exact scope。
  private var connectionScopes: [String: TransferAssemblyScope] = [:]
  private var businessReadyScopes: [String: TransferAssemblyScope] = [:]
  /// fatal terminal 是 per-machine 单向 latch。任何迟到 transport update、reconnect 或
  /// observation recovery 都不能把 revoked/incompatible/securityError 改回在线。
  private var fatalConnectionStates: [String: SessionConnectionState] = [:]
  private var connectionShutdownTasks: [String: Task<Void, Never>] = [:]
  private var catalogReducers: [String: CatalogReducer] = [:]
  private var catalogBootstraps: [String: CatalogBootstrap] = [:]
  private var catalogActiveSubscriptions: [String: CatalogActiveSubscription] = [:]
  private var updateTasks: [String: Task<Void, Never>] = [:]
  private var started = false
  private var shuttingDown = false
  private var shutdownComplete = false
  private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []
  private var lifecycleGeneration = UUID()
  private var resourceRevision: UInt64 = 0

  init(
    scope: RelaySourceScope,
    machines: [PairedMachine],
    connections: [String: any MachineConnectionUpdateSource],
    commandClient: any RelaySessionSourceCommandClient,
    maximumConversationObservations: Int = RelaySessionSource.maximumConversationObservations,
    maximumConversationObservationsPerMachine: Int =
      RelaySessionSource.maximumConversationObservationsPerMachine
  ) throws {
    guard maximumConversationObservations > 0,
      maximumConversationObservations
        <= RelaySessionSource.maximumConversationObservations,
      maximumConversationObservationsPerMachine > 0,
      maximumConversationObservationsPerMachine
        <= RelaySessionSource.maximumConversationObservationsPerMachine
    else {
      throw SessionSourceFailure(code: .securityError)
    }
    var machinesByID: [String: PairedMachine] = [:]
    for machine in machines {
      guard !machine.id.isEmpty, machinesByID.updateValue(machine, forKey: machine.id) == nil else {
        throw SessionSourceFailure(code: .securityError)
      }
    }
    guard Set(machinesByID.keys) == Set(connections.keys) else {
      throw SessionSourceFailure(code: .storageUnavailable)
    }
    if case .machine(let machineID) = scope, machinesByID[machineID] == nil {
      throw SessionSourceFailure(code: .machineOffline)
    }

    let machineGeneration = BoundedBroadcastGeneration()
    let inboxGeneration = BoundedBroadcastGeneration()
    self.scope = scope
    self.commandClient = commandClient
    self.machinesByID = machinesByID
    self.connections = connections
    conversationObservationLimit = maximumConversationObservations
    conversationObservationPerMachineLimit = maximumConversationObservationsPerMachine
    machineBroadcaster = BoundedBroadcaster(
      capacity: 1,
      overflowStrategy: .bufferingNewest,
      generation: machineGeneration
    )
    self.machineGeneration = machineGeneration
    inboxBroadcaster = BoundedBroadcaster(
      capacity: 1,
      overflowStrategy: .bufferingNewest,
      generation: inboxGeneration
    )
    self.inboxGeneration = inboxGeneration
    connectionStates = Dictionary(
      uniqueKeysWithValues: machinesByID.keys.map { ($0, .connecting) }
    )
  }

  /// 从 PairedMachineStore 的 audited material 组装一机一 connection owner，并从同一
  /// owner 同时取得 update source 与 Runtime endpoint。外部不能再注入与 transport
  /// 无关的 command client，从类型边界上避免“能观察但命令发到另一条连接”。
  ///
  /// 这里只做 cold-open readback、owner wiring 与幂等 `start` lifecycle 边界；当前
  /// `MachineConnection.start` 仅发布 connecting，真实 transport/auth supervisor 仍由后续
  /// composition 驱动，不能把 `open` 视为 E2E ready。
  public static func open(
    scope: RelaySourceScope,
    pairedMachineStore: PairedMachineStore
  ) async throws -> RelaySessionSource {
    try await pairedMachineStore.resumeIncompleteCleanups()
    try await pairedMachineStore.recoverPendingPairings(
      nowMilliseconds: UInt64(max(1, Date().timeIntervalSince1970 * 1_000))
    )
    let assembled = try await assembleOwners(
      scope: scope,
      provider: PairedStoreMachineConnectionAssemblyProvider(store: pairedMachineStore)
    )
    let endpoints = Dictionary(
      uniqueKeysWithValues: assembled.owners.map { machineID, owner in
        (machineID, owner as any MachineRuntimeRequestEndpoint)
      }
    )
    let commandClient = try RelayRuntimeCommandClient(
      endpoints: endpoints,
      pairing: ProductionRelayPairingCommandHandler(
        pairedMachineStore: pairedMachineStore
      )
    )
    return try RelaySessionSource(
      scope: scope,
      machines: assembled.machines,
      connections: assembled.owners.mapValues {
        $0 as any MachineConnectionUpdateSource
      },
      commandClient: commandClient
    )
  }

  static func assemble(
    scope: RelaySourceScope,
    provider: any RelayMachineConnectionAssemblyProvider,
    commandClient: any RelaySessionSourceCommandClient
  ) async throws -> RelaySessionSource {
    let assembled = try await assembleOwners(scope: scope, provider: provider)
    return try RelaySessionSource(
      scope: scope,
      machines: assembled.machines,
      connections: assembled.owners.mapValues {
        $0 as any MachineConnectionUpdateSource
      },
      commandClient: commandClient
    )
  }

  private static func assembleOwners(
    scope: RelaySourceScope,
    provider: any RelayMachineConnectionAssemblyProvider
  ) async throws -> (
    machines: [PairedMachine],
    owners: [String: any RelayMachineConnectionOwner]
  ) {
    let available = try await provider.listMachines()
    let selected: [PairedMachine]
    switch scope {
    case .allPairedMachines:
      selected = available
    case .machine(let machineID):
      let matches = available.filter { $0.id == machineID }
      guard matches.count == 1 else {
        throw SessionSourceFailure(code: matches.isEmpty ? .machineOffline : .securityError)
      }
      selected = matches
    }

    var owners: [String: any RelayMachineConnectionOwner] = [:]
    do {
      for machine in selected {
        guard owners[machine.id] == nil else {
          throw SessionSourceFailure(code: .securityError)
        }
        let owner = try await provider.openStartedConnection(machineID: machine.id)
        guard owner.machineID == machine.id else {
          await owner.shutdown()
          throw SessionSourceFailure(code: .securityError)
        }
        owners[machine.id] = owner
      }
    } catch {
      // provider 返回的 owner 已经 start；任一后续 open/identity 失败都必须先
      // shutdown 并 join 已取得的 owner，不能让部分 WSS supervisor 脱离 composition。
      for machineID in owners.keys.sorted() {
        await owners[machineID]?.shutdown()
      }
      throw error
    }
    return (selected, owners)
  }

  public func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    await ensureStarted()
    guard !shuttingDown else { return shutdownResourceStream() }
    guard let stream = await machineBroadcaster.streamIfAvailable() else {
      return observationCapacityResourceStream()
    }
    return stream
  }

  public func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    await ensureStarted()
    guard !shuttingDown else { return shutdownResourceStream() }
    guard machineIsInScope(machineID) else {
      return terminalResourceStream(
        .failed(error: SessionSourceFailure(code: .machineOffline), retryable: false)
      )
    }
    if let terminal = fatalConnectionStates[machineID] {
      return terminalResourceStream(
        .failed(
          error: SessionSourceFailure(code: failureCode(for: terminal)),
          retryable: false
        )
      )
    }
    let channel = catalogChannel(for: machineID)
    if let reducer = catalogReducers[machineID] {
      _ = await channel.broadcaster.publish(
        .ready(value: reducer.projection.summaries, revision: reducer.projection.revision),
        on: channel.generation
      )
    }
    guard let stream = await channel.broadcaster.streamIfAvailable() else {
      return observationCapacityResourceStream()
    }
    return stream
  }

  public func conversation(
    conversationID: String
  ) async -> AsyncStream<ConversationUpdate> {
    await ensureStarted()
    guard !shuttingDown else { return terminalConversationStream(.machineOffline) }
    if let retiringMachineID = conversationRetirements[conversationID] {
      if let state = fatalConnectionStates[retiringMachineID] {
        return terminalConversationStream(state)
      }
      return observationCapacityConversationStream()
    }
    let machineID: String
    if let existing = conversationObservations[conversationID] {
      machineID = existing.machineID
    } else {
      do {
        machineID = try resolveMachineID(conversationID: conversationID)
      } catch {
        return terminalConversationStream(.securityError)
      }
    }
    if let state = fatalConnectionStates[machineID] {
      return terminalConversationStream(state)
    }

    if conversationObservations[conversationID] != nil {
      // MVP ViewModel 对每个 conversation 固定一个 subscription task。broadcaster 不保留
      // 完整 transcript，因此 cap/+1 只能给 offending late observer 返回定向
      // snapshot-required；绝不能为它轮换共享 generation、清空既有 observer 队列。
      return observationCapacityConversationStream()
    }

    do {
      guard canAdmitConversationObservation(machineID: machineID) else {
        return observationCapacityConversationStream()
      }
      let observerID = UUID()
      let runtimeID = RuntimeConversationID(rawValue: conversationID)
      let resume = try RelayConversationResumeCoordinator(
        machineID: machineID,
        conversationID: runtimeID,
        persistedCursor: nil,
        inMemoryBaseline: nil
      )
      let generation = BoundedBroadcastGeneration()
      let broadcaster = BoundedBroadcaster<ConversationUpdate>(
        capacity: 512,
        overflowStrategy: .invalidateGeneration,
        generation: generation,
        maximumObservers: Self.maximumObserversPerConversation
      )
      let requestID = makeSubscriptionRequestID()
      conversationObservations[conversationID] = ConversationObservation(
        machineID: machineID,
        broadcaster: broadcaster,
        broadcastGeneration: generation,
        resume: resume,
        subscriptionRequestID: requestID,
        observerIDs: [observerID]
      )
      guard
        let stream = await broadcaster.streamIfAvailable(
          onTermination: conversationTermination(
            conversationID: conversationID,
            observerID: observerID
          )
        )
      else {
        conversationObservations.removeValue(forKey: conversationID)
        return observationCapacityConversationStream()
      }
      // Machine 可能早于 conversation ViewModel 进入 connected。late observer 必须先
      // 取得当前非默认连接态，不能只能等待下一次 reconnect 才知道 endpoint 已在线。
      if let currentState = connectionStates[machineID], currentState != .connecting {
        _ = await broadcaster.publish(
          .connectionState(currentState),
          on: generation
        )
      }
      await issueConversationSubscription(
        machineID: machineID,
        conversationID: runtimeID,
        requestID: requestID
      )
      return stream
    } catch {
      return terminalConversationStream(.securityError)
    }
  }

  public func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    await ensureStarted()
    guard !shuttingDown else { return shutdownResourceStream() }
    await publishInbox()
    guard let stream = await inboxBroadcaster.streamIfAvailable() else {
      return observationCapacityResourceStream()
    }
    return stream
  }

  public func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    try requireOperational()
    return try await commandClient.inspectPairInvite(encoded)
  }

  public func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    try requireOperational()
    return try await commandClient.pair(encodedInvite)
  }

  public func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    try requireOperational()
    guard machineIsInScope(machineID) else {
      throw SessionSourceFailure(code: .machineOffline)
    }
    return try await commandClient.revokeSelf(machineID: machineID)
  }

  public func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    try requireOperational()
    let (machineID, projection) = try onlineConversationProjection(conversationID)
    return try await commandClient.sendPrompt(
      machineID: machineID,
      conversationID: conversationID,
      text: text,
      idempotencyKey: idempotencyKey,
      expectedConfigurationRevision: projection.configurationRevision
    )
  }

  public func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    try requireOperational()
    let (machineID, projection) = try onlineConversationProjection(conversationID)
    guard
      let pending = projection.pendingApprovals.first(where: {
        $0.approvalID == approvalID && $0.turnID == turnID
      })
    else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    return try await commandClient.resolveApproval(
      machineID: machineID,
      conversationID: conversationID,
      turnID: turnID,
      approvalID: approvalID,
      requestID: pending.requestID,
      decision: decision,
      idempotencyKey: idempotencyKey
    )
  }

  public func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    try requireOperational()
    let (machineID, _) = try onlineConversationProjection(conversationID)
    return try await commandClient.retryApprovalDelivery(
      machineID: machineID,
      conversationID: conversationID,
      approvalID: approvalID
    )
  }

  /// foreground/app lifecycle 的确定性 teardown。先阻止新工作并取消 source consumers，
  /// 再让每条 connection 结束 generation（解除未决 durable permit、释放 transfer scope），
  /// 最后 join consumers 并关闭所有 observation stream。
  public func shutdown() async {
    if shutdownComplete { return }
    if shuttingDown {
      await withCheckedContinuation { continuation in
        shutdownWaiters.append(continuation)
      }
      return
    }
    shuttingDown = true
    lifecycleGeneration = UUID()

    let tasks = updateTasks
    updateTasks.removeAll(keepingCapacity: false)
    for task in tasks.values {
      task.cancel()
    }

    async let commandClientShutdown: Void = commandClient.shutdown()

    for machineID in connections.keys {
      beginConnectionShutdown(machineID)
    }
    let shutdownTasks = Array(connectionShutdownTasks.values)
    for task in shutdownTasks {
      await task.value
    }
    for task in tasks.values {
      await task.value
    }
    await commandClientShutdown

    for observation in conversationObservations.values {
      await observation.broadcaster.finish()
    }
    conversationObservations.removeAll(keepingCapacity: false)
    for channel in catalogChannels.values {
      await channel.broadcaster.finish()
    }
    await machineBroadcaster.finish()
    await inboxBroadcaster.finish()
    shutdownComplete = true
    let waiters = shutdownWaiters
    shutdownWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func debugConversationObservationCount() -> Int {
    conversationObservations.count
  }

  func debugConversationRetirementCount() -> Int {
    conversationRetirements.count
  }

  func debugConversationCursor(_ conversationID: String) -> RuntimeStreamCursorV1? {
    conversationObservations[conversationID]?.resume.committedProjection?.cursor
  }

  func debugConversationSubscriptionRequestID(_ conversationID: String) -> RuntimeMessageID? {
    conversationObservations[conversationID]?.subscriptionRequestID
  }

  func debugRetainedConversationBootstrapItemCount(_ conversationID: String) -> Int? {
    conversationObservations[conversationID]?.resume.retainedBootstrapItemCount
  }

  func debugForceConversationRecovery(
    _ conversationID: String,
    afterInvalidatingGeneration: (@Sendable () async -> Void)? = nil
  ) async {
    await recoverConversation(
      conversationID,
      reason: .snapshotRequired,
      afterInvalidatingGeneration: afterInvalidatingGeneration
    )
  }

  private func ensureStarted() async {
    guard !started, !shuttingDown else { return }
    started = true
    let expectedLifecycleGeneration = lifecycleGeneration
    await publishMachines()
    guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
    _ = await inboxBroadcaster.publish(
      .ready(value: [], revision: resourceRevision),
      on: inboxGeneration
    )
    guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }

    for machineID in machinesByID.keys.sorted() {
      guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
      let channel = catalogChannel(for: machineID)
      _ = await channel.broadcaster.publish(
        .loading(previous: nil),
        on: channel.generation
      )
      guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
      guard let connection = connections[machineID] else { continue }
      // claim 单消费者 stream 是 start readback 的一部分；ensureStarted 返回时不得
      // 仍把 claim 留给未调度 Task，避免首批 verified update 落入竞态窗口。
      let stream = await connection.updates()
      guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
      let task = Task { [weak self] in
        for await update in stream {
          guard !Task.isCancelled else { return }
          await self?.receive(update, from: machineID)
        }
      }
      guard lifecycleIsCurrent(expectedLifecycleGeneration) else {
        task.cancel()
        return
      }
      updateTasks[machineID] = task
      let readiness = await connection.readinessSnapshot()
      guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
      guard
        readiness.readyScope == nil
          || readiness.readyScope == readiness.connectionScope
      else {
        await failMachine(machineID, state: .securityError)
        continue
      }
      if let scope = readiness.connectionScope {
        await receive(.connectionScope(scope), from: machineID)
      }
      if let scope = readiness.readyScope {
        await receive(.businessReady(scope), from: machineID)
      }
    }
    guard lifecycleIsCurrent(expectedLifecycleGeneration) else { return }
    await publishMachines()
  }

  private func receive(_ update: MachineConnectionUpdate, from machineID: String) async {
    guard !shuttingDown, machinesByID[machineID] != nil else { return }
    if fatalConnectionStates[machineID] != nil {
      if case .delivery(let delivery) = update {
        await discardDelivery(delivery, machineID: machineID)
      }
      return
    }
    switch update {
    case .connectionState(let state):
      if isFatal(state) {
        await failMachine(machineID, state: state)
        return
      }
      connectionStates[machineID] = state
      bumpResourceRevision()
      await publishMachines()
      await publishConnectionState(state, machineID: machineID)
      await publishCatalogStaleness(state, machineID: machineID)
      if state != .connected {
        connectionScopes.removeValue(forKey: machineID)
        businessReadyScopes.removeValue(forKey: machineID)
      }

    case .connectionScope(let scope):
      guard let scope else {
        connectionScopes.removeValue(forKey: machineID)
        businessReadyScopes.removeValue(forKey: machineID)
        return
      }
      if connectionScopes[machineID] != scope {
        connectionScopes[machineID] = scope
        businessReadyScopes.removeValue(forKey: machineID)
      }

    case .businessReady(let scope):
      guard connectionScopes[machineID] == scope,
        businessReadyScopes[machineID] != scope
      else {
        return
      }
      businessReadyScopes[machineID] = scope
      await beginCatalogSubscription(machineID)
      let conversationIDs = conversationObservations.compactMap { conversationID, observation in
        observation.machineID == machineID ? conversationID : nil
      }
      for conversationID in conversationIDs.sorted() {
        await recoverConversation(conversationID, reason: .snapshotRequired)
      }

    case .streamRecoveryRequired(let target, let reason):
      switch target {
      case .catalog(let subscriptionRequestID):
        guard catalogRequestIsCurrent(subscriptionRequestID, machineID: machineID) else {
          return
        }
        await restartCatalog(machineID, reason: reason)
      case .conversation(let conversationID, let subscriptionRequestID):
        guard
          conversationObservations[conversationID.rawValue]?.machineID == machineID,
          conversationObservations[conversationID.rawValue]?.subscriptionRequestID
            == subscriptionRequestID
        else {
          return
        }
        await recoverConversation(conversationID.rawValue, reason: reason)
      case .request, .pairing:
        await failMachine(machineID, state: .securityError)
      }

    case .delivery(let delivery):
      guard delivery.machineID == machineID else {
        await failMachine(machineID, state: .securityError)
        return
      }
      do {
        switch delivery.target {
        case .catalog(let subscriptionRequestID):
          guard catalogRequestIsCurrent(subscriptionRequestID, machineID: machineID) else {
            // 已经被新 subscribe 取代的 bootstrap/live delivery 只能丢弃，不能触碰
            // 当前 staged/committed reducer，也不能反向覆盖新 request correlation。
            await discardDelivery(delivery, machineID: machineID)
            return
          }
          try await receiveCatalog(
            delivery,
            machineID: machineID,
            subscriptionRequestID: subscriptionRequestID
          )
        case .conversation(let conversationID, let subscriptionRequestID):
          guard
            conversationObservations[conversationID.rawValue]?.subscriptionRequestID
              == subscriptionRequestID
          else {
            // last-observer teardown 或 superseded bootstrap 的迟到 delivery。
            await discardDelivery(delivery, machineID: machineID)
            return
          }
          try await receiveConversation(
            delivery,
            conversationID: conversationID,
            subscriptionRequestID: subscriptionRequestID
          )
        case .request, .pairing:
          // request/pairing owners 必须在 command client 的 pending registry 内消费；
          // 错路由到 resource reducer 是 security fault，且在此之前零 cursor 推进。
          throw RelaySourceReducerError.invalidBootstrapOrder
        }
      } catch RelaySourceReducerError.staleSubscriptionGeneration {
        await discardDelivery(delivery, machineID: machineID)
        switch delivery.target {
        case .conversation(let conversationID, _):
          await recoverConversation(conversationID.rawValue, reason: .snapshotRequired)
        case .catalog:
          await restartCatalog(machineID, reason: .snapshotRequired)
        case .request, .pairing:
          await failMachine(machineID, state: .securityError)
        }
      } catch RelaySourceReducerError.unexpectedCursor {
        await discardDelivery(delivery, machineID: machineID)
        if case .conversation(let conversationID, _) = delivery.target {
          await recoverConversation(conversationID.rawValue, reason: .cursorGap)
        } else {
          await restartCatalog(machineID, reason: .cursorGap)
        }
      } catch RelaySourceReducerError.conversationBootstrapCapacity {
        await discardDelivery(delivery, machineID: machineID)
        if case .conversation(let conversationID, _) = delivery.target {
          await recoverConversation(conversationID.rawValue, reason: .snapshotRequired)
        } else {
          await failMachine(machineID, state: .securityError)
        }
      } catch {
        await discardDelivery(delivery, machineID: machineID)
        await failMachine(machineID, state: .securityError)
      }
    }
  }

  private func commitDelivery(
    _ delivery: VerifiedRuntimeDelivery,
    machineID: String
  ) async throws {
    guard delivery.machineID == machineID,
      let connection = connections[machineID]
    else {
      throw SessionSourceFailure(code: .securityError)
    }
    try await connection.commit(delivery)
  }

  private func discardDelivery(
    _ delivery: VerifiedRuntimeDelivery,
    machineID: String
  ) async {
    guard delivery.machineID == machineID,
      let connection = connections[machineID]
    else {
      return
    }
    await connection.discard(delivery)
  }

  private func receiveCatalog(
    _ delivery: VerifiedRuntimeDelivery,
    machineID: String,
    subscriptionRequestID: RuntimeMessageID
  ) async throws {
    switch delivery.payload {
    case .typedReply(.subscription(let receipt)):
      guard var bootstrap = catalogBootstraps[machineID],
        bootstrap.requestID == subscriptionRequestID,
        bootstrap.generation == nil,
        case .subscribed(let generation) = receipt,
        generation == delivery.streamGeneration
      else {
        throw RelaySourceReducerError.subscriptionMismatch
      }
      bootstrap.generation = generation
      try await commitDelivery(delivery, machineID: machineID)
      catalogBootstraps[machineID] = bootstrap

    case .catalogSnapshot(let page):
      guard var bootstrap = catalogBootstraps[machineID],
        bootstrap.requestID == subscriptionRequestID,
        bootstrap.generation == delivery.streamGeneration,
        !bootstrap.backfillStarted
      else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      try bootstrap.snapshot.append(page)
      if page.nextPageCursor == nil {
        bootstrap.stagedReducer = try CatalogReducer(
          machineID: machineID,
          snapshotPages: bootstrap.snapshot.pages
        )
      }
      try await commitDelivery(delivery, machineID: machineID)
      catalogBootstraps[machineID] = bootstrap

    case .catalogBackfill(let backfill):
      guard var bootstrap = catalogBootstraps[machineID],
        bootstrap.requestID == subscriptionRequestID,
        bootstrap.generation == delivery.streamGeneration,
        var reducer = bootstrap.stagedReducer
      else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      _ = try reducer.apply(backfill)
      bootstrap.stagedReducer = reducer
      bootstrap.backfillStarted = true
      try await commitDelivery(delivery, machineID: machineID)
      catalogBootstraps[machineID] = bootstrap

    case .syncComplete(let sync):
      guard let bootstrap = catalogBootstraps[machineID],
        bootstrap.requestID == subscriptionRequestID,
        bootstrap.generation == delivery.streamGeneration,
        sync.streamGeneration == delivery.streamGeneration,
        sync.streamCursor == delivery.outerCursor,
        sync.keyDirectoryRevision > 0,
        case .catalog(let innerCursor) = sync.innerCursor,
        let reducer = bootstrap.stagedReducer,
        reducer.cursor == innerCursor
      else {
        throw RelaySourceReducerError.syncCompleteMismatch
      }
      try await commitDelivery(delivery, machineID: machineID)
      catalogReducers[machineID] = reducer
      catalogActiveSubscriptions[machineID] = CatalogActiveSubscription(
        requestID: subscriptionRequestID,
        generation: delivery.streamGeneration
      )
      catalogBootstraps.removeValue(forKey: machineID)
      bumpResourceRevision()
      let channel = catalogChannel(for: machineID)
      _ = await channel.broadcaster.publish(
        .ready(value: reducer.projection.summaries, revision: reducer.projection.revision),
        on: channel.generation
      )
      await publishMachines()
      await publishInbox()

    case .catalogDelta(let delta):
      guard catalogBootstraps[machineID] == nil,
        let active = catalogActiveSubscriptions[machineID],
        active.requestID == subscriptionRequestID,
        var reducer = catalogReducers[machineID]
      else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      guard active.generation == delivery.streamGeneration else {
        throw RelaySourceReducerError.staleSubscriptionGeneration
      }
      let result = try reducer.apply(delta)
      guard result == .applied else {
        throw RelaySourceReducerError.invalidBootstrapOrder
      }
      try await commitDelivery(delivery, machineID: machineID)
      catalogReducers[machineID] = reducer
      bumpResourceRevision()
      let channel = catalogChannel(for: machineID)
      _ = await channel.broadcaster.publish(
        .ready(value: reducer.projection.summaries, revision: reducer.projection.revision),
        on: channel.generation
      )
      await publishMachines()
      await publishInbox()

    case .conversationSnapshot, .conversationBackfill, .conversationEvent, .commandState:
      throw RelaySourceReducerError.conversationMismatch
    case .typedReply:
      throw RelaySourceReducerError.invalidBootstrapOrder
    }
  }

  private func receiveConversation(
    _ delivery: VerifiedRuntimeDelivery,
    conversationID: RuntimeConversationID,
    subscriptionRequestID: RuntimeMessageID
  ) async throws {
    guard var observation = conversationObservations[conversationID.rawValue],
      observation.machineID == delivery.machineID,
      observation.subscriptionRequestID == subscriptionRequestID
    else {
      throw RelaySourceReducerError.invalidBootstrapOrder
    }
    let expectedStateToken = observation.stateToken
    let result = try observation.resume.accept(delivery)
    switch result {
    case .staged, .suppressedUntilBarrier:
      try await commitDelivery(delivery, machineID: delivery.machineID)
      _ = await installCommittedObservation(
        observation,
        conversationID: conversationID.rawValue,
        expectedStateToken: expectedStateToken
      )
      return

    case .duplicate:
      throw RelaySourceReducerError.invalidBootstrapOrder

    case .staleGeneration:
      throw RelaySourceReducerError.staleSubscriptionGeneration

    case .synchronized:
      let synchronized = observation.resume.takeSynchronizedDelivery()
      var updates: [ConversationUpdate] = []
      if let snapshot = synchronized.snapshot {
        updates.append(.snapshot(snapshot))
      }
      updates.append(
        contentsOf: synchronized.events.map(ConversationUpdate.event))
      if observation.awaitingBroadcastBarrier, updates.isEmpty {
        throw RelaySourceReducerError.syncCompleteMismatch
      }
      try await commitDelivery(delivery, machineID: delivery.machineID)
      guard
        var committed = await installCommittedObservation(
          observation,
          conversationID: conversationID.rawValue,
          expectedStateToken: expectedStateToken
        )
      else {
        // durable cut 已成功；并发 replacement/teardown 拥有后续恢复，绝不能再 discard。
        return
      }
      if updates.isEmpty {
        // warm exact-cursor resume 可合法只有 Subscribed + SyncComplete。已有
        // projection 与用户 outer stream 保持不变；BeforeFirst 仍由 coordinator 强制 snapshot。
        return
      }
      if committed.awaitingBroadcastBarrier {
        let first = updates.removeFirst()
        let resumeResult = await committed.broadcaster.resumeAfterBarrier(
          snapshot: first,
          generation: committed.broadcastGeneration
        )
        switch resumeResult {
        case .published:
          guard var current = conversationObservations[conversationID.rawValue],
            current.stateToken == committed.stateToken,
            current.subscriptionRequestID == committed.subscriptionRequestID,
            current.broadcastGeneration == committed.broadcastGeneration
          else {
            return
          }
          current.awaitingBroadcastBarrier = false
          current.stateToken = UUID()
          conversationObservations[conversationID.rawValue] = current
          committed = current
        case .staleGeneration, .awaitingBarrier, .finished:
          // 并发 recovery/teardown 已接管；fresh barrier 会覆盖该 durable cut。
          return
        case .overflow, .replacedOldest, .invalidState:
          await recoverConversation(conversationID.rawValue, reason: .snapshotRequired)
          return
        }
      }
      for update in updates {
        let publishResult = await committed.broadcaster.publish(
          update,
          on: committed.broadcastGeneration
        )
        switch publishResult {
        case .published:
          continue
        case .overflow:
          await recoverConversation(conversationID.rawValue, reason: .bufferDropped)
          return
        case .staleGeneration, .awaitingBarrier, .finished:
          return
        case .replacedOldest, .invalidState:
          await recoverConversation(conversationID.rawValue, reason: .snapshotRequired)
          return
        }
      }

    case .live:
      let update: ConversationUpdate
      switch delivery.payload {
      case .conversationEvent(let event): update = .event(event)
      case .commandState(let receipt): update = .commandState(receipt)
      default: throw RelaySourceReducerError.invalidBootstrapOrder
      }
      try await commitDelivery(delivery, machineID: delivery.machineID)
      guard
        let committed = await installCommittedObservation(
          observation,
          conversationID: conversationID.rawValue,
          expectedStateToken: expectedStateToken
        )
      else {
        return
      }
      let publishResult = await committed.broadcaster.publish(
        update,
        on: committed.broadcastGeneration
      )
      switch publishResult {
      case .published:
        break
      case .overflow:
        await recoverConversation(conversationID.rawValue, reason: .bufferDropped)
        return
      case .staleGeneration, .awaitingBarrier, .finished:
        return
      case .replacedOldest, .invalidState:
        await recoverConversation(conversationID.rawValue, reason: .snapshotRequired)
        return
      }
    }
    bumpResourceRevision()
    await publishMachines()
    await publishInbox()
  }

  /// `commitDelivery` 跨 actor 可重入；只允许把 scratch 安装回它读取时的 exact
  /// observation。token 不匹配代表 replacement/observer mutation/teardown 已发生。
  /// durable cut 此时已经成功，必须由当前 owner fresh-recover，不能 discard 或盲写旧值。
  private func installCommittedObservation(
    _ prepared: ConversationObservation,
    conversationID: String,
    expectedStateToken: UUID
  ) async -> ConversationObservation? {
    guard var current = conversationObservations[conversationID] else {
      return nil
    }
    guard current.stateToken == expectedStateToken,
      current.subscriptionRequestID == prepared.subscriptionRequestID,
      current.broadcastGeneration == prepared.broadcastGeneration
    else {
      if !current.awaitingBroadcastBarrier {
        await recoverConversation(conversationID, reason: .snapshotRequired)
      }
      return nil
    }
    current = prepared
    current.stateToken = UUID()
    conversationObservations[conversationID] = current
    return current
  }

  private func recoverConversation(
    _ conversationID: String,
    reason: SessionLagReason,
    afterInvalidatingGeneration: (@Sendable () async -> Void)? = nil
  ) async {
    guard !shuttingDown,
      var observation = conversationObservations[conversationID],
      fatalConnectionStates[observation.machineID] == nil
    else {
      return
    }
    let requestID = makeSubscriptionRequestID()
    observation.subscriptionRequestID = requestID
    observation.awaitingBroadcastBarrier = true
    observation.resume.beginRecovery()
    observation.stateToken = UUID()
    conversationObservations[conversationID] = observation

    let broadcastGeneration = await observation.broadcaster.invalidateGeneration(
      marker: .connectionState(.lagged(reason: reason))
    )
    if let afterInvalidatingGeneration {
      await afterInvalidatingGeneration()
    }
    guard var current = conversationObservations[conversationID],
      current.subscriptionRequestID == requestID
    else {
      return
    }
    current.broadcastGeneration = broadcastGeneration
    current.stateToken = UUID()
    conversationObservations[conversationID] = current
    await issueConversationSubscription(
      machineID: current.machineID,
      conversationID: RuntimeConversationID(rawValue: conversationID),
      requestID: requestID
    )
  }

  private func restartCatalog(
    _ machineID: String,
    reason: SessionLagReason
  ) async {
    let channel = catalogChannel(for: machineID)
    if let projection = catalogReducers[machineID]?.projection {
      _ = await channel.broadcaster.publish(
        .stale(value: projection.summaries, reason: .lagged(reason: reason)),
        on: channel.generation
      )
    } else {
      _ = await channel.broadcaster.publish(
        .loading(previous: nil),
        on: channel.generation
      )
    }
    await beginCatalogSubscription(machineID)
  }

  private func beginCatalogSubscription(_ machineID: String) async {
    guard !shuttingDown, fatalConnectionStates[machineID] == nil else { return }
    guard let currentScope = connectionScopes[machineID],
      businessReadyScopes[machineID] == currentScope
    else {
      return
    }
    let requestID = makeSubscriptionRequestID()
    catalogActiveSubscriptions.removeValue(forKey: machineID)
    catalogBootstraps[machineID] = CatalogBootstrap(requestID: requestID)
    do {
      try await commandClient.subscribe(
        machineID: machineID,
        target: .catalog,
        after: .beforeFirst,
        requestID: requestID
      )
    } catch {
      guard catalogBootstraps[machineID]?.requestID == requestID else { return }
      await failMachine(machineID, state: connectionState(for: error))
    }
  }

  private func issueConversationSubscription(
    machineID: String,
    conversationID: RuntimeConversationID,
    requestID: RuntimeMessageID
  ) async {
    guard !shuttingDown, fatalConnectionStates[machineID] == nil else { return }
    guard let currentScope = connectionScopes[machineID],
      businessReadyScopes[machineID] == currentScope
    else {
      return
    }
    do {
      try await commandClient.subscribe(
        machineID: machineID,
        target: .conversation(conversationID: conversationID),
        after: .beforeFirst,
        requestID: requestID
      )
    } catch {
      guard let observation = conversationObservations[conversationID.rawValue],
        observation.subscriptionRequestID == requestID
      else {
        return
      }
      let state = connectionState(for: error)
      if isFatal(state) {
        await failMachine(machineID, state: state)
        return
      }
      await failMachine(machineID, state: state)
      let generation = await observation.broadcaster.invalidateGeneration(
        marker: .connectionState(state)
      )
      guard var current = conversationObservations[conversationID.rawValue],
        current.subscriptionRequestID == requestID
      else {
        return
      }
      current.broadcastGeneration = generation
      current.awaitingBroadcastBarrier = true
      current.stateToken = UUID()
      conversationObservations[conversationID.rawValue] = current
    }
  }

  private func publishMachines() async {
    let values = scopedMachineIDs().compactMap { machineID -> MachineSummary? in
      guard let machine = machinesByID[machineID] else { return nil }
      let catalog = catalogReducers[machineID]?.projection.summaries ?? []
      let observations = conversationObservations.values.filter { $0.machineID == machineID }
      let pending = observations.reduce(0) {
        $0 + ($1.resume.committedProjection?.pendingApprovals.count ?? 0)
      }
      return MachineSummary(
        id: machine.id,
        name: machine.name,
        connectionState: connectionStates[machineID] ?? .connecting,
        lastHeartbeat: nil,
        activeConversationCount: catalog.filter { !$0.archived }.count,
        pendingApprovalCount: pending
      )
    }
    _ = await machineBroadcaster.publish(
      .ready(value: values, revision: resourceRevision),
      on: machineGeneration
    )
  }

  private func publishInbox() async {
    var items: [InboxItem] = []
    for machineID in scopedMachineIDs() {
      guard let catalog = catalogReducers[machineID]?.projection else { continue }
      let conversations: [ConversationProjection] = conversationObservations.values.compactMap {
        observation in
        guard observation.machineID == machineID else { return nil }
        return observation.resume.committedProjection
      }
      items.append(contentsOf: InboxReducer.derive(catalog: catalog, conversations: conversations))
    }
    _ = await inboxBroadcaster.publish(
      .ready(value: items, revision: resourceRevision),
      on: inboxGeneration
    )
  }

  private func publishConnectionState(
    _ state: SessionConnectionState,
    machineID: String
  ) async {
    let conversationIDs = conversationObservations.compactMap { conversationID, observation in
      observation.machineID == machineID ? conversationID : nil
    }
    for conversationID in conversationIDs {
      guard let observation = conversationObservations[conversationID] else { continue }
      if isFatal(state) {
        _ = await observation.broadcaster.finish(
          delivering: .connectionState(state)
        )
        continue
      }
      let result = await observation.broadcaster.publish(
        .connectionState(state),
        on: observation.broadcastGeneration
      )
      if result == .overflow {
        await recoverConversation(conversationID, reason: .bufferDropped)
      }
    }
  }

  private func publishCatalogStaleness(
    _ state: SessionConnectionState,
    machineID: String
  ) async {
    let channel = catalogChannel(for: machineID)
    if isFatal(state) {
      let code: SessionSourceFailureCode
      switch state {
      case .revoked: code = .revoked
      case .incompatible: code = .incompatible
      default: code = .securityError
      }
      _ = await channel.broadcaster.publish(
        .failed(error: SessionSourceFailure(code: code), retryable: false),
        on: channel.generation
      )
      await channel.broadcaster.finish()
      return
    }
    guard let projection = catalogReducers[machineID]?.projection else { return }
    _ = await channel.broadcaster.publish(
      .stale(value: projection.summaries, reason: staleReason(state)),
      on: channel.generation
    )
  }

  private func failMachine(_ machineID: String, state: SessionConnectionState) async {
    let effectiveState: SessionConnectionState
    if let terminal = fatalConnectionStates[machineID] {
      effectiveState = terminal
    } else {
      effectiveState = state
      if isFatal(state) {
        fatalConnectionStates[machineID] = state
      }
    }
    connectionStates[machineID] = effectiveState
    if effectiveState != .connected {
      connectionScopes.removeValue(forKey: machineID)
      businessReadyScopes.removeValue(forKey: machineID)
    }
    bumpResourceRevision()
    await publishMachines()
    await publishConnectionState(effectiveState, machineID: machineID)
    await publishCatalogStaleness(effectiveState, machineID: machineID)
    if isFatal(effectiveState) {
      beginConnectionShutdown(machineID)
    }
  }

  private func beginConnectionShutdown(_ machineID: String) {
    guard connectionShutdownTasks[machineID] == nil,
      let connection = connections[machineID]
    else {
      return
    }
    connectionShutdownTasks[machineID] = Task {
      await connection.shutdown()
    }
  }

  private func catalogChannel(
    for machineID: String
  ) -> BroadcastChannel<ResourceState<[ConversationSummary]>> {
    if let existing = catalogChannels[machineID] { return existing }
    let generation = BoundedBroadcastGeneration()
    let broadcaster = BoundedBroadcaster<ResourceState<[ConversationSummary]>>(
      capacity: 1,
      overflowStrategy: .bufferingNewest,
      generation: generation
    )
    let channel = BroadcastChannel(broadcaster: broadcaster, generation: generation)
    catalogChannels[machineID] = channel
    return channel
  }

  private func catalogRequestIsCurrent(
    _ requestID: RuntimeMessageID,
    machineID: String
  ) -> Bool {
    if let bootstrap = catalogBootstraps[machineID] {
      return bootstrap.requestID == requestID
    }
    return catalogActiveSubscriptions[machineID]?.requestID == requestID
  }

  private func makeSubscriptionRequestID() -> RuntimeMessageID {
    RuntimeMessageID(rawValue: "relay-subscription-\(UUID().uuidString.lowercased())")
  }

  private func conversationTermination(
    conversationID: String,
    observerID: UUID
  ) -> @Sendable () -> Void {
    { [weak self] in
      guard let self else { return }
      Task {
        await self.conversationObserverDidTerminate(
          conversationID: conversationID,
          observerID: observerID
        )
      }
    }
  }

  private func conversationObserverDidTerminate(
    conversationID: String,
    observerID: UUID
  ) async {
    guard var observation = conversationObservations[conversationID],
      observation.observerIDs.remove(observerID) != nil
    else {
      return
    }
    guard observation.observerIDs.isEmpty else {
      observation.stateToken = UUID()
      conversationObservations[conversationID] = observation
      return
    }

    conversationRetirements[conversationID] = observation.machineID
    defer { conversationRetirements.removeValue(forKey: conversationID) }
    conversationObservations.removeValue(forKey: conversationID)
    await observation.broadcaster.finish()
    if !shuttingDown, fatalConnectionStates[observation.machineID] == nil {
      do {
        try await commandClient.unsubscribe(
          machineID: observation.machineID,
          target: .conversation(
            conversationID: RuntimeConversationID(rawValue: conversationID)
          )
        )
      } catch {
        await failMachine(
          observation.machineID,
          state: connectionState(for: error)
        )
      }
    }
    bumpResourceRevision()
    await publishMachines()
    await publishInbox()
  }

  private func resolveMachineID(conversationID: String) throws -> String {
    switch scope {
    case .machine(let machineID):
      return machineID
    case .allPairedMachines:
      let matches = catalogReducers.compactMap { machineID, reducer in
        reducer.projection.summaries.contains { $0.id == conversationID } ? machineID : nil
      }
      guard matches.count == 1, let machineID = matches.first else {
        throw SessionSourceFailure(
          code: matches.isEmpty ? .commandRejected : .securityError
        )
      }
      return machineID
    }
  }

  private func onlineConversationProjection(
    _ conversationID: String
  ) throws -> (String, ConversationProjection) {
    let machineID = try resolveMachineID(conversationID: conversationID)
    guard connectionStates[machineID] == .connected else {
      let state = connectionStates[machineID] ?? .connecting
      switch state {
      case .machineOffline: throw SessionSourceFailure(code: .machineOffline)
      case .revoked: throw SessionSourceFailure(code: .revoked)
      case .incompatible: throw SessionSourceFailure(code: .incompatible)
      case .securityError: throw SessionSourceFailure(code: .securityError)
      default: throw SessionSourceFailure(code: .transportUnavailable)
      }
    }
    guard let projection = conversationObservations[conversationID]?.resume.committedProjection,
      projection.machineID == machineID
    else {
      throw SessionSourceFailure(code: .commandRejected)
    }
    return (machineID, projection)
  }

  private func machineIsInScope(_ machineID: String) -> Bool {
    guard machinesByID[machineID] != nil else { return false }
    switch scope {
    case .allPairedMachines: return true
    case .machine(let expected): return machineID == expected
    }
  }

  private func canAdmitConversationObservation(machineID: String) -> Bool {
    let retainedCount = conversationObservations.count + conversationRetirements.count
    guard retainedCount < conversationObservationLimit else {
      return false
    }
    var retainedForMachine = conversationObservations.values.reduce(into: 0) {
      count, observation in
      if observation.machineID == machineID { count += 1 }
    }
    retainedForMachine += conversationRetirements.values.reduce(into: 0) {
      count, retiringMachineID in
      if retiringMachineID == machineID { count += 1 }
    }
    return retainedForMachine < conversationObservationPerMachineLimit
  }

  private func scopedMachineIDs() -> [String] {
    switch scope {
    case .allPairedMachines: return machinesByID.keys.sorted()
    case .machine(let machineID): return machinesByID[machineID] == nil ? [] : [machineID]
    }
  }

  private func bumpResourceRevision() {
    let (next, overflow) = resourceRevision.addingReportingOverflow(1)
    if !overflow { resourceRevision = next }
  }

  private func connectionState(for error: Error) -> SessionConnectionState {
    guard let failure = error as? SessionSourceFailure else { return .relayUnavailable }
    switch failure.code {
    case .machineOffline: return .machineOffline
    case .revoked: return .revoked
    case .incompatible: return .incompatible
    case .securityError: return .securityError
    default: return .relayUnavailable
    }
  }

  private func staleReason(_ state: SessionConnectionState) -> ResourceStaleReason {
    switch state {
    case .machineOffline: return .machineOffline
    case .lagged(let reason): return .lagged(reason: reason)
    case .relayUnavailable: return .relayUnavailable
    default: return .reconnecting
    }
  }

  private func isFatal(_ state: SessionConnectionState) -> Bool {
    switch state {
    case .revoked, .incompatible, .securityError: true
    default: false
    }
  }

  private func failureCode(
    for state: SessionConnectionState
  ) -> SessionSourceFailureCode {
    switch state {
    case .revoked: .revoked
    case .incompatible: .incompatible
    default: .securityError
    }
  }

  private func requireOperational() throws {
    guard !shuttingDown else {
      throw SessionSourceFailure(code: .transportUnavailable)
    }
  }

  private func lifecycleIsCurrent(_ expected: UUID) -> Bool {
    !shuttingDown && lifecycleGeneration == expected
  }

  private func shutdownResourceStream<Value: Sendable>() -> AsyncStream<ResourceState<Value>> {
    terminalResourceStream(
      .failed(
        error: SessionSourceFailure(code: .transportUnavailable),
        retryable: false
      )
    )
  }

  private func terminalResourceStream<Value: Sendable>(
    _ value: ResourceState<Value>
  ) -> AsyncStream<ResourceState<Value>> {
    AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
      continuation.yield(value)
      continuation.finish()
    }
  }

  private func terminalConversationStream(
    _ state: SessionConnectionState
  ) -> AsyncStream<ConversationUpdate> {
    AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
      continuation.yield(.connectionState(state))
      continuation.finish()
    }
  }

  private func observationCapacityResourceStream<Value: Sendable>()
    -> AsyncStream<ResourceState<Value>>
  {
    terminalResourceStream(
      .failed(
        error: SessionSourceFailure(code: .transportUnavailable),
        retryable: true
      )
    )
  }

  private func observationCapacityConversationStream() -> AsyncStream<ConversationUpdate> {
    terminalConversationStream(.lagged(reason: .snapshotRequired))
  }
}
