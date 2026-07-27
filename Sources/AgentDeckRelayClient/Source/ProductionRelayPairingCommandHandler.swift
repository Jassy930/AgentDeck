import AgentDeckSessionSource
import Foundation

protocol RelayPairingTransportSession: Sendable {
  func connect() async throws -> RelayTransportGeneration
  func incomingFrames(
    on generation: RelayTransportGeneration
  ) async -> AsyncThrowingStream<ReceivedRelayFrame, any Error>
  func send(
    _ frame: RelayV2OutboundFrame,
    on generation: RelayTransportGeneration
  ) async throws
  func close(generation: RelayTransportGeneration) async throws
  func shutdown() async
}

private actor ProductionRelayPairingTransportSession:
  RelayPairingTransportSession
{
  private let transport: RelayWebSocketTransport

  init(transport: RelayWebSocketTransport) {
    self.transport = transport
  }

  func connect() async throws -> RelayTransportGeneration {
    try await transport.connect()
  }

  func incomingFrames(
    on generation: RelayTransportGeneration
  ) async -> AsyncThrowingStream<ReceivedRelayFrame, any Error> {
    await transport.incomingFrames(on: generation)
  }

  func send(
    _ frame: RelayV2OutboundFrame,
    on generation: RelayTransportGeneration
  ) async throws {
    try await transport.send(frame, on: generation)
  }

  func close(generation: RelayTransportGeneration) async throws {
    try await transport.close(generation: generation)
  }

  func shutdown() async {
    await transport.shutdown()
  }
}

protocol RelayPairingTransportFactory: Sendable {
  func makeTransport(
    for invite: PairInviteV1
  ) throws -> any RelayPairingTransportSession
}

struct ProductionRelayPairingTransportFactory: RelayPairingTransportFactory {
  func makeTransport(
    for invite: PairInviteV1
  ) throws -> any RelayPairingTransportSession {
    guard let origin = URL(string: invite.wssURL) else {
      throw SessionSourceFailure(code: .invalidPairInvite)
    }
    let endpoint = try RelayTransportEndpoint(origin: origin, route: .pairing)
    let nextPin =
      invite.nextSPKIPin == invite.currentSPKIPin
      ? nil : invite.nextSPKIPin
    let tls = try RelayTLSPolicy.pinnedSPKI(
      current: invite.currentSPKIPin,
      next: nextPin
    )
    return ProductionRelayPairingTransportSession(
      transport: RelayWebSocketTransport(
        configuration: RelayTransportConfiguration(
          endpoint: endpoint,
          tlsPolicy: tls
        )
      )
    )
  }
}

protocol RelayPairingClock: Sendable {
  func nowMilliseconds() -> UInt64
}

struct WallRelayPairingClock: RelayPairingClock {
  func nowMilliseconds() -> UInt64 {
    UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
  }
}

protocol RelayPairingSleeper: Sendable {
  func sleep(milliseconds: UInt64) async throws
}

struct ContinuousRelayPairingSleeper: RelayPairingSleeper {
  func sleep(milliseconds: UInt64) async throws {
    try await Task.sleep(for: .milliseconds(Int64(clamping: milliseconds)))
  }
}

private enum ProductionRelayPairingAttemptResult: Sendable {
  case paired(PairedMachine)
  case terminal(PairTerminalOutcomeV1)
}

private enum ProductionRelayPairingPayload: Sendable {
  case pending
  case terminal(PairTerminalOutcomeV1)
  case response(VerifiedPendingPairResponseV1)
  case persistedResponseReplay
}

private struct ProductionRelayPairingRemoteFailure: Error, Sendable {
  let failure: RelayV2Failure
}

/// `/v2/pair` 的 production owner。PairRequest marker-last 落盘后才上网；任何
/// reconnect 都重发相同 carrier。PairResponse 先完整验签/HPKE open，再 durable
/// stage response state 与 paired marker，最后才发送 persisted receipt；只有 Relay
/// 的 matching PairRouteClosed 才能把 staged marker 提交并发布 `.paired`。
actor ProductionRelayPairingCommandHandler: RelayPairingCommandHandling {
  static let maximumReconnectAttempts: UInt32 = 8
  static let attemptDeadlineMilliseconds: UInt64 = 30_000

  private let pairedMachineStore: PairedMachineStore
  private let transportFactory: any RelayPairingTransportFactory
  private let clock: any RelayPairingClock
  private let sleeper: any RelayPairingSleeper
  private let reconnectPolicy: RelayReconnectPolicy
  private let deviceDisplayName: String
  private let attemptDeadlineMilliseconds: UInt64
  private var pairingTasks: [UUID: Task<Void, Never>] = [:]
  private var pairingTransports: [UUID: any RelayPairingTransportSession] = [:]
  private var pairingTransportShutdownTasks: [UUID: Task<Void, Never>] = [:]
  private var pairingPreparations = 0
  private var pairingPreparationWaiters: [CheckedContinuation<Void, Never>] = []
  private var shuttingDown = false
  private var shutdownComplete = false
  private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

  init(
    pairedMachineStore: PairedMachineStore,
    transportFactory: any RelayPairingTransportFactory =
      ProductionRelayPairingTransportFactory(),
    clock: any RelayPairingClock = WallRelayPairingClock(),
    sleeper: any RelayPairingSleeper = ContinuousRelayPairingSleeper(),
    reconnectPolicy: RelayReconnectPolicy = RelayReconnectPolicy(),
    deviceDisplayName: String = "AgentDeck Companion",
    attemptDeadlineMilliseconds: UInt64 =
      ProductionRelayPairingCommandHandler.attemptDeadlineMilliseconds
  ) {
    precondition(attemptDeadlineMilliseconds > 0)
    self.pairedMachineStore = pairedMachineStore
    self.transportFactory = transportFactory
    self.clock = clock
    self.sleeper = sleeper
    self.reconnectPolicy = reconnectPolicy
    self.deviceDisplayName = deviceDisplayName
    self.attemptDeadlineMilliseconds = attemptDeadlineMilliseconds
  }

  func shutdown() async {
    if shutdownComplete { return }
    if shuttingDown {
      await withCheckedContinuation { continuation in
        shutdownWaiters.append(continuation)
      }
      return
    }
    shuttingDown = true

    let tasks = Array(pairingTasks.values)
    for task in tasks {
      task.cancel()
    }
    let transportWorkerIDs = Set(pairingTransports.keys).union(
      pairingTransportShutdownTasks.keys
    )
    await withTaskGroup(of: Void.self) { group in
      for workerID in transportWorkerIDs {
        group.addTask {
          await self.shutdownTransport(for: workerID)
        }
      }
    }
    for task in tasks {
      await task.value
    }
    pairingTasks.removeAll(keepingCapacity: false)
    if pairingPreparations > 0 {
      await withCheckedContinuation { continuation in
        pairingPreparationWaiters.append(continuation)
      }
    }

    shutdownComplete = true
    let waiters = shutdownWaiters
    shutdownWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    try await recoverDurablePairingState()
    let invite = try decodeInvite(encoded, enforcingExpiry: true)
    guard let relayHost = URL(string: invite.wssURL)?.host, !relayHost.isEmpty else {
      throw SessionSourceFailure(code: .invalidPairInvite)
    }
    return PairingPreview(
      name: invite.machineDisplayName,
      relayHost: relayHost,
      rootFingerprint: invite.machineRootFingerprint,
      expiresAtMs: invite.expiresAtMilliseconds,
      relayServerID: invite.relayServerID,
      currentSPKIPin: invite.currentSPKIPin,
      nextSPKIPin: invite.nextSPKIPin
    )
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    try await acquirePairingPreparation()
    defer { finishPairingPreparation() }

    // AsyncStream cancellation cannot await its onTermination cleanup. Treat a new
    // pair request as an explicit supersession barrier: cancel/close/join every old
    // worker before reading or creating durable state for the replacement invite.
    // This also serializes two concurrent callers through the same latest-wins gate.
    await cancelAndJoinAllPairingWorkers()
    try requireAcceptingPairing()
    try await recoverDurablePairingState()
    try requireAcceptingPairing()
    // responsePrepared + staged promotion 是 outcome-unknown durable transaction；即使
    // invite 已到期也必须允许用原 URI 恢复 Close/terminal reconciliation。
    let invite = try decodeInvite(encodedInvite, enforcingExpiry: false)
    let authorization = try makeDefaultAuthorization()
    let pendingStore = try await pairedMachineStore.makePendingPairingStore()

    let restored = try await resumePendingPairing(
      pendingStore,
      invite: invite,
      authorization: authorization,
      nowMilliseconds: clock.nowMilliseconds()
    )
    let initial: PendingPairingPrepareResult
    if let restored {
      initial = restored
    } else if let paired = try await existingPairedMachine(for: invite) {
      try requireAcceptingPairing()
      return Self.finishedStream(.paired(paired))
    } else {
      initial = try await pendingStore.prepare(
        invite: invite,
        authorizationRequest: authorization,
        nowMilliseconds: clock.nowMilliseconds()
      )
    }
    try requireAcceptingPairing()

    switch initial {
    case .terminal(let outcome):
      return Self.finishedStream(Self.progress(for: outcome))
    case .completed(let machineRoute, _):
      guard let paired = try await pairedMachine(machineRoute: machineRoute) else {
        throw SessionSourceFailure(code: .storageUnavailable)
      }
      try requireAcceptingPairing()
      return Self.finishedStream(.paired(paired))
    case .active(let prepared):
      let streamPair = AsyncThrowingStream<PairingProgress, Error>.makeStream(
        bufferingPolicy: .bufferingNewest(4)
      )
      let stream = streamPair.stream
      let continuation = streamPair.continuation
      let workerID = UUID()
      let task = Task { [weak self] in
        guard let self else {
          continuation.finish(
            throwing: SessionSourceFailure(code: .storageUnavailable)
          )
          return
        }
        await self.runPairingWorker(
          workerID: workerID,
          invite: invite,
          authorization: authorization,
          initialPrepared: prepared,
          pendingStore: pendingStore,
          continuation: continuation
        )
      }
      pairingTasks[workerID] = task
      continuation.onTermination = { @Sendable [weak self] _ in
        Task { [weak self] in
          await self?.cancelPairingWorker(workerID)
        }
      }
      return stream
    }
  }

  private func runPairingWorker(
    workerID: UUID,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    initialPrepared: PreparedPendingPairingV1,
    pendingStore: PendingPairingStore,
    continuation: AsyncThrowingStream<PairingProgress, Error>.Continuation
  ) async {
    defer { pairingTasks.removeValue(forKey: workerID) }
    do {
      try requireActivePairingWorker()
      _ = continuation.yield(.preparing)
      let result = try await runPairing(
        workerID: workerID,
        invite: invite,
        authorization: authorization,
        initialPrepared: initialPrepared,
        pendingStore: pendingStore,
        continuation: continuation
      )
      try requireActivePairingWorker()
      switch result {
      case .paired(let machine):
        _ = continuation.yield(.paired(machine))
      case .terminal(let outcome):
        _ = continuation.yield(Self.progress(for: outcome))
      }
      continuation.finish()
    } catch is CancellationError {
      continuation.finish()
    } catch {
      continuation.finish(throwing: Self.publicError(error))
    }
  }

  private func runPairing(
    workerID: UUID,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    initialPrepared: PreparedPendingPairingV1,
    pendingStore: PendingPairingStore,
    continuation: AsyncThrowingStream<PairingProgress, Error>.Continuation
  ) async throws -> ProductionRelayPairingAttemptResult {
    var prepared = initialPrepared
    var attempt: UInt32 = 0

    while attempt < Self.maximumReconnectAttempts {
      try requireActivePairingWorker()
      let now = clock.nowMilliseconds()
      var promotionState = try await pairingPromotionStateIfPresent(prepared: prepared)
      if case .committed(let record) = promotionState {
        try await pendingStore.markCompleted(for: prepared)
        return .paired(record.pairedMachine)
      }
      if now >= invite.expiresAtMilliseconds, promotionState == nil {
        try await recoverDurablePairingState()
        throw SessionSourceFailure(code: .pairInviteExpired)
      }
      if let restored = try await resumePendingPairing(
        pendingStore,
        invite: invite,
        authorization: authorization,
        nowMilliseconds: now
      ) {
        switch restored {
        case .active(let value):
          prepared = value
          promotionState = try await pairingPromotionStateIfPresent(prepared: value)
          if case .committed(let record) = promotionState {
            try await pendingStore.markCompleted(for: value)
            return .paired(record.pairedMachine)
          }
        case .terminal(let outcome): return .terminal(outcome)
        case .completed(let machineRoute, _):
          guard let machine = try await pairedMachine(machineRoute: machineRoute) else {
            throw SessionSourceFailure(code: .storageUnavailable)
          }
          return .paired(machine)
        }
      }

      try requireActivePairingWorker()
      let transport = try transportFactory.makeTransport(for: invite)
      pairingTransports[workerID] = transport
      do {
        let result = try await runAttemptWithDeadline(
          transport: transport,
          invite: invite,
          authorization: authorization,
          prepared: prepared,
          pendingStore: pendingStore,
          continuation: continuation,
          allowPastInviteExpiry: promotionState != nil
        )
        await shutdownTransport(for: workerID)
        try requireActivePairingWorker()
        return result
      } catch {
        await shutdownTransport(for: workerID)
        try requireActivePairingWorker()
        guard Self.isRetryableTransportFailure(error),
          attempt + 1 < Self.maximumReconnectAttempts
        else {
          throw error
        }
        if let restored = try await resumePendingPairing(
          pendingStore,
          invite: invite,
          authorization: authorization,
          nowMilliseconds: clock.nowMilliseconds()
        ) {
          switch restored {
          case .active(let value): prepared = value
          case .terminal(let outcome): return .terminal(outcome)
          case .completed(let machineRoute, _):
            guard let machine = try await pairedMachine(machineRoute: machineRoute) else {
              throw SessionSourceFailure(code: .storageUnavailable)
            }
            return .paired(machine)
          }
        }
        promotionState = try await pairingPromotionStateIfPresent(prepared: prepared)
        if case .committed(let record) = promotionState {
          try await pendingStore.markCompleted(for: prepared)
          return .paired(record.pairedMachine)
        }
        let delay = try reconnectPolicy.delayMilliseconds(
          forAttempt: attempt,
          reason: Self.reconnectReason(error),
          nowMilliseconds: clock.nowMilliseconds(),
          jitterUnitInterval: 0.5
        )
        let current = clock.nowMilliseconds()
        if current >= invite.expiresAtMilliseconds, promotionState == nil {
          try await recoverDurablePairingState()
          throw SessionSourceFailure(code: .pairInviteExpired)
        }
        let boundedDelay: UInt64
        if promotionState != nil {
          boundedDelay = delay
        } else {
          let remaining = invite.expiresAtMilliseconds - current
          boundedDelay = min(delay, remaining)
        }
        try await sleeper.sleep(milliseconds: boundedDelay)
        attempt += 1
      }
    }
    throw SessionSourceFailure(code: .transportUnavailable)
  }

  private func requireAcceptingPairing() throws {
    try Task.checkCancellation()
    guard !shuttingDown else {
      throw SessionSourceFailure(code: .commandRejected)
    }
  }

  private func acquirePairingPreparation() async throws {
    while pairingPreparations > 0 {
      await withCheckedContinuation { continuation in
        pairingPreparationWaiters.append(continuation)
      }
      try requireAcceptingPairing()
    }
    try requireAcceptingPairing()
    pairingPreparations = 1
  }

  private func finishPairingPreparation() {
    precondition(pairingPreparations > 0)
    pairingPreparations -= 1
    guard pairingPreparations == 0 else { return }
    let waiters = pairingPreparationWaiters
    pairingPreparationWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters {
      waiter.resume()
    }
  }

  private func requireActivePairingWorker() throws {
    try Task.checkCancellation()
    guard !shuttingDown else { throw CancellationError() }
  }

  private func cancelPairingWorker(_ workerID: UUID) async {
    let task = pairingTasks[workerID]
    task?.cancel()
    await shutdownTransport(for: workerID)
    await task?.value
    pairingTasks.removeValue(forKey: workerID)
  }

  private func cancelAndJoinAllPairingWorkers() async {
    let workerIDs = Set(pairingTasks.keys)
      .union(pairingTransports.keys)
      .union(pairingTransportShutdownTasks.keys)
    await withTaskGroup(of: Void.self) { group in
      for workerID in workerIDs {
        group.addTask {
          await self.cancelPairingWorker(workerID)
        }
      }
    }
  }

  private func shutdownTransport(for workerID: UUID) async {
    if let task = pairingTransportShutdownTasks[workerID] {
      await task.value
      pairingTransportShutdownTasks.removeValue(forKey: workerID)
      return
    }
    guard let transport = pairingTransports.removeValue(forKey: workerID) else { return }
    let task = Task {
      await transport.shutdown()
    }
    pairingTransportShutdownTasks[workerID] = task
    await task.value
    pairingTransportShutdownTasks.removeValue(forKey: workerID)
  }

  func debugActivePairingLifecycleCounts() -> (workers: Int, transports: Int) {
    (
      pairingTasks.count,
      pairingTransports.count + pairingTransportShutdownTasks.count
    )
  }

  private func recoverDurablePairingState() async throws {
    try await pairedMachineStore.resumeIncompleteCleanups()
    try await pairedMachineStore.recoverPendingPairings(
      nowMilliseconds: clock.nowMilliseconds()
    )
  }

  private func resumePendingPairing(
    _ pendingStore: PendingPairingStore,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    nowMilliseconds: UInt64
  ) async throws -> PendingPairingPrepareResult? {
    do {
      return try await pendingStore.resumeIfPresent(
        invite: invite,
        authorizationRequest: authorization,
        nowMilliseconds: nowMilliseconds
      )
    } catch PairRequestCryptoError.expired {
      try await recoverDurablePairingState()
      throw SessionSourceFailure(code: .pairInviteExpired)
    }
  }

  private func runAttemptWithDeadline(
    transport: any RelayPairingTransportSession,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    prepared: PreparedPendingPairingV1,
    pendingStore: PendingPairingStore,
    continuation: AsyncThrowingStream<PairingProgress, Error>.Continuation,
    allowPastInviteExpiry: Bool
  ) async throws -> ProductionRelayPairingAttemptResult {
    let deadline: UInt64
    if allowPastInviteExpiry {
      deadline = attemptDeadlineMilliseconds
    } else {
      let now = clock.nowMilliseconds()
      guard now < invite.expiresAtMilliseconds else {
        throw SessionSourceFailure(code: .pairInviteExpired)
      }
      deadline = min(
        attemptDeadlineMilliseconds,
        invite.expiresAtMilliseconds - now
      )
    }
    return try await withThrowingTaskGroup(
      of: ProductionRelayPairingAttemptResult.self
    ) { group in
      group.addTask {
        try await self.runAttempt(
          transport: transport,
          invite: invite,
          authorization: authorization,
          prepared: prepared,
          pendingStore: pendingStore,
          continuation: continuation
        )
      }
      group.addTask {
        try await Task.sleep(
          for: .milliseconds(Int64(clamping: deadline))
        )
        throw RelayTransportError.connectionTimedOut
      }
      guard let result = try await group.next() else {
        throw RelayTransportError.connectionTimedOut
      }
      group.cancelAll()
      return result
    }
  }

  private func runAttempt(
    transport: any RelayPairingTransportSession,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    prepared: PreparedPendingPairingV1,
    pendingStore: PendingPairingStore,
    continuation: AsyncThrowingStream<PairingProgress, Error>.Continuation
  ) async throws -> ProductionRelayPairingAttemptResult {
    var activePrepared = prepared
    let generation = try await transport.connect()
    try requireActivePairingWorker()
    let stream = await transport.incomingFrames(on: generation)
    try requireActivePairingWorker()
    let pairingHello = RelayV2OutboundFrame.control(
      .pairingHello(
        relayServerId: invite.relayServerID,
        pairRoute: invite.pairRoute
      )
    )
    try await transport.send(
      pairingHello,
      on: generation
    )

    var authenticated = false
    var announcedPending = false
    var promoted = try await promotedRecordIfPresent(prepared: activePrepared)
    for try await received in stream {
      try requireActivePairingWorker()
      guard received.generation == generation else {
        throw SessionSourceFailure(code: .securityError)
      }
      if !authenticated {
        switch received.frame.body {
        case .authenticated:
          authenticated = true
          if case .responsePrepared(let response) = activePrepared.record.phase,
            promoted != nil
          {
            try await sendPersistedReceipt(
              response,
              invite: invite,
              transport: transport,
              generation: generation
            )
          } else {
            try await transport.send(.pairData(activePrepared.requestCarrier), on: generation)
          }
        case .error(let failure):
          throw ProductionRelayPairingRemoteFailure(failure: failure)
        case .serverRestarting(let deadline):
          throw RelayTransportError.serverRestarting(
            drainDeadlineMilliseconds: deadline
          )
        case .ping, .pong:
          break
        case .pairRouteClosed(let pairRoute, _):
          guard pairRoute == invite.pairRoute else {
            throw SessionSourceFailure(code: .securityError)
          }
          throw RelayTransportError.connectionClosed
        case .hello, .challenge, .authenticate, .openPairRoute, .pairRouteOpened,
          .pairData, .closePairRoute, .registerStream, .publish, .subscribe,
          .unsubscribe, .ack, .gap, .replayComplete, .send, .reply,
          .installGrant, .grantCommitted, .revokeDevice, .revocationCommitted,
          .retireMachine, .retirementCommitted, .pairingHello, .routeAccepted:
          throw SessionSourceFailure(code: .securityError)
        }
        continue
      }
      switch received.frame.body {
      case .routeAccepted(.pairFrame(let pairRoute)):
        guard pairRoute == invite.pairRoute else {
          throw SessionSourceFailure(code: .securityError)
        }

      case .pairData(let pairRoute, let sealedBlob):
        guard pairRoute == invite.pairRoute else {
          throw SessionSourceFailure(code: .securityError)
        }
        switch try decodePayload(
          sealedBlob,
          invite: invite,
          authorization: authorization,
          prepared: activePrepared
        ) {
        case .pending:
          guard promoted == nil else {
            throw SessionSourceFailure(code: .securityError)
          }
          if !announcedPending {
            announcedPending = true
            _ = continuation.yield(.waitingForLocalConfirmation)
          }

        case .terminal(let outcome):
          try requireActivePairingWorker()
          // promotion cleanup 与 pending terminal 是一个不可中断的 durable 收敛单元；
          // cancellation 只允许落在单元两侧，不能制造已删 material 的 responsePrepared。
          if case .responsePrepared(let response) = activePrepared.record.phase {
            if case .committed? = try await pairedMachineStore.pairingPromotionState(
              prepared: activePrepared,
              response: response
            ) {
              throw SessionSourceFailure(code: .securityError)
            }
            try await pairedMachineStore.abortPairingPromotion(
              prepared: activePrepared,
              response: response
            )
            promoted = nil
          } else if let promoted {
            try await pairedMachineStore.deleteExact(promoted)
          }
          try await pendingStore.stageTerminal(outcome, for: activePrepared)
          try requireActivePairingWorker()
          return .terminal(outcome)

        case .response(let verified):
          try requireActivePairingWorker()
          let staged = try await stageResponse(
            verified,
            prepared: prepared,
            pendingStore: pendingStore
          )
          let promotion = try await pairedMachineStore.makePairingPromotion(
            verified: verified,
            prepared: staged.prepared,
            response: staged.response
          )
          activePrepared = staged.prepared
          _ = try await pairedMachineStore.stagePairingPromotion(promotion)
          try requireActivePairingWorker()
          if let promoted, promoted != promotion.record {
            throw SessionSourceFailure(code: .securityError)
          }
          try await sendPersistedReceipt(
            staged.response,
            invite: invite,
            transport: transport,
            generation: generation
          )
          promoted = promotion.record

        case .persistedResponseReplay:
          try requireActivePairingWorker()
          guard case .responsePrepared(let response) = activePrepared.record.phase,
            promoted != nil
          else {
            throw SessionSourceFailure(code: .securityError)
          }
          try await sendPersistedReceipt(
            response,
            invite: invite,
            transport: transport,
            generation: generation
          )
        }

      case .pairRouteClosed(let pairRoute, let outcome):
        try requireActivePairingWorker()
        guard pairRoute == invite.pairRoute,
          outcome == .closed || outcome == .alreadyAbsent,
          let promoted,
          case .responsePrepared(let response) = activePrepared.record.phase
        else {
          throw SessionSourceFailure(code: .securityError)
        }
        // committed visibility 与 pending completed 同样连续收敛；若前者成功，必须先
        // 完成后者再观察 cancellation，避免把普通 supersession 变成恢复切点。
        let committed = try await pairedMachineStore.finalizePairingPromotion(
          prepared: activePrepared,
          response: response
        )
        guard committed == promoted else {
          throw SessionSourceFailure(code: .securityError)
        }
        try await pendingStore.markCompleted(for: activePrepared)
        try requireActivePairingWorker()
        try? await transport.close(generation: generation)
        return .paired(committed.pairedMachine)

      case .error(let failure):
        throw ProductionRelayPairingRemoteFailure(failure: failure)

      case .serverRestarting(let deadline):
        throw RelayTransportError.serverRestarting(
          drainDeadlineMilliseconds: deadline
        )

      case .authenticated, .ping, .pong:
        break

      case .hello, .challenge, .authenticate, .openPairRoute, .pairRouteOpened,
        .closePairRoute, .registerStream, .publish, .subscribe, .unsubscribe,
        .ack, .gap, .replayComplete, .send, .reply, .installGrant,
        .grantCommitted, .revokeDevice, .revocationCommitted, .retireMachine,
        .retirementCommitted, .pairingHello, .routeAccepted:
        throw SessionSourceFailure(code: .securityError)
      }
    }
    throw RelayTransportError.connectionClosed
  }

  private func decodePayload(
    _ canonicalBytes: Data,
    invite: PairInviteV1,
    authorization: AuthorizationRequestV1,
    prepared: PreparedPendingPairingV1
  ) throws -> ProductionRelayPairingPayload {
    let now = clock.nowMilliseconds()
    if (try? PairResponseCanonicalCodec.decode(canonicalBytes)) != nil {
      if case .responsePrepared(let response) = prepared.record.phase,
        CanonicalCodec.sha256(canonicalBytes) == response.responseHash
      {
        return .persistedResponseReplay
      }
      return .response(
        try PairResponseCrypto.openVerified(
          canonicalResponse: canonicalBytes,
          invite: invite,
          authorizationRequest: authorization,
          requestHash: prepared.record.requestHash,
          deviceSigningKey: prepared.deviceSigningKey,
          deviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey,
          nowMilliseconds: now
        )
      )
    }
    _ = try PairTerminalEnvelopeCodec.decode(canonicalBytes)
    if (try? PairResponseCrypto.openPairPending(
      canonicalEnvelope: canonicalBytes,
      invite: invite,
      requestHash: prepared.record.requestHash,
      deviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey,
      nowMilliseconds: now
    )) != nil {
      return .pending
    }
    let terminal = try PairTerminalVerifier.openVerifiedFromInvite(
      canonicalEnvelope: canonicalBytes,
      recipientDeviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey,
      invite: invite,
      requestHash: prepared.record.requestHash,
      nowMilliseconds: now
    )
    return .terminal(terminal.outcome)
  }

  private func sendPersistedReceipt(
    _ response: PendingPairingResponseStateV1,
    invite: PairInviteV1,
    transport: any RelayPairingTransportSession,
    generation: RelayTransportGeneration
  ) async throws {
    let receipt = try OpaquePairResponseReceivedCarrier(
      pairRoute: invite.pairRoute,
      canonicalBytes: response.receiptCarrier
    )
    try await transport.send(.pairData(receipt), on: generation)
  }

  private func stageResponse(
    _ verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    pendingStore: PendingPairingStore
  ) async throws -> (
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) {
    if case .responsePrepared(let existing) = prepared.record.phase {
      try validate(existing, verified: verified)
      return (prepared, existing)
    }
    let candidate = try await pairedMachineStore.makePendingPairingResponseState(
      verified: verified,
      prepared: prepared,
      nowMilliseconds: clock.nowMilliseconds()
    )
    do {
      let staged = try await pendingStore.stageResponse(candidate, for: prepared)
      return (staged, candidate)
    } catch PendingPairingStoreError.immutableConflict {
      guard
        case .active(let winner)? = try await pendingStore.resumeIfPresent(
          invite: prepared.invite,
          authorizationRequest: prepared.authorizationRequest,
          nowMilliseconds: clock.nowMilliseconds()
        ), case .responsePrepared(let response) = winner.record.phase
      else {
        throw PendingPairingStoreError.immutableConflict
      }
      try validate(response, verified: verified)
      return (winner, response)
    }
  }

  private func validate(
    _ response: PendingPairingResponseStateV1,
    verified: VerifiedPendingPairResponseV1
  ) throws {
    guard response.responseHash == verified.responseHash,
      response.machineRoute == verified.info.machineRoute,
      response.deviceRoute == verified.info.deviceRoute
    else {
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private func existingPairedMachine(
    for invite: PairInviteV1
  ) async throws -> PairedMachine? {
    let records = try await pairedMachineStore.list().filter {
      $0.machineRootFingerprint == invite.machineRootFingerprint
    }
    guard records.count <= 1 else {
      throw SessionSourceFailure(code: .securityError)
    }
    guard let record = records.first else { return nil }
    guard record.relayServerID == invite.relayServerID,
      record.relayURL.absoluteString == invite.wssURL
    else {
      throw SessionSourceFailure(code: .securityError)
    }
    return record.pairedMachine
  }

  private func promotedRecordIfPresent(
    prepared: PreparedPendingPairingV1
  ) async throws -> StoredPairedMachineRecordV1? {
    guard case .responsePrepared(let response) = prepared.record.phase else {
      return nil
    }
    return try await pairedMachineStore.pairingPromotionState(
      prepared: prepared,
      response: response
    )?.record
  }

  private func pairedMachine(
    machineRoute: Data
  ) async throws -> PairedMachine? {
    let records = try await pairedMachineStore.list().filter {
      $0.machineRoute == machineRoute
    }
    guard records.count <= 1 else {
      throw SessionSourceFailure(code: .securityError)
    }
    return records.first?.pairedMachine
  }

  private func decodeInvite(
    _ encoded: String,
    enforcingExpiry: Bool
  ) throws -> PairInviteV1 {
    do {
      if enforcingExpiry {
        return try PairInviteV1.decodeURI(
          encoded,
          nowMilliseconds: clock.nowMilliseconds()
        )
      }
      guard encoded.utf8.count <= PairInviteCanonicalCodec.maximumURIBytes,
        !encoded.contains("="),
        encoded.hasPrefix(PairInviteCanonicalCodec.uriPrefix)
      else {
        throw PairRequestCryptoError.invalidEncoding
      }
      let payload = String(encoded.dropFirst(PairInviteCanonicalCodec.uriPrefix.count))
      var base64 = payload.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
      let remainder = base64.utf8.count % 4
      guard remainder != 1 else { throw PairRequestCryptoError.invalidEncoding }
      if remainder > 0 {
        base64.append(String(repeating: "=", count: 4 - remainder))
      }
      guard let bytes = Data(base64Encoded: base64) else {
        throw PairRequestCryptoError.invalidEncoding
      }
      let canonicalPayload = bytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
      guard canonicalPayload == payload else {
        throw PairRequestCryptoError.invalidEncoding
      }
      let invite = try PairInviteCanonicalCodec.decode(bytes)
      try invite.validateStatic()
      return invite
    } catch PairRequestCryptoError.expired {
      throw SessionSourceFailure(code: .pairInviteExpired)
    } catch {
      throw SessionSourceFailure(code: .invalidPairInvite)
    }
  }

  private func pairingPromotionStateIfPresent(
    prepared: PreparedPendingPairingV1
  ) async throws -> DurablePairingPromotionState? {
    guard case .responsePrepared(let response) = prepared.record.phase else {
      return nil
    }
    return try await pairedMachineStore.pairingPromotionState(
      prepared: prepared,
      response: response
    )
  }

  private func makeDefaultAuthorization() throws -> AuthorizationRequestV1 {
    do {
      return try AuthorizationRequestV1(
        deviceDisplayName: deviceDisplayName,
        capabilities: AuthorizationCapabilityV1.allCases,
        permissions: AuthorizationPermissionV1.allCases
      )
    } catch {
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private static func progress(
    for outcome: PairTerminalOutcomeV1
  ) -> PairingProgress {
    switch outcome {
    case .canceled: .canceled
    case .expired: .expired
    }
  }

  private static func finishedStream(
    _ progress: PairingProgress
  ) -> AsyncThrowingStream<PairingProgress, Error> {
    AsyncThrowingStream { continuation in
      _ = continuation.yield(progress)
      continuation.finish()
    }
  }

  private static func isRetryableTransportFailure(_ error: Error) -> Bool {
    guard let error = error as? RelayTransportError else { return false }
    switch error {
    case .connectionFailed, .connectionClosed, .connectionTimedOut,
      .connectionCleanupStalled, .peerClosed, .notConnected, .staleGeneration,
      .outcomeUnknown, .serverRestarting, .outgoingBackpressure:
      return true
    case .invalidEndpoint, .incomingAlreadyClaimed, .handshakeFrameReserved,
      .generationExhausted, .canceled, .textMessage, .frameTooLarge,
      .invalidFrame, .unsupportedVersion, .incomingBackpressure, .tls:
      return false
    }
  }

  private static func reconnectReason(_ error: Error) -> RelayReconnectReason {
    if case RelayTransportError.serverRestarting(let deadline) = error {
      return .serverRestarting(drainDeadlineMilliseconds: deadline)
    }
    return .transportFailure
  }

  private static func publicError(_ error: Error) -> Error {
    if let failure = error as? SessionSourceFailure { return failure }
    if error is ProductionRelayPairingRemoteFailure {
      return SessionSourceFailure(code: .transportUnavailable)
    }
    if let transport = error as? RelayTransportError {
      switch transport {
      case .unsupportedVersion:
        return SessionSourceFailure(code: .incompatible)
      case .invalidFrame, .textMessage, .frameTooLarge, .incomingBackpressure,
        .handshakeFrameReserved, .incomingAlreadyClaimed, .tls:
        return SessionSourceFailure(code: .securityError)
      case .canceled:
        return CancellationError()
      default:
        return SessionSourceFailure(code: .transportUnavailable)
      }
    }
    if error is PendingPairingStoreError || error is PairedMachineStoreError
      || error is KeyStoreError || error is CryptoStateStoreError
    {
      return SessionSourceFailure(code: .storageUnavailable)
    }
    return SessionSourceFailure(code: .securityError)
  }
}
