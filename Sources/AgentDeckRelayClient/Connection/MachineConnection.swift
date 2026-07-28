import AgentDeckCore
import AgentDeckSessionSource
import CryptoKit
import Foundation

enum MachineKeySyncPolicy {
  static let deadlineMilliseconds = DeviceKeySyncEpisodeV1.deadlineMilliseconds
}

struct MachineKeySyncEpisodeStatus: Equatable, Sendable {
  let observedRevision: UInt64
  let attempt: UInt8
}

enum MachineInboundDisposition: Equatable, Sendable {
  case applied
  case exactDuplicate
  case staleReplay
}

/// MachineConnection 入站处理的可注入 stage seam。
///
/// `PreparedReduction` 必须只承载在 clone/scratch reducer 上已完整验证的结果；
/// `publish` 是 durable progress 成功后的 nonthrow swap/broadcast，避免 cursor 已提交而
/// 内存 reducer 仍旧的分叉状态。
protocol MachineInboundPipelineStages: Sendable {
  associatedtype PreparedReduction: Sendable

  func verify(
    wireBytes: Data,
    context: OuterContextV1
  ) async throws -> VerifiedSealedBlobV1

  func admitReplay(
    _ verified: VerifiedSealedBlobV1
  ) async throws -> ReplayDisposition

  func open(
    _ verified: VerifiedSealedBlobV1,
    context: OuterContextV1
  ) async throws -> Data

  func decodeRuntime(_ payload: Data) async throws -> RuntimeEnvelopeV2

  func prepareReduction(
    _ envelope: RuntimeEnvelopeV2
  ) async throws -> PreparedReduction

  func commitVerifiedProgress(
    _ verified: VerifiedSealedBlobV1,
    preparedReduction: PreparedReduction
  ) async throws

  func publish(_ preparedReduction: PreparedReduction) async
}

struct MachineInboundPipeline<Stages: MachineInboundPipelineStages>: Sendable {
  private let stages: Stages

  init(stages: Stages) {
    self.stages = stages
  }

  func process(
    wireBytes: Data,
    context: OuterContextV1
  ) async throws -> MachineInboundDisposition {
    let verified = try await stages.verify(
      wireBytes: wireBytes,
      context: context
    )
    let replayDisposition = try await stages.admitReplay(verified)
    if replayDisposition == .stale {
      return .staleReplay
    }

    let plaintext = try await stages.open(verified, context: context)
    let envelope = try await stages.decodeRuntime(plaintext)
    if replayDisposition == .exactDuplicate {
      return .exactDuplicate
    }

    let preparedReduction = try await stages.prepareReduction(envelope)
    try await stages.commitVerifiedProgress(
      verified,
      preparedReduction: preparedReduction
    )
    await stages.publish(preparedReduction)
    return .applied
  }
}

enum MachineConnectionVerifiedIngressOutcome: Sendable {
  case ignored
  case delivery(VerifiedRuntimeDelivery)
  case transportActions([RelayV2OutboundFrame])
  case streamRecoveryRequired(target: VerifiedRuntimeTarget, reason: SessionLagReason)
  case keySyncRequired(observedRevision: UInt64)
  case keySyncAttemptFailed(observedRevision: UInt64)
  case keySyncSucceeded(
    acceptedRevision: UInt64,
    recoveryTargets: [VerifiedRuntimeTarget]
  )
  case revoked
  case incompatible
  case securityError
  case machineOffline
  case relayUnavailable
}

private enum MachineConnectionPostDrainAction: Sendable {
  case keySyncSucceeded(
    acceptedRevision: UInt64,
    recoveryTargets: [VerifiedRuntimeTarget]
  )
}

/// post-auth generation 的唯一 raw-frame consumer seam。
///
/// production 实现必须在 `receive` 内调用 `MachineInboundPipeline`（或处理经过同等
/// root-signature 验证的 terminal/control），并且只能返回 verified delivery 或 typed
/// outcome。raw Relay frame、未验签 sealed blob 与 Runtime plaintext 都不能越过本协议。
protocol MachineConnectionVerifiedIngress: Sendable {
  func resumeFrames(
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope,
    heartbeatIntervalSeconds: UInt16
  ) async throws -> [RelayV2OutboundFrame]

  func receive(
    _ frame: ReceivedRelayFrame,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome

  /// production ingress 从首个 authenticated higher-revision probe 起返回 absolute
  /// KeySync deadline 的剩余时长。`nil` 表示当前 generation 没有未决 KeySync。
  func keySyncDeadlineRemainingMilliseconds(
    scope: TransferAssemblyScope
  ) async throws -> UInt64?

  /// reconnect/cold-open 后把 durable revision/attempt 恢复进 supervisor state；不会
  /// 创建或推进 episode。
  func keySyncEpisodeStatus(
    scope: TransferAssemblyScope
  ) async throws -> MachineKeySyncEpisodeStatus?

  /// absolute timer 到点后的 durable fail-close cut。
  func expireKeySyncEpisode(scope: TransferAssemblyScope) async throws

  func commit(_ delivery: VerifiedRuntimeDelivery) async throws

  func discard(_ delivery: VerifiedRuntimeDelivery) async

  /// delivery 已交给 Source 后等待 exact commit/discard；production ingress 用它把
  /// replay snapshot 与 reducer commit 串行化，禁止下一帧越过未决 durable cut。
  func awaitResolution(_ delivery: VerifiedRuntimeDelivery) async throws

  func prepareDirected(
    envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest

  func prepareSubscription(
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest

  func cancelPrepared(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async

  func awaitDirectedReply(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async throws -> RuntimeReplyV2

  func retireSubscription(
    target: RuntimeSubscriptionTargetV1,
    scope: TransferAssemblyScope
  ) async throws -> MachineSubscriptionRetirement

  /// generation teardown 的线性化点。实现必须同步终止该 scope 的 request/stream owner，
  /// 并解除所有 `awaitResolution` waiter；返回后 `MachineConnection.shutdown()` 才能安全 join。
  func generationEnded(scope: TransferAssemblyScope) async
}

extension MachineConnectionVerifiedIngress {
  func keySyncDeadlineRemainingMilliseconds(
    scope _: TransferAssemblyScope
  ) async throws -> UInt64? {
    nil
  }

  func keySyncEpisodeStatus(
    scope _: TransferAssemblyScope
  ) async throws -> MachineKeySyncEpisodeStatus? {
    nil
  }

  func expireKeySyncEpisode(scope _: TransferAssemblyScope) async throws {}

  func retireSubscription(
    target _: RuntimeSubscriptionTargetV1,
    scope _: TransferAssemblyScope
  ) async throws -> MachineSubscriptionRetirement {
    throw SessionSourceFailure(code: .securityError)
  }

  func prepareDirected(
    envelope _: RuntimeEnvelopeV2,
    contract _: MachineDirectedReplyContract,
    scope _: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    throw MachineConnectionSupervisorFailure.securityError
  }

  func prepareSubscription(
    target _: RuntimeSubscriptionTargetV1,
    after _: RuntimeStreamCursorV1,
    requestID _: RuntimeMessageID,
    scope _: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    throw MachineConnectionSupervisorFailure.securityError
  }

  func cancelPrepared(
    _: MachinePreparedOutboundRequestToken,
    scope _: TransferAssemblyScope
  ) async {}

  func awaitDirectedReply(
    _: MachinePreparedOutboundRequestToken,
    scope _: TransferAssemblyScope
  ) async throws -> RuntimeReplyV2 {
    throw MachineConnectionSupervisorFailure.securityError
  }
}

struct MachineSubscriptionRetirement: Sendable {
  let outerUnsubscribe: RelayV2OutboundFrame?
  let requiresGenerationRollover: Bool
}

protocol MachineConnectionTransport: Actor {
  func connect() async throws -> RelayTransportGeneration
  func incomingFrames(on generation: RelayTransportGeneration)
    -> AsyncThrowingStream<ReceivedRelayFrame, any Error>
  func send(
    _ frame: RelayV2OutboundFrame,
    on generation: RelayTransportGeneration
  ) async throws
  func close(generation: RelayTransportGeneration) async throws
  func shutdown() async
}

extension RelayWebSocketTransport: MachineConnectionTransport {}

typealias MachineConnectionTransportBuilder =
  @Sendable () async throws -> any MachineConnectionTransport

protocol MachineConnectionAuthenticating: Sendable {
  func authenticationFrame(
    challenge: RelayDeviceAuthenticationChallenge
  ) async throws -> RelayV2OutboundFrame
}

struct PairedDeviceConnectionAuthenticator:
  MachineConnectionAuthenticating
{
  private let expectedRelayServerID: Data
  private let credential: VerifiedRelayGrantCredential
  private let signingKey: Curve25519.Signing.PrivateKey

  init(
    expectedRelayServerID: Data,
    credential: VerifiedRelayGrantCredential,
    signingKey: Curve25519.Signing.PrivateKey
  ) throws {
    let canonical = try RelayGrantCanonicalCodec.encode(credential.grant)
    guard expectedRelayServerID.count == 16,
      expectedRelayServerID.contains(where: { $0 != 0 }),
      credential.grant.deviceSignPubkey == signingKey.publicKey.rawRepresentation,
      credential.canonicalBytes == canonical
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    self.expectedRelayServerID = expectedRelayServerID
    self.credential = credential
    self.signingKey = signingKey
  }

  func authenticationFrame(
    challenge: RelayDeviceAuthenticationChallenge
  ) async throws -> RelayV2OutboundFrame {
    guard challenge.relayServerID == expectedRelayServerID else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    let transcript = try AuthenticationTranscriptV1.encode(
      challenge: challenge,
      grant: credential.grant
    )
    let signature = try signingKey.signature(for: transcript)
    guard signature.count == 64, signature.contains(where: { $0 != 0 }) else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    return .control(
      .authenticate(
        proof: .device(relayGrant: credential.grant),
        signature: signature
      )
    )
  }
}

enum MachineConnectionSupervisorFailure: Error, Equatable, Sendable {
  case handshakeTimedOut
  case handshakeRejected
  case relayFailure(code: String)
  case transport(RelayTransportError)
  case machineOffline
  case relayUnavailable
  case revoked
  case incompatible
  case securityError
  case terminalAlreadyPublished
}

protocol MachineConnectionReconnectSleeping: Sendable {
  func sleep(milliseconds: UInt64) async throws
}

private struct ContinuousMachineConnectionReconnectSleeper:
  MachineConnectionReconnectSleeping
{
  func sleep(milliseconds: UInt64) async throws {
    try await Task.sleep(for: .milliseconds(Int64(clamping: milliseconds)))
  }
}

protocol MachineConnectionClock: Sendable {
  func nowMilliseconds() -> UInt64
}

private struct WallMachineConnectionClock: MachineConnectionClock {
  func nowMilliseconds() -> UInt64 {
    UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
  }
}

protocol MachineConnectionJitterSource: Sendable {
  func nextUnitInterval() -> Double
}

private struct SystemMachineConnectionJitterSource:
  MachineConnectionJitterSource
{
  func nextUnitInterval() -> Double {
    var generator = SystemRandomNumberGenerator()
    return Double.random(in: 0.0...1.0, using: &generator)
  }
}

private enum MachineConnectionReconnectDecision {
  case reconnect(
    event: MachineConnectionEvent,
    policyReason: RelayReconnectReason
  )
  case terminal(MachineConnectionEvent)
  case stop
}

/// 单台 paired machine 的 production connection owner。
///
/// owner 每轮构造 fresh pinned WSS transport，严格执行
/// `Challenge -> Authenticate -> Authenticated`，随后把 raw frame 交给唯一 verified
/// ingress。每个 generation 都拥有独立 transfer scope；断线、重连、取消与 shutdown
/// 均先关闭 exact generation，再释放 assembler 的 process-global 预算。
actor MachineConnection: MachineConnectionUpdateSource, MachineRuntimeRequestEndpoint {
  static let handshakeTimeoutMilliseconds: UInt64 = 10_000

  nonisolated private let machineIDValue: String
  private let grantSerial: UInt64?
  private let updateChannel = MachineConnectionUpdateChannel<MachineConnectionUpdate>(
    capacity: 512
  )
  private let transportBuilder: MachineConnectionTransportBuilder
  private let authenticator: any MachineConnectionAuthenticating
  private let verifiedIngress: any MachineConnectionVerifiedIngress
  private let transferBudgetCoordinator: TransferAssemblyBudgetCoordinator
  private let reconnectPolicy: RelayReconnectPolicy
  private let reconnectSleeper: any MachineConnectionReconnectSleeping
  private let clock: any MachineConnectionClock
  private let jitterSource: any MachineConnectionJitterSource
  private let handshakeDeadlineMilliseconds: UInt64
  private var stateMachine: MachineConnectionStateMachine
  private var started = false
  private var stopping = false
  private var supervisorTask: Task<Void, Never>?
  private var activeTransport: (any MachineConnectionTransport)?
  private var activeGeneration: RelayTransportGeneration?
  private var activeScope: TransferAssemblyScope?
  private var businessReadyScope: TransferAssemblyScope?
  private var keySyncDeadlineTask: Task<Void, Never>?
  private var keySyncDeadlineScope: TransferAssemblyScope?
  private var keySyncDeadlineToken: UUID?
  private var keySyncDeadlineForcedCloseScope: TransferAssemblyScope?

  private init(
    material: PairedMachineConnectionMaterial,
    maximumKeySyncAttempts: UInt8 = 3,
    verifiedIngress: any MachineConnectionVerifiedIngress
  ) {
    machineIDValue = material.record.machineID
    grantSerial = material.relayGrant.grant.grantSerial
    var transportBuilder: MachineConnectionTransportBuilder = {
      throw MachineConnectionSupervisorFailure.securityError
    }
    var authenticator: any MachineConnectionAuthenticating =
      RejectingMachineConnectionAuthenticator()
    do {
      let endpoint = try RelayTransportEndpoint(
        origin: material.record.relayURL,
        route: .principal
      )
      let nextPin =
        material.record.nextSPKIPin == material.record.currentSPKIPin
        ? nil
        : material.record.nextSPKIPin
      let tlsPolicy = try RelayTLSPolicy.pinnedSPKI(
        current: material.record.currentSPKIPin,
        next: nextPin
      )
      let configuration = RelayTransportConfiguration(
        endpoint: endpoint,
        tlsPolicy: tlsPolicy
      )
      transportBuilder = {
        RelayWebSocketTransport(configuration: configuration)
      }
      authenticator = try PairedDeviceConnectionAuthenticator(
        expectedRelayServerID: material.record.relayServerID,
        credential: material.relayGrant,
        signingKey: material.deviceSigningKey
      )
    } catch {}
    self.transportBuilder = transportBuilder
    self.authenticator = authenticator
    self.verifiedIngress = verifiedIngress
    transferBudgetCoordinator = .shared
    reconnectPolicy = RelayReconnectPolicy()
    reconnectSleeper = ContinuousMachineConnectionReconnectSleeper()
    clock = WallMachineConnectionClock()
    jitterSource = SystemMachineConnectionJitterSource()
    handshakeDeadlineMilliseconds = Self.handshakeTimeoutMilliseconds
    stateMachine = MachineConnectionStateMachine(
      maximumKeySyncAttempts: maximumKeySyncAttempts
    )
  }

  static func open(
    material: PairedMachineConnectionMaterial,
    maximumKeySyncAttempts: UInt8 = 3
  ) async throws -> MachineConnection {
    let ingress = try await ProductionMachineConnectionVerifiedIngress.open(
      material: material,
      expectedConversationRoutes: try expectedConversationRoutes(material)
    )
    return MachineConnection(
      material: material,
      maximumKeySyncAttempts: maximumKeySyncAttempts,
      verifiedIngress: ingress
    )
  }

  init(
    machineID: String,
    grantSerial: UInt64? = nil,
    transportBuilder: @escaping MachineConnectionTransportBuilder,
    authenticator: any MachineConnectionAuthenticating,
    verifiedIngress: any MachineConnectionVerifiedIngress,
    transferBudgetCoordinator: TransferAssemblyBudgetCoordinator,
    reconnectPolicy: RelayReconnectPolicy = RelayReconnectPolicy(),
    reconnectSleeper: any MachineConnectionReconnectSleeping =
      ContinuousMachineConnectionReconnectSleeper(),
    clock: any MachineConnectionClock = WallMachineConnectionClock(),
    jitterSource: any MachineConnectionJitterSource =
      SystemMachineConnectionJitterSource(),
    handshakeDeadlineMilliseconds: UInt64 =
      MachineConnection.handshakeTimeoutMilliseconds,
    maximumKeySyncAttempts: UInt8 = 3
  ) {
    precondition(!machineID.isEmpty)
    precondition(handshakeDeadlineMilliseconds > 0)
    machineIDValue = machineID
    self.grantSerial = grantSerial
    self.transportBuilder = transportBuilder
    self.authenticator = authenticator
    self.verifiedIngress = verifiedIngress
    self.transferBudgetCoordinator = transferBudgetCoordinator
    self.reconnectPolicy = reconnectPolicy
    self.reconnectSleeper = reconnectSleeper
    self.clock = clock
    self.jitterSource = jitterSource
    self.handshakeDeadlineMilliseconds = handshakeDeadlineMilliseconds
    stateMachine = MachineConnectionStateMachine(
      maximumKeySyncAttempts: maximumKeySyncAttempts
    )
  }

  nonisolated var machineID: String {
    machineIDValue
  }

  func updates() async -> AsyncStream<MachineConnectionUpdate> {
    await updateChannel.stream()
  }

  func commit(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard delivery.machineID == machineIDValue else {
      throw SessionSourceFailure(code: .securityError)
    }
    try await verifiedIngress.commit(delivery)
  }

  func discard(_ delivery: VerifiedRuntimeDelivery) async {
    guard delivery.machineID == machineIDValue else { return }
    await verifiedIngress.discard(delivery)
  }

  /// production composition 的显式 lifecycle 边界；重复 start 不建立第二条 owner task。
  func start() async {
    guard !started else { return }
    started = true
    let result = await updateChannel.send(
      .connectionState(stateMachine.connectionState)
    )
    await failClosedIfProducerInvariantBroke(result)
    guard !stateMachine.shouldFinishObservations else { return }
    supervisorTask = Task { [weak self] in
      await self?.supervise()
    }
  }

  /// foreground owner 的最终 stop。先 cancel 并关闭观察流，以解除满队列上的 pending
  /// producer；再以 `generationEnded` 强制解除未决 delivery resolution，最后 join owner task。
  func shutdown() async {
    guard started, !stopping else { return }
    stopping = true
    supervisorTask?.cancel()
    await updateChannel.finish()
    await teardownActiveGeneration()
    let task = supervisorTask
    supervisorTask = nil
    await task?.value
  }

  func currentConnectionState() -> SessionConnectionState {
    stateMachine.connectionState
  }

  func readinessSnapshot() -> MachineConnectionReadinessSnapshot {
    MachineConnectionReadinessSnapshot(
      connectionScope: activeScope,
      readyScope: businessReadyScope
    )
  }

  func debugPendingUpdateSendCount() async -> Int {
    await updateChannel.debugPendingSendCount
  }

  func requireOnlineGeneration() throws -> RelayTransportGeneration {
    try stateMachine.requireOnlineGeneration()
  }

  func expectedGrantSerial() async throws -> UInt64 {
    guard let grantSerial, grantSerial > 0 else {
      throw SessionSourceFailure(code: .securityError)
    }
    return grantSerial
  }

  func beginSubscription(
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) async throws {
    let capture = try activeEndpointCapture()
    let prepared: MachinePreparedOutboundRequest
    do {
      prepared = try await verifiedIngress.prepareSubscription(
        target: target,
        after: after,
        requestID: requestID,
        scope: capture.scope
      )
    } catch {
      throw Self.endpointError(error)
    }
    guard !Task.isCancelled, endpointCaptureIsCurrent(capture) else {
      await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
      if Task.isCancelled { throw CancellationError() }
      throw SessionSourceFailure(code: .transportUnavailable)
    }
    do {
      try await capture.transport.send(prepared.frame, on: capture.generation)
    } catch {
      await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
      throw Self.endpointError(error)
    }
  }

  func endSubscription(
    target: RuntimeSubscriptionTargetV1,
    requestID: RuntimeMessageID
  ) async throws {
    let capture = try activeEndpointCapture()
    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: requestID,
      body: .request(.unsubscribe(target: target))
    )
    do {
      let reply = try await performDirectedRequest(
        envelope,
        contract: .unsubscribe,
        capture: capture
      )
      guard case .subscription(.unsubscribed) = reply else {
        throw SessionSourceFailure(code: .commandRejected)
      }
      let retirement = try await verifiedIngress.retireSubscription(
        target: target,
        scope: capture.scope
      )
      guard !Task.isCancelled, endpointCaptureIsCurrent(capture) else {
        if Task.isCancelled { throw CancellationError() }
        throw SessionSourceFailure(code: .transportUnavailable)
      }
      if let frame = retirement.outerUnsubscribe {
        try await capture.transport.send(frame, on: capture.generation)
      }
      if retirement.requiresGenerationRollover {
        await teardownActiveGeneration(expectedScope: capture.scope)
      }
    } catch {
      await teardownActiveGeneration(expectedScope: capture.scope)
      throw Self.endpointError(error)
    }
  }

  func sendDirectedRequest(
    _ envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract
  ) async throws -> RuntimeReplyV2 {
    let capture = try activeEndpointCapture()
    do {
      return try await performDirectedRequest(
        envelope,
        contract: contract,
        capture: capture
      )
    } catch {
      throw Self.endpointError(error)
    }
  }

  private func performDirectedRequest(
    _ envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract,
    capture: ActiveEndpointCapture
  ) async throws -> RuntimeReplyV2 {
    let prepared: MachinePreparedOutboundRequest
    do {
      prepared = try await verifiedIngress.prepareDirected(
        envelope: envelope,
        contract: contract,
        scope: capture.scope
      )
    } catch { throw error }
    guard !Task.isCancelled, endpointCaptureIsCurrent(capture) else {
      await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
      if Task.isCancelled { throw CancellationError() }
      throw SessionSourceFailure(code: .transportUnavailable)
    }
    do {
      try await capture.transport.send(prepared.frame, on: capture.generation)
    } catch {
      await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
      throw error
    }

    do {
      return try await withTaskCancellationHandler {
        try await verifiedIngress.awaitDirectedReply(
          prepared.token,
          scope: capture.scope
        )
      } onCancel: {
        Task {
          await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
        }
      }
    } catch {
      await verifiedIngress.cancelPrepared(prepared.token, scope: capture.scope)
      throw error
    }
  }

  func handle(_ event: MachineConnectionEvent) async {
    stateMachine.handle(event)
    let result = await updateChannel.send(
      .connectionState(stateMachine.connectionState)
    )
    await failClosedIfProducerInvariantBroke(result)
    if stateMachine.shouldFinishObservations {
      await updateChannel.finish()
    }
  }

  func publishVerifiedDelivery(
    _ delivery: VerifiedRuntimeDelivery
  ) async throws {
    _ = try stateMachine.requireOnlineGeneration()
    guard delivery.machineID == machineIDValue else {
      throw SessionSourceFailure(code: .securityError)
    }
    let result = await updateChannel.send(.delivery(delivery))
    switch result {
    case .sent:
      return
    case .closed:
      throw SessionSourceFailure(code: .transportUnavailable)
    case .producerInvariantViolation:
      stateMachine.handle(.securityError)
      await updateChannel.fail(
        finalElement: .connectionState(.securityError)
      )
      throw SessionSourceFailure(code: .securityError)
    }
  }

  private func supervise() async {
    var reconnectAttempt: UInt32 = 0
    while !Task.isCancelled, !stopping, !stateMachine.shouldFinishObservations {
      var attemptTransport: (any MachineConnectionTransport)?
      var attemptScope: TransferAssemblyScope?
      do {
        let transport = try await transportBuilder()
        attemptTransport = transport
        let generation = try await transport.connect()
        guard !Task.isCancelled, !stopping else {
          try? await transport.close(generation: generation)
          await transport.shutdown()
          return
        }

        let scope = TransferAssemblyScope(
          connectionID: UUID(),
          generation: generation
        )
        attemptScope = scope
        activeTransport = transport
        activeGeneration = generation
        activeScope = scope
        businessReadyScope = nil

        let incoming = await transport.incomingFrames(on: generation)
        let heartbeat = try await Self.authenticate(
          incoming: incoming,
          transport: transport,
          generation: generation,
          authenticator: authenticator,
          verifiedIngress: verifiedIngress,
          scope: scope,
          timeoutMilliseconds: handshakeDeadlineMilliseconds
        )
        let resumeFrames = try await verifiedIngress.resumeFrames(
          generation: generation,
          scope: scope,
          heartbeatIntervalSeconds: heartbeat
        )
        for frame in resumeFrames {
          try await transport.send(frame, on: generation)
        }
        let resumedKeySync = try await verifiedIngress.keySyncEpisodeStatus(scope: scope)
        try await synchronizeKeySyncDeadline(scope: scope)
        await publishConnectionScope(scope)
        await handle(.connected(generation: generation))
        if let resumedKeySync {
          await handle(
            .keySyncResumed(
              observedRevision: resumedKeySync.observedRevision,
              attempt: resumedKeySync.attempt
            ))
          guard !stateMachine.shouldFinishObservations else {
            throw MachineConnectionSupervisorFailure.terminalAlreadyPublished
          }
        } else {
          await publishBusinessReady(scope)
        }
        reconnectAttempt = 0
        try await readAuthenticatedFrames(
          incoming,
          generation: generation,
          scope: scope
        )
        throw MachineConnectionSupervisorFailure.transport(.connectionClosed)
      } catch {
        if let scope = attemptScope {
          await teardownActiveGeneration(expectedScope: scope)
        } else {
          await attemptTransport?.shutdown()
        }
        guard !Task.isCancelled, !stopping else { return }

        let decision = reconnectDecision(for: error)
        switch decision {
        case .stop:
          return
        case .terminal(let event):
          await handle(event)
          return
        case .reconnect(let event, let policyReason):
          await handle(event)
          guard !stateMachine.shouldFinishObservations else { return }
          do {
            let delay = try reconnectPolicy.delayMilliseconds(
              forAttempt: reconnectAttempt,
              reason: policyReason,
              nowMilliseconds: clock.nowMilliseconds(),
              jitterUnitInterval: jitterSource.nextUnitInterval()
            )
            let next = reconnectAttempt.addingReportingOverflow(1)
            reconnectAttempt = next.overflow ? UInt32.max : next.partialValue
            try await reconnectSleeper.sleep(milliseconds: delay)
          } catch {
            guard !Task.isCancelled, !stopping else { return }
            await handle(.securityError)
            return
          }
        }
      }
    }
  }

  private static func authenticate(
    incoming: AsyncThrowingStream<ReceivedRelayFrame, any Error>,
    transport: any MachineConnectionTransport,
    generation: RelayTransportGeneration,
    authenticator: any MachineConnectionAuthenticating,
    verifiedIngress: any MachineConnectionVerifiedIngress,
    scope: TransferAssemblyScope,
    timeoutMilliseconds: UInt64
  ) async throws -> UInt16 {
    try await withThrowingTaskGroup(of: UInt16.self) { group in
      group.addTask {
        var iterator = incoming.makeAsyncIterator()
        guard let challengeFrame = try await iterator.next(),
          challengeFrame.generation == generation,
          case .challenge(
            let relayServerID,
            let connectionInstance,
            let challengeNonce
          ) = challengeFrame.frame.body
        else {
          throw MachineConnectionSupervisorFailure.handshakeRejected
        }
        let challenge: RelayDeviceAuthenticationChallenge
        do {
          challenge = try RelayDeviceAuthenticationChallenge(
            relayServerID: relayServerID,
            connectionInstance: connectionInstance,
            challengeNonce: challengeNonce
          )
        } catch {
          throw MachineConnectionSupervisorFailure.securityError
        }
        let authentication = try await authenticator.authenticationFrame(
          challenge: challenge
        )
        try await transport.send(authentication, on: generation)

        guard let outcome = try await iterator.next(),
          outcome.generation == generation
        else {
          throw MachineConnectionSupervisorFailure.handshakeRejected
        }
        switch outcome.frame.body {
        case .authenticated(let heartbeatIntervalSeconds):
          return heartbeatIntervalSeconds
        case .revocationCommitted, .retirementCommitted:
          let terminal = try await verifiedIngress.receive(
            outcome,
            scope: scope
          )
          switch terminal {
          case .revoked:
            throw MachineConnectionSupervisorFailure.revoked
          case .incompatible:
            throw MachineConnectionSupervisorFailure.incompatible
          case .securityError:
            throw MachineConnectionSupervisorFailure.securityError
          case .ignored, .delivery, .transportActions, .keySyncRequired,
            .keySyncAttemptFailed, .keySyncSucceeded, .machineOffline,
            .relayUnavailable, .streamRecoveryRequired:
            throw MachineConnectionSupervisorFailure.securityError
          }
        case .error(let failure):
          throw relayFailure(failure)
        case .hello, .challenge, .authenticate, .openPairRoute, .pairRouteOpened,
          .pairData, .closePairRoute, .pairRouteClosed, .registerStream,
          .publish, .subscribe, .unsubscribe, .ack, .gap, .replayComplete,
          .send, .reply, .installGrant, .grantCommitted, .revokeDevice,
          .retireMachine, .ping, .pong, .routeAccepted, .serverRestarting,
          .pairingHello:
          throw MachineConnectionSupervisorFailure.handshakeRejected
        }
      }
      group.addTask {
        try await Task.sleep(
          for: .milliseconds(Int64(clamping: timeoutMilliseconds))
        )
        throw MachineConnectionSupervisorFailure.handshakeTimedOut
      }
      guard let result = try await group.next() else {
        throw MachineConnectionSupervisorFailure.handshakeRejected
      }
      group.cancelAll()
      return result
    }
  }

  private func readAuthenticatedFrames(
    _ incoming: AsyncThrowingStream<ReceivedRelayFrame, any Error>,
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope
  ) async throws {
    for try await frame in incoming {
      try Task.checkCancellation()
      guard frame.generation == generation else {
        throw MachineConnectionSupervisorFailure.securityError
      }
      switch frame.frame.body {
      case .pong:
        continue
      case .serverRestarting(let deadline):
        throw MachineConnectionSupervisorFailure.transport(
          .serverRestarting(drainDeadlineMilliseconds: deadline)
        )
      case .publish, .reply, .gap, .replayComplete, .routeAccepted, .error,
        .revocationCommitted, .retirementCommitted, .ack:
        let outcome = try await verifiedIngress.receive(frame, scope: scope)
        let postDrain = try await apply(
          outcome,
          generation: generation,
          scope: scope
        )
        try await synchronizeKeySyncDeadline(scope: scope)
        try await drainIngressTransportActions(
          generation: generation,
          scope: scope
        )
        try await completePostDrainAction(
          postDrain,
          generation: generation,
          scope: scope
        )
      case .hello, .challenge, .authenticate, .authenticated, .openPairRoute,
        .pairRouteOpened, .pairData, .closePairRoute, .pairRouteClosed,
        .registerStream, .subscribe, .unsubscribe, .send, .installGrant,
        .grantCommitted, .revokeDevice, .retireMachine, .ping, .pairingHello:
        throw MachineConnectionSupervisorFailure.securityError
      }
    }
  }

  private func apply(
    _ outcome: MachineConnectionVerifiedIngressOutcome,
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionPostDrainAction? {
    switch outcome {
    case .ignored:
      return nil
    case .delivery(let delivery):
      switch delivery.target {
      case .request:
        // Directed replies terminate inside ingress after durable replay admission and never
        // borrow stream cursor/generation fields or cross the Source reducer boundary.
        await verifiedIngress.discard(delivery)
        throw MachineConnectionSupervisorFailure.securityError
      case .catalog, .conversation:
        try await publishVerifiedDelivery(delivery)
        try await verifiedIngress.awaitResolution(delivery)
      case .pairing:
        await verifiedIngress.discard(delivery)
        throw MachineConnectionSupervisorFailure.securityError
      }
    case .transportActions(let frames):
      try await sendIngressTransportActions(
        frames,
        generation: generation,
        scope: scope
      )
      return nil
    case .streamRecoveryRequired(let target, let reason):
      try await publishStreamRecovery(target: target, reason: reason)
      return nil
    case .keySyncRequired(let observedRevision):
      await handle(.keySyncRequired(observedRevision: observedRevision))
      guard !stateMachine.shouldFinishObservations else {
        throw MachineConnectionSupervisorFailure.terminalAlreadyPublished
      }
      return nil
    case .keySyncAttemptFailed(let observedRevision):
      await handle(.keySyncAttemptFailed(observedRevision: observedRevision))
      if stateMachine.shouldFinishObservations {
        throw MachineConnectionSupervisorFailure.terminalAlreadyPublished
      }
      return nil
    case .keySyncSucceeded(let acceptedRevision, let recoveryTargets):
      cancelKeySyncDeadline(scope: scope)
      return .keySyncSucceeded(
        acceptedRevision: acceptedRevision,
        recoveryTargets: recoveryTargets
      )
    case .revoked:
      throw MachineConnectionSupervisorFailure.revoked
    case .incompatible:
      throw MachineConnectionSupervisorFailure.incompatible
    case .securityError:
      throw MachineConnectionSupervisorFailure.securityError
    case .machineOffline:
      throw MachineConnectionSupervisorFailure.machineOffline
    case .relayUnavailable:
      throw MachineConnectionSupervisorFailure.relayUnavailable
    }
    return nil
  }

  private func completePostDrainAction(
    _ action: MachineConnectionPostDrainAction?,
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope
  ) async throws {
    guard let action else { return }
    guard activeGeneration == generation, activeScope == scope else {
      throw MachineConnectionSupervisorFailure.transport(.staleGeneration)
    }
    switch action {
    case .keySyncSucceeded(let acceptedRevision, let recoveryTargets):
      await handle(
        .keySyncSucceeded(
          generation: generation,
          acceptedRevision: acceptedRevision
        )
      )
      guard !stateMachine.shouldFinishObservations,
        activeGeneration == generation,
        activeScope == scope
      else {
        throw MachineConnectionSupervisorFailure.terminalAlreadyPublished
      }
      // 先把所有 target 标为需要 snapshot，再发布同 scope ready。Source 因此只会
      // 为每个 target 发一次 fresh Subscribe，且不会让 partial barrier 触发抢跑。
      for target in recoveryTargets {
        try await publishStreamRecovery(target: target, reason: .snapshotRequired)
      }
      await publishBusinessReady(scope)
    }
  }

  private func publishStreamRecovery(
    target: VerifiedRuntimeTarget,
    reason: SessionLagReason
  ) async throws {
    let result = await updateChannel.send(
      .streamRecoveryRequired(target: target, reason: reason)
    )
    switch result {
    case .sent:
      return
    case .closed:
      throw MachineConnectionSupervisorFailure.securityError
    case .producerInvariantViolation:
      await failClosedIfProducerInvariantBroke(result)
      throw MachineConnectionSupervisorFailure.terminalAlreadyPublished
    }
  }

  private func publishConnectionScope(_ scope: TransferAssemblyScope?) async {
    let result = await updateChannel.send(.connectionScope(scope))
    await failClosedIfProducerInvariantBroke(result)
  }

  private func publishBusinessReady(_ scope: TransferAssemblyScope) async {
    guard activeScope == scope, activeGeneration == scope.generation else { return }
    let result = await updateChannel.send(.businessReady(scope))
    await failClosedIfProducerInvariantBroke(result)
    if result == .sent, activeScope == scope, activeGeneration == scope.generation {
      businessReadyScope = scope
    }
  }

  private typealias ActiveEndpointCapture = (
    transport: any MachineConnectionTransport,
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope
  )

  private func activeEndpointCapture() throws -> ActiveEndpointCapture {
    let generation = try stateMachine.requireOnlineGeneration()
    guard !stopping,
      let transport = activeTransport,
      activeGeneration == generation,
      let scope = activeScope,
      scope.generation == generation
    else {
      throw SessionSourceFailure(code: .transportUnavailable)
    }
    return (transport, generation, scope)
  }

  private func endpointCaptureIsCurrent(_ capture: ActiveEndpointCapture) -> Bool {
    !stopping
      && activeGeneration == capture.generation
      && activeScope == capture.scope
  }

  private func drainIngressTransportActions(
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope
  ) async throws {
    guard
      let source = verifiedIngress as? any MachineConnectionIngressTransportActionSource
    else {
      return
    }
    let frames = try await source.drainTransportActions(scope: scope)
    try await sendIngressTransportActions(
      frames,
      generation: generation,
      scope: scope
    )
  }

  private func synchronizeKeySyncDeadline(
    scope: TransferAssemblyScope
  ) async throws {
    guard activeScope == scope, activeGeneration == scope.generation else {
      throw MachineConnectionSupervisorFailure.transport(.staleGeneration)
    }
    let remaining =
      try await verifiedIngress
      .keySyncDeadlineRemainingMilliseconds(scope: scope)
    guard activeScope == scope, activeGeneration == scope.generation else {
      throw MachineConnectionSupervisorFailure.transport(.staleGeneration)
    }
    guard let remaining else {
      cancelKeySyncDeadline(scope: scope)
      return
    }
    guard remaining > 0,
      remaining <= MachineKeySyncPolicy.deadlineMilliseconds
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    if keySyncDeadlineTask != nil {
      guard keySyncDeadlineScope == scope, keySyncDeadlineToken != nil else {
        throw MachineConnectionSupervisorFailure.securityError
      }
      return
    }

    let token = UUID()
    keySyncDeadlineScope = scope
    keySyncDeadlineToken = token
    keySyncDeadlineTask = Task { [weak self] in
      do {
        try await Task.sleep(
          for: .milliseconds(Int64(clamping: remaining))
        )
      } catch {
        return
      }
      await self?.keySyncDeadlineExpired(scope: scope, token: token)
    }
  }

  private func keySyncDeadlineExpired(
    scope: TransferAssemblyScope,
    token: UUID
  ) async {
    guard !stopping,
      activeScope == scope,
      activeGeneration == scope.generation,
      keySyncDeadlineScope == scope,
      keySyncDeadlineToken == token
    else {
      return
    }
    keySyncDeadlineTask = nil
    keySyncDeadlineScope = nil
    keySyncDeadlineToken = nil
    keySyncDeadlineForcedCloseScope = scope
    do {
      try await verifiedIngress.expireKeySyncEpisode(scope: scope)
    } catch {
      // Durable fail-close 失败时仍必须关闭 transport；下一次 cold-open 会从原 absolute
      // expiry 再次拒绝，绝不刷新 episode。
    }
    await handle(.securityError)
    guard let transport = activeTransport else { return }
    do {
      try await transport.close(generation: scope.generation)
    } catch {
      await transport.shutdown()
    }
  }

  private func cancelKeySyncDeadline(scope: TransferAssemblyScope?) {
    guard scope == nil || keySyncDeadlineScope == scope else { return }
    keySyncDeadlineTask?.cancel()
    keySyncDeadlineTask = nil
    keySyncDeadlineScope = nil
    keySyncDeadlineToken = nil
  }

  private func sendIngressTransportActions(
    _ frames: [RelayV2OutboundFrame],
    generation: RelayTransportGeneration,
    scope: TransferAssemblyScope?
  ) async throws {
    guard frames.count <= 512 else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    guard !frames.isEmpty else { return }
    guard let scope,
      let transport = activeTransport,
      activeGeneration == generation,
      activeScope == scope,
      scope.generation == generation
    else {
      throw MachineConnectionSupervisorFailure.transport(.staleGeneration)
    }
    for frame in frames {
      guard activeGeneration == generation, activeScope == scope else {
        throw MachineConnectionSupervisorFailure.transport(.staleGeneration)
      }
      try await transport.send(frame, on: generation)
    }
  }

  private static func endpointError(_ error: Error) -> Error {
    if error is CancellationError { return CancellationError() }
    if let failure = error as? SessionSourceFailure { return failure }
    if let failure = error as? MachineConnectionSupervisorFailure {
      switch failure {
      case .machineOffline:
        return SessionSourceFailure(code: .machineOffline)
      case .revoked:
        return SessionSourceFailure(code: .revoked)
      case .incompatible:
        return SessionSourceFailure(code: .incompatible)
      case .transport, .relayUnavailable, .handshakeTimedOut:
        return SessionSourceFailure(code: .transportUnavailable)
      case .handshakeRejected, .relayFailure, .securityError,
        .terminalAlreadyPublished:
        return SessionSourceFailure(code: .securityError)
      }
    }
    if let transport = error as? RelayTransportError {
      switch transport {
      case .connectionFailed, .connectionClosed, .connectionTimedOut, .peerClosed,
        .canceled, .notConnected, .outcomeUnknown, .serverRestarting:
        return SessionSourceFailure(code: .transportUnavailable)
      case .unsupportedVersion:
        return SessionSourceFailure(code: .incompatible)
      case .invalidEndpoint, .incomingAlreadyClaimed, .handshakeFrameReserved,
        .staleGeneration, .generationExhausted, .connectionCleanupStalled,
        .textMessage, .frameTooLarge, .invalidFrame, .incomingBackpressure,
        .outgoingBackpressure, .tls:
        return SessionSourceFailure(code: .securityError)
      }
    }
    return SessionSourceFailure(code: .securityError)
  }

  private static func expectedConversationRoutes(
    _ material: PairedMachineConnectionMaterial
  ) throws -> [Data] {
    let state = material.auditedCryptoState.state
    let routes: [Data]
    if let lifecycle = state.keyLifecycle {
      routes = lifecycle.slots.compactMap { slot in
        slot.id.purpose == .conversationDEK ? slot.id.streamRoute : nil
      }
    } else {
      routes = state.keyDirectory.entries.compactMap { entry in
        entry.keyID.purpose == .conversationDEK ? entry.streamRoute : nil
      }
    }
    guard
      routes.allSatisfy({
        $0.count == 16 && $0.contains(where: { $0 != 0 })
      })
    else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    let sorted = routes.sorted { $0.lexicographicallyPrecedes($1) }
    guard Set(sorted).count == sorted.count else {
      throw MachineConnectionSupervisorFailure.securityError
    }
    return sorted
  }
  private func reconnectDecision(
    for error: Error
  ) -> MachineConnectionReconnectDecision {
    if error is CancellationError {
      return .stop
    }
    if let failure = error as? MachineConnectionSupervisorFailure {
      switch failure {
      case .terminalAlreadyPublished:
        return .stop
      case .revoked:
        return .terminal(.revoked)
      case .incompatible:
        return .terminal(.incompatible)
      case .securityError, .handshakeRejected:
        return .terminal(.securityError)
      case .machineOffline:
        return .reconnect(
          event: .machineOffline,
          policyReason: .transportFailure
        )
      case .relayUnavailable:
        return .reconnect(
          event: .relayUnavailable,
          policyReason: .transportFailure
        )
      case .handshakeTimedOut:
        return .reconnect(
          event: .transportFailed,
          policyReason: .transportFailure
        )
      case .relayFailure(let code):
        return Self.relayFailureDecision(code: code)
      case .transport(let transport):
        return Self.transportDecision(transport)
      }
    }
    if let transport = error as? RelayTransportError {
      return Self.transportDecision(transport)
    }
    return .terminal(.securityError)
  }

  private static func transportDecision(
    _ error: RelayTransportError
  ) -> MachineConnectionReconnectDecision {
    switch error {
    case .serverRestarting(let deadline):
      return .reconnect(
        event: .relayUnavailable,
        policyReason: .serverRestarting(
          drainDeadlineMilliseconds: deadline
        )
      )
    case .connectionFailed, .connectionClosed, .connectionTimedOut, .peerClosed,
      .canceled, .notConnected, .outcomeUnknown:
      return .reconnect(
        event: .transportFailed,
        policyReason: .transportFailure
      )
    case .unsupportedVersion:
      return .terminal(.incompatible)
    case .invalidEndpoint, .incomingAlreadyClaimed, .handshakeFrameReserved,
      .staleGeneration, .generationExhausted, .connectionCleanupStalled,
      .textMessage, .frameTooLarge, .invalidFrame, .incomingBackpressure,
      .outgoingBackpressure, .tls:
      return .terminal(.securityError)
    }
  }

  private static func relayFailureDecision(
    code: String
  ) -> MachineConnectionReconnectDecision {
    switch code {
    case "relay.version.unsupported":
      return .terminal(.incompatible)
    case "relay.auth.challenge_expired", "relay.store.unavailable",
      "relay.quota.exceeded", "relay.disk.low":
      return .reconnect(
        event: .relayUnavailable,
        policyReason: .transportFailure
      )
    case "relay.route.not_found":
      return .reconnect(
        event: .machineOffline,
        policyReason: .transportFailure
      )
    default:
      return .terminal(.securityError)
    }
  }

  private static func relayFailure(
    _ failure: RelayV2Failure
  ) -> MachineConnectionSupervisorFailure {
    let code = failure.code
    guard !code.isEmpty,
      code.utf8.count <= 128,
      code.hasPrefix("relay.") || code.hasPrefix("remote.transport."),
      code.utf8.allSatisfy({ byte in
        byte.isASCIILowercase || byte.isASCIIDigit
          || byte == 0x2E || byte == 0x5F || byte == 0x2D
      })
    else {
      return .securityError
    }
    return .relayFailure(code: code)
  }

  private func teardownActiveGeneration(
    expectedScope: TransferAssemblyScope? = nil
  ) async {
    guard let transport = activeTransport,
      let generation = activeGeneration,
      let scope = activeScope,
      expectedScope.map({ $0 == scope }) ?? true
    else {
      return
    }
    let deadlineAlreadyForcedClose = keySyncDeadlineForcedCloseScope == scope
    if deadlineAlreadyForcedClose {
      keySyncDeadlineForcedCloseScope = nil
    }
    cancelKeySyncDeadline(scope: scope)
    activeTransport = nil
    activeGeneration = nil
    activeScope = nil
    businessReadyScope = nil
    await publishConnectionScope(nil)

    if !deadlineAlreadyForcedClose {
      do {
        try await transport.close(generation: generation)
      } catch {
        await transport.shutdown()
      }
    }
    await verifiedIngress.generationEnded(scope: scope)
    transferBudgetCoordinator.releaseAll(scope: scope)
  }

  private func failClosedIfProducerInvariantBroke(
    _ result: MachineConnectionUpdateChannelSendResult
  ) async {
    guard result == .producerInvariantViolation else { return }
    stateMachine.handle(.securityError)
    await updateChannel.fail(
      finalElement: .connectionState(.securityError)
    )
  }
}

private struct RejectingMachineConnectionAuthenticator:
  MachineConnectionAuthenticating
{
  func authenticationFrame(
    challenge: RelayDeviceAuthenticationChallenge
  ) async throws -> RelayV2OutboundFrame {
    throw MachineConnectionSupervisorFailure.securityError
  }
}

extension UInt8 {
  fileprivate var isASCIILowercase: Bool { (0x61...0x7A).contains(self) }
  fileprivate var isASCIIDigit: Bool { (0x30...0x39).contains(self) }
}

/// Connection→Source 是单消费者 actor handoff，不需要第二套 snapshot recovery。
/// 固定 512 队列满时 producer 挂起形成背压，既不静默丢 verified delivery，也不会
/// 进入 Source 无法解除的 awaitingBarrier。
enum MachineConnectionUpdateChannelSendResult: Equatable, Sendable {
  case sent
  case closed
  case producerInvariantViolation
}

actor MachineConnectionUpdateChannel<Element: Sendable> {
  private struct PendingSend {
    let element: Element
    let continuation: CheckedContinuation<MachineConnectionUpdateChannelSendResult, Never>
  }

  private let capacity: Int
  private var queue: [Element] = []
  private var pendingSends: [PendingSend] = []
  private var consumerWaiter: CheckedContinuation<Element?, Never>?
  private var streamWasClaimed = false
  private var isFinished = false

  init(capacity: Int) {
    precondition(capacity > 0)
    self.capacity = capacity
  }

  var debugPendingSendCount: Int {
    pendingSends.count
  }

  func stream() -> AsyncStream<Element> {
    guard !streamWasClaimed else {
      return AsyncStream { continuation in continuation.finish() }
    }
    streamWasClaimed = true
    return AsyncStream(
      unfolding: { [weak self] in
        guard let self else { return nil }
        return await self.next()
      },
      onCancel: { [weak self] in
        guard let self else { return }
        Task { await self.finish() }
      }
    )
  }

  func send(_ element: Element) async -> MachineConnectionUpdateChannelSendResult {
    guard !isFinished else { return .closed }
    if let consumerWaiter {
      self.consumerWaiter = nil
      consumerWaiter.resume(returning: element)
      return .sent
    }
    if queue.count < capacity {
      queue.append(element)
      return .sent
    }
    guard pendingSends.isEmpty else {
      return .producerInvariantViolation
    }
    return await withCheckedContinuation { continuation in
      pendingSends.append(
        PendingSend(element: element, continuation: continuation)
      )
    }
  }

  func finish() {
    guard !isFinished else { return }
    isFinished = true
    consumerWaiter?.resume(returning: nil)
    consumerWaiter = nil
    let senders = pendingSends.map(\.continuation)
    pendingSends.removeAll(keepingCapacity: false)
    for sender in senders {
      sender.resume(returning: .closed)
    }
  }

  func fail(finalElement: Element) {
    guard !isFinished else { return }
    isFinished = true
    queue.removeAll(keepingCapacity: false)
    let senders = pendingSends.map(\.continuation)
    pendingSends.removeAll(keepingCapacity: false)
    for sender in senders {
      sender.resume(returning: .closed)
    }
    if let consumerWaiter {
      self.consumerWaiter = nil
      consumerWaiter.resume(returning: finalElement)
    } else {
      queue.append(finalElement)
    }
  }

  private func next() async -> Element? {
    if !queue.isEmpty {
      let element = queue.removeFirst()
      admitPendingSendIfPossible()
      return element
    }
    guard !isFinished else { return nil }
    return await withCheckedContinuation { continuation in
      precondition(consumerWaiter == nil)
      consumerWaiter = continuation
    }
  }

  private func admitPendingSendIfPossible() {
    guard queue.count < capacity, !pendingSends.isEmpty else { return }
    let pending = pendingSends.removeFirst()
    queue.append(pending.element)
    pending.continuation.resume(returning: .sent)
  }
}
