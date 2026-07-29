import AgentDeckCore
import CryptoKit
import Foundation

enum ProductionMachineConnectionVerifiedIngressError: Error, Equatable, Sendable {
  case invalidConfiguration
  case invalidGeneration
  case generationAlreadyActive
  case generationNotActive
  case generationEnded
  case noncanonicalFrame
  case resolutionPending
  case invalidPermit
  case duplicateWaiter
  case correlationSuperseded
  case outboundCapacity
  case unsupportedFrame
  case unsupportedTransfer
  case unsupportedKeyControl
  case keySyncMismatch
  case keySyncTimedOut
}

struct MachinePreparedOutboundRequestToken: Hashable, Sendable {
  fileprivate let rawValue: UUID

  init() {
    rawValue = UUID()
  }
}

/// MachineConnection 在 actor 内 exact recheck active generation 后发送的唯一 prepared
/// request。raw SignedSealedBlob 不越过此 carrier，取消时只消费 opaque token。
struct MachinePreparedOutboundRequest: Sendable {
  let token: MachinePreparedOutboundRequestToken
  let frame: RelayV2OutboundFrame
}

/// Verified ingress 不私持 transport；MachineConnection 在处理每个 receive outcome 后
/// 必须立即 drain，并在同一 active generation 按数组顺序发送。
protocol MachineConnectionIngressTransportActionSource: Sendable {
  func drainTransportActions(
    scope: TransferAssemblyScope
  ) async throws -> [RelayV2OutboundFrame]
}

protocol ProductionTransferExpirySleeping: Sendable {
  func sleep(milliseconds: UInt64) async throws
}

private struct ContinuousProductionTransferExpirySleeper: ProductionTransferExpirySleeping {
  func sleep(milliseconds: UInt64) async throws {
    try await Task.sleep(for: .milliseconds(Int64(clamping: milliseconds)))
  }
}

private struct ProductionTransferCompletion: Sendable {
  let assembly: TransferAssembly
  let firstStreamSequence: UInt64?
  let lastStreamSequence: UInt64?
}

/// `TransferAssembler` 是 noncopyable generation owner；reference wrapper 只由 ingress
/// actor 隔离访问，确保 disconnect/reset 精确释放 global budget。
private final class ProductionTransferAssemblerOwner {
  private struct Binding {
    let channel: RuntimeTransferChannelV2
    let requestRoute: Data?
    let streamRoute: Data?
    let streamGeneration: Data?
    let firstStreamSequence: UInt64?
    let lastStreamSequence: UInt64?
    var completedAtMS: UInt64?

    func matches(_ other: Self) -> Bool {
      channel.rawValue == other.channel.rawValue
        && requestRoute == other.requestRoute
        && streamRoute == other.streamRoute
        && streamGeneration == other.streamGeneration
        && firstStreamSequence == other.firstStreamSequence
        && lastStreamSequence == other.lastStreamSequence
    }
  }

  private let scope: TransferAssemblyScope
  private let ttlMilliseconds: UInt64
  private var assembler: TransferAssembler
  private var bindings: [RuntimeTransferID: Binding] = [:]

  init(
    scope: TransferAssemblyScope,
    budgetCoordinator: TransferAssemblyBudgetCoordinator,
    ttlMilliseconds: UInt64
  ) {
    self.scope = scope
    self.ttlMilliseconds = ttlMilliseconds
    assembler = TransferAssembler(
      scope: scope,
      budgetCoordinator: budgetCoordinator,
      ttlMilliseconds: ttlMilliseconds
    )
  }

  func accept(
    _ carrier: RuntimeTransferCarrierV2,
    context: OuterContextV1,
    nowMS: UInt64
  ) throws -> ProductionTransferCompletion? {
    sweepExpired(nowMS: nowMS)

    let candidate = try Self.binding(carrier: carrier, context: context)
    if let existing = bindings[carrier.transfer.transferID] {
      guard existing.matches(candidate) else {
        throw TransferAssemblerError.hashMismatch
      }
    } else {
      bindings[carrier.transfer.transferID] = candidate
    }

    do {
      switch try assembler.accept(carrier, scope: scope, nowMS: nowMS) {
      case .inProgress, .alreadyComplete:
        return nil
      case .complete(let assembly):
        guard var completed = bindings[assembly.transferID] else {
          throw TransferAssemblerError.hashMismatch
        }
        completed.completedAtMS = nowMS
        bindings[assembly.transferID] = completed
        return ProductionTransferCompletion(
          assembly: assembly,
          firstStreamSequence: completed.firstStreamSequence,
          lastStreamSequence: completed.lastStreamSequence
        )
      }
    } catch {
      bindings.removeValue(forKey: carrier.transfer.transferID)
      throw error
    }
  }

  func discardCompleted(_ transferID: RuntimeTransferID) {
    try? assembler.discardCompleted(transferID: transferID, scope: scope)
    bindings.removeValue(forKey: transferID)
  }

  func sweepExpired(nowMS: UInt64) {
    let expired = assembler.sweepExpired(nowMS: nowMS)
    for transferID in expired {
      bindings.removeValue(forKey: transferID)
    }
    bindings = bindings.filter { _, binding in
      guard let completedAtMS = binding.completedAtMS else { return true }
      return !isExpired(completedAtMS, nowMS: nowMS)
    }
  }

  func nextAbsoluteExpiryMS() -> UInt64? {
    assembler.nextAbsoluteExpiryMS()
  }

  func reset() {
    try? assembler.reset(scope: scope)
    bindings.removeAll(keepingCapacity: false)
  }

  private func isExpired(_ startedAtMS: UInt64, nowMS: UInt64) -> Bool {
    let expiry = startedAtMS.addingReportingOverflow(ttlMilliseconds)
    let absoluteExpiry = expiry.overflow ? UInt64.max : expiry.partialValue
    return nowMS >= absoluteExpiry
  }

  private static func binding(
    carrier: RuntimeTransferCarrierV2,
    context: OuterContextV1
  ) throws -> Binding {
    switch carrier.channel {
    case .reply:
      guard context.frameKind == .directedReply,
        let requestRoute = context.requestRoute,
        context.streamRoute == nil,
        context.streamGeneration == nil,
        context.streamSeq == nil
      else {
        throw TransferAssemblerError.hashMismatch
      }
      return Binding(
        channel: carrier.channel,
        requestRoute: requestRoute,
        streamRoute: nil,
        streamGeneration: nil,
        firstStreamSequence: nil,
        lastStreamSequence: nil
      )

    case .stream:
      guard
        context.frameKind == .catalogPublish
          || context.frameKind == .conversationPublish,
        let streamRoute = context.streamRoute,
        let streamGeneration = context.streamGeneration,
        let streamSequence = context.streamSeq,
        carrier.transfer.partCount > 0,
        streamSequence >= UInt64(carrier.transfer.partIndex)
      else {
        throw TransferAssemblerError.hashMismatch
      }
      let first = streamSequence - UInt64(carrier.transfer.partIndex)
      let offset = UInt64(carrier.transfer.partCount - 1)
      let last = first.addingReportingOverflow(offset)
      guard !last.overflow else { throw TransferAssemblerError.hashMismatch }
      return Binding(
        channel: carrier.channel,
        requestRoute: nil,
        streamRoute: streamRoute,
        streamGeneration: streamGeneration,
        firstStreamSequence: first,
        lastStreamSequence: last.partialValue
      )
    }
  }
}

/// 单台 paired machine 的 production ingress、request correlation 与 outbound prepare
/// owner。所有 raw Relay frame 都在此完成 canonical/version/generation、MachineDataSign、
/// durable replay、AEAD、strict inner decode 后才产生 delivery 或 typed action。
actor ProductionMachineConnectionVerifiedIngress:
  MachineConnectionVerifiedIngress,
  MachineConnectionIngressTransportActionSource
{
  private static let maximumQueuedTransportActions = 512
  private static let maximumRecoveredAcknowledgementsPerBatch = 64

  private enum OutboundKind: Sendable {
    case directed
    case subscription
  }

  private struct OutboundRecord {
    let scope: TransferAssemblyScope
    let requestRoute: Data
    let kind: OutboundKind
    var reply: RuntimeReplyV2?
    var waiter: CheckedContinuation<RuntimeReplyV2, any Error>?
  }

  private struct KeySyncRequestRecord: Sendable {
    let observedRevision: UInt64
    let observedKeyID: KeyIDV1
    let streamRoute: Data?
    let attempt: UInt8
    let requestRoute: Data
    let replyCapability: ExactNextKeySyncReplyCapability
  }

  private struct CompletedKeySyncReplyRecord: Sendable {
    let request: KeySyncRequestRecord
    let acknowledgementPermit: DurableKeyUpdateAckPermit
  }

  private struct TransportActionReservationToken: Hashable, Sendable {
    let rawValue = UUID()
  }

  private struct TransportActionReservationRecord: Sendable {
    let actionCount: Int
    let controlRouteCount: Int
    let controlRequestRoute: Data?
    let controlRouteClaim: MachineControlRequestRouteClaim?
  }

  private struct ControlActionReservation: Sendable {
    let token: TransportActionReservationToken
    let requestRoute: Data
  }

  private struct GenerationState {
    let scope: TransferAssemblyScope
    let correlation: MachineRequestCorrelationOwner
    var outboundByToken: [MachinePreparedOutboundRequestToken: OutboundRecord] = [:]
    var tokenByRequestRoute: [Data: MachinePreparedOutboundRequestToken] = [:]
    var controlRequestRoutes: Set<Data> = []
    var keySyncRequests: [Data: KeySyncRequestRecord] = [:]
    var currentKeySyncRoute: Data?
    var completedKeySyncRoutes: Set<Data> = []
    var completedKeySyncReplies: [Data: CompletedKeySyncReplyRecord] = [:]
    var pausedKeySyncStreams: [MachineOuterStreamBinding: VerifiedRuntimeTarget] = [:]
    var pendingRecoveredStreamAppliedAcknowledgements: [DurableStreamAppliedAckPermit] = []
    var recoveredAcknowledgementRequestRoutes: Set<Data> = []
    var streamAppliedRequestRouteByProof: [Data: Data] = [:]
    var streamAppliedProofByRequestRoute: [Data: Data] = [:]
    var streamAppliedReservationByProof: [Data: TransportActionReservationToken] = [:]
    var transportActions: [RelayV2OutboundFrame] = []
    var acknowledgementReservations: Set<MachineVerifiedDeliveryPermit> = []
    var transportActionReservations:
      [TransportActionReservationToken: TransportActionReservationRecord] = [:]
    var controlReservationByRequestRoute: [Data: TransportActionReservationToken] = [:]
    var controlRouteClaimByRequestRoute: [Data: MachineControlRequestRouteClaim] = [:]
    var pendingOuterAcknowledgements: [MachineOuterStreamBinding: UInt64] = [:]
    var unresolvedPermit: MachineVerifiedDeliveryPermit?
    var keySyncMutationPending = false
    var keySyncWasAnnounced = false
    var ending = false
  }

  private enum DeliveryResolution {
    case pending
    case committing(Task<CryptoStateSnapshot?, any Error>)
    case committed
    case discarded
    case failed
  }

  private struct PublishAcknowledgement: Sendable {
    let streamRoute: Data
    let streamGeneration: Data
    let upToSeq: UInt64

    var frame: RelayV2OutboundFrame {
      .control(
        .ack(
          streamRoute: streamRoute,
          generation: streamGeneration,
          upToSeq: upToSeq
        ))
    }
  }

  private struct DeliveryRecord {
    let scope: TransferAssemblyScope
    let transferID: RuntimeTransferID?
    let expectedSnapshot: CryptoStateSnapshot?
    let replacementSnapshot: CryptoStateSnapshot?
    let preparedCorrelation: MachinePreparedRequestCorrelation?
    let correlation: MachineRequestCorrelationOwner
    let publishAcknowledgement: PublishAcknowledgement?
    var resolution: DeliveryResolution
    var waiter: CheckedContinuation<Void, any Error>?
  }

  private struct SignerContext: Sendable {
    let relayServerID: Data
    let grant: RelayV2Grant
    let machineRoute: Data
    let deviceRoute: Data
    let grantSerial: UInt64
    let machineRootPublicKey: Data
    let machineRootFingerprint: Data
    let rootKeyID: Data
    let trustEpoch: UInt64
    let deviceSigningKey: Curve25519.Signing.PrivateKey
    let deviceSignatureProducer: (any DeviceSignatureProducing)?
  }

  nonisolated let machineID: String

  private let machineRoute: Data
  private let deviceRoute: Data
  private let verifiedCertificate: VerifiedMachineDataCertificate
  private let terminalVerifier: MachineTerminalVerifier
  private let keyUpdateVerifier: KeyUpdateSetVerifier
  private let coordinator: DurableCryptoStateCoordinator
  private let stateStore: FileCryptoStateStore
  private let expectedConversationRoutes: [Data]
  private let signerContext: SignerContext
  private let counterAllocator: CounterAllocator
  private let clock: @Sendable () -> UInt64
  private let requestRouteGenerator: @Sendable () throws -> Data
  private let transferBudgetCoordinator: TransferAssemblyBudgetCoordinator
  private let transferTTLMilliseconds: UInt64
  private let transferExpirySleeper: any ProductionTransferExpirySleeping

  private var snapshot: CryptoStateSnapshot
  private var inventory: AuditedDeviceKeyInventoryV1
  private var dataVerifier: MachineDataVerifier
  private var requestSigner: DeviceRequestSigner
  private var generation: GenerationState?
  private var transferOwner: ProductionTransferAssemblerOwner?
  private var transferExpiryTask: Task<Void, Never>?
  private var transferExpiryScope: TransferAssemblyScope?
  private var transferExpiryDeadlineMS: UInt64?
  private var transferExpiryToken: UUID?
  private var deliveries: [MachineVerifiedDeliveryPermit: DeliveryRecord] = [:]

  static func open(
    material: PairedMachineConnectionMaterial,
    expectedConversationRoutes: [Data],
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(Date().timeIntervalSince1970 * 1_000)
    },
    requestRouteGenerator: @escaping @Sendable () throws -> Data = {
      var uuid = UUID().uuid
      return withUnsafeBytes(of: &uuid) { Data($0) }
    },
    deviceSignatureProducer: (any DeviceSignatureProducing)? = nil,
    transferBudgetCoordinator: TransferAssemblyBudgetCoordinator = .shared,
    transferTTLMilliseconds: UInt64 = TransferAssembler.transferTTLMilliseconds,
    transferExpirySleeper: any ProductionTransferExpirySleeping =
      ContinuousProductionTransferExpirySleeper()
  ) async throws -> ProductionMachineConnectionVerifiedIngress {
    let keyUpdateVerifier = try KeyUpdateSetVerifier(material: material)
    let inventory = try await material.cryptoStateCoordinator.auditColdOpen(
      expected: material.auditedCryptoState,
      expectedConversationRoutes: expectedConversationRoutes,
      verifier: keyUpdateVerifier
    )
    let counterAllocator = CounterAllocator(coordinator: material.cryptoStateCoordinator)
    let signerContext = SignerContext(
      relayServerID: material.record.relayServerID,
      grant: material.relayGrant.grant,
      machineRoute: material.record.machineRoute,
      deviceRoute: material.record.deviceRoute,
      grantSerial: material.record.grantSerial,
      machineRootPublicKey: material.record.machineRootPublicKey,
      machineRootFingerprint: material.record.machineRootFingerprint,
      rootKeyID: material.relayGrant.grant.rootKeyId,
      trustEpoch: material.record.trustEpoch,
      deviceSigningKey: material.deviceSigningKey,
      deviceSignatureProducer: deviceSignatureProducer
    )
    return try ProductionMachineConnectionVerifiedIngress(
      machineID: material.record.machineID,
      machineRoute: material.record.machineRoute,
      deviceRoute: material.record.deviceRoute,
      verifiedCertificate: material.machineDataCertificate,
      terminalVerifier: MachineTerminalVerifier(material: material),
      keyUpdateVerifier: keyUpdateVerifier,
      coordinator: material.cryptoStateCoordinator,
      stateStore: material.cryptoStateStore,
      expectedConversationRoutes: expectedConversationRoutes,
      signerContext: signerContext,
      counterAllocator: counterAllocator,
      snapshot: material.auditedCryptoState,
      inventory: inventory,
      clock: clock,
      requestRouteGenerator: requestRouteGenerator,
      transferBudgetCoordinator: transferBudgetCoordinator,
      transferTTLMilliseconds: transferTTLMilliseconds,
      transferExpirySleeper: transferExpirySleeper
    )
  }

  private init(
    machineID: String,
    machineRoute: Data,
    deviceRoute: Data,
    verifiedCertificate: VerifiedMachineDataCertificate,
    terminalVerifier: MachineTerminalVerifier,
    keyUpdateVerifier: KeyUpdateSetVerifier,
    coordinator: DurableCryptoStateCoordinator,
    stateStore: FileCryptoStateStore,
    expectedConversationRoutes: [Data],
    signerContext: SignerContext,
    counterAllocator: CounterAllocator,
    snapshot: CryptoStateSnapshot,
    inventory: AuditedDeviceKeyInventoryV1,
    clock: @escaping @Sendable () -> UInt64,
    requestRouteGenerator: @escaping @Sendable () throws -> Data,
    transferBudgetCoordinator: TransferAssemblyBudgetCoordinator,
    transferTTLMilliseconds: UInt64,
    transferExpirySleeper: any ProductionTransferExpirySleeping
  ) throws {
    guard !machineID.isEmpty,
      machineRoute.count == 16,
      deviceRoute.count == 16,
      machineRoute.contains(where: { $0 != 0 }),
      deviceRoute.contains(where: { $0 != 0 }),
      inventory.activeRevision > 0,
      transferTTLMilliseconds > 0,
      transferTTLMilliseconds <= TransferAssembler.transferTTLMilliseconds
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }
    self.machineID = machineID
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.verifiedCertificate = verifiedCertificate
    self.terminalVerifier = terminalVerifier
    self.keyUpdateVerifier = keyUpdateVerifier
    self.coordinator = coordinator
    self.stateStore = stateStore
    self.expectedConversationRoutes = expectedConversationRoutes
    self.signerContext = signerContext
    self.counterAllocator = counterAllocator
    self.snapshot = snapshot
    self.inventory = inventory
    self.clock = clock
    self.requestRouteGenerator = requestRouteGenerator
    self.transferBudgetCoordinator = transferBudgetCoordinator
    self.transferTTLMilliseconds = transferTTLMilliseconds
    self.transferExpirySleeper = transferExpirySleeper
    dataVerifier = try Self.makeDataVerifier(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      verifiedCertificate: verifiedCertificate,
      revision: inventory.activeRevision
    )
    requestSigner = try Self.makeRequestSigner(
      context: signerContext,
      inventory: inventory,
      counterAllocator: counterAllocator
    )
  }

  deinit {
    transferExpiryTask?.cancel()
  }

  func expectedGrantSerial() -> UInt64 {
    signerContext.grantSerial
  }

  func keySyncDeadlineRemainingMilliseconds(
    scope: TransferAssemblyScope
  ) throws -> UInt64? {
    _ = try activeGeneration(scope)
    guard let episode = snapshot.state.keySyncEpisode else { return nil }
    let now = clock()
    try validateKeySyncEpisode(episode, observedAtMS: now)
    return episode.expiresAtMS - now
  }

  func keySyncEpisodeStatus(
    scope: TransferAssemblyScope
  ) throws -> MachineKeySyncEpisodeStatus? {
    _ = try activeGeneration(scope)
    guard let episode = snapshot.state.keySyncEpisode else { return nil }
    let now = clock()
    try validateKeySyncEpisode(episode, observedAtMS: now)
    return MachineKeySyncEpisodeStatus(
      observedRevision: episode.targetRevision,
      attempt: episode.attempt
    )
  }

  func expireKeySyncEpisode(scope: TransferAssemblyScope) async throws {
    _ = try activeGeneration(scope)
    snapshot = try await coordinator.expireKeySyncEpisode(observedAtMS: clock())
  }

  func resumeFrames(
    generation transportGeneration: RelayTransportGeneration,
    scope: TransferAssemblyScope,
    heartbeatIntervalSeconds: UInt16
  ) async throws -> [RelayV2OutboundFrame] {
    guard transportGeneration == scope.generation,
      heartbeatIntervalSeconds > 0
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidGeneration
    }
    if let generation {
      guard generation.scope == scope, !generation.ending else {
        throw ProductionMachineConnectionVerifiedIngressError.generationAlreadyActive
      }
      return []
    }
    cancelTransferExpiryTimer()
    generation = GenerationState(
      scope: scope,
      correlation: MachineRequestCorrelationOwner()
    )
    transferOwner = ProductionTransferAssemblerOwner(
      scope: scope,
      budgetCoordinator: transferBudgetCoordinator,
      ttlMilliseconds: transferTTLMilliseconds
    )
    if var active = generation {
      active.keySyncMutationPending = true
      generation = active
    }
    do {
      guard let durable = try await stateStore.load() else {
        throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
      }
      snapshot = durable
      try await refreshRuntimeCapabilities(expected: durable)

      var resume: [RelayV2OutboundFrame] = []
      let acknowledgementRecovery =
        try await coordinator
        .recoverKeyLifecycleAcknowledgements(expected: durable)
      guard var recovering = generation,
        recovering.scope == scope,
        !recovering.ending
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      recovering.pendingRecoveredStreamAppliedAcknowledgements =
        acknowledgementRecovery.streamAppliedPermits
      generation = recovering
      try await queueRecoveredStreamAppliedAcknowledgements(scope: scope)
      resume.append(contentsOf: try await drainTransportActions(scope: scope))
      let episode = durable.state.keySyncEpisode
      if let episode {
        try validateKeySyncEpisode(episode, observedAtMS: clock())
        guard var current = generation,
          current.scope == scope,
          !current.ending
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        current.keySyncWasAnnounced = true
        generation = current
      }
      if let staged = durable.state.keyLifecycle?.stagedTransition {
        guard let episode,
          staged.toRevision == episode.targetRevision
        else {
          throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
        }
        let installed = try await coordinator.stageKeyUpdateSet(
          expected: durable,
          canonicalBytes: staged.canonicalUpdateSet,
          expectedConversationRoutes: expectedConversationRoutes,
          observedAtMS: clock(),
          verifier: keyUpdateVerifier
        )
        snapshot = installed.snapshot
        try await refreshRuntimeCapabilities(expected: installed.snapshot)
        guard let current = generation,
          current.scope == scope,
          !current.ending,
          let reservation = try await reserveControlActionCapacity(
            actionCount: 1,
            scope: scope
          )
        else {
          throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
        }
        do {
          let signed = try await requestSigner.signKeyUpdateAcknowledgement(
            permit: installed.acknowledgementPermit,
            authority: keyControlAuthority(),
            requestRoute: reservation.requestRoute
          )
          let frame = try RelayV2OutboundFrame.send(
            deviceRoute: deviceRoute,
            requestRoute: reservation.requestRoute,
            sealedBlob: signed.sealedBlob
          )
          try registerControlAction(
            frame,
            requestRoute: reservation.requestRoute,
            reservation: reservation.token,
            scope: scope
          )
          guard var committed = generation,
            committed.scope == scope,
            !committed.ending
          else {
            throw ProductionMachineConnectionVerifiedIngressError.generationEnded
          }
          committed.keySyncMutationPending = false
          generation = committed
          resume.append(contentsOf: try await drainTransportActions(scope: scope))
        } catch {
          await releaseTransportActionReservation(reservation.token, scope: scope)
          throw error
        }
      } else if let episode {
        guard var committed = generation,
          committed.scope == scope,
          !committed.ending
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        committed.keySyncMutationPending = false
        generation = committed
        try await queueKeySyncRequest(
          observedRevision: episode.targetRevision,
          observedKeyID: episode.observedKeyID,
          streamRoute: episode.streamRoute,
          attempt: episode.attempt,
          scope: scope
        )
        resume.append(contentsOf: try await drainTransportActions(scope: scope))
      } else {
        guard var committed = generation,
          committed.scope == scope,
          !committed.ending
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        committed.keySyncMutationPending = false
        generation = committed
      }
      return resume
    } catch {
      if generation?.scope == scope {
        cancelTransferExpiryTimer(scope: scope)
        transferOwner?.reset()
        transferOwner = nil
        generation = nil
      }
      throw error
    }
  }

  func prepareDirected(
    envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    var active = try activeGeneration(scope)
    try ensureNoMutation(active)
    let requestRoute = try freshRequestRoute(active)
    let token = MachinePreparedOutboundRequestToken()
    let correlation = active.correlation
    active.outboundByToken[token] = OutboundRecord(
      scope: scope,
      requestRoute: requestRoute,
      kind: .directed
    )
    active.tokenByRequestRoute[requestRoute] = token
    generation = active
    var correlationRegistered = false
    do {
      try await correlation.registerDirectedRequest(
        requestRoute: requestRoute,
        messageID: envelope.messageID,
        contract: contract
      )
      correlationRegistered = true
      let signed = try await requestSigner.signRuntimeRequest(
        envelope,
        machineRoute: machineRoute,
        deviceRoute: deviceRoute,
        requestRoute: requestRoute
      )
      let committed = try activeGeneration(scope)
      try ensureNoMutation(committed)
      guard committed.tokenByRequestRoute[requestRoute] == token,
        let record = committed.outboundByToken[token],
        record.requestRoute == requestRoute,
        case .directed = record.kind
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      let prepared = MachinePreparedOutboundRequest(
        token: token,
        frame: try RelayV2OutboundFrame.send(
          deviceRoute: deviceRoute,
          requestRoute: requestRoute,
          sealedBlob: signed.sealedBlob
        )
      )
      return prepared
    } catch {
      let originalError = error
      if correlationRegistered {
        do {
          _ = try await correlation.unregisterDirectedRequest(
            requestRoute: requestRoute
          )
        } catch {
          await failClosedGeneration(scope: scope, correlation: correlation)
        }
      }
      removePreparedOutbound(
        token: token,
        requestRoute: requestRoute,
        scope: scope
      )
      throw originalError
    }
  }

  func prepareSubscription(
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID,
    scope: TransferAssemblyScope
  ) async throws -> MachinePreparedOutboundRequest {
    var active = try activeGeneration(scope)
    try ensureNoMutation(active)
    let requestRoute = try freshRequestRoute(active)
    let token = MachinePreparedOutboundRequestToken()
    let correlation = active.correlation
    active.outboundByToken[token] = OutboundRecord(
      scope: scope,
      requestRoute: requestRoute,
      kind: .subscription
    )
    active.tokenByRequestRoute[requestRoute] = token
    generation = active
    let innerCursor: RuntimeInnerCursorV1
    switch target {
    case .catalog:
      innerCursor = .catalog(cursor: after)
    case .conversation(let conversationID):
      innerCursor = .conversation(conversationID: conversationID, cursor: after)
    }
    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: requestID,
      body: .request(.subscribe(innerCursor: innerCursor))
    )
    var correlationRegistered = false
    do {
      let replaced = try await correlation.registerPendingSubscription(
        requestRoute: requestRoute,
        messageID: requestID,
        target: target
      )
      correlationRegistered = true
      guard var registered = generation,
        registered.scope == scope,
        !registered.ending,
        registered.tokenByRequestRoute[requestRoute] == token,
        registered.outboundByToken[token]?.requestRoute == requestRoute
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      if let replaced,
        let replacedToken = registered.tokenByRequestRoute.removeValue(forKey: replaced),
        var record = registered.outboundByToken.removeValue(forKey: replacedToken)
      {
        record.waiter?.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
        )
        record.waiter = nil
      }
      generation = registered
      let signed = try await requestSigner.signRuntimeRequest(
        envelope,
        machineRoute: machineRoute,
        deviceRoute: deviceRoute,
        requestRoute: requestRoute
      )
      let committed = try activeGeneration(scope)
      try ensureNoMutation(committed)
      guard committed.tokenByRequestRoute[requestRoute] == token,
        let record = committed.outboundByToken[token],
        record.requestRoute == requestRoute,
        case .subscription = record.kind
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      let prepared = MachinePreparedOutboundRequest(
        token: token,
        frame: try RelayV2OutboundFrame.send(
          deviceRoute: deviceRoute,
          requestRoute: requestRoute,
          sealedBlob: signed.sealedBlob
        )
      )
      return prepared
    } catch {
      let originalError = error
      if correlationRegistered {
        do {
          _ = try await correlation.unregisterPendingSubscription(
            requestRoute: requestRoute
          )
        } catch {
          await failClosedGeneration(scope: scope, correlation: correlation)
        }
      }
      removePreparedOutbound(
        token: token,
        requestRoute: requestRoute,
        scope: scope
      )
      throw originalError
    }
  }

  func cancelPrepared(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async {
    guard let active = generation,
      active.scope == scope,
      let record = active.outboundByToken[token]
    else {
      return
    }
    let correlation = active.correlation
    do {
      switch record.kind {
      case .directed:
        _ = try await correlation.unregisterDirectedRequest(
          requestRoute: record.requestRoute
        )
      case .subscription:
        _ = try await correlation.unregisterPendingSubscription(
          requestRoute: record.requestRoute
        )
      }
    } catch {
      await failClosedGeneration(scope: scope, correlation: correlation)
      return
    }

    guard var current = generation,
      current.scope == scope,
      !current.ending,
      current.correlation === correlation,
      var currentRecord = current.outboundByToken[token],
      currentRecord.requestRoute == record.requestRoute
    else {
      return
    }
    current.outboundByToken.removeValue(forKey: token)
    if current.tokenByRequestRoute[currentRecord.requestRoute] == token {
      current.tokenByRequestRoute.removeValue(forKey: currentRecord.requestRoute)
    }
    generation = current
    currentRecord.waiter?.resume(
      throwing: ProductionMachineConnectionVerifiedIngressError.generationEnded
    )
    currentRecord.waiter = nil
  }

  func preparedSubscriptionIsPending(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async throws -> Bool {
    guard let active = generation,
      active.scope == scope,
      !active.ending
    else {
      throw ProductionMachineConnectionVerifiedIngressError.generationEnded
    }
    guard let record = active.outboundByToken[token] else { return false }
    guard case .subscription = record.kind else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }
    return true
  }

  func awaitDirectedReply(
    _ token: MachinePreparedOutboundRequestToken,
    scope: TransferAssemblyScope
  ) async throws -> RuntimeReplyV2 {
    let reply = try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<RuntimeReplyV2, any Error>) in
      guard var active = generation,
        active.scope == scope,
        var record = active.outboundByToken[token],
        case .directed = record.kind
      else {
        continuation.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.generationNotActive
        )
        return
      }
      if let reply = record.reply {
        continuation.resume(returning: reply)
        return
      }
      guard record.waiter == nil else {
        continuation.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.duplicateWaiter
        )
        return
      }
      record.waiter = continuation
      active.outboundByToken[token] = record
      generation = active
    }
    if var active = generation,
      active.scope == scope,
      let record = active.outboundByToken.removeValue(forKey: token)
    {
      active.tokenByRequestRoute.removeValue(forKey: record.requestRoute)
      generation = active
    }
    return reply
  }

  func retireSubscription(
    target: RuntimeSubscriptionTargetV1,
    scope: TransferAssemblyScope
  ) async throws -> MachineSubscriptionRetirement {
    let active = try activeGeneration(scope)
    try ensureNoMutation(active)
    let correlation = active.correlation
    let retired: MachineUnregisteredSubscription
    do {
      retired = try await correlation.unregisterSubscription(target: target)
    } catch {
      await failClosedGeneration(scope: scope, correlation: correlation)
      throw error
    }

    guard var current = generation,
      current.scope == scope,
      !current.ending,
      current.correlation === correlation
    else {
      await failClosedGeneration(scope: scope, correlation: correlation)
      throw ProductionMachineConnectionVerifiedIngressError.generationEnded
    }
    for requestRoute in retired.requestRoutes {
      if let token = current.tokenByRequestRoute.removeValue(forKey: requestRoute) {
        var record = current.outboundByToken.removeValue(forKey: token)
        record?.waiter?.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.generationEnded
        )
        record?.waiter = nil
      }
    }

    var requiresGenerationRollover = retired.requiresGenerationRollover
    let outerUnsubscribe: RelayV2OutboundFrame?
    if let binding = retired.outerBinding {
      if current.pausedKeySyncStreams.removeValue(forKey: binding) != nil
        || snapshot.state.keySyncEpisode?.streamRoute == binding.streamRoute
      {
        requiresGenerationRollover = true
      }
      current.pendingOuterAcknowledgements.removeValue(forKey: binding)
      outerUnsubscribe = .control(
        .unsubscribe(
          streamRoute: binding.streamRoute,
          generation: binding.streamGeneration
        ))
    } else {
      outerUnsubscribe = nil
    }
    generation = current
    return MachineSubscriptionRetirement(
      outerUnsubscribe: outerUnsubscribe,
      requiresGenerationRollover: requiresGenerationRollover
    )
  }

  func receive(
    _ received: ReceivedRelayFrame,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    var active = try activeGeneration(scope)
    try ensureNoMutation(active)
    guard received.generation == scope.generation,
      received.frame.version == relayProtocolVersionV2,
      try RelayWireCodecV2.encodeFixture(received.frame) == received.canonicalBytes
    else {
      throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
    }
    guard active.unresolvedPermit == nil else {
      throw ProductionMachineConnectionVerifiedIngressError.resolutionPending
    }

    switch received.frame.body {
    case .revocationCommitted, .retirementCommitted:
      switch try terminalVerifier.verify(received) {
      case .revoked:
        return .revoked
      case .retired:
        return .incompatible
      }

    case .routeAccepted(let accepted):
      guard case .request(let requestRoute) = accepted else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame
      }
      if active.controlRequestRoutes.contains(requestRoute) {
        guard
          let routeClaim = active.controlRouteClaimByRequestRoute.removeValue(
            forKey: requestRoute
          )
        else {
          throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
        }
        active.controlRequestRoutes.remove(requestRoute)
        active.recoveredAcknowledgementRequestRoutes.remove(requestRoute)
        if let proof = active.streamAppliedProofByRequestRoute.removeValue(
          forKey: requestRoute
        ) {
          active.streamAppliedRequestRouteByProof.removeValue(forKey: proof)
        }
        generation = active
        await active.correlation.releaseControlRequestRoute(routeClaim)
        try await queueRecoveredStreamAppliedAcknowledgements(scope: scope)
        return .ignored
      }
      if active.keySyncRequests[requestRoute] != nil
        || active.completedKeySyncRoutes.contains(requestRoute)
      {
        return .ignored
      }
      switch try await active.correlation.acceptRoute(requestRoute) {
      case .accepted:
        return .ignored
      case .superseded:
        return .ignored
      }

    case .publish(let streamRoute, let relayGeneration, let streamSeq, let sealedBlob):
      let context = try publicationContext(
        sealedBlob: sealedBlob,
        streamRoute: streamRoute,
        relayGeneration: relayGeneration,
        streamSeq: streamSeq
      )
      return try await receiveSealed(
        wireBytes: sealedBlob,
        context: context,
        requestRoute: nil,
        scope: scope,
        correlation: active.correlation
      )

    case .reply(let outerDeviceRoute, let requestRoute, let sealedBlob):
      guard outerDeviceRoute == deviceRoute else {
        throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
      }
      let context = try replyContext(
        sealedBlob: sealedBlob,
        requestRoute: requestRoute
      )
      return try await receiveSealed(
        wireBytes: sealedBlob,
        context: context,
        requestRoute: requestRoute,
        scope: scope,
        correlation: active.correlation
      )

    case .gap(
      let streamRoute,
      let relayGeneration,
      let needStreamSeq,
      let oldestStreamSeq
    ):
      switch try await active.correlation.correlateStreamControl(
        streamRoute: streamRoute,
        relayGeneration: relayGeneration
      ) {
      case .superseded:
        return .ignored
      case .active(let target):
        guard needStreamSeq < oldestStreamSeq,
          let durable = snapshot.state.streamStates.first(where: {
            $0.streamRoute == streamRoute && $0.generation == relayGeneration
          }),
          Self.checkedNext(durable.outerCursor) == needStreamSeq
        else {
          throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
        }
        return .streamRecoveryRequired(target: target, reason: .cursorGap)
      }

    case .replayComplete(let streamRoute, let relayGeneration, let currentCursor):
      switch try await active.correlation.correlateStreamControl(
        streamRoute: streamRoute,
        relayGeneration: relayGeneration
      ) {
      case .superseded:
        return .ignored
      case .active(let target):
        guard
          let durable = snapshot.state.streamStates.first(where: {
            $0.streamRoute == streamRoute && $0.generation == relayGeneration
          })
        else {
          throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
        }
        if currentCursor == durable.outerCursor { return .ignored }
        guard Self.cursor(currentCursor, isAfter: durable.outerCursor) else {
          throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
        }
        return .streamRecoveryRequired(target: target, reason: .cursorGap)
      }

    case .error(let failure):
      return Self.failureOutcome(failure)

    case .ack:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame

    case .hello, .challenge, .authenticate, .authenticated, .openPairRoute,
      .pairRouteOpened, .pairData, .closePairRoute, .pairRouteClosed,
      .registerStream, .subscribe, .unsubscribe, .send, .installGrant,
      .grantCommitted, .revokeDevice, .retireMachine, .ping, .pong,
      .serverRestarting, .pairingHello:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame
    }
  }

  func commit(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard delivery.machineID == machineID,
      let permit = delivery.ingressPermit,
      var record = deliveries[permit]
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidPermit
    }
    switch record.resolution {
    case .pending:
      let coordinator = self.coordinator
      let expected = record.expectedSnapshot
      let replacement = record.replacementSnapshot
      let prepared = record.preparedCorrelation
      let correlation = record.correlation
      let task = Task<CryptoStateSnapshot?, any Error> {
        if let expected, let replacement, replacement != expected {
          try await coordinator.commitNonCounterState(
            expected: expected,
            replacement: replacement
          )
        }
        if let prepared {
          guard case .active = try await correlation.commitPreparedCorrelation(prepared) else {
            throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
          }
        }
        return replacement
      }
      record.resolution = .committing(task)
      deliveries[permit] = record
      let result = await task.result
      if let error = finishDelivery(permit, result: result) { throw error }
    case .committing(let task):
      let result = await task.result
      if let error = finishDelivery(permit, result: result) { throw error }
    case .committed:
      return
    case .discarded, .failed:
      throw ProductionMachineConnectionVerifiedIngressError.invalidPermit
    }
  }

  func discard(_ delivery: VerifiedRuntimeDelivery) async {
    guard delivery.machineID == machineID,
      let permit = delivery.ingressPermit,
      var record = deliveries[permit]
    else {
      return
    }
    guard case .pending = record.resolution else { return }
    if let prepared = record.preparedCorrelation {
      await record.correlation.discardPreparedCorrelation(prepared)
    }
    if let transferID = record.transferID {
      transferOwner?.discardCompleted(transferID)
      synchronizeTransferExpiryTimer(scope: record.scope)
    }
    releaseAcknowledgementReservation(permit, scope: record.scope)
    record.resolution = .discarded
    record.waiter?.resume()
    record.waiter = nil
    deliveries[permit] = record
    clearUnresolvedPermit(permit, scope: record.scope)
  }

  func awaitResolution(_ delivery: VerifiedRuntimeDelivery) async throws {
    guard delivery.machineID == machineID,
      let permit = delivery.ingressPermit
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidPermit
    }
    try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<Void, any Error>) in
      guard var record = deliveries[permit] else {
        continuation.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.invalidPermit
        )
        return
      }
      switch record.resolution {
      case .committed, .discarded:
        continuation.resume()
      case .failed:
        continuation.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.invalidPermit
        )
      case .pending, .committing:
        guard record.waiter == nil else {
          continuation.resume(
            throwing: ProductionMachineConnectionVerifiedIngressError.duplicateWaiter
          )
          return
        }
        record.waiter = continuation
        deliveries[permit] = record
      }
    }
    deliveries.removeValue(forKey: permit)
  }

  func generationEnded(scope: TransferAssemblyScope) async {
    guard var active = generation,
      active.scope == scope,
      !active.ending
    else {
      return
    }
    active.ending = true
    active.transportActionReservations.removeAll(keepingCapacity: false)
    active.controlReservationByRequestRoute.removeAll(keepingCapacity: false)
    active.streamAppliedReservationByProof.removeAll(keepingCapacity: false)
    generation = active
    cancelTransferExpiryTimer(scope: scope)
    transferOwner?.reset()
    transferOwner = nil

    if let permit = active.unresolvedPermit,
      var record = deliveries[permit]
    {
      switch record.resolution {
      case .pending:
        if let prepared = record.preparedCorrelation {
          await record.correlation.discardPreparedCorrelation(prepared)
        }
        record.resolution = .discarded
        active.acknowledgementReservations.remove(permit)
        generation = active
        record.waiter?.resume(
          throwing: ProductionMachineConnectionVerifiedIngressError.generationEnded
        )
        record.waiter = nil
        deliveries[permit] = record
      case .committing(let task):
        let result = await task.result
        _ = finishDelivery(permit, result: result)
      case .committed, .discarded, .failed:
        break
      }
    }

    for (_, var record) in active.outboundByToken {
      record.waiter?.resume(
        throwing: ProductionMachineConnectionVerifiedIngressError.generationEnded
      )
      record.waiter = nil
    }
    _ = await active.correlation.generationEnded()
    deliveries = deliveries.filter { $0.value.scope != scope }
    generation = nil
  }

  /// correlation 注销失败意味着 ingress 与 correlation 无法继续保持 single owner。
  /// 只终止捕获的 exact generation；新 generation 永远不会被迟到 cleanup 误伤。
  private func failClosedGeneration(
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner
  ) async {
    guard let active = generation,
      active.scope == scope,
      active.correlation === correlation
    else {
      return
    }
    await generationEnded(scope: scope)
  }

  private func synchronizeTransferExpiryTimer(scope: TransferAssemblyScope) {
    guard let active = generation,
      active.scope == scope,
      !active.ending,
      let transferOwner,
      let deadlineMS = transferOwner.nextAbsoluteExpiryMS()
    else {
      cancelTransferExpiryTimer(scope: scope)
      return
    }
    if transferExpiryScope == scope,
      transferExpiryDeadlineMS == deadlineMS,
      transferExpiryToken != nil,
      transferExpiryTask != nil
    {
      return
    }

    cancelTransferExpiryTimer()
    let token = UUID()
    let nowMS = clock()
    let delayMS = deadlineMS > nowMS ? deadlineMS - nowMS : 0
    let sleeper = transferExpirySleeper
    transferExpiryScope = scope
    transferExpiryDeadlineMS = deadlineMS
    transferExpiryToken = token
    transferExpiryTask = Task { [weak self] in
      do {
        try await sleeper.sleep(milliseconds: delayMS)
      } catch {
        return
      }
      await self?.transferExpiryTimerFired(
        scope: scope,
        deadlineMS: deadlineMS,
        token: token
      )
    }
  }

  private func transferExpiryTimerFired(
    scope: TransferAssemblyScope,
    deadlineMS: UInt64,
    token: UUID
  ) {
    guard let active = generation,
      active.scope == scope,
      !active.ending,
      transferExpiryScope == scope,
      transferExpiryDeadlineMS == deadlineMS,
      transferExpiryToken == token,
      let transferOwner
    else {
      return
    }
    transferExpiryTask = nil
    transferExpiryScope = nil
    transferExpiryDeadlineMS = nil
    transferExpiryToken = nil
    transferOwner.sweepExpired(nowMS: clock())
    synchronizeTransferExpiryTimer(scope: scope)
  }

  private func cancelTransferExpiryTimer(scope: TransferAssemblyScope? = nil) {
    if let scope, let scheduledScope = transferExpiryScope, scheduledScope != scope {
      return
    }
    transferExpiryTask?.cancel()
    transferExpiryTask = nil
    transferExpiryScope = nil
    transferExpiryDeadlineMS = nil
    transferExpiryToken = nil
  }

  func drainTransportActions(
    scope: TransferAssemblyScope
  ) async throws -> [RelayV2OutboundFrame] {
    var active = try activeGeneration(scope)
    let actions = active.transportActions
    active.transportActions.removeAll(keepingCapacity: true)
    active.pendingOuterAcknowledgements.removeAll(keepingCapacity: true)
    generation = active
    return actions
  }

  private func receiveSealed(
    wireBytes: Data,
    context: OuterContextV1,
    requestRoute: Data?,
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      wireBytes,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    let now = clock()
    guard now > 0 else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }
    if let episode = snapshot.state.keySyncEpisode {
      try validateKeySyncEpisode(episode, observedAtMS: now)
    }

    if let requestRoute {
      if let keySync = generation?.keySyncRequests[requestRoute] {
        return try await receiveExactNextKeySyncReply(
          wireBytes: wireBytes,
          context: context,
          record: keySync,
          scope: scope,
          observedAtMS: now
        )
      }
      if let completed = generation?.completedKeySyncReplies[requestRoute] {
        return try await receiveCompletedKeySyncReply(
          wireBytes: wireBytes,
          context: context,
          record: completed,
          scope: scope,
          observedAtMS: now
        )
      }
      if generation?.completedKeySyncRoutes.contains(requestRoute) == true {
        return .ignored
      }
    }

    let capability: AuditedReceivingKeyCapabilityV1
    do {
      capability = try inventory.resolveReceivingKey(
        keyID: signed.inner.keyID,
        keyDirectoryRevision: signed.inner.keyDirectoryRevision,
        streamRoute: context.streamRoute,
        nowMS: now
      )
    } catch {
      let next = inventory.activeRevision.addingReportingOverflow(1)
      if !next.overflow,
        let staged = try? inventory.resolveReceivingKey(
          keyID: signed.inner.keyID,
          keyDirectoryRevision: next.partialValue,
          streamRoute: context.streamRoute,
          nowMS: now
        ), case .staged = staged.lifecycle
      {
        return try await receiveStagedControl(
          wireBytes: wireBytes,
          context: context,
          capability: staged,
          scope: scope
        )
      }
      let probe = try dataVerifier.verifyExactNextHigherRevisionProbe(
        wireBytes: wireBytes,
        context: context,
        expectedRequestRoute: requestRoute
      )
      return try await beginKeySync(
        probe: probe,
        scope: scope,
        observedAtMS: now
      )
    }

    let opened: OpenedMachineDataPayload
    let replay: DurableReplayAdmissionResult
    switch capability.lifecycle {
    case .current:
      let binding = try capability.machineDataBinding()
      let verification = try dataVerifier.verify(
        wireBytes: wireBytes,
        context: context,
        receivingKey: binding
      )
      guard case .current(let verified) = verification else {
        let probe = try dataVerifier.verifyExactNextHigherRevisionProbe(
          wireBytes: wireBytes,
          context: context,
          expectedRequestRoute: requestRoute
        )
        return try await beginKeySync(
          probe: probe,
          scope: scope,
          observedAtMS: now
        )
      }
      replay = try await coordinator.admitReplay(
        scope: capability.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: now
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else { return .ignored }
      opened = try dataVerifier.open(verified, receivingKey: binding)

    case .activatedPending:
      let verified = try dataVerifier.verifyActivatedPendingMachineData(
        wireBytes: wireBytes,
        context: context,
        capability: capability,
        expectedRequestRoute: requestRoute
      )
      replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: now
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else { return .ignored }
      switch try dataVerifier.openActivatedPendingMachineData(
        verified,
        replayAdmission: replay
      ) {
      case .data(let value):
        opened = value
      case .epochBarrierDuplicate(let barrier):
        return try await recoverCommittedEpochBarrier(
          barrier,
          context: context,
          replay: replay,
          scope: scope
        )
      }

    case .epochBarrierProofAlias:
      let verified = try dataVerifier.verifyEpochBarrierProofAlias(
        wireBytes: wireBytes,
        context: context,
        capability: capability
      )
      replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: now
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else { return .ignored }
      let barrier = try dataVerifier.openEpochBarrierProofAlias(
        verified,
        replayAdmission: replay
      )
      return try await recoverCommittedEpochBarrier(
        barrier,
        context: context,
        replay: replay,
        scope: scope
      )

    case .directoryAdvancePredecessor:
      let verified = try dataVerifier.verifyDirectoryAdvancePredecessor(
        wireBytes: wireBytes,
        context: context,
        capability: capability
      )
      replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: now
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else { return .ignored }
      let advance = try dataVerifier.openDirectoryAdvancePredecessor(
        verified,
        replayAdmission: replay
      )
      return try await recoverCommittedDirectoryAdvance(
        advance,
        replay: replay,
        scope: scope
      )

    case .retired:
      let verified = try dataVerifier.verifyRetiredMachineData(
        wireBytes: wireBytes,
        context: context,
        capability: capability,
        expectedRequestRoute: requestRoute
      )
      replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: now
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else { return .ignored }
      opened = try dataVerifier.openRetiredMachineData(
        verified,
        replayAdmission: replay
      )

    case .staged:
      return try await receiveStagedControl(
        wireBytes: wireBytes,
        context: context,
        capability: capability,
        scope: scope
      )
    }

    if opened.payloadKind == .keyUpdate {
      return try await receiveCurrentKeyControl(
        opened.payload,
        wireBytes: wireBytes,
        context: context,
        requestRoute: requestRoute,
        replay: replay,
        scope: scope,
        correlation: correlation
      )
    }
    if opened.payloadKind == .transferPart {
      if keySyncPauses(context) { return .ignored }
      return try await receiveTransferPart(
        opened.payload,
        context: context,
        requestRoute: requestRoute,
        replayDisposition: replay.disposition,
        replaySnapshot: replay.snapshot,
        scope: scope,
        correlation: correlation,
        observedAtMS: now
      )
    }
    let envelope = try RuntimeWireCodec.decodeEnvelope(opened.payload)
    if keySyncPauses(context) { return .ignored }
    switch context.frameKind {
    case .catalogPublish, .conversationPublish:
      return try await receiveRuntimePublish(
        envelope,
        payloadKind: opened.payloadKind,
        context: context,
        replayDisposition: replay.disposition,
        replaySnapshot: replay.snapshot,
        scope: scope,
        correlation: correlation
      )
    case .directedReply:
      guard let requestRoute else {
        throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
      }
      return try await receiveRuntimeReply(
        envelope,
        payloadKind: opened.payloadKind,
        requestRoute: requestRoute,
        replaySnapshot: replay.snapshot,
        scope: scope,
        correlation: correlation
      )
    case .uplinkSend, .pairRequest, .pairResponse, .keyUpdate, .pairPending,
      .pairResponseReceived, .deviceKeyRecovery, .pairTerminal:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame
    }
  }

  private func beginKeySync(
    probe: VerifiedHigherRevisionMachineDataProbe,
    scope: TransferAssemblyScope,
    observedAtMS: UInt64
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    var active = try activeGeneration(scope)
    let next = inventory.activeRevision.addingReportingOverflow(1)
    guard !next.overflow,
      probe.keyDirectoryRevision == next.partialValue
    else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    try await rememberPausedKeySyncStream(
      streamRoute: probe.streamRoute,
      streamGeneration: probe.streamGeneration,
      scope: scope
    )
    active = try activeGeneration(scope)
    if let currentRoute = active.currentKeySyncRoute,
      let current = active.keySyncRequests[currentRoute]
    {
      guard current.observedRevision == probe.keyDirectoryRevision else {
        throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
      }
      return .keySyncRequired(observedRevision: current.observedRevision)
    }
    try ensureNoMutation(active)
    active.keySyncMutationPending = true
    generation = active
    do {
      snapshot = try await coordinator.beginOrResumeKeySyncEpisode(
        targetRevision: probe.keyDirectoryRevision,
        observedKeyID: probe.keyID,
        streamRoute: probe.streamRoute,
        observedAtMS: observedAtMS
      )
      guard let episode = snapshot.state.keySyncEpisode,
        var committed = generation,
        committed.scope == scope,
        !committed.ending,
        committed.keySyncMutationPending
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      committed.keySyncWasAnnounced = true
      committed.keySyncMutationPending = false
      generation = committed
      try await queueKeySyncRequest(
        observedRevision: episode.targetRevision,
        observedKeyID: episode.observedKeyID,
        streamRoute: episode.streamRoute,
        attempt: episode.attempt,
        scope: scope
      )
    } catch {
      clearKeySyncMutation(scope: scope)
      throw error
    }
    return .keySyncRequired(observedRevision: probe.keyDirectoryRevision)
  }

  private func queueKeySyncRequest(
    observedRevision: UInt64,
    observedKeyID: KeyIDV1,
    streamRoute: Data?,
    attempt: UInt8,
    scope: TransferAssemblyScope
  ) async throws {
    let active = try activeGeneration(scope)
    try ensureNoMutation(active)
    let next = inventory.activeRevision.addingReportingOverflow(1)
    guard let episode = snapshot.state.keySyncEpisode else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    try validateKeySyncEpisode(episode, observedAtMS: clock())
    guard !next.overflow,
      observedRevision == next.partialValue,
      observedRevision == episode.targetRevision,
      observedKeyID == episode.observedKeyID,
      streamRoute == episode.streamRoute,
      attempt == episode.attempt,
      (1...DeviceKeySyncEpisodeV1.maximumAttempts).contains(attempt),
      active.currentKeySyncRoute == nil,
      active.keySyncRequests.count < Int(DeviceKeySyncEpisodeV1.maximumAttempts)
    else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    guard
      let reservation = try await reserveControlActionCapacity(
        actionCount: 1,
        scope: scope
      )
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    let requestRoute = reservation.requestRoute
    do {
      let capability = try inventory.exactNextKeySyncReplyCapability(
        requestRoute: requestRoute
      )
      let requestStreamRoute =
        observedKeyID.purpose == .conversationDEK ? streamRoute : nil
      let request = DeviceKeyControlRequestV1.keySync(
        try DeviceKeySyncRequestV1(
          authority: keyControlAuthority(),
          knownKeyDirectoryRevision: inventory.activeRevision,
          requestedKeyDirectoryRevision: observedRevision,
          keyID: observedKeyID,
          streamRoute: requestStreamRoute,
          attempt: attempt
        ))
      let record = KeySyncRequestRecord(
        observedRevision: observedRevision,
        observedKeyID: observedKeyID,
        streamRoute: streamRoute,
        attempt: attempt,
        requestRoute: requestRoute,
        replyCapability: capability
      )
      var reserved = try activeGeneration(scope)
      guard reserved.currentKeySyncRoute == nil,
        reserved.keySyncRequests.count < Int(DeviceKeySyncEpisodeV1.maximumAttempts),
        reserved.controlReservationByRequestRoute[requestRoute] == reservation.token
      else {
        throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
      }
      if attempt == 1, reserved.keySyncRequests.isEmpty {
        reserved.keySyncWasAnnounced = true
      }
      reserved.keySyncRequests[requestRoute] = record
      reserved.currentKeySyncRoute = requestRoute
      reserved.keySyncMutationPending = true
      generation = reserved

      let signed = try await requestSigner.signKeyControlRequest(
        request,
        requestRoute: requestRoute
      )
      let frame = try RelayV2OutboundFrame.send(
        deviceRoute: deviceRoute,
        requestRoute: requestRoute,
        sealedBlob: signed.sealedBlob
      )
      guard var committed = generation,
        committed.scope == scope,
        !committed.ending,
        committed.currentKeySyncRoute == requestRoute,
        committed.keySyncRequests[requestRoute] != nil
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      try registerControlAction(
        frame,
        requestRoute: requestRoute,
        reservation: reservation.token,
        scope: scope
      )
      committed = try activeGeneration(scope)
      guard committed.currentKeySyncRoute == requestRoute,
        committed.keySyncRequests[requestRoute] != nil
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      committed.keySyncMutationPending = false
      generation = committed
    } catch {
      if var rollback = generation, rollback.scope == scope {
        rollback.keySyncRequests.removeValue(forKey: requestRoute)
        if rollback.currentKeySyncRoute == requestRoute {
          rollback.currentKeySyncRoute = nil
        }
        rollback.keySyncMutationPending = false
        generation = rollback
      }
      await releaseTransportActionReservation(reservation.token, scope: scope)
      throw error
    }
  }

  private func receiveExactNextKeySyncReply(
    wireBytes: Data,
    context: OuterContextV1,
    record: KeySyncRequestRecord,
    scope: TransferAssemblyScope,
    observedAtMS: UInt64
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    var active = try activeGeneration(scope)
    try ensureNoMutation(active)
    guard active.keySyncRequests[record.requestRoute] != nil else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    active.keySyncMutationPending = true
    generation = active

    do {
      let verified = try dataVerifier.verifyExactNextKeySyncReply(
        wireBytes: wireBytes,
        context: context,
        capability: record.replyCapability
      )
      let replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: observedAtMS
      )
      snapshot = replay.snapshot
      guard replay.disposition != .stale else {
        clearKeySyncMutation(scope: scope)
        return .ignored
      }
      switch try dataVerifier.openExactNextKeySyncResponse(verified) {
      case .updateSet(let updateSet):
        let installed = try await coordinator.stageKeyUpdateSet(
          expected: replay.snapshot,
          canonicalBytes: updateSet.canonicalBytes,
          expectedConversationRoutes: expectedConversationRoutes,
          observedAtMS: observedAtMS,
          verifier: keyUpdateVerifier
        )
        snapshot = installed.snapshot
        try await refreshRuntimeCapabilities(expected: installed.snapshot)

        guard let committed = generation,
          committed.scope == scope,
          !committed.ending,
          committed.keySyncRequests[record.requestRoute] != nil
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        guard
          let reservation = try await reserveControlActionCapacity(
            actionCount: 1,
            scope: scope
          )
        else {
          throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
        }
        do {
          let signed = try await requestSigner.signKeyUpdateAcknowledgement(
            permit: installed.acknowledgementPermit,
            authority: keyControlAuthority(),
            requestRoute: reservation.requestRoute
          )
          let frame = try RelayV2OutboundFrame.send(
            deviceRoute: deviceRoute,
            requestRoute: reservation.requestRoute,
            sealedBlob: signed.sealedBlob
          )
          guard let current = generation,
            current.scope == scope,
            !current.ending,
            current.keySyncRequests[record.requestRoute] != nil
          else {
            throw ProductionMachineConnectionVerifiedIngressError.generationEnded
          }
          try registerControlAction(
            frame,
            requestRoute: reservation.requestRoute,
            reservation: reservation.token,
            scope: scope
          )
          guard var acknowledged = generation,
            acknowledged.scope == scope,
            !acknowledged.ending,
            acknowledged.keySyncRequests[record.requestRoute] != nil
          else {
            throw ProductionMachineConnectionVerifiedIngressError.generationEnded
          }
          acknowledged.completedKeySyncReplies[record.requestRoute] =
            CompletedKeySyncReplyRecord(
              request: record,
              acknowledgementPermit: installed.acknowledgementPermit
            )
          acknowledged.completedKeySyncRoutes.formUnion(
            acknowledged.keySyncRequests.keys
          )
          acknowledged.keySyncRequests.removeAll(keepingCapacity: true)
          acknowledged.currentKeySyncRoute = nil
          acknowledged.keySyncMutationPending = false
          generation = acknowledged
        } catch {
          await releaseTransportActionReservation(reservation.token, scope: scope)
          throw error
        }
        return .ignored

      case .directoryCurrent(let status):
        let authority = try keyControlAuthority()
        guard status.authority == authority,
          status.currentKeyDirectoryRevision == inventory.activeRevision,
          status.requestedKeyDirectoryRevision == record.observedRevision
        else {
          throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
        }
        guard var current = generation,
          current.scope == scope,
          !current.ending
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        if current.currentKeySyncRoute != record.requestRoute {
          current.keySyncMutationPending = false
          generation = current
          return .ignored
        }
        snapshot = try await coordinator.recordKeySyncAttemptFailure(
          targetRevision: record.observedRevision,
          attempt: record.attempt,
          observedAtMS: observedAtMS
        )
        guard let episode = snapshot.state.keySyncEpisode,
          var committed = generation,
          committed.scope == scope,
          !committed.ending,
          committed.currentKeySyncRoute == record.requestRoute
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        committed.currentKeySyncRoute = nil
        committed.keySyncMutationPending = false
        generation = committed
        if !episode.exhausted {
          try await queueKeySyncRequest(
            observedRevision: episode.targetRevision,
            observedKeyID: episode.observedKeyID,
            streamRoute: episode.streamRoute,
            attempt: episode.attempt,
            scope: scope
          )
        }
        return .keySyncAttemptFailed(observedRevision: record.observedRevision)
      }
    } catch {
      clearKeySyncMutation(scope: scope)
      throw error
    }
  }

  private func receiveCompletedKeySyncReply(
    wireBytes: Data,
    context: OuterContextV1,
    record: CompletedKeySyncReplyRecord,
    scope: TransferAssemblyScope,
    observedAtMS: UInt64
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    var active = try activeGeneration(scope)
    try ensureNoMutation(active)
    guard
      active.completedKeySyncReplies[record.request.requestRoute] != nil,
      let episode = snapshot.state.keySyncEpisode,
      episode.targetRevision == record.request.observedRevision
    else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    try validateKeySyncEpisode(episode, observedAtMS: observedAtMS)
    active.keySyncMutationPending = true
    generation = active

    do {
      let verified = try dataVerifier.verifyExactNextKeySyncReply(
        wireBytes: wireBytes,
        context: context,
        capability: record.request.replyCapability
      )
      let replay = try await coordinator.admitReplay(
        scope: verified.replayScope,
        counter: verified.counter,
        ciphertextHash: verified.ciphertextHash,
        observedAtMS: observedAtMS
      )
      snapshot = replay.snapshot
      guard replay.disposition == .exactDuplicate,
        case .updateSet(let updateSet) = try dataVerifier.openExactNextKeySyncResponse(verified),
        updateSet.keyDirectoryRevision == record.acknowledgementPermit.keyDirectoryRevision,
        CanonicalCodec.sha256(updateSet.canonicalBytes)
          == record.acknowledgementPermit.updateSetSHA256
      else {
        throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
      }

      guard let current = generation,
        current.scope == scope,
        !current.ending,
        current.completedKeySyncReplies[record.request.requestRoute] != nil
      else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      guard
        let reservation = try await reserveControlActionCapacity(
          actionCount: 1,
          scope: scope
        )
      else {
        throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
      }
      do {
        let signed = try await requestSigner.signKeyUpdateAcknowledgement(
          permit: record.acknowledgementPermit,
          authority: keyControlAuthority(),
          requestRoute: reservation.requestRoute
        )
        let frame = try RelayV2OutboundFrame.send(
          deviceRoute: deviceRoute,
          requestRoute: reservation.requestRoute,
          sealedBlob: signed.sealedBlob
        )
        guard let registered = generation,
          registered.scope == scope,
          !registered.ending,
          registered.completedKeySyncReplies[record.request.requestRoute] != nil
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        try registerControlAction(
          frame,
          requestRoute: reservation.requestRoute,
          reservation: reservation.token,
          scope: scope
        )
        guard var acknowledged = generation,
          acknowledged.scope == scope,
          !acknowledged.ending,
          acknowledged.completedKeySyncReplies[record.request.requestRoute] != nil
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        acknowledged.keySyncMutationPending = false
        generation = acknowledged
      } catch {
        await releaseTransportActionReservation(reservation.token, scope: scope)
        throw error
      }
      return .ignored
    } catch {
      clearKeySyncMutation(scope: scope)
      throw error
    }
  }

  private func clearKeySyncMutation(scope: TransferAssemblyScope) {
    guard var active = generation, active.scope == scope else { return }
    active.keySyncMutationPending = false
    generation = active
  }

  private func rememberPausedKeySyncStream(
    streamRoute: Data?,
    streamGeneration: Data?,
    scope: TransferAssemblyScope
  ) async throws {
    guard let streamRoute, let streamGeneration else { return }
    let active = try activeGeneration(scope)
    let binding = MachineOuterStreamBinding(
      streamRoute: streamRoute,
      streamGeneration: streamGeneration
    )
    if active.pausedKeySyncStreams[binding] != nil { return }
    let target: VerifiedRuntimeTarget
    switch try await active.correlation.correlateStreamControl(
      streamRoute: streamRoute,
      relayGeneration: streamGeneration
    ) {
    case .superseded:
      return
    case .active(let value):
      target = value
    }
    guard var committed = generation,
      committed.scope == scope,
      !committed.ending,
      committed.pausedKeySyncStreams.count < DeviceCryptoStateV1.maximumStreamStates
    else {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
    }
    committed.pausedKeySyncStreams[binding] = target
    generation = committed
  }

  private func keySyncPauses(_ context: OuterContextV1) -> Bool {
    guard let streamRoute = context.streamRoute,
      let streamGeneration = context.streamGeneration,
      snapshot.state.keySyncEpisode != nil
    else {
      return false
    }
    return generation?.pausedKeySyncStreams[
      MachineOuterStreamBinding(
        streamRoute: streamRoute,
        streamGeneration: streamGeneration
      )
    ] != nil
  }

  private func restorePausedKeySyncStreamIfNeeded(
    binding: MachineOuterStreamBinding,
    target: VerifiedRuntimeTarget,
    scope: TransferAssemblyScope
  ) throws {
    guard snapshot.state.keySyncEpisode?.streamRoute == binding.streamRoute else { return }
    var active = try activeGeneration(scope)
    for stale in Array(active.pausedKeySyncStreams.keys)
    where
      stale.streamRoute == binding.streamRoute && stale != binding
    {
      active.pausedKeySyncStreams.removeValue(forKey: stale)
    }
    if active.pausedKeySyncStreams[binding] == nil {
      guard active.pausedKeySyncStreams.count < DeviceCryptoStateV1.maximumStreamStates else {
        throw ProductionMachineConnectionVerifiedIngressError.keySyncMismatch
      }
    }
    active.pausedKeySyncStreams[binding] = target
    generation = active
  }

  private func validateKeySyncEpisode(
    _ episode: DeviceKeySyncEpisodeV1,
    observedAtMS: UInt64
  ) throws {
    do {
      try episode.validateActive(at: observedAtMS)
    } catch DeviceCryptoStateError.keySyncEpisodeEnded {
      throw ProductionMachineConnectionVerifiedIngressError.keySyncTimedOut
    } catch {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }
  }

  private func receiveTransferPart(
    _ payload: Data,
    context: OuterContextV1,
    requestRoute: Data?,
    replayDisposition: ReplayDisposition,
    replaySnapshot: CryptoStateSnapshot,
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner,
    observedAtMS: UInt64
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    let carrier = try RuntimeWireCodec.decodeTransferCarrier(payload)
    switch carrier.channel {
    case .reply:
      guard let requestRoute,
        let active = generation,
        active.scope == scope,
        active.tokenByRequestRoute[requestRoute] != nil
      else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
      }
    case .stream:
      guard let streamRoute = context.streamRoute,
        let streamGeneration = context.streamGeneration
      else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
      }
      switch try await correlation.correlateStreamControl(
        streamRoute: streamRoute,
        relayGeneration: streamGeneration
      ) {
      case .superseded:
        return .ignored
      case .active:
        break
      }
    }

    guard
      let completed = try acceptTransferPart(
        carrier,
        context: context,
        scope: scope,
        nowMS: observedAtMS
      )
    else {
      return .ignored
    }
    let envelope = try RuntimeWireCodec.decodeAssembledTransferEnvelope(
      completed.assembly.payload,
      channel: completed.assembly.channel
    )
    guard envelope.messageID == completed.assembly.messageID else {
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
    }

    switch completed.assembly.channel {
    case .reply:
      guard let requestRoute, case .reply(let reply) = envelope.body else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
      }
      return try await receiveRuntimeReply(
        envelope,
        payloadKind: try Self.payloadKind(for: reply),
        requestRoute: requestRoute,
        replaySnapshot: replaySnapshot,
        scope: scope,
        correlation: correlation,
        transferID: completed.assembly.transferID
      )

    case .stream:
      guard case .stream(let item) = envelope.body,
        let first = completed.firstStreamSequence,
        let last = completed.lastStreamSequence
      else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
      }
      var completedContext = context
      completedContext.streamSeq = last
      return try await receiveRuntimePublish(
        envelope,
        payloadKind: try Self.payloadKind(for: item),
        context: completedContext,
        replayDisposition: replayDisposition,
        replaySnapshot: replaySnapshot,
        scope: scope,
        correlation: correlation,
        transferRange: first...last,
        transferID: completed.assembly.transferID
      )
    }
  }

  private func acceptTransferPart(
    _ carrier: RuntimeTransferCarrierV2,
    context: OuterContextV1,
    scope: TransferAssemblyScope,
    nowMS: UInt64
  ) throws -> ProductionTransferCompletion? {
    guard let active = generation,
      active.scope == scope,
      !active.ending,
      let transferOwner
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidGeneration
    }
    defer { synchronizeTransferExpiryTimer(scope: scope) }
    return try transferOwner.accept(
      carrier,
      context: context,
      nowMS: nowMS
    )
  }

  private func receiveRuntimePublish(
    _ envelope: RuntimeEnvelopeV2,
    payloadKind: SealedPayloadKind,
    context: OuterContextV1,
    replayDisposition: ReplayDisposition,
    replaySnapshot: CryptoStateSnapshot,
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner,
    transferRange: ClosedRange<UInt64>? = nil,
    transferID: RuntimeTransferID? = nil
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard let streamRoute = context.streamRoute,
      let relayGeneration = context.streamGeneration,
      let streamSeq = context.streamSeq
    else {
      throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
    }
    let correlated: MachineCorrelatedRuntimeStream
    switch try await correlation.correlateStream(
      streamRoute: streamRoute,
      relayGeneration: relayGeneration,
      streamSeq: streamSeq,
      envelope: envelope
    ) {
    case .superseded:
      return .ignored
    case .active(let value):
      correlated = value
    }
    let payload: VerifiedRuntimePayload
    let innerCursor: DeviceInnerCursorV1
    switch correlated.item {
    case .catalogDelta(let delta):
      guard payloadKind == .catalogDelta else {
        throw MachineDataVerifierError.payloadKindMismatch
      }
      payload = .catalogDelta(delta)
      innerCursor = .catalog(.at(delta.catalogRevision))
    case .event(let event):
      guard payloadKind == .conversationEvent else {
        throw MachineDataVerifierError.payloadKindMismatch
      }
      payload = .conversationEvent(event)
      innerCursor = .conversation(
        id: event.conversationID.rawValue,
        cursor: .at(event.eventSeq)
      )
    case .transferPart:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
    case .pairingPending:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame
    }
    if replayDisposition == .exactDuplicate,
      let durable = replaySnapshot.state.streamStates.first(where: {
        $0.streamRoute == streamRoute && $0.generation == relayGeneration
      }),
      case .at(let durableSequence) = durable.outerCursor,
      durableSequence >= streamSeq
    {
      try queueOuterAcknowledgement(
        streamRoute: streamRoute,
        streamGeneration: relayGeneration,
        upToSeq: durableSequence,
        scope: scope
      )
      return .ignored
    }
    let publicationOverlap = replaySnapshot.state.streamStates.contains(where: {
      $0.streamRoute == streamRoute
        && $0.generation == relayGeneration
        && Self.innerCursor($0.innerCursor, covers: innerCursor)
    })
    let replacementState: DeviceCryptoStateV1
    if publicationOverlap {
      let first = transferRange?.lowerBound ?? streamSeq
      let last = transferRange?.upperBound ?? streamSeq
      replacementState = try replaySnapshot.state.advancingPublishedOverlapProgress(
        streamRoute: streamRoute,
        streamGeneration: relayGeneration,
        firstStreamSequence: first,
        lastStreamSequence: last,
        coveredInnerCursor: innerCursor
      )
    } else if let transferRange {
      guard transferRange.upperBound == streamSeq else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
      }
      replacementState = try replaySnapshot.state.advancingPublishedTransferProgress(
        streamRoute: streamRoute,
        streamGeneration: relayGeneration,
        firstStreamSequence: transferRange.lowerBound,
        lastStreamSequence: transferRange.upperBound,
        innerCursor: innerCursor
      )
    } else {
      replacementState = try replaySnapshot.state.advancingPublishedStreamProgress(
        streamRoute: streamRoute,
        streamGeneration: relayGeneration,
        streamSequence: streamSeq,
        innerCursor: innerCursor
      )
    }
    let replacement = try CryptoStateSnapshot(replacementState)
    return try makeDelivery(
      target: correlated.target,
      streamGeneration: correlated.streamGeneration,
      outerCursor: correlated.outerCursor,
      payload: publicationOverlap ? .publicationOverlap : payload,
      scope: scope,
      expectedSnapshot: replaySnapshot,
      replacementSnapshot: replacement,
      preparedCorrelation: nil,
      correlation: correlation,
      transferID: transferID,
      publishAcknowledgement: PublishAcknowledgement(
        streamRoute: streamRoute,
        streamGeneration: relayGeneration,
        upToSeq: streamSeq
      )
    )
  }

  private func receiveRuntimeReply(
    _ envelope: RuntimeEnvelopeV2,
    payloadKind: SealedPayloadKind,
    requestRoute: Data,
    replaySnapshot: CryptoStateSnapshot,
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner,
    transferID: RuntimeTransferID? = nil
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    let prepared: MachinePreparedRequestCorrelation
    switch try await correlation.prepareCorrelation(
      requestRoute: requestRoute,
      envelope: envelope
    ) {
    case .superseded:
      return .ignored
    case .active(let value):
      prepared = value
    }
    do {
      let correlated = prepared.correlated
      try Self.validatePayloadKind(payloadKind, reply: correlated.reply)
      if case .request = correlated.target {
        guard case .active = try await correlation.commitPreparedCorrelation(prepared)
        else {
          throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
        }
        try finishDirectedReply(
          requestRoute: requestRoute,
          reply: correlated.reply,
          scope: scope
        )
        return .ignored
      }
      if case .failure(let failure) = correlated.reply {
        guard case .active = try await correlation.commitPreparedCorrelation(prepared)
        else {
          return .ignored
        }
        removeOutboundRequest(requestRoute: requestRoute, scope: scope)
        return Self.subscriptionFailureOutcome(
          failure,
          target: correlated.target
        )
      }
      guard let streamGeneration = correlated.streamGeneration else {
        throw MachineRequestCorrelationError.invalidSubscriptionOrder
      }
      return try makeDelivery(
        target: correlated.target,
        streamGeneration: streamGeneration,
        outerCursor: Self.replyOuterCursor(correlated.reply),
        payload: try Self.verifiedPayload(correlated.reply, target: correlated.target),
        scope: scope,
        expectedSnapshot: nil,
        replacementSnapshot: nil,
        preparedCorrelation: prepared,
        correlation: correlation,
        transferID: transferID
      )
    } catch {
      await correlation.discardPreparedCorrelation(prepared)
      throw error
    }
  }

  private func receiveCurrentKeyControl(
    _ payload: Data,
    wireBytes: Data,
    context: OuterContextV1,
    requestRoute: Data?,
    replay: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope,
    correlation: MachineRequestCorrelationOwner
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    switch try DaemonKeyControlCanonicalCodec.decode(payload) {
    case .streamBinding(let binding):
      guard let requestRoute else {
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedKeyControl
      }
      let durableBinding = try DeviceDurableStreamBindingV1(binding)
      let prepared: MachinePreparedStreamBindingCorrelation
      switch try await correlation.prepareStreamBinding(
        requestRoute: requestRoute,
        binding: durableBinding
      ) {
      case .superseded:
        return .ignored
      case .active(let value):
        prepared = value
      }
      do {
        let correlated = prepared.correlated
        let installed = try await coordinator.commitSubscriptionBootstrap(
          expected: replay.snapshot,
          binding: binding,
          synchronizedInnerCursor: DeviceInnerCursorV1(
            correlated.synchronizedInnerCursor
          )
        )
        snapshot = installed.snapshot
        try await refreshRuntimeCapabilities(expected: installed.snapshot)
        guard
          case .active(let committed) =
            try await correlation
            .commitPreparedStreamBinding(prepared)
        else {
          throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
        }
        try restorePausedKeySyncStreamIfNeeded(
          binding: committed.binding,
          target: committed.target,
          scope: scope
        )
        try validateRetiredBinding(
          durable: installed.retiredBinding,
          correlated: committed.retiredBinding
        )
        var actions: [RelayV2OutboundFrame] = []
        if let retired = installed.retiredBinding {
          actions.append(
            .control(
              .unsubscribe(
                streamRoute: retired.streamRoute,
                generation: retired.streamGeneration
              )))
        }
        actions.append(
          .control(
            .subscribe(
              streamRoute: committed.binding.streamRoute,
              generation: committed.binding.streamGeneration,
              cursor: committed.bindingCursor
            )))
        if let durableCursor = installed.snapshot.state.streamStates.first(where: {
          $0.streamRoute == committed.binding.streamRoute
            && $0.generation == committed.binding.streamGeneration
        })?.outerCursor,
          case .at(let upToSeq) = durableCursor
        {
          actions.append(
            .control(
              .ack(
                streamRoute: committed.binding.streamRoute,
                generation: committed.binding.streamGeneration,
                upToSeq: upToSeq
              )))
        }
        removeOutboundRequest(requestRoute: requestRoute, scope: scope)
        return .transportActions(actions)
      } catch {
        await correlation.discardPreparedStreamBinding(prepared)
        throw error
      }

    case .epochBarrier(let barrier):
      switch replay.disposition {
      case .fresh where barrier.oldEpoch == 0:
        return try await applyBootstrapEpochBarrier(
          barrier,
          context: context,
          replay: replay,
          scope: scope
        )
      case .exactDuplicate where barrier.oldEpoch == 0:
        do {
          return try await recoverCommittedEpochBarrier(
            barrier,
            context: context,
            replay: replay,
            scope: scope
          )
        } catch DeviceKeyLifecycleError.invalidBarrier {
          // replay admission 与 activation 是两笔 crash-safe CAS。若前者已提交而
          // 后者尚未开始，exact retry 必须在新的 transport reservation 下补做
          // 单向 bootstrap activation，不能永久卡在“duplicate but no proof”。
          return try await applyBootstrapEpochBarrier(
            barrier,
            context: context,
            replay: replay,
            scope: scope
          )
        }
      case .exactDuplicate:
        return try await recoverCommittedEpochBarrier(
          barrier,
          context: context,
          replay: replay,
          scope: scope
        )
      case .fresh:
        throw ProductionMachineConnectionVerifiedIngressError.unsupportedKeyControl
      case .stale:
        return .ignored
      }

    case .directoryRevisionAdvance(let advance):
      let boundAdvance = try advance.binding(to: context)
      switch replay.disposition {
      case .fresh:
        return try await applyFreshDirectoryAdvance(
          boundAdvance,
          replay: replay,
          scope: scope
        )
      case .exactDuplicate:
        return try await recoverCommittedDirectoryAdvance(
          boundAdvance,
          replay: replay,
          scope: scope
        )
      case .stale:
        return .ignored
      }

    case .updateSet, .directoryCurrent:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedKeyControl
    }
  }

  private func applyBootstrapEpochBarrier(
    _ barrier: DeviceEpochBarrierV1,
    context: OuterContextV1,
    replay: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard replay.disposition == .fresh || replay.disposition == .exactDuplicate,
      barrier.oldEpoch == 0,
      context.streamRoute == barrier.streamRoute,
      context.streamGeneration == barrier.streamGeneration,
      context.streamSeq == barrier.appliedStreamSequence,
      let reservation = try await reserveControlActionCapacity(
        actionCount: 2,
        scope: scope
      )
    else {
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedKeyControl
    }
    do {
      let activated = try await coordinator.applyBootstrapEpochBarrier(
        expected: replay.snapshot,
        barrier: barrier,
        expectedConversationRoutes: expectedConversationRoutes,
        verifier: keyUpdateVerifier
      )
      snapshot = activated.snapshot
      let ownsProof = try claimStreamAppliedProof(
        barrier.canonicalSHA256,
        reservation: reservation.token,
        scope: scope
      )
      try await refreshRuntimeCapabilities(expected: activated.snapshot)
      if !ownsProof {
        await releaseTransportActionReservation(reservation.token, scope: scope)
        try queueOuterAcknowledgement(
          streamRoute: barrier.streamRoute,
          streamGeneration: barrier.streamGeneration,
          upToSeq: barrier.appliedStreamSequence,
          scope: scope
        )
        return .ignored
      }
      let signed = try await requestSigner.signStreamAppliedAcknowledgement(
        permit: activated.acknowledgementPermit,
        authority: try keyControlAuthority(),
        requestRoute: reservation.requestRoute
      )
      let frame = try RelayV2OutboundFrame.send(
        deviceRoute: deviceRoute,
        requestRoute: reservation.requestRoute,
        sealedBlob: signed.sealedBlob
      )
      try registerControlAction(
        frame,
        requestRoute: reservation.requestRoute,
        reservation: reservation.token,
        proofSHA256: barrier.canonicalSHA256,
        followingAcknowledgement: PublishAcknowledgement(
          streamRoute: barrier.streamRoute,
          streamGeneration: barrier.streamGeneration,
          upToSeq: barrier.appliedStreamSequence
        ),
        scope: scope
      )
      return .ignored
    } catch {
      await releaseTransportActionReservation(reservation.token, scope: scope)
      throw error
    }
  }

  private func recoverCommittedEpochBarrier(
    _ barrier: DeviceEpochBarrierV1,
    context: OuterContextV1,
    replay: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard replay.disposition == .exactDuplicate,
      context.streamRoute == barrier.streamRoute,
      context.streamGeneration == barrier.streamGeneration,
      context.streamSeq == barrier.appliedStreamSequence
    else {
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedKeyControl
    }
    if try streamAppliedProofIsInFlight(barrier.canonicalSHA256, scope: scope) {
      try queueOuterAcknowledgement(
        streamRoute: barrier.streamRoute,
        streamGeneration: barrier.streamGeneration,
        upToSeq: barrier.appliedStreamSequence,
        scope: scope
      )
      return .ignored
    }
    guard
      let reservation = try await reserveControlActionCapacity(
        actionCount: 2,
        scope: scope
      )
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    do {
      let permit = try await coordinator.recoverStreamAppliedAcknowledgement(
        expected: replay.snapshot,
        barrier: barrier
      )
      guard
        try claimStreamAppliedProof(
          barrier.canonicalSHA256,
          reservation: reservation.token,
          scope: scope
        )
      else {
        await releaseTransportActionReservation(reservation.token, scope: scope)
        try queueOuterAcknowledgement(
          streamRoute: barrier.streamRoute,
          streamGeneration: barrier.streamGeneration,
          upToSeq: barrier.appliedStreamSequence,
          scope: scope
        )
        return .ignored
      }
      let signed = try await requestSigner.signStreamAppliedAcknowledgement(
        permit: permit,
        authority: try keyControlAuthority(),
        requestRoute: reservation.requestRoute
      )
      let frame = try RelayV2OutboundFrame.send(
        deviceRoute: deviceRoute,
        requestRoute: reservation.requestRoute,
        sealedBlob: signed.sealedBlob
      )
      try registerControlAction(
        frame,
        requestRoute: reservation.requestRoute,
        reservation: reservation.token,
        proofSHA256: barrier.canonicalSHA256,
        followingAcknowledgement: PublishAcknowledgement(
          streamRoute: barrier.streamRoute,
          streamGeneration: barrier.streamGeneration,
          upToSeq: barrier.appliedStreamSequence
        ),
        scope: scope
      )
      let durable = replay.snapshot.state
      if durable.senderCounter.keyDirectoryRevision == barrier.keyDirectoryRevision,
        durable.keySyncEpisode == nil
      {
        return keySyncActivationOutcome(
          acceptedRevision: barrier.keyDirectoryRevision,
          scope: scope
        )
      }
      if durable.keyLifecycle?.stagedTransition?.toRevision
        == barrier.keyDirectoryRevision,
        durable.keySyncEpisode?.targetRevision == barrier.keyDirectoryRevision
      {
        return partialKeySyncActivationOutcome(barrier: barrier, scope: scope)
      }
      return .ignored
    } catch {
      await releaseTransportActionReservation(reservation.token, scope: scope)
      throw error
    }
  }

  private func recoverCommittedDirectoryAdvance(
    _ advance: DeviceDirectoryRevisionAdvanceV1,
    replay: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard replay.disposition == .exactDuplicate,
      let reservation = try reserveTransportActionCapacity(
        actionCount: 1,
        scope: scope
      )
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    do {
      try await coordinator.validateRecoveredDirectoryAdvance(
        expected: replay.snapshot,
        advance: advance
      )
      try queueOuterAcknowledgement(
        streamRoute: advance.streamRoute,
        streamGeneration: advance.streamGeneration,
        upToSeq: advance.streamSequence,
        reservation: reservation,
        scope: scope
      )
      return .ignored
    } catch {
      await releaseTransportActionReservation(reservation, scope: scope)
      throw error
    }
  }

  private func applyFreshDirectoryAdvance(
    _ advance: DeviceDirectoryRevisionAdvanceV1,
    replay: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    guard replay.disposition == .fresh,
      let reservation = try reserveTransportActionCapacity(
        actionCount: 1,
        scope: scope
      )
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    do {
      try await rememberPausedKeySyncStream(
        streamRoute: advance.streamRoute,
        streamGeneration: advance.streamGeneration,
        scope: scope
      )
      let committed = try await coordinator.applyDirectoryRevisionAdvance(
        expected: replay.snapshot,
        advance: advance
      )
      snapshot = committed
      try await refreshRuntimeCapabilities(expected: committed)
      try queueOuterAcknowledgement(
        streamRoute: advance.streamRoute,
        streamGeneration: advance.streamGeneration,
        upToSeq: advance.streamSequence,
        reservation: reservation,
        scope: scope
      )
      return keySyncActivationOutcome(
        acceptedRevision: committed.state.senderCounter.keyDirectoryRevision,
        scope: scope
      )
    } catch {
      await releaseTransportActionReservation(reservation, scope: scope)
      throw error
    }
  }

  private func receiveStagedControl(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    let verified = try dataVerifier.verifyStagedKeyControl(
      wireBytes: wireBytes,
      context: context,
      capability: capability
    )
    let replay = try await coordinator.admitReplay(
      scope: verified.replayScope,
      counter: verified.counter,
      ciphertextHash: verified.ciphertextHash,
      observedAtMS: clock()
    )
    snapshot = replay.snapshot
    guard replay.disposition != .stale else { return .ignored }
    return try await receiveStagedControl(
      wireBytes: wireBytes,
      context: context,
      capability: capability,
      replayAdmission: replay,
      scope: scope
    )
  }

  private func receiveStagedControl(
    wireBytes: Data,
    context: OuterContextV1,
    capability: AuditedReceivingKeyCapabilityV1,
    replayAdmission: DurableReplayAdmissionResult,
    scope: TransferAssemblyScope
  ) async throws -> MachineConnectionVerifiedIngressOutcome {
    let verified = try dataVerifier.verifyStagedKeyControl(
      wireBytes: wireBytes,
      context: context,
      capability: capability
    )
    try await rememberPausedKeySyncStream(
      streamRoute: context.streamRoute,
      streamGeneration: context.streamGeneration,
      scope: scope
    )
    switch try dataVerifier.openStagedKeyControl(
      verified,
      replayAdmission: replayAdmission
    ) {
    case .epochBarrier(let barrier):
      guard
        let reservation = try await reserveControlActionCapacity(
          actionCount: 2,
          scope: scope
        )
      else {
        throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
      }
      do {
        let activated = try await coordinator.applyEpochBarrier(
          expected: replayAdmission.snapshot,
          barrier: barrier
        )
        snapshot = activated.snapshot
        let ownsProof = try claimStreamAppliedProof(
          barrier.canonicalSHA256,
          reservation: reservation.token,
          scope: scope
        )
        try await refreshRuntimeCapabilities(expected: activated.snapshot)
        if !ownsProof {
          await releaseTransportActionReservation(reservation.token, scope: scope)
          try queueOuterAcknowledgement(
            streamRoute: barrier.streamRoute,
            streamGeneration: barrier.streamGeneration,
            upToSeq: barrier.appliedStreamSequence,
            scope: scope
          )
          if activated.snapshot.state.senderCounter.keyDirectoryRevision
            != replayAdmission.snapshot.state.senderCounter.keyDirectoryRevision
          {
            return keySyncActivationOutcome(
              acceptedRevision: activated.snapshot.state.senderCounter.keyDirectoryRevision,
              scope: scope
            )
          }
          return partialKeySyncActivationOutcome(barrier: barrier, scope: scope)
        }
        let signed = try await requestSigner.signStreamAppliedAcknowledgement(
          permit: activated.acknowledgementPermit,
          authority: try keyControlAuthority(),
          requestRoute: reservation.requestRoute
        )
        let frame = try RelayV2OutboundFrame.send(
          deviceRoute: deviceRoute,
          requestRoute: reservation.requestRoute,
          sealedBlob: signed.sealedBlob
        )
        try registerControlAction(
          frame,
          requestRoute: reservation.requestRoute,
          reservation: reservation.token,
          proofSHA256: barrier.canonicalSHA256,
          followingAcknowledgement: PublishAcknowledgement(
            streamRoute: barrier.streamRoute,
            streamGeneration: barrier.streamGeneration,
            upToSeq: barrier.appliedStreamSequence
          ),
          scope: scope
        )
        if activated.snapshot.state.senderCounter.keyDirectoryRevision
          != replayAdmission.snapshot.state.senderCounter.keyDirectoryRevision
        {
          return keySyncActivationOutcome(
            acceptedRevision: activated.snapshot.state.senderCounter.keyDirectoryRevision,
            scope: scope
          )
        }
        return partialKeySyncActivationOutcome(barrier: barrier, scope: scope)
      } catch {
        await releaseTransportActionReservation(reservation.token, scope: scope)
        throw error
      }

    case .directoryRevisionAdvance(let advance):
      return try await applyFreshDirectoryAdvance(
        advance,
        replay: replayAdmission,
        scope: scope
      )
    }
  }

  private func keySyncActivationOutcome(
    acceptedRevision: UInt64,
    scope: TransferAssemblyScope
  ) -> MachineConnectionVerifiedIngressOutcome {
    guard var active = generation, active.scope == scope else {
      return .ignored
    }
    let shouldAnnounce = active.keySyncWasAnnounced
    let recoveryTargets = Array(active.pausedKeySyncStreams.values)
    active.keySyncWasAnnounced = false
    active.pausedKeySyncStreams.removeAll(keepingCapacity: false)
    active.completedKeySyncReplies.removeAll(keepingCapacity: false)
    generation = active
    guard shouldAnnounce else { return .ignored }
    return .keySyncSucceeded(
      acceptedRevision: acceptedRevision,
      recoveryTargets: recoveryTargets
    )
  }

  private func partialKeySyncActivationOutcome(
    barrier: DeviceEpochBarrierV1,
    scope: TransferAssemblyScope
  ) -> MachineConnectionVerifiedIngressOutcome {
    guard var active = generation, active.scope == scope else { return .ignored }
    let binding = MachineOuterStreamBinding(
      streamRoute: barrier.streamRoute,
      streamGeneration: barrier.streamGeneration
    )
    guard let target = active.pausedKeySyncStreams.removeValue(forKey: binding) else {
      return .ignored
    }
    generation = active
    return .streamRecoveryRequired(target: target, reason: .snapshotRequired)
  }

  private func makeDelivery(
    target: VerifiedRuntimeTarget,
    streamGeneration: RuntimeStreamGeneration,
    outerCursor: RuntimeStreamCursorV1,
    payload: VerifiedRuntimePayload,
    scope: TransferAssemblyScope,
    expectedSnapshot: CryptoStateSnapshot?,
    replacementSnapshot: CryptoStateSnapshot?,
    preparedCorrelation: MachinePreparedRequestCorrelation?,
    correlation: MachineRequestCorrelationOwner,
    transferID: RuntimeTransferID? = nil,
    publishAcknowledgement: PublishAcknowledgement? = nil
  ) throws -> MachineConnectionVerifiedIngressOutcome {
    var active = try activeGeneration(scope)
    guard active.unresolvedPermit == nil else {
      throw ProductionMachineConnectionVerifiedIngressError.resolutionPending
    }
    let permit = MachineVerifiedDeliveryPermit()
    if publishAcknowledgement != nil {
      guard
        hasTransportActionCapacity(
          actionCount: 1,
          controlRouteCount: 0,
          active: active
        )
      else {
        throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
      }
      active.acknowledgementReservations.insert(permit)
    }
    let delivery = VerifiedRuntimeDelivery(
      machineID: machineID,
      target: target,
      streamGeneration: streamGeneration,
      outerCursor: outerCursor,
      payload: payload,
      ingressPermit: permit
    )
    deliveries[permit] = DeliveryRecord(
      scope: scope,
      transferID: transferID,
      expectedSnapshot: expectedSnapshot,
      replacementSnapshot: replacementSnapshot,
      preparedCorrelation: preparedCorrelation,
      correlation: correlation,
      publishAcknowledgement: publishAcknowledgement,
      resolution: .pending
    )
    active.unresolvedPermit = permit
    generation = active
    return .delivery(delivery)
  }

  @discardableResult
  private func finishDelivery(
    _ permit: MachineVerifiedDeliveryPermit,
    result: Result<CryptoStateSnapshot?, any Error>
  ) -> (any Error)? {
    guard var record = deliveries[permit] else {
      return ProductionMachineConnectionVerifiedIngressError.invalidPermit
    }
    switch record.resolution {
    case .committed:
      return nil
    case .committing:
      break
    case .pending, .discarded, .failed:
      return ProductionMachineConnectionVerifiedIngressError.invalidPermit
    }
    switch result {
    case .success(let committed):
      if let committed { snapshot = committed }
      if record.publishAcknowledgement != nil {
        guard var active = generation,
          active.scope == record.scope,
          active.acknowledgementReservations.remove(permit) != nil
        else {
          let error = ProductionMachineConnectionVerifiedIngressError.invalidPermit
          record.resolution = .failed
          record.waiter?.resume(throwing: error)
          record.waiter = nil
          deliveries[permit] = record
          clearUnresolvedPermit(permit, scope: record.scope)
          return error
        }
        if !active.ending, let acknowledgement = record.publishAcknowledgement {
          let binding = MachineOuterStreamBinding(
            streamRoute: acknowledgement.streamRoute,
            streamGeneration: acknowledgement.streamGeneration
          )
          if active.pendingOuterAcknowledgements[binding].map({
            $0 >= acknowledgement.upToSeq
          }) != true {
            active.transportActions.append(acknowledgement.frame)
            active.pendingOuterAcknowledgements[binding] = acknowledgement.upToSeq
          }
        }
        generation = active
      }
      record.resolution = .committed
      record.waiter?.resume()
      record.waiter = nil
      deliveries[permit] = record
      clearUnresolvedPermit(permit, scope: record.scope)
      return nil
    case .failure(let error):
      releaseAcknowledgementReservation(permit, scope: record.scope)
      record.resolution = .failed
      record.waiter?.resume(throwing: error)
      record.waiter = nil
      deliveries[permit] = record
      clearUnresolvedPermit(permit, scope: record.scope)
      return error
    }
  }

  private func releaseAcknowledgementReservation(
    _ permit: MachineVerifiedDeliveryPermit,
    scope: TransferAssemblyScope
  ) {
    guard var active = generation, active.scope == scope else { return }
    active.acknowledgementReservations.remove(permit)
    generation = active
  }

  private func clearUnresolvedPermit(
    _ permit: MachineVerifiedDeliveryPermit,
    scope: TransferAssemblyScope
  ) {
    guard var active = generation,
      active.scope == scope,
      active.unresolvedPermit == permit
    else {
      return
    }
    active.unresolvedPermit = nil
    generation = active
  }

  private func finishDirectedReply(
    requestRoute: Data,
    reply: RuntimeReplyV2,
    scope: TransferAssemblyScope
  ) throws {
    guard var active = generation,
      active.scope == scope,
      let token = active.tokenByRequestRoute[requestRoute],
      var record = active.outboundByToken[token],
      case .directed = record.kind
    else {
      throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
    }
    record.reply = reply
    record.waiter?.resume(returning: reply)
    record.waiter = nil
    active.outboundByToken[token] = record
    generation = active
  }

  private func removeOutboundRequest(
    requestRoute: Data,
    scope: TransferAssemblyScope
  ) {
    guard var active = generation, active.scope == scope else { return }
    if let token = active.tokenByRequestRoute.removeValue(forKey: requestRoute) {
      active.outboundByToken.removeValue(forKey: token)
    }
    generation = active
  }

  private func removePreparedOutbound(
    token: MachinePreparedOutboundRequestToken,
    requestRoute: Data,
    scope: TransferAssemblyScope
  ) {
    guard var active = generation, active.scope == scope else { return }
    if active.tokenByRequestRoute[requestRoute] == token {
      active.tokenByRequestRoute.removeValue(forKey: requestRoute)
    }
    if active.outboundByToken[token]?.requestRoute == requestRoute {
      active.outboundByToken.removeValue(forKey: token)
    }
    generation = active
  }

  private func registerControlAction(
    _ frame: RelayV2OutboundFrame,
    requestRoute: Data,
    reservation: TransportActionReservationToken,
    proofSHA256: Data? = nil,
    followingAcknowledgement: PublishAcknowledgement? = nil,
    scope: TransferAssemblyScope
  ) throws {
    var active = try activeGeneration(scope)
    let reserved = active.transportActionReservations[reservation]
    let proofReservationMatches =
      proofSHA256.map {
        active.streamAppliedRequestRouteByProof[$0] == nil
          && active.streamAppliedReservationByProof[$0] == reservation
      } ?? true
    guard reserved?.controlRequestRoute == requestRoute,
      reserved?.controlRouteCount == 1,
      reserved?.controlRouteClaim?.requestRoute == requestRoute,
      active.controlReservationByRequestRoute[requestRoute] == reservation,
      !active.controlRequestRoutes.contains(requestRoute),
      active.controlRouteClaimByRequestRoute[requestRoute] == nil,
      proofReservationMatches
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    var frames = [frame]
    if let acknowledgement = followingAcknowledgement {
      let binding = MachineOuterStreamBinding(
        streamRoute: acknowledgement.streamRoute,
        streamGeneration: acknowledgement.streamGeneration
      )
      if active.pendingOuterAcknowledgements[binding].map({
        $0 >= acknowledgement.upToSeq
      }) != true {
        frames.append(acknowledgement.frame)
        active.pendingOuterAcknowledgements[binding] = acknowledgement.upToSeq
      }
    }
    try consumeTransportActionReservation(
      reservation,
      frames: frames,
      controlRequestRoute: requestRoute,
      in: &active
    )
    active.controlRequestRoutes.insert(requestRoute)
    if let proofSHA256 {
      active.streamAppliedReservationByProof.removeValue(forKey: proofSHA256)
      active.streamAppliedRequestRouteByProof[proofSHA256] = requestRoute
      active.streamAppliedProofByRequestRoute[requestRoute] = proofSHA256
    }
    generation = active
  }

  private func reserveTransportActionCapacity(
    actionCount: Int,
    scope: TransferAssemblyScope
  ) throws -> TransportActionReservationToken? {
    var active = try activeGeneration(scope)
    guard actionCount > 0,
      hasTransportActionCapacity(
        actionCount: actionCount,
        controlRouteCount: 0,
        active: active
      )
    else { return nil }
    let token = TransportActionReservationToken()
    active.transportActionReservations[token] = TransportActionReservationRecord(
      actionCount: actionCount,
      controlRouteCount: 0,
      controlRequestRoute: nil,
      controlRouteClaim: nil
    )
    generation = active
    return token
  }

  private func reserveControlActionCapacity(
    actionCount: Int,
    scope: TransferAssemblyScope
  ) async throws -> ControlActionReservation? {
    let captured = try activeGeneration(scope)
    guard actionCount > 0,
      hasTransportActionCapacity(
        actionCount: actionCount,
        controlRouteCount: 1,
        active: captured
      )
    else { return nil }
    let requestRoute = try freshRequestRoute(captured)
    let correlation = captured.correlation
    let routeClaim: MachineControlRequestRouteClaim
    do {
      routeClaim = try await correlation.claimControlRequestRoute(requestRoute)
    } catch MachineRequestCorrelationError.capacityExceeded {
      return nil
    } catch MachineRequestCorrelationError.generationEnded {
      throw ProductionMachineConnectionVerifiedIngressError.generationEnded
    } catch {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }

    do {
      var active = try activeGeneration(scope)
      guard active.correlation === correlation else {
        throw ProductionMachineConnectionVerifiedIngressError.generationEnded
      }
      guard
        hasTransportActionCapacity(
          actionCount: actionCount,
          controlRouteCount: 1,
          active: active
        )
      else {
        await correlation.releaseControlRequestRoute(routeClaim)
        return nil
      }
      try validateFreshRequestRoute(requestRoute, active: active)
      let token = TransportActionReservationToken()
      active.transportActionReservations[token] = TransportActionReservationRecord(
        actionCount: actionCount,
        controlRouteCount: 1,
        controlRequestRoute: requestRoute,
        controlRouteClaim: routeClaim
      )
      active.controlReservationByRequestRoute[requestRoute] = token
      generation = active
      return ControlActionReservation(token: token, requestRoute: requestRoute)
    } catch {
      await correlation.releaseControlRequestRoute(routeClaim)
      throw error
    }
  }

  private func releaseTransportActionReservation(
    _ token: TransportActionReservationToken,
    scope: TransferAssemblyScope
  ) async {
    guard var active = generation, active.scope == scope else { return }
    let correlation = active.correlation
    let routeClaim = releaseTransportActionReservation(token, in: &active)
    generation = active
    if let routeClaim {
      await correlation.releaseControlRequestRoute(routeClaim)
    }
  }

  private func releaseTransportActionReservation(
    _ token: TransportActionReservationToken,
    in active: inout GenerationState
  ) -> MachineControlRequestRouteClaim? {
    let reserved = active.transportActionReservations.removeValue(forKey: token)
    if let requestRoute = reserved?.controlRequestRoute,
      active.controlReservationByRequestRoute[requestRoute] == token
    {
      active.controlReservationByRequestRoute.removeValue(forKey: requestRoute)
    }
    active.streamAppliedReservationByProof = active.streamAppliedReservationByProof.filter {
      $0.value != token
    }
    return reserved?.controlRouteClaim
  }

  private func claimStreamAppliedProof(
    _ proofSHA256: Data,
    reservation: TransportActionReservationToken,
    scope: TransferAssemblyScope
  ) throws -> Bool {
    var active = try activeGeneration(scope)
    guard let reserved = active.transportActionReservations[reservation],
      let requestRoute = reserved.controlRequestRoute,
      reserved.controlRouteCount == 1,
      active.controlReservationByRequestRoute[requestRoute] == reservation
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    guard active.streamAppliedRequestRouteByProof[proofSHA256] == nil,
      active.streamAppliedReservationByProof[proofSHA256] == nil
    else { return false }
    active.streamAppliedReservationByProof[proofSHA256] = reservation
    generation = active
    return true
  }

  private func streamAppliedProofIsInFlight(
    _ proofSHA256: Data,
    scope: TransferAssemblyScope
  ) throws -> Bool {
    let active = try activeGeneration(scope)
    return active.streamAppliedRequestRouteByProof[proofSHA256] != nil
      || active.streamAppliedReservationByProof[proofSHA256] != nil
  }

  private func consumeTransportActionReservation(
    _ token: TransportActionReservationToken,
    frames: [RelayV2OutboundFrame],
    controlRequestRoute: Data?,
    in active: inout GenerationState
  ) throws {
    guard let reserved = active.transportActionReservations[token],
      !frames.isEmpty,
      frames.count <= reserved.actionCount,
      reserved.controlRouteCount == (controlRequestRoute == nil ? 0 : 1),
      reserved.controlRequestRoute == controlRequestRoute,
      (controlRequestRoute == nil) == (reserved.controlRouteClaim == nil)
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    if let controlRequestRoute {
      guard active.controlReservationByRequestRoute[controlRequestRoute] == token,
        let routeClaim = reserved.controlRouteClaim,
        routeClaim.requestRoute == controlRequestRoute,
        active.controlRouteClaimByRequestRoute[controlRequestRoute] == nil
      else {
        throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
      }
      active.controlReservationByRequestRoute.removeValue(forKey: controlRequestRoute)
      active.controlRouteClaimByRequestRoute[controlRequestRoute] = routeClaim
    } else {
      guard !active.controlReservationByRequestRoute.values.contains(token) else {
        throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
      }
    }
    active.transportActionReservations.removeValue(forKey: token)
    try appendTransportActions(frames, to: &active)
  }

  private func queueOuterAcknowledgement(
    streamRoute: Data,
    streamGeneration: Data,
    upToSeq: UInt64,
    reservation: TransportActionReservationToken? = nil,
    scope: TransferAssemblyScope
  ) throws {
    var active = try activeGeneration(scope)
    let binding = MachineOuterStreamBinding(
      streamRoute: streamRoute,
      streamGeneration: streamGeneration
    )
    if active.pendingOuterAcknowledgements[binding].map({ $0 >= upToSeq }) == true {
      if let reservation {
        _ = releaseTransportActionReservation(reservation, in: &active)
      }
      generation = active
      return
    }
    let frames = [
      RelayV2OutboundFrame.control(
        .ack(
          streamRoute: streamRoute,
          generation: streamGeneration,
          upToSeq: upToSeq
        ))
    ]
    if let reservation {
      try consumeTransportActionReservation(
        reservation,
        frames: frames,
        controlRequestRoute: nil,
        in: &active
      )
    } else {
      try appendTransportActions(frames, to: &active)
    }
    active.pendingOuterAcknowledgements[binding] = upToSeq
    generation = active
  }

  private func queueRecoveredStreamAppliedAcknowledgements(
    scope: TransferAssemblyScope
  ) async throws {
    while true {
      let active = try activeGeneration(scope)
      guard
        active.recoveredAcknowledgementRequestRoutes.count
          < Self.maximumRecoveredAcknowledgementsPerBatch
      else {
        return
      }
      guard let permit = active.pendingRecoveredStreamAppliedAcknowledgements.first else {
        return
      }
      guard
        let reservation = try await reserveControlActionCapacity(
          actionCount: 1,
          scope: scope
        )
      else { return }
      do {
        guard
          try claimStreamAppliedProof(
            permit.epochBarrierSHA256,
            reservation: reservation.token,
            scope: scope
          )
        else {
          await releaseTransportActionReservation(reservation.token, scope: scope)
          return
        }
        let signed = try await requestSigner.signStreamAppliedAcknowledgement(
          permit: permit,
          authority: try keyControlAuthority(),
          requestRoute: reservation.requestRoute
        )
        let frame = try RelayV2OutboundFrame.send(
          deviceRoute: deviceRoute,
          requestRoute: reservation.requestRoute,
          sealedBlob: signed.sealedBlob
        )
        try registerControlAction(
          frame,
          requestRoute: reservation.requestRoute,
          reservation: reservation.token,
          proofSHA256: permit.epochBarrierSHA256,
          scope: scope
        )
        guard var committed = generation,
          committed.scope == scope,
          !committed.ending,
          committed.pendingRecoveredStreamAppliedAcknowledgements.first?
            .epochBarrierSHA256 == permit.epochBarrierSHA256
        else {
          throw ProductionMachineConnectionVerifiedIngressError.generationEnded
        }
        committed.recoveredAcknowledgementRequestRoutes.insert(
          reservation.requestRoute
        )
        committed.pendingRecoveredStreamAppliedAcknowledgements.removeFirst()
        generation = committed
      } catch {
        await releaseTransportActionReservation(reservation.token, scope: scope)
        throw error
      }
    }
  }

  private func appendTransportActions(
    _ frames: [RelayV2OutboundFrame],
    to active: inout GenerationState
  ) throws {
    let queued = active.transportActions.count.addingReportingOverflow(frames.count)
    let deliveryReserved = queued.partialValue.addingReportingOverflow(
      active.acknowledgementReservations.count
    )
    let actionReserved = reservedTransportActionCount(active)
    let total = deliveryReserved.partialValue.addingReportingOverflow(actionReserved ?? 0)
    guard !queued.overflow,
      !deliveryReserved.overflow,
      actionReserved != nil,
      !total.overflow,
      total.partialValue <= Self.maximumQueuedTransportActions
    else {
      throw ProductionMachineConnectionVerifiedIngressError.outboundCapacity
    }
    active.transportActions.append(contentsOf: frames)
  }

  private func hasTransportActionCapacity(
    actionCount: Int,
    controlRouteCount: Int,
    active: GenerationState
  ) -> Bool {
    guard let actionReserved = reservedTransportActionCount(active),
      let routeReserved = reservedControlRouteCount(active)
    else { return false }
    let queuedAndDelivery = active.transportActions.count.addingReportingOverflow(
      active.acknowledgementReservations.count
    )
    let usedActions = queuedAndDelivery.partialValue.addingReportingOverflow(actionReserved)
    let projectedActions = usedActions.partialValue.addingReportingOverflow(actionCount)
    let usedRoutes = active.controlRequestRoutes.count.addingReportingOverflow(routeReserved)
    let projectedRoutes = usedRoutes.partialValue.addingReportingOverflow(controlRouteCount)
    return !queuedAndDelivery.overflow
      && !usedActions.overflow
      && !projectedActions.overflow
      && projectedActions.partialValue <= Self.maximumQueuedTransportActions
      && !usedRoutes.overflow
      && !projectedRoutes.overflow
      && projectedRoutes.partialValue <= Self.maximumQueuedTransportActions
  }

  private func reservedTransportActionCount(_ active: GenerationState) -> Int? {
    active.transportActionReservations.values.reduce(Optional(0)) { partial, record in
      guard let partial else { return nil }
      let sum = partial.addingReportingOverflow(record.actionCount)
      return sum.overflow ? nil : sum.partialValue
    }
  }

  private func reservedControlRouteCount(_ active: GenerationState) -> Int? {
    active.transportActionReservations.values.reduce(Optional(0)) { partial, record in
      guard let partial else { return nil }
      let sum = partial.addingReportingOverflow(record.controlRouteCount)
      return sum.overflow ? nil : sum.partialValue
    }
  }

  private func refreshRuntimeCapabilities(
    expected: CryptoStateSnapshot
  ) async throws {
    let audited = try await coordinator.auditColdOpen(
      expected: expected,
      expectedConversationRoutes: expectedConversationRoutes,
      verifier: keyUpdateVerifier
    )
    inventory = audited
    dataVerifier = try Self.makeDataVerifier(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      verifiedCertificate: verifiedCertificate,
      revision: audited.activeRevision
    )
    requestSigner = try Self.makeRequestSigner(
      context: signerContext,
      inventory: audited,
      counterAllocator: counterAllocator
    )
  }

  private func activeGeneration(
    _ scope: TransferAssemblyScope
  ) throws -> GenerationState {
    guard let generation,
      generation.scope == scope,
      !generation.ending
    else {
      throw ProductionMachineConnectionVerifiedIngressError.generationNotActive
    }
    return generation
  }

  private func ensureNoMutation(_ active: GenerationState) throws {
    guard active.unresolvedPermit == nil,
      !active.keySyncMutationPending
    else {
      throw ProductionMachineConnectionVerifiedIngressError.resolutionPending
    }
  }

  private func freshRequestRoute(_ active: GenerationState) throws -> Data {
    let route = try requestRouteGenerator()
    try validateFreshRequestRoute(route, active: active)
    return route
  }

  private func validateFreshRequestRoute(
    _ route: Data,
    active: GenerationState
  ) throws {
    guard route.count == 16,
      route.contains(where: { $0 != 0 }),
      active.tokenByRequestRoute[route] == nil,
      !active.outboundByToken.values.contains(where: { $0.requestRoute == route }),
      !active.controlRequestRoutes.contains(route),
      active.controlReservationByRequestRoute[route] == nil,
      active.keySyncRequests[route] == nil,
      active.currentKeySyncRoute != route,
      !active.completedKeySyncRoutes.contains(route),
      active.completedKeySyncReplies[route] == nil,
      !active.recoveredAcknowledgementRequestRoutes.contains(route),
      active.streamAppliedProofByRequestRoute[route] == nil,
      !active.streamAppliedRequestRouteByProof.values.contains(route)
    else {
      throw ProductionMachineConnectionVerifiedIngressError.invalidConfiguration
    }
  }

  private func publicationContext(
    sealedBlob: Data,
    streamRoute: Data,
    relayGeneration: Data,
    streamSeq: UInt64
  ) throws -> OuterContextV1 {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      sealedBlob,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    let frameKind: OuterFrameKind
    switch signed.inner.keyID.purpose {
    case .catalog:
      frameKind = .catalogPublish
    case .conversationDEK:
      frameKind = .conversationPublish
    case .deviceCommandTx, .deviceReplyTx:
      throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
    }
    return OuterContextV1(
      frameKind: frameKind,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: machineRoute,
      deviceRoute: nil,
      streamRoute: streamRoute,
      requestRoute: nil,
      streamGeneration: relayGeneration,
      streamCursor: nil,
      streamSeq: streamSeq,
      messageKeyEpoch: signed.inner.keyEpoch
    )
  }

  private func replyContext(
    sealedBlob: Data,
    requestRoute: Data
  ) throws -> OuterContextV1 {
    let signed = try RelayV2SignedSealedBlobCodec.decode(
      sealedBlob,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    guard signed.inner.keyID.purpose == .deviceReplyTx else {
      throw ProductionMachineConnectionVerifiedIngressError.noncanonicalFrame
    }
    return OuterContextV1(
      frameKind: .directedReply,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      streamRoute: nil,
      requestRoute: requestRoute,
      streamGeneration: nil,
      streamCursor: nil,
      streamSeq: nil,
      messageKeyEpoch: signed.inner.keyEpoch
    )
  }

  private func keyControlAuthority() throws -> DeviceKeyControlAuthorityV1 {
    try DeviceKeyControlAuthorityV1(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: signerContext.grantSerial,
      rootTrustEpoch: signerContext.trustEpoch
    )
  }

  private func validateRetiredBinding(
    durable: DeviceDurableStreamBindingV1?,
    correlated: MachineOuterStreamBinding?
  ) throws {
    switch (durable, correlated) {
    case (nil, nil):
      return
    case (.some(let durable), .some(let correlated)):
      guard durable.streamRoute == correlated.streamRoute,
        durable.streamGeneration == correlated.streamGeneration
      else {
        throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
      }
    case (.some, .none):
      // Correlation owner 只活在当前 transport generation；durable state 才能在
      // reconnect 后精确指出必须先退休的旧 binding。
      return
    case (.none, .some):
      throw ProductionMachineConnectionVerifiedIngressError.correlationSuperseded
    }
  }

  private static func makeDataVerifier(
    machineRoute: Data,
    deviceRoute: Data,
    verifiedCertificate: VerifiedMachineDataCertificate,
    revision: UInt64
  ) throws -> MachineDataVerifier {
    try MachineDataVerifier(
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      verifiedCertificate: verifiedCertificate,
      currentKeyDirectoryRevision: revision,
      maximumKeySyncAdvance: 1
    )
  }

  private static func makeRequestSigner(
    context: SignerContext,
    inventory: AuditedDeviceKeyInventoryV1,
    counterAllocator: CounterAllocator
  ) throws -> DeviceRequestSigner {
    if let deviceSignatureProducer = context.deviceSignatureProducer {
      return try DeviceRequestSigner(
        expectedRelayServerID: context.relayServerID,
        expectedGrant: context.grant,
        expectedMachineRoute: context.machineRoute,
        expectedDeviceRoute: context.deviceRoute,
        expectedGrantSerial: context.grantSerial,
        machineRootPublicKey: context.machineRootPublicKey,
        machineRootFingerprint: context.machineRootFingerprint,
        expectedRootKeyID: context.rootKeyID,
        expectedTrustEpoch: context.trustEpoch,
        signatureProducer: deviceSignatureProducer,
        commandKey: inventory.commandKey,
        counterAllocator: counterAllocator
      )
    }
    return try DeviceRequestSigner(
      expectedRelayServerID: context.relayServerID,
      expectedGrant: context.grant,
      expectedMachineRoute: context.machineRoute,
      expectedDeviceRoute: context.deviceRoute,
      expectedGrantSerial: context.grantSerial,
      machineRootPublicKey: context.machineRootPublicKey,
      machineRootFingerprint: context.machineRootFingerprint,
      expectedRootKeyID: context.rootKeyID,
      expectedTrustEpoch: context.trustEpoch,
      deviceSigningKey: context.deviceSigningKey,
      commandKey: inventory.commandKey,
      counterAllocator: counterAllocator
    )
  }

  private static func validatePayloadKind(
    _ payloadKind: SealedPayloadKind,
    reply: RuntimeReplyV2
  ) throws {
    guard payloadKind == (try Self.payloadKind(for: reply)) else {
      throw MachineDataVerifierError.payloadKindMismatch
    }
  }

  private static func payloadKind(
    for reply: RuntimeReplyV2
  ) throws -> SealedPayloadKind {
    switch reply {
    case .catalog:
      return .catalogSnapshot
    case .snapshot:
      return .conversationSnapshot
    case .backfill:
      return .backfillChunk
    case .transferPart:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
    case .hello, .agents, .configuration, .conversationMetadata, .stageUpgrade,
      .command, .commandStatus, .conversationStart, .cancellation, .approval,
      .revocation, .subscription, .syncComplete, .pairInvite, .pendingPairings,
      .pairing, .machineRemoteStatus, .failure:
      return .commandReceipt
    }
  }

  private static func payloadKind(
    for item: RuntimeStreamItemV2
  ) throws -> SealedPayloadKind {
    switch item {
    case .catalogDelta:
      return .catalogDelta
    case .event:
      return .conversationEvent
    case .transferPart:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
    case .pairingPending:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedFrame
    }
  }

  private static func verifiedPayload(
    _ reply: RuntimeReplyV2,
    target: VerifiedRuntimeTarget
  ) throws -> VerifiedRuntimePayload {
    switch reply {
    case .catalog(let snapshot):
      return .catalogSnapshot(snapshot)
    case .snapshot(let snapshot):
      return .conversationSnapshot(snapshot)
    case .backfill(let chunk):
      switch target {
      case .catalog:
        return .catalogBackfill(chunk)
      case .conversation:
        return .conversationBackfill(chunk)
      case .request, .pairing:
        throw MachineRequestCorrelationError.subscriptionMismatch
      }
    case .commandStatus(let receipt):
      return .commandState(receipt)
    case .syncComplete(let sync):
      return .syncComplete(sync)
    case .transferPart:
      throw ProductionMachineConnectionVerifiedIngressError.unsupportedTransfer
    case .hello, .agents, .configuration, .conversationMetadata, .stageUpgrade,
      .command, .conversationStart, .cancellation, .approval, .revocation,
      .subscription, .pairInvite, .pendingPairings, .pairing,
      .machineRemoteStatus, .failure:
      return .typedReply(reply)
    }
  }

  private static func replyOuterCursor(
    _ reply: RuntimeReplyV2
  ) -> RuntimeStreamCursorV1 {
    if case .syncComplete(let sync) = reply {
      return sync.streamCursor
    }
    return .beforeFirst
  }

  private static func checkedNext(_ cursor: StreamCursor) -> UInt64? {
    switch cursor {
    case .beforeFirst:
      return 0
    case .at(let value):
      let next = value.addingReportingOverflow(1)
      return next.overflow ? nil : next.partialValue
    }
  }

  private static func cursor(
    _ candidate: StreamCursor,
    isAfter previous: StreamCursor
  ) -> Bool {
    switch (candidate, previous) {
    case (.beforeFirst, _):
      return false
    case (.at, .beforeFirst):
      return true
    case (.at(let candidate), .at(let previous)):
      return candidate > previous
    }
  }

  private static func cursor(
    _ candidate: StreamCursor,
    isAtOrAfter previous: StreamCursor
  ) -> Bool {
    switch (candidate, previous) {
    case (_, .beforeFirst):
      return true
    case (.beforeFirst, .at):
      return false
    case (.at(let candidate), .at(let previous)):
      return candidate >= previous
    }
  }

  private static func innerCursor(
    _ candidate: DeviceInnerCursorV1,
    covers covered: DeviceInnerCursorV1
  ) -> Bool {
    switch (candidate, covered) {
    case (.catalog(let candidate), .catalog(let covered)):
      return cursor(candidate, isAtOrAfter: covered)
    case (
      .conversation(let candidateID, let candidate),
      .conversation(let coveredID, let covered)
    ):
      return candidateID == coveredID && cursor(candidate, isAtOrAfter: covered)
    case (.catalog, .conversation), (.conversation, .catalog):
      return false
    }
  }

  private static func failureOutcome(
    _ failure: RelayV2Failure
  ) -> MachineConnectionVerifiedIngressOutcome {
    switch failure.code {
    case "relay.route.not_found":
      return .machineOffline
    case "relay.auth.challenge_expired", "relay.store.unavailable",
      "relay.quota.exceeded", "relay.disk.low":
      return .relayUnavailable
    case "relay.version.unsupported":
      return .incompatible
    default:
      return .securityError
    }
  }

  /// Runtime subscribe 可以在 `Subscribed`/stream generation 之前合法返回 typed
  /// Failure。该 reply 已完成 MachineDataSign、replay 与 exact request correlation，
  /// 不能再被当成订阅顺序攻击；只允许固定 allowlist 决定 fresh snapshot 或重连。
  private static func subscriptionFailureOutcome(
    _ failure: RuntimeFailureV1,
    target: VerifiedRuntimeTarget
  ) -> MachineConnectionVerifiedIngressOutcome {
    if failure.code == "daemon.runtime.snapshot_required"
      || failure.message == "retained range requires a new snapshot"
    {
      return .streamRecoveryRequired(target: target, reason: .snapshotRequired)
    }
    switch failure.code {
    case "daemon.remote.transition.business_fenced",
      "daemon.remote.transition.progress_pending",
      "daemon.remote.transition.reconnect_pending",
      "daemon.runtime.connection_unavailable",
      "daemon.runtime.read_unavailable",
      "daemon.runtime.store_unavailable",
      "daemon.runtime.store_busy",
      "daemon.runtime.recovering",
      "daemon.runtime.not_ready",
      "daemon.runtime.disk_low":
      return .relayUnavailable
    case "daemon.runtime.protocol_mismatch":
      return .incompatible
    default:
      return .securityError
    }
  }
}
