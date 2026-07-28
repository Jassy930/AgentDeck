import Foundation
import Security

enum CryptoStatePersistenceStage: Equatable, Sendable {
  case guardPendingDurable
  case stateGuardPendingDurable
  case stateDurable
  case guardStableDurable
  case keyTransitionGuardPendingDurable
  case keyTransitionStateDurable
  case keyTransitionGuardStableDurable
  case securityQuarantineDurable
}

typealias CryptoStatePersistenceObserver =
  @Sendable (CryptoStatePersistenceStage) async throws -> Void
typealias CounterReservationIDGenerator = @Sendable () throws -> Data
typealias CryptoStateClock = @Sendable () -> UInt64

/// pairing promotion 才能构造的初始 guard capability；不属于 public API。
struct CounterBootstrapPermit: Sendable {
  let snapshot: CryptoStateSnapshot
  let promotionID: Data

  init(snapshot: CryptoStateSnapshot, promotionID: Data) throws {
    guard promotionID.count == 32,
      !promotionID.allSatisfy({ $0 == 0 }),
      snapshot.state.stateRevision == 1,
      snapshot.state.senderCounter.reservedHighWater == 0,
      snapshot.state.senderCounter.reservationID.allSatisfy({ $0 == 0 }),
      snapshot.state.securityState == .active
    else {
      throw CounterAllocatorError.invalidState
    }
    self.snapshot = snapshot
    self.promotionID = promotionID
  }
}

struct CounterBootstrapEvidence: Equatable, Sendable {
  let initialStateCommitment: Data
  let initialGuardCommitment: Data
}

/// 只有 exact KeyUpdateSet 已经 sealed-state durable 且 CounterGuard stable readback 后才能 mint。
struct DurableKeyUpdateAckPermit: Sendable, CustomDebugStringConvertible {
  let trustScope: DeviceCryptoTrustScopeV1
  let keyDirectoryRevision: UInt64
  let updateSetSHA256: Data

  fileprivate init(
    trustScope: DeviceCryptoTrustScopeV1,
    keyDirectoryRevision: UInt64,
    updateSetSHA256: Data
  ) throws {
    guard keyDirectoryRevision > 0,
      updateSetSHA256.count == 32,
      updateSetSHA256.contains(where: { $0 != 0 })
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    self.trustScope = trustScope
    self.keyDirectoryRevision = keyDirectoryRevision
    self.updateSetSHA256 = updateSetSHA256
  }

  var debugDescription: String {
    "DurableKeyUpdateAckPermit(revision: \(keyDirectoryRevision), proof: <redacted>)"
  }
}

/// 只有 exact barrier activation 与 cursor/replay/key CAS durable 后才能 mint。
struct DurableStreamAppliedAckPermit: Sendable, CustomDebugStringConvertible {
  let trustScope: DeviceCryptoTrustScopeV1
  let streamRoute: Data
  let streamGeneration: Data
  let appliedStreamSequence: UInt64
  let innerCursor: DeviceInnerCursorV1
  let keyDirectoryRevision: UInt64
  let keyEpoch: UInt64
  let epochBarrierSHA256: Data

  fileprivate init(
    trustScope: DeviceCryptoTrustScopeV1,
    barrier: DeviceEpochBarrierV1
  ) throws {
    guard barrier.canonicalSHA256.count == 32,
      barrier.canonicalSHA256.contains(where: { $0 != 0 })
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    self.trustScope = trustScope
    streamRoute = barrier.streamRoute
    streamGeneration = barrier.streamGeneration
    appliedStreamSequence = barrier.appliedStreamSequence
    innerCursor = barrier.innerCursor
    keyDirectoryRevision = barrier.keyDirectoryRevision
    keyEpoch = barrier.newEpoch
    epochBarrierSHA256 = barrier.canonicalSHA256
  }

  var debugDescription: String {
    "DurableStreamAppliedAckPermit(revision: \(keyDirectoryRevision), proof: <redacted>)"
  }
}

struct DurableKeyUpdateInstallResult: Sendable {
  let snapshot: CryptoStateSnapshot
  let acknowledgementPermit: DurableKeyUpdateAckPermit
}

struct DurableStreamActivationResult: Sendable {
  let snapshot: CryptoStateSnapshot
  let acknowledgementPermit: DurableStreamAppliedAckPermit
}

struct DurableKeyLifecycleAcknowledgementRecovery: Sendable {
  let streamAppliedPermits: [DurableStreamAppliedAckPermit]
  let directoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1?
}

struct DurableStreamBindingInstallResult: Sendable {
  let snapshot: CryptoStateSnapshot
  let binding: DeviceDurableStreamBindingV1
  let retiredBinding: DeviceDurableStreamBindingV1?
  let disposition: DeviceStreamBindingInstallDisposition
}

/// replay tuple 经过 CounterGuard recovery 与 durable admission 后的 authenticated
/// continuation token。fresh 返回 committed successor；duplicate/stale 返回同一轮
/// guard-recovered stable snapshot，ingress 不需要也不得绕过 coordinator 直读 state file。
struct DurableReplayAdmissionProofV1: Equatable, Sendable {
  let scope: DeviceCryptoKeyScopeV1
  let counter: UInt64
  let ciphertextHash: Data
  let replayStatus: DeviceReplayStatusV1
}

public struct DurableReplayAdmissionResult: Equatable, Sendable {
  public let disposition: ReplayDisposition
  public let snapshot: CryptoStateSnapshot
  let admissionProof: DurableReplayAdmissionProofV1

  fileprivate init(
    disposition: ReplayDisposition,
    snapshot: CryptoStateSnapshot,
    admissionProof: DurableReplayAdmissionProofV1
  ) {
    self.disposition = disposition
    self.snapshot = snapshot
    self.admissionProof = admissionProof
  }
}

/// 统一拥有 machine lease、CounterGuard 与完整 sealed-state transition。
///
/// `CounterAllocator` 只消费本 actor 在三段 durable readback 后返回的 block。
public actor DurableCryptoStateCoordinator: CounterBlockReserving {
  private enum StateFirstMutationAllowance {
    case none
    case pendingStreamBindings
    case keySyncEpisode
    case securityQuarantine
  }

  private let stateStore: FileCryptoStateStore
  private let keyStore: any KeyStore
  private let guardKey: KeyStoreKey
  private let leaseManager: MachineCryptoLeaseManager
  private let observer: CryptoStatePersistenceObserver?
  private let reservationIDGenerator: CounterReservationIDGenerator
  private let clock: CryptoStateClock

  public init(
    rootURL: URL,
    identity: CryptoStateIdentity,
    stateStore: FileCryptoStateStore,
    keyStore: any KeyStore,
    guardKey: KeyStoreKey
  ) throws {
    self.stateStore = stateStore
    self.keyStore = keyStore
    self.guardKey = guardKey
    leaseManager = try MachineCryptoLeaseManager(rootURL: rootURL, identity: identity)
    observer = nil
    reservationIDGenerator = Self.generateReservationID
    clock = Self.currentTimeMilliseconds
  }

  init(
    rootURL: URL,
    identity: CryptoStateIdentity,
    stateStore: FileCryptoStateStore,
    keyStore: any KeyStore,
    guardKey: KeyStoreKey,
    observer: CryptoStatePersistenceObserver?,
    reservationIDGenerator: @escaping CounterReservationIDGenerator,
    clock: @escaping CryptoStateClock
  ) throws {
    self.stateStore = stateStore
    self.keyStore = keyStore
    self.guardKey = guardKey
    leaseManager = try MachineCryptoLeaseManager(rootURL: rootURL, identity: identity)
    self.observer = observer
    self.reservationIDGenerator = reservationIDGenerator
    self.clock = clock
  }

  /// 仅由 marker-last pairing promotion 在 initial sealed state durable 后调用。
  func bootstrap(_ permit: CounterBootstrapPermit) async throws -> CounterBootstrapEvidence {
    try await withMachineLease {
      try await bootstrapUnlocked(permit)
    }
  }

  /// PairedMachineStore 已持有同一 transaction lease 时使用，避免嵌套 flock 自锁。
  func bootstrap(
    _ permit: CounterBootstrapPermit,
    under lease: MachineCryptoLease
  ) async throws -> CounterBootstrapEvidence {
    guard await lease.isActive(for: leaseManager.identifier) else {
      throw CounterAllocatorError.invalidState
    }
    return try await bootstrapUnlocked(permit)
  }

  /// marker-last promotion 尚未写 marker 时，只接受与初始 sealed state 和
  /// exact promotion ID 完全一致的 bootstrap guard。回滚不得仅凭非空 bytes
  /// 删除可能属于其他 promotion 的 CounterGuard。
  static func auditInitialBootstrapGuard(
    _ guardData: Data,
    snapshot: CryptoStateSnapshot,
    promotionID: Data
  ) throws {
    let permit = try CounterBootstrapPermit(
      snapshot: snapshot,
      promotionID: promotionID
    )
    let scope = try CounterGuardScope(
      state: permit.snapshot.state,
      promotionID: permit.promotionID
    )
    let stable = CounterGuardStable(
      stateRevision: permit.snapshot.state.stateRevision,
      reservedHighWater: permit.snapshot.state.senderCounter.reservedHighWater,
      stateCommitment: permit.snapshot.commitment
    )
    let initialGuardCommitment = CounterGuardState.bootstrapCommitment(
      scope: scope,
      initialStateCommitment: permit.snapshot.commitment
    )
    let expected = CounterGuardState.stable(
      CounterGuardEnvelope(
        bootstrapScope: scope,
        currentScope: scope,
        initialStateCommitment: permit.snapshot.commitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .stable(stable)
      ))
    guard try CounterGuardState.decode(guardData) == expected else {
      throw CounterAllocatorError.epochRetirementRequired
    }
  }

  func auditBootstrap(
    _ evidence: CounterBootstrapEvidence,
    promotionID: Data,
    under lease: MachineCryptoLease
  ) async throws {
    guard await lease.isActive(for: leaseManager.identifier) else {
      throw CounterAllocatorError.invalidState
    }
    guard let guardData = try await keyStore.load(guardKey),
      var snapshot = try await stateStore.load()
    else {
      throw CounterAllocatorError.epochRetirementRequired
    }
    var guardState = try CounterGuardState.decode(guardData)
    switch guardState {
    case .pending, .statePending, .keyTransitionPending:
      _ = try await recoverStableState()
      guard let recoveredData = try await keyStore.load(guardKey) else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      guardState = try CounterGuardState.decode(recoveredData)
      guard let recoveredSnapshot = try await stateStore.load() else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      snapshot = recoveredSnapshot
    case .stable, .retired:
      break
    }
    let envelope: CounterGuardEnvelope
    switch guardState {
    case .stable(let stableEnvelope):
      guard case .stable(let stable) = stableEnvelope.phase,
        stableMatchesState(stable, envelope: stableEnvelope, snapshot: snapshot)
      else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      envelope = stableEnvelope
    case .retired(let retiredEnvelope):
      guard case .retired(let retired) = retiredEnvelope.phase,
        scopeMatches(retiredEnvelope.currentScope, state: snapshot.state),
        snapshot.state.securityState != .active,
        retired.stateRevision == snapshot.state.stateRevision,
        retired.reservedHighWater == snapshot.state.senderCounter.reservedHighWater,
        retired.stateCommitment == snapshot.commitment
      else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      envelope = retiredEnvelope
    case .pending, .statePending, .keyTransitionPending:
      throw CounterAllocatorError.invalidGuard
    }
    guard envelope.bootstrapScope.promotionID == promotionID,
      envelope.initialStateCommitment == evidence.initialStateCommitment,
      envelope.initialGuardCommitment == evidence.initialGuardCommitment
    else {
      throw CounterAllocatorError.epochRetirementRequired
    }
  }

  public func reserveCounterBlock() async throws -> CounterBlock {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot.state.securityState == .active else {
        let reason: DeviceCryptoSecurityReason
        switch recovered.snapshot.state.securityState {
        case .active:
          reason = .authenticatedStateRollback
        case .quarantined(let quarantinedReason, _, _):
          reason = quarantinedReason
        }
        try await retireGuard(recovered, reason: reason)
        throw CounterAllocatorError.epochRetirementRequired
      }
      let start = recovered.snapshot.state.senderCounter.reservedHighWater
      let addition = start.addingReportingOverflow(CounterBlock.size)
      guard !addition.overflow else {
        try await retireAndQuarantine(
          recovered,
          reason: .authenticatedStateRollback
        )
      }
      let end = addition.partialValue
      let reservationID = try reservationIDGenerator()
      guard reservationID.count == 16,
        !reservationID.allSatisfy({ $0 == 0 })
      else {
        throw CounterAllocatorError.entropyUnavailable
      }
      let candidateState = try recovered.snapshot.state.reservingCounterBlock(
        endExclusive: end,
        reservationID: reservationID
      )
      let candidate = try CryptoStateSnapshot(candidateState)
      let pending = CounterGuardPending(
        previous: recovered.stable,
        nextStateRevision: candidateState.stateRevision,
        nextHighWater: end,
        reservationID: reservationID,
        nextStateCommitment: candidate.commitment
      )
      let pendingEnvelope = CounterGuardEnvelope(
        bootstrapScope: recovered.envelope.bootstrapScope,
        currentScope: recovered.envelope.currentScope,
        initialStateCommitment: recovered.envelope.initialStateCommitment,
        initialGuardCommitment: recovered.envelope.initialGuardCommitment,
        phase: .pending(pending)
      )
      let pendingData = try CounterGuardState.pending(pendingEnvelope).encode()

      try await keyStore.compareAndReplaceExact(
        expected: recovered.guardData,
        replacement: pendingData,
        for: guardKey
      )
      guard try await keyStore.load(guardKey) == pendingData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      try await observer?(.guardPendingDurable)

      try await stateStore.compareAndReplaceExact(
        expected: recovered.snapshot,
        replacement: candidate
      )
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      try await observer?(.stateDurable)

      let nextStable = CounterGuardStable(
        stateRevision: candidateState.stateRevision,
        reservedHighWater: end,
        stateCommitment: candidate.commitment
      )
      let stableEnvelope = CounterGuardEnvelope(
        bootstrapScope: recovered.envelope.bootstrapScope,
        currentScope: recovered.envelope.currentScope,
        initialStateCommitment: recovered.envelope.initialStateCommitment,
        initialGuardCommitment: recovered.envelope.initialGuardCommitment,
        phase: .stable(nextStable)
      )
      let stableData = try CounterGuardState.stable(stableEnvelope).encode()
      try await keyStore.compareAndReplaceExact(
        expected: pendingData,
        replacement: stableData,
        for: guardKey
      )
      guard try await keyStore.load(guardKey) == stableData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      try await observer?(.guardStableDurable)
      return try CounterBlock(start: start, endExclusive: end)
    }
  }

  /// replay 判定与 durable state mutation 的唯一 production 入口。
  /// nonce reuse 会先提交 machine quarantine，再向连接层返回 security error。
  public func admitReplay(
    scope: DeviceCryptoKeyScopeV1,
    counter: UInt64,
    ciphertextHash: Data,
    observedAtMS: UInt64
  ) async throws -> DurableReplayAdmissionResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      switch recovered.snapshot.state.securityState {
      case .active:
        break
      case .quarantined(let reason, _, _):
        try await retireGuard(recovered, reason: reason)
        if reason == .nonceReuse { throw RelayCryptoError.nonceReuse }
        throw CounterAllocatorError.epochRetirementRequired
      }
      guard
        let replay = recovered.snapshot.state.replayStates.first(where: {
          $0.scope == scope
        })
      else {
        throw DeviceCryptoStateError.missingReplayState
      }
      guard observedAtMS > 0 else {
        throw DeviceCryptoStateError.invalidClock
      }
      let acceptsFresh: Bool
      switch replay.status {
      case .active:
        acceptsFresh = true
      case .retired(_, let deleteAfterMS):
        guard observedAtMS < deleteAfterMS else {
          throw CounterAllocatorError.epochRetirementRequired
        }
        acceptsFresh = false
      case .quarantined:
        throw CounterAllocatorError.epochRetirementRequired
      }
      var window = try ReplayWindow(snapshot: replay.window)
      do {
        let disposition = try window.observe(
          counter: counter,
          ciphertextHash: ciphertextHash
        )
        if disposition == .fresh, !acceptsFresh {
          let quarantined = try recovered.snapshot.state.quarantining(
            reason: .keyRevisionRollback,
            scope: scope,
            observedAtMS: observedAtMS
          )
          try await commitStateFirst(
            recovered: recovered,
            candidate: CryptoStateSnapshot(quarantined),
            mutationAllowance: .securityQuarantine
          )
          let quarantinedRecovered = try await recoverStableState()
          try await retireGuard(
            quarantinedRecovered,
            reason: .keyRevisionRollback
          )
          try await observer?(.securityQuarantineDurable)
          throw CounterAllocatorError.epochRetirementRequired
        }
        let proof = DurableReplayAdmissionProofV1(
          scope: scope,
          counter: counter,
          ciphertextHash: ciphertextHash,
          replayStatus: replay.status
        )
        guard disposition == .fresh else {
          return DurableReplayAdmissionResult(
            disposition: disposition,
            snapshot: recovered.snapshot,
            admissionProof: proof
          )
        }
        let nextReplay = try DeviceReplayStateV1(
          scope: scope,
          window: window.snapshot,
          status: .active
        )
        let nextState = try recovered.snapshot.state.replacingReplayState(nextReplay)
        let nextSnapshot = try CryptoStateSnapshot(nextState)
        try await commitStateFirst(
          recovered: recovered,
          candidate: nextSnapshot
        )
        let committed = try await recoverStableState()
        guard committed.snapshot == nextSnapshot else {
          throw CryptoStateStoreError.persistenceReadbackFailed
        }
        return DurableReplayAdmissionResult(
          disposition: .fresh,
          snapshot: committed.snapshot,
          admissionProof: proof
        )
      } catch RelayCryptoError.nonceReuse {
        let quarantined = try recovered.snapshot.state.quarantining(
          reason: .nonceReuse,
          scope: scope,
          observedAtMS: observedAtMS
        )
        try await commitStateFirst(
          recovered: recovered,
          candidate: CryptoStateSnapshot(quarantined),
          mutationAllowance: .securityQuarantine
        )
        let quarantinedRecovered = try await recoverStableState()
        try await retireGuard(quarantinedRecovered, reason: .nonceReuse)
        try await observer?(.securityQuarantineDurable)
        throw RelayCryptoError.nonceReuse
      }
    }
  }

  /// 后续 key/cursor repository 共用的 full-state exact transition seam。
  func commitNonCounterState(
    expected: CryptoStateSnapshot,
    replacement: CryptoStateSnapshot
  ) async throws {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      try validateStateFirstTransition(previous: expected.state, next: replacement.state)
      try validateMonotonicNonCounterTransition(
        previous: expected.state,
        next: replacement.state
      )
      try await commitStateFirst(recovered: recovered, candidate: replacement)
    }
  }

  /// authenticated daemon StreamBinding 的唯一 durable install seam。所有 authority、
  /// key identity、revision、target 与 generation/cursor 规则先在纯 state transition
  /// 完成；错误 binding 在任何 state/guard 写入前失败。CAS + full readback 后调用方才
  /// 能注册 correlation owner 并发送 Relay Subscribe。
  func installStreamBinding(
    expected: CryptoStateSnapshot,
    binding: DaemonStreamBindingV1
  ) async throws -> DurableStreamBindingInstallResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let transition = try expected.state.installingStreamBinding(binding)
      let candidate = try CryptoStateSnapshot(transition.state)
      if candidate != expected {
        try await commitStateFirst(
          recovered: recovered,
          candidate: candidate,
          mutationAllowance: .pendingStreamBindings
        )
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return DurableStreamBindingInstallResult(
        snapshot: candidate,
        binding: transition.installed,
        retiredBinding: transition.retired,
        disposition: transition.disposition
      )
    }
  }

  /// production subscription 的最终 atomic cut：Runtime bootstrap 已提交后，最后到达的
  /// verified StreamBinding 与 synchronized inner cursor 在同一 state CAS 中提升为 live
  /// route/generation。返回旧 binding 供 transport owner 在 Subscribe 前精确退休。
  func commitSubscriptionBootstrap(
    expected: CryptoStateSnapshot,
    binding: DaemonStreamBindingV1,
    synchronizedInnerCursor: DeviceInnerCursorV1
  ) async throws -> DurableStreamBindingInstallResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let transition = try expected.state.committingSubscriptionBootstrap(
        binding,
        synchronizedInnerCursor: synchronizedInnerCursor
      )
      let candidate = try CryptoStateSnapshot(transition.state)
      if candidate != expected {
        try await commitStateFirst(
          recovered: recovered,
          candidate: candidate,
          mutationAllowance: .pendingStreamBindings
        )
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return DurableStreamBindingInstallResult(
        snapshot: candidate,
        binding: transition.installed,
        retiredBinding: transition.retired,
        disposition: transition.disposition
      )
    }
  }

  /// Source 已提交最终 SyncComplete scratch reducer 后，原子提升 exact pending
  /// StreamBinding 为 live generation/cursor。generic non-counter seam 不允许删除或
  /// 改写 pending binding，避免绕过 bootstrap completion gate。
  @discardableResult
  func commitSynchronizedStreamProgress(
    expected: CryptoStateSnapshot,
    streamRoute: Data,
    streamGeneration: Data,
    outerCursor: StreamCursor,
    innerCursor: DeviceInnerCursorV1
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let candidate = try CryptoStateSnapshot(
        expected.state.advancingSynchronizedStreamProgress(
          streamRoute: streamRoute,
          streamGeneration: streamGeneration,
          outerCursor: outerCursor,
          innerCursor: innerCursor
        ))
      if candidate != expected {
        try await commitStateFirst(
          recovered: recovered,
          candidate: candidate,
          mutationAllowance: .pendingStreamBindings
        )
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return candidate
    }
  }

  /// 由已验证的 exact-next KeyDirectory 构造并提交 crash-safe successor。
  /// sender/replay/cursor 规则由 `DeviceCryptoStateV1` 统一生成，调用方不能自行遗忘
  /// counter block 或 receive replay window。
  @discardableResult
  func advanceKeyDirectory(
    expected: CryptoStateSnapshot,
    to nextDirectory: DeviceKeyDirectoryV1,
    senderCounter nextSender: DeviceSenderCounterV1
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let candidate: CryptoStateSnapshot
      do {
        candidate = try CryptoStateSnapshot(
          expected.state.advancingKeyDirectory(
            to: nextDirectory,
            senderCounter: nextSender,
            retiredAtMS: clock()
          ))
      } catch DeviceCryptoStateError.invalidKeyTransition {
        try await retireAndQuarantine(recovered, reason: .keyRevisionRollback)
      }
      try await commitKeyDirectoryTransition(recovered: recovered, candidate: candidate)
      return candidate
    }
  }

  /// repository / recovery tests 使用的 exact replacement seam。它仍执行完整 canonical
  /// successor 验证，不能退化成 `commitNonCounterState` 的 statePending。
  func advanceKeyDirectory(
    expected: CryptoStateSnapshot,
    replacement: CryptoStateSnapshot
  ) async throws {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      do {
        try validateKeyDirectoryTransition(
          previous: expected.state,
          next: replacement.state
        )
      } catch DeviceCryptoStateError.invalidKeyTransition {
        try await retireAndQuarantine(recovered, reason: .keyRevisionRollback)
      }
      try await commitKeyDirectoryTransition(recovered: recovered, candidate: replacement)
    }
  }

  /// 已验签 KeyUpdate 在 HPKE / plaintext lineage 阶段失败时的 typed fail-close seam。
  /// verifier 先持久化 quarantine + retired guard，随后才把原始 security error 返回连接层。
  func quarantineKeyDirectoryViolation(
    expected: CryptoStateSnapshot
  ) async throws {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      do {
        try await retireAndQuarantine(recovered, reason: .keyRevisionRollback)
      } catch CounterAllocatorError.epochRetirementRequired {
        return
      }
    }
  }

  /// 首个 authenticated exact-next probe 的唯一 durable admission。若同一 episode
  /// 已存在则只做完整 active/readback 核对；不会刷新 startedAt/expiresAt 或 attempt。
  @discardableResult
  func beginOrResumeKeySyncEpisode(
    targetRevision: UInt64,
    observedKeyID: KeyIDV1,
    streamRoute: Data?,
    observedAtMS: UInt64
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      let candidate = try CryptoStateSnapshot(
        recovered.snapshot.state.startingOrResumingKeySyncEpisode(
          targetRevision: targetRevision,
          observedKeyID: observedKeyID,
          streamRoute: streamRoute,
          observedAtMS: observedAtMS
        ))
      if candidate != recovered.snapshot {
        try await commitStateFirst(
          recovered: recovered,
          candidate: candidate,
          mutationAllowance: .keySyncEpisode
        )
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return candidate
    }
  }

  /// 已验签 DirectoryCurrent 后，先 durable 推进 attempt（或标记第 3 次耗尽），调用方
  /// 才能发送下一次 request / 发布 terminal。
  @discardableResult
  func recordKeySyncAttemptFailure(
    targetRevision: UInt64,
    attempt: UInt8,
    observedAtMS: UInt64
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      let candidate = try CryptoStateSnapshot(
        recovered.snapshot.state.recordingKeySyncAttemptFailure(
          targetRevision: targetRevision,
          attempt: attempt,
          observedAtMS: observedAtMS
        ))
      try await commitStateFirst(
        recovered: recovered,
        candidate: candidate,
        mutationAllowance: .keySyncEpisode
      )
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return candidate
    }
  }

  /// MachineConnection absolute timer 到点后的 durable fail-close cut。调用方即使在
  /// request signing 后持有旧 snapshot，也只能按 recovered exact episode 结束。
  @discardableResult
  func expireKeySyncEpisode(observedAtMS: UInt64) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      let candidate = try CryptoStateSnapshot(
        recovered.snapshot.state.expiringKeySyncEpisode(observedAtMS: observedAtMS)
      )
      try await commitStateFirst(
        recovered: recovered,
        candidate: candidate,
        mutationAllowance: .keySyncEpisode
      )
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return candidate
    }
  }

  /// production KeyUpdateSet ingress：整 set verify/open/roster 后一次 durable stage；成功
  /// readback 才返回 ACK permit。exact retry 零写但会重读完整 cold-open inventory。
  func stageKeyUpdateSet(
    expected: CryptoStateSnapshot,
    canonicalBytes: Data,
    expectedConversationRoutes: [Data],
    observedAtMS: UInt64? = nil,
    verifier: KeyUpdateSetVerifier
  ) async throws -> DurableKeyUpdateInstallResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      guard let episode = expected.state.keySyncEpisode else {
        throw DeviceCryptoStateError.invalidKeySyncEpisode
      }
      try episode.validateActive(at: observedAtMS ?? clock())
      let candidateState = try verifier.prepareDurableStage(
        state: expected.state,
        canonicalBytes: canonicalBytes,
        expectedConversationRoutes: expectedConversationRoutes
      )
      let candidate = try CryptoStateSnapshot(candidateState)
      if candidate != expected {
        try await commitKeyLifecycleStatePending(
          recovered: recovered,
          candidate: candidate
        )
      }
      _ = try verifier.auditColdOpen(
        state: candidate.state,
        expectedConversationRoutes: expectedConversationRoutes
      )
      guard let transition = candidate.state.keyLifecycle?.stagedTransition,
        candidate.state.keySyncEpisode == episode,
        transition.toRevision == episode.targetRevision,
        transition.canonicalUpdateSet == canonicalBytes,
        try await stateStore.load() == candidate
      else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return DurableKeyUpdateInstallResult(
        snapshot: candidate,
        acknowledgementPermit: try DurableKeyUpdateAckPermit(
          trustScope: candidate.state.trustScope,
          keyDirectoryRevision: transition.toRevision,
          updateSetSHA256: transition.updateSetSHA256
        )
      )
    }
  }

  /// exact barrier、cursor、replay 与 single-slot activation 同一 CAS；partial barrier 保持
  /// current CounterGuard scope，最后一个 proof 才以 keyTransitionPending 切 revision。
  func applyEpochBarrier(
    expected: CryptoStateSnapshot,
    barrier: DeviceEpochBarrierV1
  ) async throws -> DurableStreamActivationResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let now = clock()
      let candidateState = try expected.state.applyingEpochBarrier(
        barrier,
        activatedAtMS: now
      )
      let candidate = try CryptoStateSnapshot(candidateState)
      if candidate != expected {
        guard let episode = expected.state.keySyncEpisode else {
          throw DeviceCryptoStateError.invalidKeySyncEpisode
        }
        try episode.validateActive(at: now)
        if candidate.state.senderCounter.keyDirectoryRevision
          == expected.state.senderCounter.keyDirectoryRevision
        {
          try await commitKeyLifecycleStatePending(
            recovered: recovered,
            candidate: candidate
          )
        } else {
          try await commitKeyTransitionPending(
            recovered: recovered,
            candidate: candidate
          )
        }
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return DurableStreamActivationResult(
        snapshot: candidate,
        acknowledgementPermit: try DurableStreamAppliedAckPermit(
          trustScope: candidate.state.trustScope,
          barrier: barrier
        )
      )
    }
  }

  /// 首个 remote member 的 `0 -> 1` barrier 只提交 bootstrap carrier 的 exact
  /// activation proof 与 stream cut；sender revision/counter scope 和 key material 均不变。
  func applyBootstrapEpochBarrier(
    expected: CryptoStateSnapshot,
    barrier: DeviceEpochBarrierV1,
    expectedConversationRoutes: [Data],
    verifier: KeyUpdateSetVerifier
  ) async throws -> DurableStreamActivationResult {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let candidate = try CryptoStateSnapshot(
        verifier.prepareBootstrapEpochBarrier(
          state: expected.state,
          barrier: barrier,
          expectedConversationRoutes: expectedConversationRoutes
        )
      )
      if candidate != expected {
        try await commitKeyLifecycleStatePending(
          recovered: recovered,
          candidate: candidate
        )
      }
      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      return DurableStreamActivationResult(
        snapshot: candidate,
        acknowledgementPermit: try DurableStreamAppliedAckPermit(
          trustScope: candidate.state.trustScope,
          barrier: barrier
        )
      )
    }
  }

  /// ActivateConversation cuts 为空时只接受 current Catalog 上 exact-next revision proof。
  @discardableResult
  func applyDirectoryRevisionAdvance(
    expected: CryptoStateSnapshot,
    advance: DeviceDirectoryRevisionAdvanceV1
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      guard let episode = expected.state.keySyncEpisode else {
        throw DeviceCryptoStateError.invalidKeySyncEpisode
      }
      try episode.validateActive(at: clock())
      let candidate = try CryptoStateSnapshot(
        expected.state.applyingDirectoryRevisionAdvance(advance)
      )
      try await commitKeyTransitionPending(recovered: recovered, candidate: candidate)
      return candidate
    }
  }

  func auditColdOpen(
    expected: CryptoStateSnapshot,
    expectedConversationRoutes: [Data],
    verifier: KeyUpdateSetVerifier
  ) async throws -> AuditedDeviceKeyInventoryV1 {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      return try verifier.auditColdOpen(
        state: recovered.snapshot.state,
        expectedConversationRoutes: expectedConversationRoutes
      )
    }
  }

  /// 从 stable sealed-state readback 恢复所有仍可安全重发的 lifecycle ACK basis。
  /// proof 不被消费：Relay/daemon ACK outcome-unknown 时，下一次 cold-open 仍可重封。
  func recoverKeyLifecycleAcknowledgements(
    expected: CryptoStateSnapshot
  ) async throws -> DurableKeyLifecycleAcknowledgementRecovery {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let state = recovered.snapshot.state
      let basis = try state.auditingKeyLifecycleAcknowledgementBasis()
      let permits = try basis.epochBarriers.map {
        try DurableStreamAppliedAckPermit(
          trustScope: state.trustScope,
          barrier: $0
        )
      }
      return DurableKeyLifecycleAcknowledgementRecovery(
        streamAppliedPermits: permits,
        directoryAdvanceProof: basis.directoryAdvance
      )
    }
  }

  func recoverStreamAppliedAcknowledgement(
    expected: CryptoStateSnapshot,
    barrier: DeviceEpochBarrierV1
  ) async throws -> DurableStreamAppliedAckPermit {
    let recovery = try await recoverKeyLifecycleAcknowledgements(expected: expected)
    guard
      let permit = recovery.streamAppliedPermits.first(where: {
        $0.epochBarrierSHA256 == barrier.canonicalSHA256
          && $0.streamRoute == barrier.streamRoute
          && $0.streamGeneration == barrier.streamGeneration
          && $0.appliedStreamSequence == barrier.appliedStreamSequence
      })
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    return permit
  }

  func validateRecoveredDirectoryAdvance(
    expected: CryptoStateSnapshot,
    advance: DeviceDirectoryRevisionAdvanceV1
  ) async throws {
    let recovery = try await recoverKeyLifecycleAcknowledgements(expected: expected)
    guard recovery.directoryAdvanceProof == advance else {
      throw DeviceKeyLifecycleError.invalidDirectoryAdvance
    }
  }

  @discardableResult
  func garbageCollectRetiredKeys(
    expected: CryptoStateSnapshot,
    nowMS: UInt64
  ) async throws -> CryptoStateSnapshot {
    try await withMachineLease {
      let recovered = try await recoverStableState()
      guard recovered.snapshot == expected else {
        throw CryptoStateStoreError.compareAndReplaceMismatch
      }
      let candidate = try CryptoStateSnapshot(
        expected.state.garbageCollectingRetiredKeys(nowMS: nowMS)
      )
      if candidate != expected {
        try await commitKeyLifecycleStatePending(
          recovered: recovered,
          candidate: candidate
        )
      }
      return candidate
    }
  }

  private func recoverStableState() async throws -> RecoveredCounterState {
    guard let snapshot = try await stateStore.load() else {
      throw CounterAllocatorError.epochRetirementRequired
    }
    guard let guardData = try await keyStore.load(guardKey) else {
      try await quarantineWithoutUsableGuard(snapshot)
      throw CounterAllocatorError.epochRetirementRequired
    }
    let guardState: CounterGuardState
    do {
      guardState = try CounterGuardState.decode(guardData)
    } catch {
      try await quarantineAndRetireCorruptGuard(snapshot: snapshot, guardData: guardData)
      throw CounterAllocatorError.invalidGuard
    }

    switch guardState {
    case .retired:
      try await quarantineWithoutUsableGuard(snapshot)
      throw CounterAllocatorError.epochRetirementRequired

    case .stable(let envelope):
      guard case .stable(let stable) = envelope.phase else {
        throw CounterAllocatorError.invalidGuard
      }
      if stableMatchesState(stable, envelope: envelope, snapshot: snapshot) {
        return RecoveredCounterState(
          snapshot: snapshot,
          envelope: envelope,
          stable: stable,
          guardData: guardData
        )
      }

      // Stable guard 与 state 不一致时没有可信的 expected-next commitment，禁止只凭
      // revision +1 猜测这是合法 crash cut。合法 non-counter transition 必须先写
      // statePending，其他分叉一律隔离并退休。
      let reason: DeviceCryptoSecurityReason =
        snapshot.state.keyDirectory.revision < envelope.currentScope.keyDirectoryRevision
        ? .keyRevisionRollback
        : .authenticatedStateRollback
      try await failCloseKeyTransition(
        snapshot: snapshot,
        envelope: envelope,
        guardData: guardData,
        reason: reason
      )

    case .pending(let envelope):
      guard case .pending(let pending) = envelope.phase else {
        throw CounterAllocatorError.invalidGuard
      }
      guard scopeMatches(envelope.currentScope, state: snapshot.state) else {
        let previous = RecoveredCounterState(
          snapshot: snapshot,
          envelope: envelope,
          stable: pending.previous,
          guardData: guardData
        )
        try await retireAndQuarantine(previous, reason: .authenticatedStateRollback)
      }
      let candidate: CryptoStateSnapshot
      if snapshot.state.stateRevision == pending.previous.stateRevision,
        snapshot.state.senderCounter.reservedHighWater
          == pending.previous.reservedHighWater,
        snapshot.commitment == pending.previous.stateCommitment
      {
        let candidateState = try snapshot.state.reservingCounterBlock(
          endExclusive: pending.nextHighWater,
          reservationID: pending.reservationID
        )
        candidate = try CryptoStateSnapshot(candidateState)
        guard candidate.state.stateRevision == pending.nextStateRevision,
          candidate.commitment == pending.nextStateCommitment
        else {
          throw CounterAllocatorError.epochRetirementRequired
        }
        try await stateStore.compareAndReplaceExact(
          expected: snapshot,
          replacement: candidate
        )
      } else if snapshot.state.stateRevision == pending.nextStateRevision,
        snapshot.state.senderCounter.reservedHighWater == pending.nextHighWater,
        snapshot.state.senderCounter.reservationID == pending.reservationID,
        snapshot.commitment == pending.nextStateCommitment
      {
        candidate = snapshot
      } else {
        let previous = RecoveredCounterState(
          snapshot: snapshot,
          envelope: envelope,
          stable: pending.previous,
          guardData: guardData
        )
        try await retireAndQuarantine(previous, reason: .authenticatedStateRollback)
      }

      guard try await stateStore.load() == candidate else {
        throw CryptoStateStoreError.persistenceReadbackFailed
      }
      let stable = CounterGuardStable(
        stateRevision: pending.nextStateRevision,
        reservedHighWater: pending.nextHighWater,
        stateCommitment: pending.nextStateCommitment
      )
      let stableEnvelope = CounterGuardEnvelope(
        bootstrapScope: envelope.bootstrapScope,
        currentScope: envelope.currentScope,
        initialStateCommitment: envelope.initialStateCommitment,
        initialGuardCommitment: envelope.initialGuardCommitment,
        phase: .stable(stable)
      )
      let stableData = try CounterGuardState.stable(stableEnvelope).encode()
      try await keyStore.compareAndReplaceExact(
        expected: guardData,
        replacement: stableData,
        for: guardKey
      )
      guard try await keyStore.load(guardKey) == stableData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      return RecoveredCounterState(
        snapshot: candidate,
        envelope: stableEnvelope,
        stable: stable,
        guardData: stableData
      )

    case .statePending(let envelope):
      guard case .statePending(let pending) = envelope.phase else {
        throw CounterAllocatorError.invalidGuard
      }
      guard scopeMatches(envelope.currentScope, state: snapshot.state) else {
        let previous = RecoveredCounterState(
          snapshot: snapshot,
          envelope: envelope,
          stable: pending.previous,
          guardData: guardData
        )
        try await retireAndQuarantine(previous, reason: .authenticatedStateRollback)
      }

      let stable: CounterGuardStable
      if stableMatchesState(
        pending.previous,
        envelope: envelope,
        snapshot: snapshot
      ) {
        // Crash before the state CAS: no state mutation happened, so roll the trusted
        // guard back to the exact previous Stable value.
        stable = pending.previous
      } else if snapshot.state.stateRevision == pending.nextStateRevision,
        snapshot.state.senderCounter.reservedHighWater
          == pending.previous.reservedHighWater,
        snapshot.commitment == pending.nextStateCommitment
      {
        // Crash after the state CAS: only the exact commitment captured in Keychain
        // may be finalized. An authenticated sibling state is still a fork.
        stable = CounterGuardStable(
          stateRevision: pending.nextStateRevision,
          reservedHighWater: pending.previous.reservedHighWater,
          stateCommitment: pending.nextStateCommitment
        )
      } else {
        let previous = RecoveredCounterState(
          snapshot: snapshot,
          envelope: envelope,
          stable: pending.previous,
          guardData: guardData
        )
        try await retireAndQuarantine(previous, reason: .authenticatedStateRollback)
      }

      let stableEnvelope = CounterGuardEnvelope(
        bootstrapScope: envelope.bootstrapScope,
        currentScope: envelope.currentScope,
        initialStateCommitment: envelope.initialStateCommitment,
        initialGuardCommitment: envelope.initialGuardCommitment,
        phase: .stable(stable)
      )
      let stableData = try CounterGuardState.stable(stableEnvelope).encode()
      try await keyStore.compareAndReplaceExact(
        expected: guardData,
        replacement: stableData,
        for: guardKey
      )
      guard try await keyStore.load(guardKey) == stableData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      return RecoveredCounterState(
        snapshot: snapshot,
        envelope: stableEnvelope,
        stable: stable,
        guardData: stableData
      )

    case .keyTransitionPending(let envelope):
      guard case .keyTransitionPending(let pending) = envelope.phase else {
        throw CounterAllocatorError.invalidGuard
      }

      let stable: CounterGuardStable
      let currentScope: CounterGuardScope
      if stableMatchesState(
        pending.previous,
        envelope: envelope,
        snapshot: snapshot
      ) {
        // Crash before state CAS: exact previous state is the only legal rollback cut.
        stable = pending.previous
        currentScope = envelope.currentScope
      } else if scopeMatches(pending.nextScope, state: snapshot.state),
        snapshot.state.stateRevision == pending.nextStateRevision,
        snapshot.state.senderCounter.reservedHighWater == pending.nextReservedHighWater,
        snapshot.commitment == pending.nextStateCommitment
      {
        // Crash after state CAS: only the exact next scope + full-state commitment
        // captured in Keychain can be finalized.
        stable = CounterGuardStable(
          stateRevision: pending.nextStateRevision,
          reservedHighWater: pending.nextReservedHighWater,
          stateCommitment: pending.nextStateCommitment
        )
        currentScope = pending.nextScope
      } else {
        try await failCloseKeyTransition(
          snapshot: snapshot,
          envelope: envelope,
          guardData: guardData,
          reason: .keyRevisionRollback
        )
      }

      let stableEnvelope = CounterGuardEnvelope(
        bootstrapScope: envelope.bootstrapScope,
        currentScope: currentScope,
        initialStateCommitment: envelope.initialStateCommitment,
        initialGuardCommitment: envelope.initialGuardCommitment,
        phase: .stable(stable)
      )
      let stableData = try CounterGuardState.stable(stableEnvelope).encode()
      try await keyStore.compareAndReplaceExact(
        expected: guardData,
        replacement: stableData,
        for: guardKey
      )
      guard try await keyStore.load(guardKey) == stableData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      return RecoveredCounterState(
        snapshot: snapshot,
        envelope: stableEnvelope,
        stable: stable,
        guardData: stableData
      )
    }
  }

  private func bootstrapUnlocked(
    _ permit: CounterBootstrapPermit
  ) async throws -> CounterBootstrapEvidence {
    guard let durable = try await stateStore.load(), durable == permit.snapshot else {
      throw CounterAllocatorError.invalidState
    }
    let scope = try CounterGuardScope(
      state: durable.state,
      promotionID: permit.promotionID
    )
    let stable = CounterGuardStable(
      stateRevision: durable.state.stateRevision,
      reservedHighWater: durable.state.senderCounter.reservedHighWater,
      stateCommitment: durable.commitment
    )
    let initialGuardCommitment = CounterGuardState.bootstrapCommitment(
      scope: scope,
      initialStateCommitment: durable.commitment
    )
    let guardState = CounterGuardState.stable(
      CounterGuardEnvelope(
        bootstrapScope: scope,
        currentScope: scope,
        initialStateCommitment: durable.commitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .stable(stable)
      ))
    let encoded = try guardState.encode()

    if let existing = try await keyStore.load(guardKey) {
      guard try CounterGuardState.decode(existing) == guardState else {
        throw CounterAllocatorError.epochRetirementRequired
      }
    } else {
      _ = try await keyStore.persistImmutable(encoded, for: guardKey)
    }
    guard let persisted = try await keyStore.load(guardKey),
      try CounterGuardState.decode(persisted) == guardState
    else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    return CounterBootstrapEvidence(
      initialStateCommitment: durable.commitment,
      initialGuardCommitment: initialGuardCommitment
    )
  }

  private func commitStateFirst(
    recovered: RecoveredCounterState,
    candidate: CryptoStateSnapshot,
    mutationAllowance: StateFirstMutationAllowance = .none
  ) async throws {
    try validateStateFirstTransition(
      previous: recovered.snapshot.state,
      next: candidate.state,
      mutationAllowance: mutationAllowance
    )

    let pending = CounterGuardStatePending(
      previous: recovered.stable,
      nextStateRevision: candidate.state.stateRevision,
      nextStateCommitment: candidate.commitment
    )
    let pendingEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .statePending(pending)
    )
    let pendingData = try CounterGuardState.statePending(pendingEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: recovered.guardData,
      replacement: pendingData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == pendingData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.stateGuardPendingDurable)

    try await stateStore.compareAndReplaceExact(
      expected: recovered.snapshot,
      replacement: candidate
    )
    guard try await stateStore.load() == candidate else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
    try await observer?(.stateDurable)

    let nextStable = CounterGuardStable(
      stateRevision: candidate.state.stateRevision,
      reservedHighWater: candidate.state.senderCounter.reservedHighWater,
      stateCommitment: candidate.commitment
    )
    let nextEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .stable(nextStable)
    )
    let nextData = try CounterGuardState.stable(nextEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: pendingData,
      replacement: nextData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == nextData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.guardStableDurable)
  }

  private func commitKeyDirectoryTransition(
    recovered: RecoveredCounterState,
    candidate: CryptoStateSnapshot
  ) async throws {
    try validateKeyDirectoryTransition(
      previous: recovered.snapshot.state,
      next: candidate.state
    )
    try await commitKeyTransitionPending(recovered: recovered, candidate: candidate)
  }

  private func commitKeyLifecycleStatePending(
    recovered: RecoveredCounterState,
    candidate: CryptoStateSnapshot
  ) async throws {
    let revision = recovered.snapshot.state.stateRevision.addingReportingOverflow(1)
    guard !revision.overflow,
      candidate.state.stateRevision == revision.partialValue,
      candidate.state.trustScope == recovered.snapshot.state.trustScope,
      candidate.state.keyDirectory == recovered.snapshot.state.keyDirectory,
      candidate.state.senderCounter == recovered.snapshot.state.senderCounter,
      candidate.state.securityState == recovered.snapshot.state.securityState,
      candidate.state.pendingStreamBindings
        == recovered.snapshot.state.pendingStreamBindings,
      candidate.state.keySyncEpisode == recovered.snapshot.state.keySyncEpisode
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    let pending = CounterGuardStatePending(
      previous: recovered.stable,
      nextStateRevision: candidate.state.stateRevision,
      nextStateCommitment: candidate.commitment
    )
    let pendingEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .statePending(pending)
    )
    let pendingData = try CounterGuardState.statePending(pendingEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: recovered.guardData,
      replacement: pendingData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == pendingData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.stateGuardPendingDurable)

    try await stateStore.compareAndReplaceExact(
      expected: recovered.snapshot,
      replacement: candidate
    )
    guard try await stateStore.load() == candidate else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
    try await observer?(.stateDurable)

    let stable = CounterGuardStable(
      stateRevision: candidate.state.stateRevision,
      reservedHighWater: candidate.state.senderCounter.reservedHighWater,
      stateCommitment: candidate.commitment
    )
    let stableEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .stable(stable)
    )
    let stableData = try CounterGuardState.stable(stableEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: pendingData,
      replacement: stableData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == stableData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.guardStableDurable)
  }

  private func commitKeyTransitionPending(
    recovered: RecoveredCounterState,
    candidate: CryptoStateSnapshot
  ) async throws {
    let revision = recovered.snapshot.state.stateRevision.addingReportingOverflow(1)
    guard !revision.overflow,
      candidate.state.stateRevision == revision.partialValue,
      candidate.state.trustScope == recovered.snapshot.state.trustScope,
      candidate.state.securityState == recovered.snapshot.state.securityState,
      candidate.state.pendingStreamBindings
        == recovered.snapshot.state.pendingStreamBindings,
      keySyncEpisodeTransitionIsValid(
        previous: recovered.snapshot.state,
        next: candidate.state
      )
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    let nextScope = try CounterGuardScope(
      state: candidate.state,
      promotionID: recovered.envelope.bootstrapScope.promotionID
    )
    let pending = CounterGuardKeyTransitionPending(
      previous: recovered.stable,
      nextScope: nextScope,
      nextStateRevision: candidate.state.stateRevision,
      nextReservedHighWater: candidate.state.senderCounter.reservedHighWater,
      nextStateCommitment: candidate.commitment
    )
    let pendingEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .keyTransitionPending(pending)
    )
    let pendingData = try CounterGuardState.keyTransitionPending(pendingEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: recovered.guardData,
      replacement: pendingData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == pendingData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.keyTransitionGuardPendingDurable)

    try await stateStore.compareAndReplaceExact(
      expected: recovered.snapshot,
      replacement: candidate
    )
    guard try await stateStore.load() == candidate else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
    try await observer?(.keyTransitionStateDurable)

    let nextStable = CounterGuardStable(
      stateRevision: candidate.state.stateRevision,
      reservedHighWater: candidate.state.senderCounter.reservedHighWater,
      stateCommitment: candidate.commitment
    )
    let nextEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: nextScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .stable(nextStable)
    )
    let nextData = try CounterGuardState.stable(nextEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: pendingData,
      replacement: nextData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == nextData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.keyTransitionGuardStableDurable)
  }

  private func validateKeyDirectoryTransition(
    previous: DeviceCryptoStateV1,
    next: DeviceCryptoStateV1
  ) throws {
    guard next.trustScope == previous.trustScope,
      next.securityState == previous.securityState,
      next.streamStates == previous.streamStates
    else {
      throw DeviceCryptoStateError.invalidKeyTransition
    }

    var retirementTime: UInt64?
    for old in previous.replayStates {
      guard let successor = next.replayStates.first(where: { $0.scope == old.scope }) else {
        throw DeviceCryptoStateError.invalidKeyTransition
      }
      guard case .retired(let retiredAtMS, let deleteAfterMS) = successor.status else {
        continue
      }
      if case .retired = old.status { continue }
      let retentionEnd = retiredAtMS.addingReportingOverflow(
        ReplayWindow.retiredWindowRetentionMilliseconds
      )
      guard !retentionEnd.overflow,
        deleteAfterMS == retentionEnd.partialValue,
        retirementTime == nil || retirementTime == retiredAtMS
      else {
        throw DeviceCryptoStateError.invalidKeyTransition
      }
      retirementTime = retiredAtMS
    }

    let canonical = try previous.advancingKeyDirectory(
      to: next.keyDirectory,
      senderCounter: next.senderCounter,
      retiredAtMS: retirementTime ?? 1
    )
    guard canonical == next else {
      throw DeviceCryptoStateError.invalidKeyTransition
    }
  }

  private func keySyncEpisodeTransitionIsValid(
    previous: DeviceCryptoStateV1,
    next: DeviceCryptoStateV1
  ) -> Bool {
    if next.senderCounter.keyDirectoryRevision
      == previous.senderCounter.keyDirectoryRevision
    {
      return next.keySyncEpisode == previous.keySyncEpisode
    }
    let successor = previous.senderCounter.keyDirectoryRevision.addingReportingOverflow(1)
    guard !successor.overflow,
      next.senderCounter.keyDirectoryRevision == successor.partialValue
    else {
      return false
    }
    switch previous.keySyncEpisode {
    case nil:
      return next.keySyncEpisode == nil
    case .some(let episode):
      return episode.targetRevision == next.senderCounter.keyDirectoryRevision
        && !episode.exhausted
        && next.keySyncEpisode == nil
    }
  }

  private func validateStateFirstTransition(
    previous: DeviceCryptoStateV1,
    next: DeviceCryptoStateV1,
    mutationAllowance: StateFirstMutationAllowance = .none
  ) throws {
    let revision = previous.stateRevision.addingReportingOverflow(1)
    guard !revision.overflow,
      next.stateRevision == revision.partialValue,
      next.trustScope == previous.trustScope,
      next.keyDirectory == previous.keyDirectory,
      next.senderCounter == previous.senderCounter,
      next.keyLifecycle == previous.keyLifecycle
    else {
      throw CounterAllocatorError.invalidState
    }
    switch mutationAllowance {
    case .none:
      guard next.pendingStreamBindings == previous.pendingStreamBindings,
        next.keySyncEpisode == previous.keySyncEpisode
      else {
        throw CounterAllocatorError.invalidState
      }
    case .pendingStreamBindings:
      guard next.keySyncEpisode == previous.keySyncEpisode else {
        throw CounterAllocatorError.invalidState
      }
    case .keySyncEpisode:
      guard next.pendingStreamBindings == previous.pendingStreamBindings else {
        throw CounterAllocatorError.invalidState
      }
    case .securityQuarantine:
      guard previous.securityState == .active,
        next.securityState != .active,
        next.pendingStreamBindings == previous.pendingStreamBindings,
        next.keySyncEpisode == nil
      else {
        throw CounterAllocatorError.invalidState
      }
    }
  }

  /// 通用 repository seam 只能推进 replay/cursor 投影，不能借一次合法的
  /// `stateRevision + 1` 重激活 machine、遗忘 replay tuple 或回退 cursor。
  /// nonce-reuse quarantine 仍只走 `admitReplay` 的 typed transition。
  private func validateMonotonicNonCounterTransition(
    previous: DeviceCryptoStateV1,
    next: DeviceCryptoStateV1
  ) throws {
    guard next.securityState == previous.securityState,
      replayStatesAdvance(previous: previous.replayStates, next: next.replayStates),
      streamStatesAdvance(previous: previous.streamStates, next: next.streamStates)
    else {
      throw CounterAllocatorError.invalidState
    }
  }

  private func replayStatesAdvance(
    previous: [DeviceReplayStateV1],
    next: [DeviceReplayStateV1]
  ) -> Bool {
    let nextByScope = Dictionary(uniqueKeysWithValues: next.map { ($0.scope, $0) })
    return previous.allSatisfy { old in
      guard let candidate = nextByScope[old.scope],
        replayStatusAdvances(previous: old.status, next: candidate.status),
        replayWindowAdvances(previous: old.window, next: candidate.window)
      else {
        return false
      }
      return true
    }
  }

  private func replayStatusAdvances(
    previous: DeviceReplayStatusV1,
    next: DeviceReplayStatusV1
  ) -> Bool {
    switch (previous, next) {
    case (.active, .active), (.active, .quarantined), (.active, .retired),
      (.quarantined, .retired):
      return true
    case (.quarantined, .quarantined), (.retired, .retired):
      return previous == next
    case (.quarantined, .active), (.retired, .active), (.retired, .quarantined):
      return false
    }
  }

  private func replayWindowAdvances(
    previous: ReplayWindowSnapshot,
    next: ReplayWindowSnapshot
  ) -> Bool {
    switch (previous.highWater, next.highWater) {
    case (.some, nil):
      return false
    case (.some(let old), .some(let candidate)) where candidate < old:
      return false
    default:
      break
    }
    guard next.floor >= previous.floor else { return false }

    let nextHashes = Dictionary(
      uniqueKeysWithValues: next.entries.map { ($0.counter, $0.ciphertextHash) }
    )
    return previous.entries.allSatisfy { entry in
      entry.counter < next.floor || nextHashes[entry.counter] == entry.ciphertextHash
    }
  }

  private func streamStatesAdvance(
    previous: [DeviceStreamCursorStateV1],
    next: [DeviceStreamCursorStateV1]
  ) -> Bool {
    let nextByRoute = Dictionary(uniqueKeysWithValues: next.map { ($0.streamRoute, $0) })
    return previous.allSatisfy { old in
      guard let candidate = nextByRoute[old.streamRoute],
        candidate.generation == old.generation,
        cursor(candidate.outerCursor, isAtLeast: old.outerCursor),
        innerCursor(candidate.innerCursor, advances: old.innerCursor)
      else {
        return false
      }
      return true
    }
  }

  private func innerCursor(
    _ next: DeviceInnerCursorV1,
    advances previous: DeviceInnerCursorV1
  ) -> Bool {
    switch (previous, next) {
    case (.catalog(let old), .catalog(let candidate)):
      return cursor(candidate, isAtLeast: old)
    case (
      .conversation(let oldID, let old),
      .conversation(let candidateID, let candidate)
    ):
      return candidateID == oldID && cursor(candidate, isAtLeast: old)
    default:
      return false
    }
  }

  private func cursor(_ next: StreamCursor, isAtLeast previous: StreamCursor) -> Bool {
    switch (previous, next) {
    case (.beforeFirst, _):
      return true
    case (.at, .beforeFirst):
      return false
    case (.at(let old), .at(let candidate)):
      return candidate >= old
    }
  }

  private func stableMatchesState(
    _ stable: CounterGuardStable,
    envelope: CounterGuardEnvelope,
    snapshot: CryptoStateSnapshot
  ) -> Bool {
    scopeMatches(envelope.currentScope, state: snapshot.state)
      && stable.stateRevision == snapshot.state.stateRevision
      && stable.reservedHighWater == snapshot.state.senderCounter.reservedHighWater
      && stable.stateCommitment == snapshot.commitment
  }

  private func scopeMatches(
    _ scope: CounterGuardScope,
    state: DeviceCryptoStateV1
  ) -> Bool {
    guard let binding = try? CounterGuardScope.invariantCommitment(state: state) else {
      return false
    }
    return scope.trustEpoch == state.trustScope.trustEpoch
      && scope.keyDirectoryRevision == state.senderCounter.keyDirectoryRevision
      && scope.keyEpoch == state.senderCounter.keyID.epoch
      && scope.noncePrefix == state.senderCounter.noncePrefix
      && scope.invariantCommitment == binding
  }

  private func quarantineWithoutUsableGuard(
    _ snapshot: CryptoStateSnapshot
  ) async throws {
    guard snapshot.state.securityState == .active else { return }
    let candidate = try CryptoStateSnapshot(
      snapshot.state.quarantining(
        reason: .authenticatedStateRollback,
        scope: nil,
        observedAtMS: clock()
      ))
    try await stateStore.compareAndReplaceExact(
      expected: snapshot,
      replacement: candidate
    )
    guard try await stateStore.load() == candidate else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
    try await observer?(.securityQuarantineDurable)
  }

  private func quarantineAndRetireCorruptGuard(
    snapshot: CryptoStateSnapshot,
    guardData: Data
  ) async throws {
    let observedAtMS = clock()
    let quarantined: CryptoStateSnapshot
    if snapshot.state.securityState == .active {
      quarantined = try CryptoStateSnapshot(
        snapshot.state.quarantining(
          reason: .authenticatedStateRollback,
          scope: nil,
          observedAtMS: observedAtMS
        ))
      try await stateStore.compareAndReplaceExact(
        expected: snapshot,
        replacement: quarantined
      )
    } else {
      quarantined = snapshot
    }
    guard try await stateStore.load() == quarantined else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }

    let bootstrapScope: CounterGuardScope
    let initialStateCommitment: Data
    let initialGuardCommitment: Data
    if let binding = CounterGuardState.salvageBootstrapBinding(guardData) {
      bootstrapScope = binding.scope
      initialStateCommitment = binding.initialStateCommitment
      initialGuardCommitment = binding.initialGuardCommitment
    } else {
      var seed = Data("AgentDeck/CorruptCounterGuardRetirementV1\0".utf8)
      seed.append(guardData)
      var promotionID = CanonicalCodec.sha256(seed)
      if promotionID.allSatisfy({ $0 == 0 }) {
        promotionID = Data(repeating: 0xFF, count: 32)
      }
      bootstrapScope = try CounterGuardScope(
        state: snapshot.state,
        promotionID: promotionID
      )
      initialStateCommitment = snapshot.commitment
      initialGuardCommitment = CounterGuardState.bootstrapCommitment(
        scope: bootstrapScope,
        initialStateCommitment: initialStateCommitment
      )
    }
    let terminalScope = try CounterGuardScope(
      state: quarantined.state,
      promotionID: bootstrapScope.promotionID
    )
    let retired = CounterGuardRetired(
      reason: .authenticatedStateRollback,
      retiredAtMS: observedAtMS,
      stateRevision: quarantined.state.stateRevision,
      reservedHighWater: quarantined.state.senderCounter.reservedHighWater,
      stateCommitment: quarantined.commitment
    )
    let envelope = CounterGuardEnvelope(
      bootstrapScope: bootstrapScope,
      currentScope: terminalScope,
      initialStateCommitment: initialStateCommitment,
      initialGuardCommitment: initialGuardCommitment,
      phase: .retired(retired)
    )
    let retiredData = try CounterGuardState.retired(envelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: guardData,
      replacement: retiredData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == retiredData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.securityQuarantineDurable)
  }

  private func retireAndQuarantine(
    _ recovered: RecoveredCounterState,
    reason: DeviceCryptoSecurityReason
  ) async throws -> Never {
    let quarantined: CryptoStateSnapshot
    if recovered.snapshot.state.securityState == .active {
      quarantined = try CryptoStateSnapshot(
        recovered.snapshot.state.quarantining(
          reason: reason,
          scope: nil,
          observedAtMS: clock()
        ))
      try await stateStore.compareAndReplaceExact(
        expected: recovered.snapshot,
        replacement: quarantined
      )
    } else {
      quarantined = recovered.snapshot
    }
    guard try await stateStore.load() == quarantined else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
    try await retireGuard(recoveredWithSnapshot(recovered, snapshot: quarantined), reason: reason)
    try await observer?(.securityQuarantineDurable)
    throw CounterAllocatorError.epochRetirementRequired
  }

  /// key transition pending 可能面对 previous、exact-next 之外的任意 authenticated
  /// sibling。此时旧 currentScope 已不能描述磁盘 state；先对当前 full state 做 durable
  /// quarantine，再以同一 immutable bootstrap authority 派生 terminal currentScope。
  private func failCloseKeyTransition(
    snapshot: CryptoStateSnapshot,
    envelope: CounterGuardEnvelope,
    guardData: Data,
    reason: DeviceCryptoSecurityReason
  ) async throws -> Never {
    let observedAtMS = clock()
    let quarantined: CryptoStateSnapshot
    if snapshot.state.securityState == .active {
      quarantined = try CryptoStateSnapshot(
        snapshot.state.quarantining(
          reason: reason,
          scope: nil,
          observedAtMS: observedAtMS
        ))
      try await stateStore.compareAndReplaceExact(
        expected: snapshot,
        replacement: quarantined
      )
    } else {
      quarantined = snapshot
    }
    guard try await stateStore.load() == quarantined else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }

    let terminalScope = try CounterGuardScope(
      state: quarantined.state,
      promotionID: envelope.bootstrapScope.promotionID
    )
    let retired = CounterGuardRetired(
      reason: reason,
      retiredAtMS: observedAtMS,
      stateRevision: quarantined.state.stateRevision,
      reservedHighWater: quarantined.state.senderCounter.reservedHighWater,
      stateCommitment: quarantined.commitment
    )
    let retiredEnvelope = CounterGuardEnvelope(
      bootstrapScope: envelope.bootstrapScope,
      currentScope: terminalScope,
      initialStateCommitment: envelope.initialStateCommitment,
      initialGuardCommitment: envelope.initialGuardCommitment,
      phase: .retired(retired)
    )
    let retiredData = try CounterGuardState.retired(retiredEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: guardData,
      replacement: retiredData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == retiredData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    try await observer?(.securityQuarantineDurable)
    throw CounterAllocatorError.epochRetirementRequired
  }

  private func retireGuard(
    _ recovered: RecoveredCounterState,
    reason: DeviceCryptoSecurityReason
  ) async throws {
    if case .retired = recovered.envelope.phase { return }
    let retired = CounterGuardRetired(
      reason: reason,
      retiredAtMS: clock(),
      stateRevision: recovered.snapshot.state.stateRevision,
      reservedHighWater: recovered.snapshot.state.senderCounter.reservedHighWater,
      stateCommitment: recovered.snapshot.commitment
    )
    let retiredEnvelope = CounterGuardEnvelope(
      bootstrapScope: recovered.envelope.bootstrapScope,
      currentScope: recovered.envelope.currentScope,
      initialStateCommitment: recovered.envelope.initialStateCommitment,
      initialGuardCommitment: recovered.envelope.initialGuardCommitment,
      phase: .retired(retired)
    )
    let retiredData = try CounterGuardState.retired(retiredEnvelope).encode()
    try await keyStore.compareAndReplaceExact(
      expected: recovered.guardData,
      replacement: retiredData,
      for: guardKey
    )
    guard try await keyStore.load(guardKey) == retiredData else {
      throw KeyStoreError.persistenceReadbackFailed
    }
  }

  private func recoveredWithSnapshot(
    _ recovered: RecoveredCounterState,
    snapshot: CryptoStateSnapshot
  ) -> RecoveredCounterState {
    RecoveredCounterState(
      snapshot: snapshot,
      envelope: recovered.envelope,
      stable: CounterGuardStable(
        stateRevision: snapshot.state.stateRevision,
        reservedHighWater: snapshot.state.senderCounter.reservedHighWater,
        stateCommitment: snapshot.commitment
      ),
      guardData: recovered.guardData
    )
  }

  private func withMachineLease<Value: Sendable>(
    _ operation: () async throws -> Value
  ) async throws -> Value {
    let lease = try await leaseManager.acquire()
    do {
      let value = try await operation()
      await lease.release()
      return value
    } catch {
      await lease.release()
      throw error
    }
  }

  private static func generateReservationID() throws -> Data {
    var bytes = Data(repeating: 0, count: 16)
    let status = bytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard status == errSecSuccess,
      !bytes.allSatisfy({ $0 == 0 })
    else {
      throw CounterAllocatorError.entropyUnavailable
    }
    return bytes
  }

  private static func currentTimeMilliseconds() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1_000)
  }
}

private struct RecoveredCounterState: Sendable {
  let snapshot: CryptoStateSnapshot
  let envelope: CounterGuardEnvelope
  let stable: CounterGuardStable
  let guardData: Data
}

private struct CounterGuardScope: Equatable, Sendable {
  let promotionID: Data
  let trustEpoch: UInt64
  let keyDirectoryRevision: UInt64
  let keyEpoch: UInt64
  let noncePrefix: Data
  let invariantCommitment: Data

  init(state: DeviceCryptoStateV1, promotionID: Data) throws {
    guard promotionID.count == 32,
      !promotionID.allSatisfy({ $0 == 0 })
    else {
      throw CounterAllocatorError.invalidGuard
    }
    self.promotionID = promotionID
    trustEpoch = state.trustScope.trustEpoch
    keyDirectoryRevision = state.senderCounter.keyDirectoryRevision
    keyEpoch = state.senderCounter.keyID.epoch
    noncePrefix = state.senderCounter.noncePrefix
    invariantCommitment = try Self.invariantCommitment(state: state)
    try validate()
  }

  init(
    promotionID: Data,
    trustEpoch: UInt64,
    keyDirectoryRevision: UInt64,
    keyEpoch: UInt64,
    noncePrefix: Data,
    invariantCommitment: Data
  ) throws {
    self.promotionID = promotionID
    self.trustEpoch = trustEpoch
    self.keyDirectoryRevision = keyDirectoryRevision
    self.keyEpoch = keyEpoch
    self.noncePrefix = noncePrefix
    self.invariantCommitment = invariantCommitment
    try validate()
  }

  private func validate() throws {
    guard promotionID.count == 32,
      !promotionID.allSatisfy({ $0 == 0 }),
      trustEpoch > 0,
      keyDirectoryRevision > 0,
      keyEpoch > 0,
      noncePrefix.count == 4,
      invariantCommitment.count == 32,
      !invariantCommitment.allSatisfy({ $0 == 0 })
    else {
      throw CounterAllocatorError.invalidGuard
    }
  }

  static func invariantCommitment(state: DeviceCryptoStateV1) throws -> Data {
    let initialSender = try DeviceSenderCounterV1(
      keyID: state.senderCounter.keyID,
      keyDirectoryRevision: state.senderCounter.keyDirectoryRevision,
      noncePrefix: state.senderCounter.noncePrefix,
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    )
    let normalizedLifecycle: DeviceKeyLifecycleStateV1?
    if state.senderCounter.keyDirectoryRevision == state.keyDirectory.revision {
      normalizedLifecycle = nil
    } else {
      let slots = try state.keyDirectory.entries.map { entry in
        var fingerprintInput = Data("AgentDeck/CounterGuardLiveKeySlotV1\0".utf8)
        fingerprintInput.append(entry.keyID.purpose.canonicalTag)
        fingerprintInput.appendInteger(entry.keyID.epoch)
        fingerprintInput.append(entry.streamRoute ?? Data(repeating: 0, count: 16))
        fingerprintInput.append(entry.enc)
        fingerprintInput.append(entry.wrappedKey)
        let carrier = try DeviceStoredKeyCarrierV1(
          keyID: entry.keyID,
          streamRoute: entry.streamRoute,
          keyDirectoryRevision: state.keyDirectory.revision,
          secretFingerprint: CanonicalCodec.sha256(fingerprintInput),
          source: .bootstrapDirectory
        )
        return try DeviceKeySlotStateV1(
          id: carrier.slotID,
          current: carrier,
          staged: nil,
          retired: []
        )
      }
      normalizedLifecycle = try DeviceKeyLifecycleStateV1(
        activeRevision: state.senderCounter.keyDirectoryRevision,
        activeUpdateSet: nil,
        stagedTransition: nil,
        slots: slots,
        retiredSecretFingerprints: []
      )
    }
    let invariant = try DeviceCryptoStateV1(
      stateRevision: 1,
      trustScope: state.trustScope,
      keyDirectory: state.keyDirectory,
      senderCounter: initialSender,
      securityState: .active,
      replayStates: [],
      streamStates: [],
      keyLifecycle: normalizedLifecycle
    )
    return try CryptoStateSnapshot(invariant).commitment
  }
}

private struct CounterGuardStable: Equatable, Sendable {
  let stateRevision: UInt64
  let reservedHighWater: UInt64
  let stateCommitment: Data
}

private struct CounterGuardPending: Equatable, Sendable {
  let previous: CounterGuardStable
  let nextStateRevision: UInt64
  let nextHighWater: UInt64
  let reservationID: Data
  let nextStateCommitment: Data
}

private struct CounterGuardStatePending: Equatable, Sendable {
  let previous: CounterGuardStable
  let nextStateRevision: UInt64
  let nextStateCommitment: Data
}

private struct CounterGuardKeyTransitionPending: Equatable, Sendable {
  let previous: CounterGuardStable
  let nextScope: CounterGuardScope
  let nextStateRevision: UInt64
  let nextReservedHighWater: UInt64
  let nextStateCommitment: Data
}

private struct CounterGuardRetired: Equatable, Sendable {
  let reason: DeviceCryptoSecurityReason
  let retiredAtMS: UInt64
  let stateRevision: UInt64
  let reservedHighWater: UInt64
  let stateCommitment: Data
}

private enum CounterGuardPhase: Equatable, Sendable {
  case stable(CounterGuardStable)
  case pending(CounterGuardPending)
  case statePending(CounterGuardStatePending)
  case keyTransitionPending(CounterGuardKeyTransitionPending)
  case retired(CounterGuardRetired)
}

private struct CounterGuardEnvelope: Equatable, Sendable {
  /// pairing bootstrap 时的 immutable scope；initialGuardCommitment 永远只绑定它。
  let bootstrapScope: CounterGuardScope
  /// 当前可消费 sender/replay state 的 scope；只能由 typed key transition exact 推进。
  let currentScope: CounterGuardScope
  let initialStateCommitment: Data
  let initialGuardCommitment: Data
  let phase: CounterGuardPhase
}

private struct CounterGuardBootstrapBinding: Sendable {
  let scope: CounterGuardScope
  let initialStateCommitment: Data
  let initialGuardCommitment: Data
}

private enum CounterGuardState: Equatable, Sendable {
  case stable(CounterGuardEnvelope)
  case pending(CounterGuardEnvelope)
  case statePending(CounterGuardEnvelope)
  case keyTransitionPending(CounterGuardEnvelope)
  case retired(CounterGuardEnvelope)

  private static let magic = Data("ADCG".utf8)
  private static let legacyVersion: UInt16 = 2
  private static let version: UInt16 = 3

  func encode() throws -> Data {
    let envelope: CounterGuardEnvelope
    let phaseTag: UInt8
    switch self {
    case .stable(let value):
      envelope = value
      phaseTag = 0
      guard case .stable = value.phase else { throw CounterAllocatorError.invalidGuard }
    case .pending(let value):
      envelope = value
      phaseTag = 1
      guard case .pending = value.phase else { throw CounterAllocatorError.invalidGuard }
    case .retired(let value):
      envelope = value
      phaseTag = 2
      guard case .retired = value.phase else { throw CounterAllocatorError.invalidGuard }
    case .statePending(let value):
      envelope = value
      phaseTag = 3
      guard case .statePending = value.phase else {
        throw CounterAllocatorError.invalidGuard
      }
    case .keyTransitionPending(let value):
      envelope = value
      phaseTag = 4
      guard case .keyTransitionPending = value.phase else {
        throw CounterAllocatorError.invalidGuard
      }
    }
    try Self.validateEnvelope(envelope)

    var data = Self.magic
    data.appendInteger(Self.version)
    data.append(phaseTag)
    data.append(0)
    Self.appendScope(envelope.bootstrapScope, to: &data)
    Self.appendScope(envelope.currentScope, to: &data)
    data.append(envelope.initialStateCommitment)
    data.append(envelope.initialGuardCommitment)
    switch envelope.phase {
    case .stable(let stable):
      Self.appendStable(stable, to: &data)
    case .pending(let pending):
      Self.appendStable(pending.previous, to: &data)
      data.appendInteger(pending.nextStateRevision)
      data.appendInteger(pending.nextHighWater)
      data.append(pending.reservationID)
      data.append(pending.nextStateCommitment)
    case .statePending(let pending):
      Self.appendStable(pending.previous, to: &data)
      data.appendInteger(pending.nextStateRevision)
      data.append(pending.nextStateCommitment)
    case .keyTransitionPending(let pending):
      Self.appendStable(pending.previous, to: &data)
      Self.appendScope(pending.nextScope, to: &data)
      data.appendInteger(pending.nextStateRevision)
      data.appendInteger(pending.nextReservedHighWater)
      data.append(pending.nextStateCommitment)
    case .retired(let retired):
      data.append(retired.reason.rawValue)
      data.append(contentsOf: [0, 0, 0, 0, 0, 0, 0])
      data.appendInteger(retired.retiredAtMS)
      data.appendInteger(retired.stateRevision)
      data.appendInteger(retired.reservedHighWater)
      data.append(retired.stateCommitment)
    }
    return data
  }

  static func decode(_ data: Data) throws -> Self {
    var decoder = GuardDecoder(data: data)
    guard try decoder.fixed(count: 4) == magic else {
      throw CounterAllocatorError.invalidGuard
    }
    let decodedVersion = try decoder.u16()
    guard decodedVersion == legacyVersion || decodedVersion == version else {
      throw CounterAllocatorError.invalidGuard
    }
    let phaseTag = try decoder.u8()
    guard try decoder.u8() == 0 else { throw CounterAllocatorError.invalidGuard }
    let bootstrapScope = try decodeScope(from: &decoder)
    let currentScope =
      decodedVersion == legacyVersion
      ? bootstrapScope
      : try decodeScope(from: &decoder)
    let initialStateCommitment = try decoder.fixed(count: 32)
    let initialGuardCommitment = try decoder.fixed(count: 32)
    let phase: CounterGuardPhase
    switch phaseTag {
    case 0:
      phase = .stable(try decodeStable(from: &decoder))
    case 1:
      phase = .pending(
        CounterGuardPending(
          previous: try decodeStable(from: &decoder),
          nextStateRevision: try decoder.u64(),
          nextHighWater: try decoder.u64(),
          reservationID: try decoder.fixed(count: 16),
          nextStateCommitment: try decoder.fixed(count: 32)
        ))
    case 2:
      guard let reason = DeviceCryptoSecurityReason(rawValue: try decoder.u8()),
        try decoder.fixed(count: 7).allSatisfy({ $0 == 0 })
      else {
        throw CounterAllocatorError.invalidGuard
      }
      phase = .retired(
        CounterGuardRetired(
          reason: reason,
          retiredAtMS: try decoder.u64(),
          stateRevision: try decoder.u64(),
          reservedHighWater: try decoder.u64(),
          stateCommitment: try decoder.fixed(count: 32)
        ))
    case 3:
      phase = .statePending(
        CounterGuardStatePending(
          previous: try decodeStable(from: &decoder),
          nextStateRevision: try decoder.u64(),
          nextStateCommitment: try decoder.fixed(count: 32)
        ))
    case 4 where decodedVersion == version:
      phase = .keyTransitionPending(
        CounterGuardKeyTransitionPending(
          previous: try decodeStable(from: &decoder),
          nextScope: try decodeScope(from: &decoder),
          nextStateRevision: try decoder.u64(),
          nextReservedHighWater: try decoder.u64(),
          nextStateCommitment: try decoder.fixed(count: 32)
        ))
    default:
      throw CounterAllocatorError.invalidGuard
    }
    guard decoder.isAtEnd else { throw CounterAllocatorError.invalidGuard }
    let envelope = CounterGuardEnvelope(
      bootstrapScope: bootstrapScope,
      currentScope: currentScope,
      initialStateCommitment: initialStateCommitment,
      initialGuardCommitment: initialGuardCommitment,
      phase: phase
    )
    try validateEnvelope(envelope)
    switch phase {
    case .stable: return .stable(envelope)
    case .pending: return .pending(envelope)
    case .retired: return .retired(envelope)
    case .statePending: return .statePending(envelope)
    case .keyTransitionPending: return .keyTransitionPending(envelope)
    }
  }

  /// decode 已 fail 时只抢救 immutable bootstrap binding，用于把损坏 guard 原子替换成
  /// terminal retired marker；不会据此恢复 active state。v3 与 legacy v2 两种布局都尝试。
  fileprivate static func salvageBootstrapBinding(
    _ data: Data
  ) -> CounterGuardBootstrapBinding? {
    func decodeBinding(hasCurrentScope: Bool) -> CounterGuardBootstrapBinding? {
      do {
        var decoder = GuardDecoder(data: data)
        guard try decoder.fixed(count: 4) == magic else { return nil }
        _ = try decoder.u16()
        _ = try decoder.u8()
        guard try decoder.u8() == 0 else { return nil }
        let bootstrapScope = try decodeScope(from: &decoder)
        if hasCurrentScope { _ = try decodeScope(from: &decoder) }
        let initialStateCommitment = try decoder.fixed(count: 32)
        let initialGuardCommitment = try decoder.fixed(count: 32)
        guard initialStateCommitment.count == 32,
          !initialStateCommitment.allSatisfy({ $0 == 0 }),
          initialGuardCommitment
            == bootstrapCommitment(
              scope: bootstrapScope,
              initialStateCommitment: initialStateCommitment
            )
        else {
          return nil
        }
        return CounterGuardBootstrapBinding(
          scope: bootstrapScope,
          initialStateCommitment: initialStateCommitment,
          initialGuardCommitment: initialGuardCommitment
        )
      } catch {
        return nil
      }
    }
    return decodeBinding(hasCurrentScope: true) ?? decodeBinding(hasCurrentScope: false)
  }

  private static func appendScope(_ scope: CounterGuardScope, to data: inout Data) {
    data.append(scope.promotionID)
    data.appendInteger(scope.trustEpoch)
    data.appendInteger(scope.keyDirectoryRevision)
    data.appendInteger(scope.keyEpoch)
    data.append(scope.noncePrefix)
    data.append(contentsOf: [0, 0, 0, 0])
    data.append(scope.invariantCommitment)
  }

  private static func decodeScope(from decoder: inout GuardDecoder) throws -> CounterGuardScope {
    let promotionID = try decoder.fixed(count: 32)
    let trustEpoch = try decoder.u64()
    let keyDirectoryRevision = try decoder.u64()
    let keyEpoch = try decoder.u64()
    let noncePrefix = try decoder.fixed(count: 4)
    guard try decoder.fixed(count: 4).allSatisfy({ $0 == 0 }) else {
      throw CounterAllocatorError.invalidGuard
    }
    return try CounterGuardScope(
      promotionID: promotionID,
      trustEpoch: trustEpoch,
      keyDirectoryRevision: keyDirectoryRevision,
      keyEpoch: keyEpoch,
      noncePrefix: noncePrefix,
      invariantCommitment: decoder.fixed(count: 32)
    )
  }

  private static func appendStable(_ stable: CounterGuardStable, to data: inout Data) {
    data.appendInteger(stable.stateRevision)
    data.appendInteger(stable.reservedHighWater)
    data.append(stable.stateCommitment)
  }

  private static func decodeStable(from decoder: inout GuardDecoder) throws -> CounterGuardStable {
    CounterGuardStable(
      stateRevision: try decoder.u64(),
      reservedHighWater: try decoder.u64(),
      stateCommitment: try decoder.fixed(count: 32)
    )
  }

  private static func validateEnvelope(_ envelope: CounterGuardEnvelope) throws {
    guard envelope.initialStateCommitment.count == 32,
      !envelope.initialStateCommitment.allSatisfy({ $0 == 0 }),
      envelope.initialGuardCommitment.count == 32,
      !envelope.initialGuardCommitment.allSatisfy({ $0 == 0 }),
      envelope.bootstrapScope.promotionID == envelope.currentScope.promotionID,
      envelope.bootstrapScope.trustEpoch == envelope.currentScope.trustEpoch,
      envelope.currentScope.keyDirectoryRevision
        >= envelope.bootstrapScope.keyDirectoryRevision,
      envelope.currentScope.keyEpoch >= envelope.bootstrapScope.keyEpoch,
      envelope.initialGuardCommitment
        == bootstrapCommitment(
          scope: envelope.bootstrapScope,
          initialStateCommitment: envelope.initialStateCommitment
        )
    else {
      throw CounterAllocatorError.invalidGuard
    }
    switch envelope.phase {
    case .stable(let stable):
      try validateStable(stable)
    case .pending(let pending):
      try validateStable(pending.previous)
      let revision = pending.previous.stateRevision.addingReportingOverflow(1)
      let highWater = pending.previous.reservedHighWater.addingReportingOverflow(
        CounterBlock.size
      )
      guard !revision.overflow,
        !highWater.overflow,
        pending.nextStateRevision == revision.partialValue,
        pending.nextHighWater == highWater.partialValue,
        pending.reservationID.count == 16,
        !pending.reservationID.allSatisfy({ $0 == 0 }),
        pending.nextStateCommitment.count == 32,
        !pending.nextStateCommitment.allSatisfy({ $0 == 0 }),
        pending.nextStateCommitment != pending.previous.stateCommitment
      else {
        throw CounterAllocatorError.invalidGuard
      }
    case .statePending(let pending):
      try validateStable(pending.previous)
      let revision = pending.previous.stateRevision.addingReportingOverflow(1)
      guard !revision.overflow,
        pending.nextStateRevision == revision.partialValue,
        pending.nextStateCommitment.count == 32,
        !pending.nextStateCommitment.allSatisfy({ $0 == 0 }),
        pending.nextStateCommitment != pending.previous.stateCommitment
      else {
        throw CounterAllocatorError.invalidGuard
      }
    case .keyTransitionPending(let pending):
      try validateStable(pending.previous)
      let stateRevision = pending.previous.stateRevision.addingReportingOverflow(1)
      let directoryRevision = envelope.currentScope.keyDirectoryRevision
        .addingReportingOverflow(1)
      let keyEpoch = envelope.currentScope.keyEpoch.addingReportingOverflow(1)
      let senderContinues =
        pending.nextScope.keyEpoch == envelope.currentScope.keyEpoch
        && pending.nextScope.noncePrefix == envelope.currentScope.noncePrefix
        && pending.nextReservedHighWater == pending.previous.reservedHighWater
      let senderRotates =
        !keyEpoch.overflow
        && pending.nextScope.keyEpoch == keyEpoch.partialValue
        && pending.nextScope.noncePrefix != envelope.currentScope.noncePrefix
        && !pending.nextScope.noncePrefix.allSatisfy({ $0 == 0 })
        && pending.nextReservedHighWater == 0
      guard !stateRevision.overflow,
        !directoryRevision.overflow,
        pending.nextScope.promotionID == envelope.currentScope.promotionID,
        pending.nextScope.trustEpoch == envelope.currentScope.trustEpoch,
        pending.nextScope.keyDirectoryRevision == directoryRevision.partialValue,
        pending.nextScope.invariantCommitment != envelope.currentScope.invariantCommitment,
        senderContinues || senderRotates,
        pending.nextStateRevision == stateRevision.partialValue,
        pending.nextStateCommitment.count == 32,
        !pending.nextStateCommitment.allSatisfy({ $0 == 0 }),
        pending.nextStateCommitment != pending.previous.stateCommitment
      else {
        throw CounterAllocatorError.invalidGuard
      }
    case .retired(let retired):
      guard retired.retiredAtMS > 0,
        retired.stateRevision > 0,
        retired.stateCommitment.count == 32,
        !retired.stateCommitment.allSatisfy({ $0 == 0 })
      else {
        throw CounterAllocatorError.invalidGuard
      }
    }
  }

  private static func validateStable(_ stable: CounterGuardStable) throws {
    guard stable.stateRevision > 0,
      stable.stateCommitment.count == 32,
      !stable.stateCommitment.allSatisfy({ $0 == 0 })
    else {
      throw CounterAllocatorError.invalidGuard
    }
  }

  fileprivate static func bootstrapCommitment(
    scope: CounterGuardScope,
    initialStateCommitment: Data
  ) -> Data {
    var input = Data("AgentDeck/CounterGuardBootstrapCommitmentV1\0".utf8)
    input.append(scope.promotionID)
    input.appendInteger(scope.trustEpoch)
    input.appendInteger(scope.keyDirectoryRevision)
    input.appendInteger(scope.keyEpoch)
    input.append(scope.noncePrefix)
    input.append(scope.invariantCommitment)
    input.append(initialStateCommitment)
    return CanonicalCodec.sha256(input)
  }
}

private struct GuardDecoder {
  let data: Data
  private(set) var offset = 0
  var isAtEnd: Bool { offset == data.count }

  mutating func u8() throws -> UInt8 { try fixed(count: 1)[0] }
  mutating func u16() throws -> UInt16 { try integer(count: 2) }
  mutating func u64() throws -> UInt64 { try integer(count: 8) }

  mutating func fixed(count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= data.count else {
      throw CounterAllocatorError.invalidGuard
    }
    defer { offset = end.partialValue }
    return data.subdata(in: offset..<end.partialValue)
  }

  private mutating func integer<T: FixedWidthInteger>(count: Int) throws -> T {
    try fixed(count: count).reduce(0) { ($0 << 8) | T($1) }
  }
}

extension Data {
  fileprivate mutating func appendInteger<T: FixedWidthInteger>(_ value: T) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
  }
}
