import Foundation
import Security

enum CryptoStatePersistenceStage: Equatable, Sendable {
  case guardPendingDurable
  case stateGuardPendingDurable
  case stateDurable
  case guardStableDurable
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

/// 统一拥有 machine lease、CounterGuard 与完整 sealed-state transition。
///
/// `CounterAllocator` 只消费本 actor 在三段 durable readback 后返回的 block。
public actor DurableCryptoStateCoordinator: CounterBlockReserving {
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
    case .pending, .statePending:
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
        scopeMatches(retiredEnvelope.scope, state: snapshot.state),
        snapshot.state.securityState != .active,
        retired.stateRevision == snapshot.state.stateRevision,
        retired.reservedHighWater == snapshot.state.senderCounter.reservedHighWater,
        retired.stateCommitment == snapshot.commitment
      else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      envelope = retiredEnvelope
    case .pending, .statePending:
      throw CounterAllocatorError.invalidGuard
    }
    guard envelope.scope.promotionID == promotionID,
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
        scope: recovered.envelope.scope,
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
        scope: recovered.envelope.scope,
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
  ) async throws -> ReplayDisposition {
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
      guard replay.status == .active else {
        throw CounterAllocatorError.epochRetirementRequired
      }
      var window = try ReplayWindow(snapshot: replay.window)
      do {
        let disposition = try window.observe(
          counter: counter,
          ciphertextHash: ciphertextHash
        )
        guard disposition == .fresh else { return disposition }
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
        return .fresh
      } catch RelayCryptoError.nonceReuse {
        let quarantined = try recovered.snapshot.state.quarantining(
          reason: .nonceReuse,
          scope: scope,
          observedAtMS: observedAtMS
        )
        try await commitStateFirst(
          recovered: recovered,
          candidate: CryptoStateSnapshot(quarantined)
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
      try await quarantineWithoutUsableGuard(snapshot)
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
      let recovered = RecoveredCounterState(
        snapshot: snapshot,
        envelope: envelope,
        stable: stable,
        guardData: guardData
      )
      try await retireAndQuarantine(recovered, reason: .authenticatedStateRollback)

    case .pending(let envelope):
      guard case .pending(let pending) = envelope.phase else {
        throw CounterAllocatorError.invalidGuard
      }
      guard scopeMatches(envelope.scope, state: snapshot.state) else {
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
        scope: envelope.scope,
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
      guard scopeMatches(envelope.scope, state: snapshot.state) else {
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
        scope: envelope.scope,
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
        scope: scope,
        initialStateCommitment: durable.commitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .stable(stable)
      ))
    let encoded = try guardState.encode()

    if let existing = try await keyStore.load(guardKey) {
      guard existing == encoded,
        try CounterGuardState.decode(existing) == guardState
      else {
        throw CounterAllocatorError.epochRetirementRequired
      }
    } else {
      _ = try await keyStore.persistImmutable(encoded, for: guardKey)
    }
    guard try await keyStore.load(guardKey) == encoded else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    return CounterBootstrapEvidence(
      initialStateCommitment: durable.commitment,
      initialGuardCommitment: initialGuardCommitment
    )
  }

  private func commitStateFirst(
    recovered: RecoveredCounterState,
    candidate: CryptoStateSnapshot
  ) async throws {
    try validateStateFirstTransition(
      previous: recovered.snapshot.state,
      next: candidate.state
    )

    let pending = CounterGuardStatePending(
      previous: recovered.stable,
      nextStateRevision: candidate.state.stateRevision,
      nextStateCommitment: candidate.commitment
    )
    let pendingEnvelope = CounterGuardEnvelope(
      scope: recovered.envelope.scope,
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
      scope: recovered.envelope.scope,
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

  private func validateStateFirstTransition(
    previous: DeviceCryptoStateV1,
    next: DeviceCryptoStateV1
  ) throws {
    let revision = previous.stateRevision.addingReportingOverflow(1)
    guard !revision.overflow,
      next.stateRevision == revision.partialValue,
      next.trustScope == previous.trustScope,
      next.keyDirectory == previous.keyDirectory,
      next.senderCounter == previous.senderCounter
    else {
      throw CounterAllocatorError.invalidState
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
    scopeMatches(envelope.scope, state: snapshot.state)
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
      scope: recovered.envelope.scope,
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
    let invariant = try DeviceCryptoStateV1(
      stateRevision: 1,
      trustScope: state.trustScope,
      keyDirectory: state.keyDirectory,
      senderCounter: initialSender,
      securityState: .active,
      replayStates: [],
      streamStates: []
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
  case retired(CounterGuardRetired)
}

private struct CounterGuardEnvelope: Equatable, Sendable {
  let scope: CounterGuardScope
  let initialStateCommitment: Data
  let initialGuardCommitment: Data
  let phase: CounterGuardPhase
}

private enum CounterGuardState: Equatable, Sendable {
  case stable(CounterGuardEnvelope)
  case pending(CounterGuardEnvelope)
  case statePending(CounterGuardEnvelope)
  case retired(CounterGuardEnvelope)

  private static let magic = Data("ADCG".utf8)
  private static let version: UInt16 = 2

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
    case .statePending(let value):
      envelope = value
      phaseTag = 3
      guard case .statePending = value.phase else {
        throw CounterAllocatorError.invalidGuard
      }
    case .retired(let value):
      envelope = value
      phaseTag = 2
      guard case .retired = value.phase else { throw CounterAllocatorError.invalidGuard }
    }
    try Self.validateEnvelope(envelope)

    var data = Self.magic
    data.appendInteger(Self.version)
    data.append(phaseTag)
    data.append(0)
    data.append(envelope.scope.promotionID)
    data.appendInteger(envelope.scope.trustEpoch)
    data.appendInteger(envelope.scope.keyDirectoryRevision)
    data.appendInteger(envelope.scope.keyEpoch)
    data.append(envelope.scope.noncePrefix)
    data.append(contentsOf: [0, 0, 0, 0])
    data.append(envelope.scope.invariantCommitment)
    data.append(envelope.initialStateCommitment)
    data.append(envelope.initialGuardCommitment)
    switch envelope.phase {
    case .stable(let stable):
      data.appendInteger(stable.stateRevision)
      data.appendInteger(stable.reservedHighWater)
      data.append(stable.stateCommitment)
    case .pending(let pending):
      data.appendInteger(pending.previous.stateRevision)
      data.appendInteger(pending.previous.reservedHighWater)
      data.append(pending.previous.stateCommitment)
      data.appendInteger(pending.nextStateRevision)
      data.appendInteger(pending.nextHighWater)
      data.append(pending.reservationID)
      data.append(pending.nextStateCommitment)
    case .statePending(let pending):
      data.appendInteger(pending.previous.stateRevision)
      data.appendInteger(pending.previous.reservedHighWater)
      data.append(pending.previous.stateCommitment)
      data.appendInteger(pending.nextStateRevision)
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
    guard try decoder.fixed(count: 4) == magic,
      try decoder.u16() == version
    else {
      throw CounterAllocatorError.invalidGuard
    }
    let phase = try decoder.u8()
    guard try decoder.u8() == 0 else { throw CounterAllocatorError.invalidGuard }
    let scope = try CounterGuardScope(
      promotionID: decoder.fixed(count: 32),
      trustEpoch: decoder.u64(),
      keyDirectoryRevision: decoder.u64(),
      keyEpoch: decoder.u64(),
      noncePrefix: decoder.fixed(count: 4),
      invariantCommitment: {
        guard try decoder.fixed(count: 4).allSatisfy({ $0 == 0 }) else {
          throw CounterAllocatorError.invalidGuard
        }
        return try decoder.fixed(count: 32)
      }()
    )
    let initialStateCommitment = try decoder.fixed(count: 32)
    let initialGuardCommitment = try decoder.fixed(count: 32)
    let envelope: CounterGuardEnvelope
    switch phase {
    case 0:
      let stable = CounterGuardStable(
        stateRevision: try decoder.u64(),
        reservedHighWater: try decoder.u64(),
        stateCommitment: try decoder.fixed(count: 32)
      )
      envelope = CounterGuardEnvelope(
        scope: scope,
        initialStateCommitment: initialStateCommitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .stable(stable)
      )
      guard decoder.isAtEnd else { throw CounterAllocatorError.invalidGuard }
      try validateEnvelope(envelope)
      return .stable(envelope)
    case 1:
      let previous = CounterGuardStable(
        stateRevision: try decoder.u64(),
        reservedHighWater: try decoder.u64(),
        stateCommitment: try decoder.fixed(count: 32)
      )
      let pending = CounterGuardPending(
        previous: previous,
        nextStateRevision: try decoder.u64(),
        nextHighWater: try decoder.u64(),
        reservationID: try decoder.fixed(count: 16),
        nextStateCommitment: try decoder.fixed(count: 32)
      )
      envelope = CounterGuardEnvelope(
        scope: scope,
        initialStateCommitment: initialStateCommitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .pending(pending)
      )
      guard decoder.isAtEnd else { throw CounterAllocatorError.invalidGuard }
      try validateEnvelope(envelope)
      return .pending(envelope)
    case 2:
      guard let reason = DeviceCryptoSecurityReason(rawValue: try decoder.u8()),
        try decoder.fixed(count: 7).allSatisfy({ $0 == 0 })
      else {
        throw CounterAllocatorError.invalidGuard
      }
      let retired = CounterGuardRetired(
        reason: reason,
        retiredAtMS: try decoder.u64(),
        stateRevision: try decoder.u64(),
        reservedHighWater: try decoder.u64(),
        stateCommitment: try decoder.fixed(count: 32)
      )
      envelope = CounterGuardEnvelope(
        scope: scope,
        initialStateCommitment: initialStateCommitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .retired(retired)
      )
      guard decoder.isAtEnd else { throw CounterAllocatorError.invalidGuard }
      try validateEnvelope(envelope)
      return .retired(envelope)
    case 3:
      let previous = CounterGuardStable(
        stateRevision: try decoder.u64(),
        reservedHighWater: try decoder.u64(),
        stateCommitment: try decoder.fixed(count: 32)
      )
      let pending = CounterGuardStatePending(
        previous: previous,
        nextStateRevision: try decoder.u64(),
        nextStateCommitment: try decoder.fixed(count: 32)
      )
      envelope = CounterGuardEnvelope(
        scope: scope,
        initialStateCommitment: initialStateCommitment,
        initialGuardCommitment: initialGuardCommitment,
        phase: .statePending(pending)
      )
      guard decoder.isAtEnd else { throw CounterAllocatorError.invalidGuard }
      try validateEnvelope(envelope)
      return .statePending(envelope)
    default:
      throw CounterAllocatorError.invalidGuard
    }
  }

  private static func validateEnvelope(_ envelope: CounterGuardEnvelope) throws {
    guard envelope.initialStateCommitment.count == 32,
      !envelope.initialStateCommitment.allSatisfy({ $0 == 0 }),
      envelope.initialGuardCommitment.count == 32,
      !envelope.initialGuardCommitment.allSatisfy({ $0 == 0 })
    else {
      throw CounterAllocatorError.invalidGuard
    }
    guard
      envelope.initialGuardCommitment
        == bootstrapCommitment(
          scope: envelope.scope,
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
