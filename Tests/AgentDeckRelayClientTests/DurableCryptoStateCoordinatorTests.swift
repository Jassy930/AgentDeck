import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class DurableCryptoStateCoordinatorTests: XCTestCase {
  func testExplicitBootstrapThenReservePersistsCompleteBlockBeforeReturningCounter() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    let initialCommit = try await environment.stateStore.commitInitial(
      environment.initialSnapshot
    )
    XCTAssertEqual(initialCommit, .created)
    let coordinator = try environment.makeCoordinator()

    _ = try await coordinator.bootstrap(environment.bootstrapPermit())
    let allocator = CounterAllocator(coordinator: coordinator)
    let counter = try await allocator.nextCounter()

    XCTAssertEqual(counter, 0)
    let loaded = try await environment.stateStore.load()
    let durable = try XCTUnwrap(loaded)
    XCTAssertEqual(durable.state.senderCounter.reservedHighWater, CounterBlock.size)
    XCTAssertEqual(durable.state.stateRevision, 2)
    XCTAssertEqual(durable.state.securityState, .active)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .stable)
  }

  func testBootstrapRequiresExactDurableInitialStateAndIsIdempotent() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    let coordinator = try environment.makeCoordinator()
    let permit = try environment.bootstrapPermit()

    await assertAsyncError(CounterAllocatorError.invalidState) {
      try await coordinator.bootstrap(permit)
    }
    let missingGuard = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertNil(missingGuard)

    let initialCommit = try await environment.stateStore.commitInitial(
      environment.initialSnapshot
    )
    XCTAssertEqual(initialCommit, .created)
    let firstEvidence = try await coordinator.bootstrap(permit)
    let loadedFirstGuard = await environment.keyStore.value(for: environment.guardKey)
    let firstGuard = try XCTUnwrap(loadedFirstGuard)
    let secondEvidence = try await coordinator.bootstrap(permit)
    let loadedSecondGuard = await environment.keyStore.value(for: environment.guardKey)
    let secondGuard = try XCTUnwrap(loadedSecondGuard)

    XCTAssertEqual(firstEvidence, secondEvidence)
    XCTAssertEqual(firstEvidence.initialStateCommitment, environment.initialSnapshot.commitment)
    XCTAssertEqual(firstEvidence.initialGuardCommitment.count, 32)
    XCTAssertEqual(firstGuard, secondGuard, "幂等 bootstrap 不得改写 exact guard")
    assertGuardPhase(secondGuard, .stable)

    let conflictingPermit = try CounterBootstrapPermit(
      snapshot: environment.initialSnapshot,
      promotionID: Data(repeating: 0xC2, count: 32)
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await coordinator.bootstrap(conflictingPermit)
    }
    let guardAfterConflict = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterConflict, firstGuard, "不同 promotion 不能覆盖已存在 guard")
    let stateAfterConflict = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterConflict, environment.initialSnapshot)
  }

  func testKeySyncEpisodeSurvivesCoordinatorRestartAndGenericSeamCannotRewriteIt()
    async throws
  {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let initial = environment.initialSnapshot.state
    let targetRevision = initial.keyDirectory.revision + 1
    let startedAtMS = CoordinatorTestEnvironment.fixedTimeMS

    let firstCoordinator = try environment.makeCoordinator()
    let begun = try await firstCoordinator.beginOrResumeKeySyncEpisode(
      targetRevision: targetRevision,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 2),
      streamRoute: nil,
      observedAtMS: startedAtMS
    )
    let firstEpisode = try XCTUnwrap(begun.state.keySyncEpisode)

    let restarted = try environment.makeCoordinator()
    let exactResume = try await restarted.beginOrResumeKeySyncEpisode(
      targetRevision: targetRevision,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 77),
      streamRoute: nil,
      observedAtMS: startedAtMS + 1
    )
    XCTAssertEqual(exactResume, begun)
    XCTAssertEqual(exactResume.state.keySyncEpisode, firstEpisode)

    let attemptTwo = try await restarted.recordKeySyncAttemptFailure(
      targetRevision: targetRevision,
      attempt: 1,
      observedAtMS: startedAtMS + 2
    )
    XCTAssertEqual(attemptTwo.state.keySyncEpisode?.attempt, 2)
    XCTAssertEqual(attemptTwo.state.keySyncEpisode?.expiresAtMS, firstEpisode.expiresAtMS)

    let forbiddenState = try DeviceCryptoStateV1(
      stateRevision: attemptTwo.state.stateRevision + 1,
      trustScope: attemptTwo.state.trustScope,
      keyDirectory: attemptTwo.state.keyDirectory,
      senderCounter: attemptTwo.state.senderCounter,
      securityState: attemptTwo.state.securityState,
      replayStates: attemptTwo.state.replayStates,
      streamStates: attemptTwo.state.streamStates,
      keyLifecycle: attemptTwo.state.keyLifecycle,
      pendingStreamBindings: attemptTwo.state.pendingStreamBindings,
      keySyncEpisode: nil
    )
    do {
      try await restarted.commitNonCounterState(
        expected: attemptTwo,
        replacement: CryptoStateSnapshot(forbiddenState)
      )
      XCTFail("generic seam must not clear a durable KeySync episode")
    } catch {
      XCTAssertEqual(error as? CounterAllocatorError, .invalidState)
    }
    let afterForbiddenValue = try await environment.stateStore.load()
    XCTAssertEqual(try XCTUnwrap(afterForbiddenValue), attemptTwo)

    let expired = try await environment.makeCoordinator().expireKeySyncEpisode(
      observedAtMS: firstEpisode.expiresAtMS
    )
    XCTAssertEqual(expired.state.keySyncEpisode?.exhausted, true)
    do {
      _ = try await environment.makeCoordinator().beginOrResumeKeySyncEpisode(
        targetRevision: targetRevision,
        observedKeyID: firstEpisode.observedKeyID,
        streamRoute: firstEpisode.streamRoute,
        observedAtMS: firstEpisode.expiresAtMS + 1
      )
      XCTFail("cold-open must not refresh an expired episode")
    } catch {
      XCTAssertEqual(error as? DeviceCryptoStateError, .keySyncEpisodeEnded)
    }
  }

  func testNonceReuseQuarantineAtomicallyClearsActiveKeySyncEpisode() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let initial = environment.initialSnapshot.state
    _ = try await coordinator.beginOrResumeKeySyncEpisode(
      targetRevision: initial.keyDirectory.revision + 1,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 2),
      streamRoute: nil,
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS
    )
    let scope = initial.replayStates[0].scope
    _ = try await coordinator.admitReplay(
      scope: scope,
      counter: 11,
      ciphertextHash: Data(repeating: 0xA1, count: 32),
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1
    )
    do {
      _ = try await coordinator.admitReplay(
        scope: scope,
        counter: 11,
        ciphertextHash: Data(repeating: 0xA2, count: 32),
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 2
      )
      XCTFail("nonce reuse must fail closed")
    } catch {
      XCTAssertEqual(error as? RelayCryptoError, .nonceReuse)
    }
    let loadedValue = try await environment.stateStore.load()
    let loaded = try XCTUnwrap(loadedValue)
    XCTAssertNil(loaded.state.keySyncEpisode)
    guard case .quarantined(reason: .nonceReuse, _, _) = loaded.state.securityState else {
      return XCTFail("security quarantine must be durable before returning nonceReuse")
    }
  }

  func testOrdinaryReserveWithoutGuardDurablyQuarantinesZeroHighWaterState() async throws {
    let recorder = PersistenceStageRecorder()
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    let initialCommit = try await environment.stateStore.commitInitial(
      environment.initialSnapshot
    )
    XCTAssertEqual(initialCommit, .created)
    let coordinator = try environment.makeCoordinator(observer: { stage in
      await recorder.record(stage)
    })
    let allocator = CounterAllocator(coordinator: coordinator)

    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await allocator.nextCounter()
    }

    let loadedQuarantine = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantine)
    XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, 0)
    XCTAssertEqual(quarantined.state.stateRevision, 2)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .authenticatedStateRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let stages = await recorder.snapshot()
    XCTAssertEqual(stages, [.securityQuarantineDurable])
    let missingGuard = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertNil(missingGuard)

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let stateAfterRestart = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterRestart, quarantined)
  }

  func testAllReservationCrashCutsSkipEntireBlockAfterRestart() async throws {
    for stage in [
      CryptoStatePersistenceStage.guardPendingDurable,
      .stateDurable,
      .guardStableDurable,
    ] {
      try await exerciseReservationCrashCut(stage)
    }
  }

  func testTwoAllocatorsSharingCoordinatorReturn2048UniqueCounters() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let first = CounterAllocator(coordinator: coordinator)
    let second = CounterAllocator(coordinator: coordinator)

    let counters = try await collectCounters(count: 2_048) { index in
      if index.isMultiple(of: 2) {
        return try await first.nextCounter()
      }
      return try await second.nextCounter()
    }

    assertUniqueContiguous(counters, startingAt: 0)
    let loaded = try await environment.stateStore.load()
    let durable = try XCTUnwrap(loaded)
    XCTAssertEqual(durable.state.senderCounter.reservedHighWater, 2 * CounterBlock.size)
  }

  func testTwoIndependentCoordinatorsUseMachineLeaseFor2048UniqueCounters() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let firstCoordinator = try environment.makeCoordinator()
    let secondCoordinator = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    let first = CounterAllocator(coordinator: firstCoordinator)
    let second = CounterAllocator(coordinator: secondCoordinator)

    let counters = try await collectCounters(count: 2_048) { index in
      if index.isMultiple(of: 2) {
        return try await first.nextCounter()
      }
      return try await second.nextCounter()
    }

    assertUniqueContiguous(counters, startingAt: 0)
    let loaded = try await environment.stateStore.load()
    let durable = try XCTUnwrap(loaded)
    XCTAssertEqual(durable.state.senderCounter.reservedHighWater, 2 * CounterBlock.size)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .stable)
  }

  func testRolledBackStateDurablyQuarantinesAndRetiresMachineWithoutCounter() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let firstAllocator = CounterAllocator(coordinator: try environment.makeCoordinator())
    let firstCounter = try await firstAllocator.nextCounter()
    XCTAssertEqual(firstCounter, 0)
    let loadedCurrent = try await environment.stateStore.load()
    let current = try XCTUnwrap(loadedCurrent)
    let loadedStableGuard = await environment.keyStore.value(for: environment.guardKey)
    let stableGuard = try XCTUnwrap(loadedStableGuard)

    try await environment.stateStore.deleteExact(expected: current)
    let rollbackCommit = try await environment.stateStore.commitInitial(
      environment.initialSnapshot
    )
    XCTAssertEqual(rollbackCommit, .created)
    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }

    let loadedQuarantine = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantine)
    XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, 0)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .authenticatedStateRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let loadedRetiredGuard = await environment.keyStore.value(for: environment.guardKey)
    let retiredGuard = try XCTUnwrap(loadedRetiredGuard)
    XCTAssertNotEqual(retiredGuard, stableGuard)
    assertGuardPhase(retiredGuard, .retired)

    let secondRestart = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await secondRestart.reserveCounterBlock()
    }
    let stateAfterSecondRestart = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterSecondRestart, quarantined)
    let guardAfterSecondRestart = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterSecondRestart, retiredGuard)
  }

  func testForkedGuardDurablyQuarantinesAndRetiresMachineWithoutCounter() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let loadedBootstrapGuard = await environment.keyStore.value(for: environment.guardKey)
    let bootstrapGuard = try XCTUnwrap(loadedBootstrapGuard)
    let firstAllocator = CounterAllocator(coordinator: try environment.makeCoordinator())
    let firstCounter = try await firstAllocator.nextCounter()
    XCTAssertEqual(firstCounter, 0)
    let loadedReservedState = try await environment.stateStore.load()
    let reservedState = try XCTUnwrap(loadedReservedState)
    XCTAssertEqual(reservedState.state.senderCounter.reservedHighWater, CounterBlock.size)

    await environment.keyStore.force(bootstrapGuard, for: environment.guardKey)
    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }

    let loadedQuarantine = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantine)
    XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, CounterBlock.size)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .authenticatedStateRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let loadedRetiredGuard = await environment.keyStore.value(for: environment.guardKey)
    let retiredGuard = try XCTUnwrap(loadedRetiredGuard)
    assertGuardPhase(retiredGuard, .retired)

    let secondRestart = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await secondRestart.reserveCounterBlock()
    }
    let stateAfterSecondRestart = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterSecondRestart, quarantined)
    let guardAfterSecondRestart = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterSecondRestart, retiredGuard)
  }

  func testUnrelatedFullStateTransitionPreventsStaleExpectedOverwrite() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let expected = environment.initialSnapshot

    let changedCursor = try DeviceStreamCursorStateV1(
      streamRoute: expected.state.streamStates[0].streamRoute,
      generation: expected.state.streamStates[0].generation,
      outerCursor: .at(77),
      innerCursor: .catalog(.at(88))
    )
    let cursorCandidate = try CryptoStateSnapshot(
      replacingState(
        expected.state,
        stateRevision: expected.state.stateRevision + 1,
        streamStates: [changedCursor]
      ))
    try await coordinator.commitNonCounterState(
      expected: expected,
      replacement: cursorCandidate
    )
    let loadedGuardAfterCursor = await environment.keyStore.value(for: environment.guardKey)
    let guardAfterCursor = try XCTUnwrap(loadedGuardAfterCursor)

    var replayWindow = ReplayWindow()
    XCTAssertEqual(
      try replayWindow.observe(
        counter: 9,
        ciphertextHash: Data(repeating: 0xA9, count: 32)
      ),
      .fresh
    )
    let changedReplay = try DeviceReplayStateV1(
      scope: expected.state.replayStates[0].scope,
      window: replayWindow.snapshot,
      status: .active
    )
    let staleCandidate = try CryptoStateSnapshot(
      replacingState(
        expected.state,
        stateRevision: expected.state.stateRevision + 1,
        replayStates: [changedReplay]
      ))
    XCTAssertNotEqual(cursorCandidate.commitment, staleCandidate.commitment)

    await assertAsyncError(CryptoStateStoreError.compareAndReplaceMismatch) {
      try await coordinator.commitNonCounterState(
        expected: expected,
        replacement: staleCandidate
      )
    }
    let stateAfterStaleAttempt = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterStaleAttempt, cursorCandidate)
    let guardAfterStaleAttempt = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterStaleAttempt, guardAfterCursor)
  }

  func testNonceReuseIsDurablyQuarantinedBeforeErrorAndSurvivesRestart() async throws {
    let recorder = PersistenceStageRecorder()
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator(observer: { stage in
      await recorder.record(stage)
    })
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let firstHash = Data(repeating: 0x71, count: 32)
    let reusedHash = Data(repeating: 0x72, count: 32)

    let firstDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: 17,
      ciphertextHash: firstHash,
      observedAtMS: 200
    )
    XCTAssertEqual(firstDisposition.disposition, .fresh)
    XCTAssertEqual(firstDisposition.snapshot.state.stateRevision, 2)
    await recorder.reset()

    await assertAsyncError(RelayCryptoError.nonceReuse) {
      try await coordinator.admitReplay(
        scope: scope,
        counter: 17,
        ciphertextHash: reusedHash,
        observedAtMS: 300
      )
    }
    let quarantineStages = await recorder.snapshot()
    XCTAssertEqual(
      quarantineStages,
      [
        .stateGuardPendingDurable,
        .stateDurable,
        .guardStableDurable,
        .securityQuarantineDurable,
      ]
    )
    let loadedQuarantine = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantine)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(reason: .nonceReuse, observedAtMS: 300, scope: scope)
    )
    XCTAssertEqual(
      quarantined.state.replayStates[0].status,
      .quarantined(reason: .nonceReuse, observedAtMS: 300)
    )
    let quarantineGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(quarantineGuard, .retired)

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.admitReplay(
        scope: scope,
        counter: 18,
        ciphertextHash: Data(repeating: 0x73, count: 32),
        observedAtMS: 400
      )
    }
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let stateAfterRestart = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterRestart, quarantined)
  }

  func testReplayFreshPersistsWhileExactDuplicateAndStaleDoNotMutate() async throws {
    let recorder = PersistenceStageRecorder()
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator(observer: { stage in
      await recorder.record(stage)
    })
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let highHash = Data(repeating: 0x81, count: 32)

    let freshDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: ReplayWindow.windowSize,
      ciphertextHash: highHash,
      observedAtMS: 500
    )
    XCTAssertEqual(freshDisposition.disposition, .fresh)
    let freshStages = await recorder.snapshot()
    XCTAssertEqual(
      freshStages,
      [.stateGuardPendingDurable, .stateDurable, .guardStableDurable]
    )
    let loadedAfterFresh = try await environment.stateStore.load()
    let afterFresh = try XCTUnwrap(loadedAfterFresh)
    let loadedGuardAfterFresh = await environment.keyStore.value(for: environment.guardKey)
    let guardAfterFresh = try XCTUnwrap(loadedGuardAfterFresh)
    XCTAssertEqual(afterFresh.state.stateRevision, 2)
    XCTAssertEqual(afterFresh.state.replayStates[0].window.highWater, ReplayWindow.windowSize)
    XCTAssertEqual(afterFresh.state.replayStates[0].window.floor, 1)
    await recorder.reset()

    let duplicateDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: ReplayWindow.windowSize,
      ciphertextHash: highHash,
      observedAtMS: 600
    )
    XCTAssertEqual(duplicateDisposition.disposition, .exactDuplicate)
    let staleDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: 0,
      ciphertextHash: Data(repeating: 0x82, count: 32),
      observedAtMS: 700
    )
    XCTAssertEqual(staleDisposition.disposition, .stale)
    XCTAssertEqual(duplicateDisposition.snapshot, freshDisposition.snapshot)
    XCTAssertEqual(staleDisposition.snapshot, freshDisposition.snapshot)

    let nonMutationStages = await recorder.snapshot()
    XCTAssertEqual(nonMutationStages, [])
    let stateAfterNonMutations = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterNonMutations, afterFresh)
    let guardAfterNonMutations = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterNonMutations, guardAfterFresh)
  }

  func testRetiredReplayOnlyReturnsRecordedDuplicateBeforeExpiry() async throws {
    let ciphertextHash = Data(repeating: 0x8A, count: 32)
    let fixture = try retiredReplayFixture(ciphertextHash: ciphertextHash)
    let environment = try CoordinatorTestEnvironment(initialState: fixture.state)
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()

    let duplicate = try await coordinator.admitReplay(
      scope: fixture.scope,
      counter: ReplayWindow.windowSize,
      ciphertextHash: ciphertextHash,
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1
    )
    XCTAssertEqual(duplicate.disposition, .exactDuplicate)
    XCTAssertEqual(duplicate.snapshot, environment.initialSnapshot)
    XCTAssertEqual(
      duplicate.admissionProof.replayStatus,
      .retired(
        retiredAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        deleteAfterMS: fixture.deleteAfterMS
      )
    )

    let stale = try await coordinator.admitReplay(
      scope: fixture.scope,
      counter: 0,
      ciphertextHash: Data(repeating: 0x8B, count: 32),
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 2
    )
    XCTAssertEqual(stale.disposition, .stale)
    XCTAssertEqual(stale.snapshot, environment.initialSnapshot)

    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await coordinator.admitReplay(
        scope: fixture.scope,
        counter: ReplayWindow.windowSize,
        ciphertextHash: ciphertextHash,
        observedAtMS: fixture.deleteAfterMS
      )
    }
    let stateAfterExpiry = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterExpiry, environment.initialSnapshot)
  }

  func testRetiredFreshTupleDurablyQuarantinesAsRevisionRollback() async throws {
    let ciphertextHash = Data(repeating: 0x8C, count: 32)
    let fixture = try retiredReplayFixture(ciphertextHash: ciphertextHash)
    let environment = try CoordinatorTestEnvironment(initialState: fixture.state)
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let recorder = PersistenceStageRecorder()
    let coordinator = try environment.makeCoordinator(observer: { stage in
      await recorder.record(stage)
    })

    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await coordinator.admitReplay(
        scope: fixture.scope,
        counter: ReplayWindow.windowSize - 1,
        ciphertextHash: Data(repeating: 0x8D, count: 32),
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1
      )
    }
    let quarantineStages = await recorder.snapshot()
    XCTAssertEqual(
      quarantineStages,
      [
        .stateGuardPendingDurable,
        .stateDurable,
        .guardStableDurable,
        .securityQuarantineDurable,
      ]
    )
    let loadedSnapshot = try await environment.stateStore.load()
    let loaded = try XCTUnwrap(loadedSnapshot)
    XCTAssertEqual(
      loaded.state.securityState,
      .quarantined(
        reason: .keyRevisionRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1,
        scope: fixture.scope
      )
    )
    XCTAssertEqual(
      loaded.state.replayStates.first(where: { $0.scope == fixture.scope })?.status,
      .quarantined(
        reason: .keyRevisionRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1
      )
    )
    assertGuardPhase(await environment.keyStore.value(for: environment.guardKey), .retired)
  }

  func testRetiredDuplicateProofOpensOnlyTheExactDelayedSignedFrame() async throws {
    let crypto = try retiredCryptoDeliveryFixture()
    let environment = try CoordinatorTestEnvironment(
      initialState: crypto.state,
      identity: crypto.identity
    )
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()

    let duplicate = try await coordinator.admitReplay(
      scope: crypto.candidate.replayScope,
      counter: crypto.candidate.counter,
      ciphertextHash: crypto.candidate.ciphertextHash,
      observedAtMS: crypto.retiredAtMS + 1
    )
    XCTAssertEqual(duplicate.disposition, .exactDuplicate)
    let opened = try crypto.verifier.openRetiredMachineData(
      crypto.candidate,
      replayAdmission: duplicate
    )
    XCTAssertEqual(opened.payloadKind, .catalogDelta)
    XCTAssertEqual(opened.payload, crypto.payload)

    let stale = try await coordinator.admitReplay(
      scope: crypto.candidate.replayScope,
      counter: 0,
      ciphertextHash: Data(repeating: 0x8E, count: 32),
      observedAtMS: crypto.retiredAtMS + 2
    )
    XCTAssertEqual(stale.disposition, .stale)
    XCTAssertThrowsError(
      try crypto.verifier.openRetiredMachineData(
        crypto.candidate,
        replayAdmission: stale
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .retiredReplayAdmissionRequired)
    }
  }

  func testStagedEpochBarrierRequiresDurableReplayThenActivatesAndReplaysIdempotently()
    async throws
  {
    let crypto = try stagedEpochBarrierDeliveryFixture()
    let environment = try CoordinatorTestEnvironment(
      initialState: try stateWithActiveKeySyncEpisode(crypto.state),
      identity: crypto.identity
    )
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()

    let unrelatedScope = try XCTUnwrap(
      crypto.state.replayStates.first(where: {
        $0.scope.keyID == KeyIDV1(purpose: .catalog, epoch: 1)
      })?.scope
    )
    let unrelatedAdmission = try await coordinator.admitReplay(
      scope: unrelatedScope,
      counter: 99,
      ciphertextHash: Data(repeating: 0xFA, count: 32),
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS
    )
    XCTAssertThrowsError(
      try crypto.verifier.openStagedKeyControl(
        crypto.candidate,
        replayAdmission: unrelatedAdmission
      )
    ) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .stagedReplayAdmissionRequired)
    }

    let admission = try await coordinator.admitReplay(
      scope: crypto.candidate.replayScope,
      counter: crypto.candidate.counter,
      ciphertextHash: crypto.candidate.ciphertextHash,
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 1
    )
    XCTAssertEqual(admission.disposition, .fresh)
    let opened = try crypto.verifier.openStagedKeyControl(
      crypto.candidate,
      replayAdmission: admission
    )
    guard case .epochBarrier(let barrier) = opened else {
      return XCTFail("staged Catalog next-key frame 必须只解出 EpochBarrier")
    }
    XCTAssertEqual(barrier, crypto.barrier)

    let activated = try await coordinator.applyEpochBarrier(
      expected: admission.snapshot,
      barrier: barrier
    )
    XCTAssertEqual(activated.snapshot.state.senderCounter.keyDirectoryRevision, 8)
    XCTAssertNil(activated.snapshot.state.keySyncEpisode)
    XCTAssertEqual(
      activated.snapshot.state.replayStates.first(where: {
        $0.scope == crypto.candidate.replayScope
      })?.window.highWater,
      crypto.candidate.counter
    )

    let duplicate = try await coordinator.admitReplay(
      scope: crypto.candidate.replayScope,
      counter: crypto.candidate.counter,
      ciphertextHash: crypto.candidate.ciphertextHash,
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS + 2
    )
    XCTAssertEqual(duplicate.disposition, .exactDuplicate)
    XCTAssertEqual(
      try crypto.verifier.openStagedKeyControl(
        crypto.candidate,
        replayAdmission: duplicate
      ),
      .epochBarrier(crypto.barrier)
    )
    let duplicateActivation = try await coordinator.applyEpochBarrier(
      expected: duplicate.snapshot,
      barrier: crypto.barrier
    )
    XCTAssertEqual(duplicateActivation.snapshot, activated.snapshot)
  }

  func testStagedDirectoryAdvanceUsesCurrentHeaderReplayAndActivatesPrecreatedConversationScope()
    async throws
  {
    let crypto = try stagedDirectoryAdvanceDeliveryFixture()
    let environment = try CoordinatorTestEnvironment(
      initialState: try stateWithActiveKeySyncEpisode(crypto.state),
      identity: crypto.identity
    )
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()

    XCTAssertEqual(crypto.candidate.headerKeyDirectoryRevision, 7)
    XCTAssertEqual(crypto.candidate.stagedKeyDirectoryRevision, 8)
    let admission = try await coordinator.admitReplay(
      scope: crypto.candidate.replayScope,
      counter: crypto.candidate.counter,
      ciphertextHash: crypto.candidate.ciphertextHash,
      observedAtMS: CoordinatorTestEnvironment.fixedTimeMS
    )
    let opened = try crypto.verifier.openStagedKeyControl(
      crypto.candidate,
      replayAdmission: admission
    )
    guard case .directoryRevisionAdvance(let advance) = opened else {
      return XCTFail("zero-cut staged Catalog frame 必须只解出 DirectoryRevisionAdvance")
    }
    XCTAssertEqual(advance, crypto.advance)

    let activated = try await coordinator.applyDirectoryRevisionAdvance(
      expected: admission.snapshot,
      advance: advance
    )
    XCTAssertEqual(activated.state.senderCounter.keyDirectoryRevision, 8)
    XCTAssertNil(activated.state.keySyncEpisode)
    XCTAssertEqual(
      activated.state.replayStates.first(where: {
        $0.scope == crypto.newConversationScope
      })?.status,
      .active
    )
    XCTAssertNil(
      activated.state.replayStates.first(where: {
        $0.scope == crypto.newConversationScope
      })?.window.highWater
    )
  }

  func testNonCounterTransitionRejectsReplayDeletionHashAndHighWaterRollback() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let acceptedHash = Data(repeating: 0x91, count: 32)

    let disposition = try await coordinator.admitReplay(
      scope: scope,
      counter: ReplayWindow.windowSize,
      ciphertextHash: acceptedHash,
      observedAtMS: 800
    )
    XCTAssertEqual(disposition.disposition, .fresh)
    let loadedExpected = try await environment.stateStore.load()
    let expected = try XCTUnwrap(loadedExpected)
    let revision = expected.state.stateRevision + 1
    let replay = expected.state.replayStates[0]
    let resetReplay = try DeviceReplayStateV1(
      scope: replay.scope,
      window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
      status: replay.status
    )
    let replacedHash = try DeviceReplayStateV1(
      scope: replay.scope,
      window: ReplayWindowSnapshot(
        highWater: ReplayWindow.windowSize,
        floor: 1,
        entries: [
          ReplayWindowEntry(
            counter: ReplayWindow.windowSize,
            ciphertextHash: Data(repeating: 0x92, count: 32)
          )
        ]
      ),
      status: replay.status
    )
    let candidates = try [
      CryptoStateSnapshot(
        replacingState(expected.state, stateRevision: revision, replayStates: [])
      ),
      CryptoStateSnapshot(
        replacingState(expected.state, stateRevision: revision, replayStates: [resetReplay])
      ),
      CryptoStateSnapshot(
        replacingState(expected.state, stateRevision: revision, replayStates: [replacedHash])
      ),
    ]

    for candidate in candidates {
      await assertAsyncError(CounterAllocatorError.invalidState) {
        try await coordinator.commitNonCounterState(
          expected: expected,
          replacement: candidate
        )
      }
      let stateAfterAttempt = try await environment.stateStore.load()
      XCTAssertEqual(stateAfterAttempt, expected)
    }
  }

  func testNonCounterTransitionRejectsReplayStatusRollback() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let initial = environment.initialSnapshot
    let replay = initial.state.replayStates[0]
    let quarantinedReplay = try DeviceReplayStateV1(
      scope: replay.scope,
      window: replay.window,
      status: .quarantined(reason: .nonceReuse, observedAtMS: 900)
    )
    let quarantined = try CryptoStateSnapshot(
      replacingState(
        initial.state,
        stateRevision: initial.state.stateRevision + 1,
        replayStates: [quarantinedReplay]
      )
    )
    try await coordinator.commitNonCounterState(expected: initial, replacement: quarantined)

    let reactivatedReplay = try DeviceReplayStateV1(
      scope: replay.scope,
      window: replay.window,
      status: .active
    )
    let reactivated = try CryptoStateSnapshot(
      replacingState(
        quarantined.state,
        stateRevision: quarantined.state.stateRevision + 1,
        replayStates: [reactivatedReplay]
      )
    )
    await assertAsyncError(CounterAllocatorError.invalidState) {
      try await coordinator.commitNonCounterState(
        expected: quarantined,
        replacement: reactivated
      )
    }
    let stateAfterAttempt = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterAttempt, quarantined)
  }

  func testNonCounterTransitionRejectsStreamDeletionIdentityAndCursorRollback() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let initial = environment.initialSnapshot
    let original = initial.state.streamStates[0]
    let advancedStream = try DeviceStreamCursorStateV1(
      streamRoute: original.streamRoute,
      generation: original.generation,
      outerCursor: .at(20),
      innerCursor: .catalog(.at(30))
    )
    let advanced = try CryptoStateSnapshot(
      replacingState(
        initial.state,
        stateRevision: initial.state.stateRevision + 1,
        streamStates: [advancedStream]
      )
    )
    try await coordinator.commitNonCounterState(expected: initial, replacement: advanced)

    let changedGeneration = try DeviceStreamCursorStateV1(
      streamRoute: original.streamRoute,
      generation: Data(repeating: 0x67, count: 16),
      outerCursor: .at(20),
      innerCursor: .catalog(.at(30))
    )
    let rolledBackOuter = try DeviceStreamCursorStateV1(
      streamRoute: original.streamRoute,
      generation: original.generation,
      outerCursor: .at(19),
      innerCursor: .catalog(.at(30))
    )
    let rolledBackInner = try DeviceStreamCursorStateV1(
      streamRoute: original.streamRoute,
      generation: original.generation,
      outerCursor: .at(20),
      innerCursor: .catalog(.at(29))
    )
    let changedIdentity = try DeviceStreamCursorStateV1(
      streamRoute: original.streamRoute,
      generation: original.generation,
      outerCursor: .at(20),
      innerCursor: .conversation(id: "different-stream", cursor: .at(30))
    )
    let revision = advanced.state.stateRevision + 1
    let candidates = try [
      CryptoStateSnapshot(
        replacingState(advanced.state, stateRevision: revision, streamStates: [])
      ),
      CryptoStateSnapshot(
        replacingState(
          advanced.state,
          stateRevision: revision,
          streamStates: [changedGeneration]
        )
      ),
      CryptoStateSnapshot(
        replacingState(
          advanced.state,
          stateRevision: revision,
          streamStates: [rolledBackOuter]
        )
      ),
      CryptoStateSnapshot(
        replacingState(
          advanced.state,
          stateRevision: revision,
          streamStates: [rolledBackInner]
        )
      ),
      CryptoStateSnapshot(
        replacingState(
          advanced.state,
          stateRevision: revision,
          streamStates: [changedIdentity]
        )
      ),
    ]

    for candidate in candidates {
      await assertAsyncError(CounterAllocatorError.invalidState) {
        try await coordinator.commitNonCounterState(
          expected: advanced,
          replacement: candidate
        )
      }
      let stateAfterAttempt = try await environment.stateStore.load()
      XCTAssertEqual(stateAfterAttempt, advanced)
    }
  }

  func testNonCounterTransitionCannotReactivateQuarantinedMachineAfterCrashCut() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let acceptedHash = Data(repeating: 0xA1, count: 32)
    _ = try await environment.makeCoordinator().admitReplay(
      scope: scope,
      counter: 17,
      ciphertextHash: acceptedHash,
      observedAtMS: 1_000
    )
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .guardStableDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(
      InjectedCoordinatorCrash(stage: .guardStableDurable)
    ) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 17,
        ciphertextHash: Data(repeating: 0xA2, count: 32),
        observedAtMS: 1_100
      )
    }

    let loadedQuarantined = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantined)
    guard case .quarantined = quarantined.state.securityState else {
      return XCTFail("nonce reuse crash cut 必须先持久化 machine quarantine")
    }
    let guardBeforeAttempt = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardBeforeAttempt, .stable)
    let reactivated = try CryptoStateSnapshot(
      replacingState(
        quarantined.state,
        stateRevision: quarantined.state.stateRevision + 1,
        securityState: .active
      )
    )
    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.invalidState) {
      try await restarted.commitNonCounterState(
        expected: quarantined,
        replacement: reactivated
      )
    }
    let stateAfterAttempt = try await environment.stateStore.load()
    let guardAfterAttempt = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(stateAfterAttempt, quarantined)
    XCTAssertEqual(guardAfterAttempt, guardBeforeAttempt)
  }

  func testStatePendingCrashBeforeStateRollsBackGuardAndRetryCommitsExactTransition() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let ciphertextHash = Data(repeating: 0xB1, count: 32)
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .stateGuardPendingDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })

    await assertAsyncError(
      InjectedCoordinatorCrash(stage: .stateGuardPendingDurable)
    ) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 31,
        ciphertextHash: ciphertextHash,
        observedAtMS: 1_200
      )
    }
    let stateAtCut = try await environment.stateStore.load()
    XCTAssertEqual(stateAtCut, environment.initialSnapshot)
    let guardAtCut = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAtCut, .statePending)

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    let disposition = try await restarted.admitReplay(
      scope: scope,
      counter: 31,
      ciphertextHash: ciphertextHash,
      observedAtMS: 1_300
    )
    XCTAssertEqual(disposition.disposition, .fresh)
    XCTAssertEqual(disposition.snapshot.state.stateRevision, 2)
    let loadedRecovered = try await environment.stateStore.load()
    let recovered = try XCTUnwrap(loadedRecovered)
    XCTAssertEqual(recovered.state.stateRevision, 2)
    XCTAssertEqual(recovered.state.replayStates[0].window.highWater, 31)
    let recoveredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(recoveredGuard, .stable)
  }

  func testStatePendingCrashAfterStateFinalizesOnlyExactCommitment() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let ciphertextHash = Data(repeating: 0xB2, count: 32)
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .stateDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })

    await assertAsyncError(InjectedCoordinatorCrash(stage: .stateDurable)) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 32,
        ciphertextHash: ciphertextHash,
        observedAtMS: 1_400
      )
    }
    let loadedStateAtCut = try await environment.stateStore.load()
    let stateAtCut = try XCTUnwrap(loadedStateAtCut)
    XCTAssertEqual(stateAtCut.state.stateRevision, 2)
    let guardAtCut = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAtCut, .statePending)

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    let disposition = try await restarted.admitReplay(
      scope: scope,
      counter: 32,
      ciphertextHash: ciphertextHash,
      observedAtMS: 1_500
    )
    XCTAssertEqual(disposition.disposition, .exactDuplicate)
    XCTAssertEqual(disposition.snapshot, stateAtCut)
    let stateAfterRecovery = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterRecovery, stateAtCut)
    let guardAfterRecovery = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAfterRecovery, .stable)
  }

  func testStatePendingRejectsAuthenticatedReplayRollbackSibling() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .stateDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(InjectedCoordinatorCrash(stage: .stateDurable)) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 33,
        ciphertextHash: Data(repeating: 0xB3, count: 32),
        observedAtMS: 1_600
      )
    }
    let loadedExpectedNext = try await environment.stateStore.load()
    let expectedNext = try XCTUnwrap(loadedExpectedNext)
    let sibling = try CryptoStateSnapshot(
      replacingState(
        expectedNext.state,
        stateRevision: expectedNext.state.stateRevision,
        replayStates: environment.initialSnapshot.state.replayStates
      ))
    XCTAssertNotEqual(sibling.commitment, expectedNext.commitment)
    try await environment.stateStore.compareAndReplaceExact(
      expected: expectedNext,
      replacement: sibling
    )

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let loadedQuarantined = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantined)
    XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, 0)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .authenticatedStateRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let retiredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(retiredGuard, .retired)
  }

  func testStatePendingRejectsQuarantinedToActiveSibling() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let firstHash = Data(repeating: 0xB4, count: 32)
    _ = try await environment.makeCoordinator().admitReplay(
      scope: scope,
      counter: 34,
      ciphertextHash: firstHash,
      observedAtMS: 1_700
    )
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .stateDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(InjectedCoordinatorCrash(stage: .stateDurable)) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 34,
        ciphertextHash: Data(repeating: 0xB5, count: 32),
        observedAtMS: 1_800
      )
    }
    let loadedExpectedQuarantine = try await environment.stateStore.load()
    let expectedQuarantine = try XCTUnwrap(loadedExpectedQuarantine)
    guard case .quarantined = expectedQuarantine.state.securityState else {
      return XCTFail("nonce reuse state cut 必须已持久化 quarantine")
    }
    let reactivatedSibling = try CryptoStateSnapshot(
      replacingState(
        expectedQuarantine.state,
        stateRevision: expectedQuarantine.state.stateRevision,
        securityState: .active
      ))
    try await environment.stateStore.compareAndReplaceExact(
      expected: expectedQuarantine,
      replacement: reactivatedSibling
    )

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let loadedQuarantined = try await environment.stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantined)
    XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, 0)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .authenticatedStateRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let retiredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(retiredGuard, .retired)
  }

  func testStatePendingCodecRejectsInvalidVersionTrailingBytesAndZeroCommitment() async throws {
    for mutation in StatePendingGuardMutation.allCases {
      let environment = try CoordinatorTestEnvironment()
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let scope = environment.initialSnapshot.state.replayStates[0].scope
      let crashing = try environment.makeCoordinator(observer: { stage in
        if stage == .stateGuardPendingDurable {
          throw InjectedCoordinatorCrash(stage: stage)
        }
      })
      await assertAsyncError(
        InjectedCoordinatorCrash(stage: .stateGuardPendingDurable)
      ) {
        try await crashing.admitReplay(
          scope: scope,
          counter: 35,
          ciphertextHash: Data(repeating: 0xB6, count: 32),
          observedAtMS: 1_900
        )
      }
      let loadedGuard = await environment.keyStore.value(for: environment.guardKey)
      var malformed = try XCTUnwrap(loadedGuard)
      assertGuardPhase(malformed, .statePending)
      mutation.apply(to: &malformed)
      await environment.keyStore.force(malformed, for: environment.guardKey)

      let restarted = try environment.makeCoordinator(
        stateStore: environment.makeStateStore()
      )
      await assertAsyncError(CounterAllocatorError.invalidGuard) {
        try await restarted.reserveCounterBlock()
      }
      let loadedQuarantined = try await environment.stateStore.load()
      let quarantined = try XCTUnwrap(loadedQuarantined)
      XCTAssertEqual(quarantined.state.senderCounter.reservedHighWater, 0)
      guard case .quarantined = quarantined.state.securityState else {
        return XCTFail("malformed state pending 必须 fail-close")
      }
    }
  }

  func testKeyDirectoryAdvancePreservesSenderReservationAndRetiresReplayCanonically()
    async throws
  {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    _ = try await coordinator.reserveCounterBlock()
    let expected = try await loadedState(environment)
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )

    let committed = try await coordinator.advanceKeyDirectory(
      expected: expected,
      to: directory,
      senderCounter: sender
    )

    XCTAssertEqual(committed.state.stateRevision, expected.state.stateRevision + 1)
    XCTAssertEqual(committed.state.keyDirectory.revision, nextRevision)
    XCTAssertEqual(committed.state.senderCounter.keyID, expected.state.senderCounter.keyID)
    XCTAssertEqual(
      committed.state.senderCounter.noncePrefix,
      expected.state.senderCounter.noncePrefix
    )
    XCTAssertEqual(
      committed.state.senderCounter.reservedHighWater,
      expected.state.senderCounter.reservedHighWater
    )
    XCTAssertEqual(
      committed.state.senderCounter.reservationID,
      expected.state.senderCounter.reservationID
    )
    let oldReplay = try XCTUnwrap(
      committed.state.replayStates.first(where: {
        $0.scope == expected.state.replayStates[0].scope
      }))
    XCTAssertEqual(oldReplay.window, expected.state.replayStates[0].window)
    XCTAssertEqual(
      oldReplay.status,
      .retired(
        retiredAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        deleteAfterMS: CoordinatorTestEnvironment.fixedTimeMS
          + ReplayWindow.retiredWindowRetentionMilliseconds
      )
    )
    let newCatalogScope = DeviceCryptoKeyScopeV1(
      keyID: KeyIDV1(
        purpose: .catalog,
        epoch: CoordinatorTestFixture.replayKeyID.epoch + 1
      ),
      streamRoute: nil
    )
    let newCatalog = try XCTUnwrap(
      committed.state.replayStates.first(where: { $0.scope == newCatalogScope }))
    XCTAssertEqual(newCatalog.window, ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []))
    XCTAssertEqual(newCatalog.status, .active)
    let guardAfterAdvance = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAfterAdvance, .stable)

    let nextCounter = try await CounterAllocator(coordinator: coordinator).nextCounter()
    XCTAssertEqual(nextCounter, CounterBlock.size)
  }

  func testLegacyFullDirectoryAdvanceRejectsDirectedSenderRotation() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    _ = try await coordinator.reserveCounterBlock()
    let expected = try await loadedState(environment)
    let nextRevision = expected.state.keyDirectory.revision + 1
    let nextSenderEpoch = expected.state.senderCounter.keyID.epoch + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      senderEpoch: nextSenderEpoch
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision,
      epoch: nextSenderEpoch,
      noncePrefix: Data([0x50, 0x60, 0x70, 0x80]),
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    )

    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await coordinator.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }
    let quarantined = try await loadedState(environment)
    guard
      case .quarantined(reason: .keyRevisionRollback, _, nil) =
        quarantined.state.securityState
    else {
      return XCTFail("normal UpdateSet 禁止轮换 directed sender epoch")
    }
    XCTAssertEqual(quarantined.state.senderCounter, expected.state.senderCounter)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .retired)
  }

  func testKeyTransitionRecoveryAcceptsExactOldAndNewConversationCarrierDelta()
    async throws
  {
    let environment = try CoordinatorTestEnvironment(includeConversation: true)
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      conversationEpochs: [
        CoordinatorTestFixture.conversationKeyID.epoch,
        CoordinatorTestFixture.conversationKeyID.epoch + 1,
      ]
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )

    let committed = try await environment.makeCoordinator().advanceKeyDirectory(
      expected: expected,
      to: directory,
      senderCounter: sender
    )

    let oldScope = DeviceCryptoKeyScopeV1(
      keyID: CoordinatorTestFixture.conversationKeyID,
      streamRoute: CoordinatorTestFixture.conversationRoute
    )
    let old = try XCTUnwrap(
      committed.state.replayStates.first(where: { $0.scope == oldScope })
    )
    guard case .retired(let retiredAtMS, _) = old.status else {
      return XCTFail("old conversation epoch 必须成为 retention tombstone")
    }
    XCTAssertEqual(retiredAtMS, CoordinatorTestEnvironment.fixedTimeMS)
    let nextScope = DeviceCryptoKeyScopeV1(
      keyID: KeyIDV1(
        purpose: .conversationDEK,
        epoch: CoordinatorTestFixture.conversationKeyID.epoch + 1
      ),
      streamRoute: CoordinatorTestFixture.conversationRoute
    )
    let activated = try XCTUnwrap(
      committed.state.replayStates.first(where: { $0.scope == nextScope })
    )
    XCTAssertEqual(activated.status, .active)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .stable)
  }

  func testKeyDirectoryAdvancePropagatesInvalidLocalClockWithoutSecurityRetirement()
    async throws
  {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(revision: nextRevision)
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let zeroClock = try environment.makeCoordinator(clock: { 0 })

    await assertAsyncError(DeviceCryptoStateError.invalidClock) {
      try await zeroClock.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }

    let stateAfterClockFailure = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterClockFailure, expected)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .stable)
  }

  func testKeyDirectoryAdvancePropagatesReplayCapacityWithoutSecurityRetirement()
    async throws
  {
    let initial = try CoordinatorTestFixture.replayCapacityState()
    let environment = try CoordinatorTestEnvironment(initialState: initial)
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      conversationEpochs: [1]
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )

    await assertAsyncError(DeviceCryptoStateError.inputTooLarge) {
      try await environment.makeCoordinator().advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }

    let stateAfterCapacityFailure = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterCapacityFailure, expected)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .stable)
  }

  func testLegacyFullDirectoryRosterRejectsConversationRemovalAndNonEpochOneAddition()
    async throws
  {
    for includeConversation in [false, true] {
      let environment = try CoordinatorTestEnvironment(
        includeConversation: includeConversation
      )
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let expected = environment.initialSnapshot
      let nextRevision = expected.state.keyDirectory.revision + 1
      let conversationEpochs: [UInt64] = includeConversation ? [] : [2]
      let directory = try CoordinatorTestFixture.directory(
        revision: nextRevision,
        conversationEpochs: conversationEpochs
      )
      let sender = try CoordinatorTestFixture.sender(
        from: expected.state,
        directoryRevision: nextRevision
      )

      await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
        try await environment.makeCoordinator().advanceKeyDirectory(
          expected: expected,
          to: directory,
          senderCounter: sender
        )
      }
      let quarantined = try await loadedState(environment)
      guard
        case .quarantined(reason: .keyRevisionRollback, _, nil) =
          quarantined.state.securityState
      else {
        return XCTFail("invalid roster 必须 fail-close")
      }
      let guardData = await environment.keyStore.value(for: environment.guardKey)
      assertGuardPhase(guardData, .retired)
    }
  }

  func testKeyDirectoryAdvanceRejectsRollbackAndSkippedRevisionWithDurableRetirement()
    async throws
  {
    for revisionOffset in [0, 2] {
      let environment = try CoordinatorTestEnvironment()
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let expected = environment.initialSnapshot
      let revision = expected.state.keyDirectory.revision + UInt64(revisionOffset)
      let directory = try CoordinatorTestFixture.directory(revision: revision)
      let sender = try CoordinatorTestFixture.sender(
        from: expected.state,
        directoryRevision: revision
      )

      await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
        try await environment.makeCoordinator().advanceKeyDirectory(
          expected: expected,
          to: directory,
          senderCounter: sender
        )
      }
      let quarantined = try await loadedState(environment)
      XCTAssertEqual(
        quarantined.state.securityState,
        .quarantined(
          reason: .keyRevisionRollback,
          observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
          scope: nil
        )
      )
      let guardData = await environment.keyStore.value(for: environment.guardKey)
      assertGuardPhase(guardData, .retired)
    }
  }

  func testKeyDirectoryAdvanceRejectsUnsafeSenderResetRules() async throws {
    for scenario in [UnsafeSenderTransitionScenario.sameKeyCounterReset] {
      let environment = try CoordinatorTestEnvironment()
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let coordinator = try environment.makeCoordinator()
      _ = try await coordinator.reserveCounterBlock()
      let expected = try await loadedState(environment)
      let nextRevision = expected.state.keyDirectory.revision + 1
      let nextSenderEpoch =
        scenario.rotatesKey
        ? expected.state.senderCounter.keyID.epoch + 1
        : expected.state.senderCounter.keyID.epoch
      let directory = try CoordinatorTestFixture.directory(
        revision: nextRevision,
        senderEpoch: nextSenderEpoch
      )
      let safeSender = try CoordinatorTestFixture.sender(
        from: expected.state,
        directoryRevision: nextRevision,
        epoch: nextSenderEpoch,
        noncePrefix: scenario.rotatesKey
          ? Data([0x50, 0x60, 0x70, 0x80])
          : expected.state.senderCounter.noncePrefix,
        reservedHighWater: scenario.rotatesKey
          ? 0
          : expected.state.senderCounter.reservedHighWater,
        reservationID: scenario.rotatesKey
          ? Data(repeating: 0, count: 16)
          : expected.state.senderCounter.reservationID
      )
      let canonical = try expected.state.advancingKeyDirectory(
        to: directory,
        senderCounter: safeSender,
        retiredAtMS: CoordinatorTestEnvironment.fixedTimeMS
      )
      let unsafeSender = try scenario.makeSender(
        expected: expected.state,
        directoryRevision: nextRevision,
        senderEpoch: nextSenderEpoch
      )
      let invalid = try CryptoStateSnapshot(
        replacingState(
          canonical,
          stateRevision: canonical.stateRevision,
          keyDirectory: directory,
          senderCounter: unsafeSender
        ))

      await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
        try await coordinator.advanceKeyDirectory(expected: expected, replacement: invalid)
      }
      let quarantined = try await loadedState(environment)
      guard
        case .quarantined(reason: .keyRevisionRollback, _, nil) =
          quarantined.state.securityState
      else {
        return XCTFail("\(scenario) 必须 fail-close quarantine")
      }
      let guardData = await environment.keyStore.value(for: environment.guardKey)
      assertGuardPhase(guardData, .retired)
    }
  }

  func testKeyDirectoryAdvanceRejectsReplayWindowDeletion() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    _ = try await coordinator.admitReplay(
      scope: scope,
      counter: 77,
      ciphertextHash: Data(repeating: 0xD1, count: 32),
      observedAtMS: 2_000
    )
    let expected = try await loadedState(environment)
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let canonical = try expected.state.advancingKeyDirectory(
      to: directory,
      senderCounter: sender,
      retiredAtMS: CoordinatorTestEnvironment.fixedTimeMS
    )
    let deletedOldReplay = canonical.replayStates.filter { $0.scope != scope }
    let invalid = try CryptoStateSnapshot(
      replacingState(
        canonical,
        stateRevision: canonical.stateRevision,
        keyDirectory: directory,
        senderCounter: sender,
        replayStates: deletedOldReplay
      ))

    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await coordinator.advanceKeyDirectory(expected: expected, replacement: invalid)
    }
    let quarantined = try await loadedState(environment)
    let preserved = try XCTUnwrap(
      quarantined.state.replayStates.first(where: { $0.scope == scope }))
    XCTAssertEqual(preserved.window, expected.state.replayStates[0].window)
    let guardData = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardData, .retired)
  }

  func testKeyTransitionCrashBeforeStateRollsGuardBackThenExactRetryCommits() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .keyTransitionGuardPendingDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })

    await assertAsyncError(
      InjectedCoordinatorCrash(stage: .keyTransitionGuardPendingDurable)
    ) {
      try await crashing.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }
    let stateAtCut = try await environment.stateStore.load()
    XCTAssertEqual(stateAtCut, expected)
    let guardAtCut = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAtCut, .keyTransitionPending)

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    let committed = try await restarted.advanceKeyDirectory(
      expected: expected,
      to: directory,
      senderCounter: sender
    )
    let stateAfterRetry = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterRetry, committed)
    let recoveredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(recoveredGuard, .stable)
  }

  func testKeyTransitionCrashAfterStateFinalizesOnlyExactNextCommitment() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .keyTransitionStateDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })

    await assertAsyncError(InjectedCoordinatorCrash(stage: .keyTransitionStateDurable)) {
      try await crashing.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }
    let stateAtCut = try await loadedState(environment)
    let guardAtCut = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(guardAtCut, .keyTransitionPending)

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    await assertAsyncError(CryptoStateStoreError.compareAndReplaceMismatch) {
      try await restarted.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }
    let stateAfterRecovery = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterRecovery, stateAtCut)
    let finalizedGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(finalizedGuard, .stable)
  }

  func testKeyTransitionPendingRejectsAuthenticatedSiblingAndRetiresExactObservedScope()
    async throws
  {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(
      revision: nextRevision,
      catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
    )
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .keyTransitionStateDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(InjectedCoordinatorCrash(stage: .keyTransitionStateDurable)) {
      try await crashing.advanceKeyDirectory(
        expected: expected,
        to: directory,
        senderCounter: sender
      )
    }
    let exactNext = try await loadedState(environment)
    XCTAssertGreaterThan(exactNext.state.replayStates.count, 1)
    let sibling = try CryptoStateSnapshot(
      replacingState(
        exactNext.state,
        stateRevision: exactNext.state.stateRevision,
        keyDirectory: exactNext.state.keyDirectory,
        senderCounter: exactNext.state.senderCounter,
        replayStates: Array(exactNext.state.replayStates.reversed())
      ))
    XCTAssertNotEqual(sibling.commitment, exactNext.commitment)
    try await environment.stateStore.compareAndReplaceExact(
      expected: exactNext,
      replacement: sibling
    )

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let quarantined = try await loadedState(environment)
    XCTAssertEqual(quarantined.state.keyDirectory.revision, nextRevision)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .keyRevisionRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let retiredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(retiredGuard, .retired)
  }

  func testStableV3RejectsKeyDirectoryRollbackAfterCompletedAdvance() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let expected = environment.initialSnapshot
    let nextRevision = expected.state.keyDirectory.revision + 1
    let directory = try CoordinatorTestFixture.directory(revision: nextRevision)
    let sender = try CoordinatorTestFixture.sender(
      from: expected.state,
      directoryRevision: nextRevision
    )
    let committed = try await environment.makeCoordinator().advanceKeyDirectory(
      expected: expected,
      to: directory,
      senderCounter: sender
    )
    try await environment.stateStore.deleteExact(expected: committed)
    let rollbackCommit = try await environment.stateStore.commitInitial(expected)
    XCTAssertEqual(rollbackCommit, .created)

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let quarantined = try await loadedState(environment)
    XCTAssertEqual(
      quarantined.state.securityState,
      .quarantined(
        reason: .keyRevisionRollback,
        observedAtMS: CoordinatorTestEnvironment.fixedTimeMS,
        scope: nil
      )
    )
    let retiredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(retiredGuard, .retired)
  }

  func testKeyTransitionPendingCodecMutationsFailCloseAndReplaceGuardWithRetiredV3()
    async throws
  {
    for mutation in KeyTransitionGuardMutation.allCases {
      let environment = try CoordinatorTestEnvironment()
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let expected = environment.initialSnapshot
      let nextRevision = expected.state.keyDirectory.revision + 1
      let directory = try CoordinatorTestFixture.directory(
        revision: nextRevision,
        catalogEpoch: CoordinatorTestFixture.replayKeyID.epoch + 1
      )
      let sender = try CoordinatorTestFixture.sender(
        from: expected.state,
        directoryRevision: nextRevision
      )
      let crashing = try environment.makeCoordinator(observer: { stage in
        if stage == .keyTransitionGuardPendingDurable {
          throw InjectedCoordinatorCrash(stage: stage)
        }
      })
      await assertAsyncError(
        InjectedCoordinatorCrash(stage: .keyTransitionGuardPendingDurable)
      ) {
        try await crashing.advanceKeyDirectory(
          expected: expected,
          to: directory,
          senderCounter: sender
        )
      }
      var malformed = try await loadedGuard(environment)
      mutation.apply(to: &malformed)
      await environment.keyStore.force(malformed, for: environment.guardKey)

      let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
      await assertAsyncError(CounterAllocatorError.invalidGuard) {
        try await restarted.reserveCounterBlock()
      }
      let quarantined = try await loadedState(environment)
      guard case .quarantined = quarantined.state.securityState else {
        return XCTFail("\(mutation) 必须 fail-close")
      }
      let retiredGuard = await environment.keyStore.value(for: environment.guardKey)
      assertGuardPhase(retiredGuard, .retired)
    }
  }

  func testLegacyV2StablePendingStatePendingAndRetiredStrictlyRecover() async throws {
    try await exerciseLegacyV2StableRecovery()
    try await exerciseLegacyV2CounterPendingRecovery()
    try await exerciseLegacyV2StatePendingRecovery()
    try await exerciseLegacyV2RetiredRecovery()
  }

  func testLegacyV2CodecRejectsTrailingAndMalformedBootstrapCommitment() async throws {
    for mutation in LegacyGuardMutation.allCases {
      let environment = try CoordinatorTestEnvironment()
      defer { environment.removeSandbox() }
      try await environment.persistInitialAndBootstrap()
      let v3 = try await loadedGuard(environment)
      var malformed = try legacyV2Guard(fromV3: v3)
      mutation.apply(to: &malformed)
      await environment.keyStore.force(malformed, for: environment.guardKey)

      let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
      await assertAsyncError(CounterAllocatorError.invalidGuard) {
        try await restarted.reserveCounterBlock()
      }
      let quarantined = try await loadedState(environment)
      guard case .quarantined = quarantined.state.securityState else {
        return XCTFail("legacy v2 \(mutation) 必须 fail-close")
      }
      let retired = await environment.keyStore.value(for: environment.guardKey)
      assertGuardPhase(retired, .retired)
    }
  }

  private func exerciseLegacyV2StableRecovery() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let v3 = try await loadedGuard(environment)
    let legacy = try legacyV2Guard(fromV3: v3)
    await environment.keyStore.force(legacy, for: environment.guardKey)

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    let counter = try await CounterAllocator(coordinator: restarted).nextCounter()
    XCTAssertEqual(counter, 0)
    let migrated = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardVersion(migrated), 3)
    assertGuardPhase(migrated, .stable)
  }

  private func exerciseLegacyV2CounterPendingRecovery() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .guardPendingDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(InjectedCoordinatorCrash(stage: .guardPendingDurable)) {
      try await crashing.reserveCounterBlock()
    }
    let v3 = try await loadedGuard(environment)
    await environment.keyStore.force(
      try legacyV2Guard(fromV3: v3),
      for: environment.guardKey
    )

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    let counter = try await CounterAllocator(coordinator: restarted).nextCounter()
    XCTAssertEqual(counter, CounterBlock.size)
    let migrated = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardVersion(migrated), 3)
    assertGuardPhase(migrated, .stable)
  }

  private func exerciseLegacyV2StatePendingRecovery() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    let ciphertextHash = Data(repeating: 0xE1, count: 32)
    let crashing = try environment.makeCoordinator(observer: { stage in
      if stage == .stateGuardPendingDurable {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    await assertAsyncError(InjectedCoordinatorCrash(stage: .stateGuardPendingDurable)) {
      try await crashing.admitReplay(
        scope: scope,
        counter: 91,
        ciphertextHash: ciphertextHash,
        observedAtMS: 3_000
      )
    }
    let v3 = try await loadedGuard(environment)
    await environment.keyStore.force(
      try legacyV2Guard(fromV3: v3),
      for: environment.guardKey
    )

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    let disposition = try await restarted.admitReplay(
      scope: scope,
      counter: 91,
      ciphertextHash: ciphertextHash,
      observedAtMS: 3_100
    )
    XCTAssertEqual(disposition.disposition, .fresh)
    let migrated = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardVersion(migrated), 3)
    assertGuardPhase(migrated, .stable)
  }

  private func exerciseLegacyV2RetiredRecovery() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator()
    let scope = environment.initialSnapshot.state.replayStates[0].scope
    _ = try await coordinator.admitReplay(
      scope: scope,
      counter: 92,
      ciphertextHash: Data(repeating: 0xE2, count: 32),
      observedAtMS: 3_200
    )
    await assertAsyncError(RelayCryptoError.nonceReuse) {
      try await coordinator.admitReplay(
        scope: scope,
        counter: 92,
        ciphertextHash: Data(repeating: 0xE3, count: 32),
        observedAtMS: 3_300
      )
    }
    let v3 = try await loadedGuard(environment)
    let legacy = try legacyV2Guard(fromV3: v3)
    await environment.keyStore.force(legacy, for: environment.guardKey)

    let restarted = try environment.makeCoordinator(stateStore: environment.makeStateStore())
    await assertAsyncError(CounterAllocatorError.epochRetirementRequired) {
      try await restarted.reserveCounterBlock()
    }
    let retained = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardVersion(retained), 2)
    XCTAssertEqual(retained?[6], TestGuardPhase.retired.rawValue)
  }

  private func loadedState(
    _ environment: CoordinatorTestEnvironment,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async throws -> CryptoStateSnapshot {
    let loaded = try await environment.stateStore.load()
    return try XCTUnwrap(loaded, file: file, line: line)
  }

  private func loadedGuard(
    _ environment: CoordinatorTestEnvironment,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async throws -> Data {
    let loaded = await environment.keyStore.value(for: environment.guardKey)
    return try XCTUnwrap(loaded, file: file, line: line)
  }

  private func exerciseReservationCrashCut(
    _ crashStage: CryptoStatePersistenceStage
  ) async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let coordinator = try environment.makeCoordinator(observer: { stage in
      if stage == crashStage {
        throw InjectedCoordinatorCrash(stage: stage)
      }
    })
    let allocator = CounterAllocator(coordinator: coordinator)

    await assertAsyncError(InjectedCoordinatorCrash(stage: crashStage)) {
      try await allocator.nextCounter()
    }
    let loadedCutState = try await environment.stateStore.load()
    let cutState = try XCTUnwrap(loadedCutState)
    let cutGuard = await environment.keyStore.value(for: environment.guardKey)
    switch crashStage {
    case .guardPendingDurable:
      XCTAssertEqual(cutState.state.senderCounter.reservedHighWater, 0)
      assertGuardPhase(cutGuard, .pending)
    case .stateDurable:
      XCTAssertEqual(cutState.state.senderCounter.reservedHighWater, CounterBlock.size)
      assertGuardPhase(cutGuard, .pending)
    case .guardStableDurable:
      XCTAssertEqual(cutState.state.senderCounter.reservedHighWater, CounterBlock.size)
      assertGuardPhase(cutGuard, .stable)
    case .stateGuardPendingDurable, .keyTransitionGuardPendingDurable,
      .keyTransitionStateDurable, .keyTransitionGuardStableDurable,
      .securityQuarantineDurable:
      XCTFail("reservation 不应触发 security quarantine crash cut")
    }

    let restarted = try environment.makeCoordinator(
      stateStore: environment.makeStateStore()
    )
    let restartedAllocator = CounterAllocator(coordinator: restarted)
    let restartedCounter = try await restartedAllocator.nextCounter()
    XCTAssertEqual(
      restartedCounter,
      CounterBlock.size,
      "\(crashStage) 后重启必须跳过未暴露的整个 block"
    )
    let loadedRecovered = try await environment.stateStore.load()
    let recovered = try XCTUnwrap(loadedRecovered)
    XCTAssertEqual(recovered.state.senderCounter.reservedHighWater, 2 * CounterBlock.size)
    let recoveredGuard = await environment.keyStore.value(for: environment.guardKey)
    assertGuardPhase(recoveredGuard, .stable)
  }

  func testSubscriptionBootstrapBindingPersistsExactLiveCutAcrossRestart() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let binding = try coordinatorCatalogBinding(
      streamRoute: Data(repeating: 0x71, count: 16),
      generation: Data(repeating: 0x72, count: 16),
      outer: .at(10),
      inner: .at(20)
    )
    let installed = try await environment.makeCoordinator()
      .commitSubscriptionBootstrap(
        expected: environment.initialSnapshot,
        binding: binding,
        synchronizedInnerCursor: .catalog(.at(22))
      )

    XCTAssertEqual(installed.disposition, .installed)
    XCTAssertEqual(installed.snapshot.state.stateRevision, 2)
    XCTAssertTrue(installed.snapshot.state.pendingStreamBindings.isEmpty)
    XCTAssertEqual(installed.retiredBinding?.streamRoute, CoordinatorTestFixture.streamRoute)
    XCTAssertEqual(installed.retiredBinding?.streamGeneration, CoordinatorTestFixture.generation)
    let live = try XCTUnwrap(installed.snapshot.state.streamStates.first)
    XCTAssertEqual(live.streamRoute, binding.streamRoute)
    XCTAssertEqual(live.generation, binding.streamGeneration)
    XCTAssertEqual(live.outerCursor, .at(10))
    XCTAssertEqual(live.innerCursor, .catalog(.at(22)))

    let restartedStore = try environment.makeStateStore()
    let restarted = try environment.makeCoordinator(stateStore: restartedStore)
    let loadedReadback = try await restartedStore.load()
    let readback = try XCTUnwrap(loadedReadback)
    XCTAssertEqual(readback, installed.snapshot)
    let retry = try await restarted.commitSubscriptionBootstrap(
      expected: readback,
      binding: binding,
      synchronizedInnerCursor: .catalog(.at(22))
    )
    XCTAssertEqual(retry.disposition, .exactRetry)
    XCTAssertEqual(retry.snapshot, readback)
    XCTAssertNil(retry.retiredBinding)
  }

  func testWrongSubscriptionBindingIsZeroWrite() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let beforeGuard = await environment.keyStore.value(for: environment.guardKey)
    let wrongAuthority = try DeviceKeyControlAuthorityV1(
      machineRoute: CoordinatorTestFixture.machineRoute,
      deviceRoute: CoordinatorTestFixture.deviceRoute,
      grantSerial: 6,
      rootTrustEpoch: 3
    )
    let wrong = try DaemonStreamBindingV1(
      authority: wrongAuthority,
      streamRoute: Data(repeating: 0x73, count: 16),
      streamGeneration: Data(repeating: 0x74, count: 16),
      streamCursor: .at(1),
      innerCursor: .catalog(cursor: .at(1)),
      keyDirectoryRevision: CoordinatorTestFixture.directoryRevision,
      keyID: CoordinatorTestFixture.replayKeyID
    )

    await assertAsyncError(DeviceCryptoStateError.invalidStreamBinding) {
      try await environment.makeCoordinator().commitSubscriptionBootstrap(
        expected: environment.initialSnapshot,
        binding: wrong,
        synchronizedInnerCursor: .catalog(.at(1))
      )
    }
    let afterState = try await environment.stateStore.load()
    let afterGuard = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(afterState, environment.initialSnapshot)
    XCTAssertEqual(afterGuard, beforeGuard)
  }

  func testSubscriptionBindingReplacementReturnsExactRetiredBinding() async throws {
    let environment = try CoordinatorTestEnvironment()
    defer { environment.removeSandbox() }
    try await environment.persistInitialAndBootstrap()
    let firstBinding = try coordinatorCatalogBinding(
      streamRoute: Data(repeating: 0x75, count: 16),
      generation: Data(repeating: 0x76, count: 16),
      outer: .at(12),
      inner: .at(21)
    )
    let coordinator = try environment.makeCoordinator()
    let first = try await coordinator.commitSubscriptionBootstrap(
      expected: environment.initialSnapshot,
      binding: firstBinding,
      synchronizedInnerCursor: .catalog(.at(23))
    )
    let replacement = try coordinatorCatalogBinding(
      streamRoute: Data(repeating: 0x77, count: 16),
      generation: Data(repeating: 0x78, count: 16),
      outer: .beforeFirst,
      inner: .at(24)
    )
    let second = try await coordinator.commitSubscriptionBootstrap(
      expected: first.snapshot,
      binding: replacement,
      synchronizedInnerCursor: .catalog(.at(25))
    )

    let retired = try XCTUnwrap(second.retiredBinding)
    XCTAssertEqual(retired.streamRoute, firstBinding.streamRoute)
    XCTAssertEqual(retired.streamGeneration, firstBinding.streamGeneration)
    XCTAssertEqual(retired.streamCursor, .at(12))
    XCTAssertEqual(retired.innerCursor, .catalog(.at(23)))
    XCTAssertEqual(retired.keyDirectoryRevision, firstBinding.keyDirectoryRevision)
    XCTAssertEqual(retired.keyID, firstBinding.keyID)
    XCTAssertEqual(second.snapshot.state.streamStates.count, 1)
    XCTAssertEqual(second.snapshot.state.streamStates[0].streamRoute, replacement.streamRoute)
    XCTAssertEqual(second.snapshot.state.streamStates[0].generation, replacement.streamGeneration)
  }

  private func collectCounters(
    count: Int,
    operation: @escaping @Sendable (Int) async throws -> UInt64
  ) async throws -> [UInt64] {
    try await withThrowingTaskGroup(of: UInt64.self) { group in
      for index in 0..<count {
        group.addTask {
          try await operation(index)
        }
      }
      var counters: [UInt64] = []
      counters.reserveCapacity(count)
      for try await counter in group {
        counters.append(counter)
      }
      return counters
    }
  }

  private func assertUniqueContiguous(
    _ counters: [UInt64],
    startingAt start: UInt64,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(counters.count, 2_048, file: file, line: line)
    XCTAssertEqual(Set(counters).count, counters.count, file: file, line: line)
    XCTAssertEqual(
      counters.sorted(),
      (start..<(start + UInt64(counters.count))).map { $0 },
      file: file,
      line: line
    )
  }

  private func assertGuardPhase(
    _ data: Data?,
    _ expected: TestGuardPhase,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    guard let data, data.count >= 8 else {
      XCTFail("guard 缺失或过短", file: file, line: line)
      return
    }
    XCTAssertEqual(data.prefix(4), Data("ADCG".utf8), file: file, line: line)
    XCTAssertEqual(data[4], 0, file: file, line: line)
    XCTAssertEqual(data[5], 3, file: file, line: line)
    XCTAssertEqual(data[6], expected.rawValue, file: file, line: line)
    XCTAssertEqual(data[7], 0, file: file, line: line)
  }

  private func assertAsyncError<Value, Failure: Error & Equatable>(
    _ expected: Failure,
    file: StaticString = #filePath,
    line: UInt = #line,
    operation: () async throws -> Value
  ) async {
    do {
      _ = try await operation()
      XCTFail("expected operation to throw", file: file, line: line)
    } catch {
      XCTAssertEqual(error as? Failure, expected, file: file, line: line)
    }
  }
}

private func coordinatorCatalogBinding(
  streamRoute: Data,
  generation: Data,
  outer: StreamCursor,
  inner: RuntimeStreamCursorV1
) throws -> DaemonStreamBindingV1 {
  try DaemonStreamBindingV1(
    authority: DeviceKeyControlAuthorityV1(
      machineRoute: CoordinatorTestFixture.machineRoute,
      deviceRoute: CoordinatorTestFixture.deviceRoute,
      grantSerial: 5,
      rootTrustEpoch: 3
    ),
    streamRoute: streamRoute,
    streamGeneration: generation,
    streamCursor: outer,
    innerCursor: .catalog(cursor: inner),
    keyDirectoryRevision: CoordinatorTestFixture.directoryRevision,
    keyID: CoordinatorTestFixture.replayKeyID
  )
}

private enum TestGuardPhase: UInt8 {
  case stable = 0
  case pending = 1
  case retired = 2
  case statePending = 3
  case keyTransitionPending = 4
}

private func legacyV2Guard(fromV3 data: Data) throws -> Data {
  guard data.count > 200,
    data.prefix(4) == Data("ADCG".utf8),
    data[4] == 0,
    data[5] == 3
  else {
    throw CoordinatorTestHarnessError.invalidGuardFixture
  }
  var legacy = data
  // v3 header(8) + bootstrapScope(96) 后新增 currentScope(96)；v2 只有一份 scope。
  legacy.removeSubrange(104..<200)
  legacy[5] = 2
  return legacy
}

private func guardVersion(_ data: Data?) -> UInt16? {
  guard let data, data.count >= 6 else { return nil }
  return (UInt16(data[4]) << 8) | UInt16(data[5])
}

private enum StatePendingGuardMutation: CaseIterable {
  case invalidVersion
  case trailingByte
  case zeroNextCommitment

  func apply(to data: inout Data) {
    switch self {
    case .invalidVersion:
      data[5] = 4
    case .trailingByte:
      data.append(0)
    case .zeroNextCommitment:
      data.replaceSubrange((data.count - 32)..<data.count, with: repeatElement(0, count: 32))
    }
  }
}

private enum KeyTransitionGuardMutation: CaseIterable {
  case invalidVersion
  case trailingByte
  case zeroNextCommitment
  case skippedNextDirectoryRevision

  func apply(to data: inout Data) {
    switch self {
    case .invalidVersion:
      data[5] = 4
    case .trailingByte:
      data.append(0)
    case .zeroNextCommitment:
      data.replaceSubrange((data.count - 32)..<data.count, with: repeatElement(0, count: 32))
    case .skippedNextDirectoryRevision:
      // header + bootstrapScope + currentScope + initial commitments + previous Stable
      // + nextScope(promotionID + trustEpoch) 后是 next key-directory revision。
      data[359] &+= 1
    }
  }
}

private enum LegacyGuardMutation: CaseIterable {
  case trailingByte
  case zeroBootstrapCommitment

  func apply(to data: inout Data) {
    switch self {
    case .trailingByte:
      data.append(0)
    case .zeroBootstrapCommitment:
      // v2 header(8) + scope(96) + initialStateCommitment(32)。
      data.replaceSubrange(136..<168, with: repeatElement(0, count: 32))
    }
  }
}

private enum UnsafeSenderTransitionScenario: CaseIterable {
  case sameKeyCounterReset
  case rotatedKeyReusesNonce
  case rotatedKeyStartsWithReservedCounter

  var rotatesKey: Bool {
    switch self {
    case .sameKeyCounterReset: false
    case .rotatedKeyReusesNonce, .rotatedKeyStartsWithReservedCounter: true
    }
  }

  func makeSender(
    expected: DeviceCryptoStateV1,
    directoryRevision: UInt64,
    senderEpoch: UInt64
  ) throws -> DeviceSenderCounterV1 {
    switch self {
    case .sameKeyCounterReset:
      return try CoordinatorTestFixture.sender(
        from: expected,
        directoryRevision: directoryRevision,
        epoch: senderEpoch,
        reservedHighWater: 0,
        reservationID: Data(repeating: 0, count: 16)
      )
    case .rotatedKeyReusesNonce:
      return try CoordinatorTestFixture.sender(
        from: expected,
        directoryRevision: directoryRevision,
        epoch: senderEpoch,
        noncePrefix: expected.senderCounter.noncePrefix,
        reservedHighWater: 0,
        reservationID: Data(repeating: 0, count: 16)
      )
    case .rotatedKeyStartsWithReservedCounter:
      return try CoordinatorTestFixture.sender(
        from: expected,
        directoryRevision: directoryRevision,
        epoch: senderEpoch,
        noncePrefix: Data([0x50, 0x60, 0x70, 0x80]),
        reservedHighWater: CounterBlock.size,
        reservationID: Data(repeating: 0xF1, count: 16)
      )
    }
  }
}

private struct InjectedCoordinatorCrash: Error, Equatable {
  let stage: CryptoStatePersistenceStage
}

private actor PersistenceStageRecorder {
  private var stages: [CryptoStatePersistenceStage] = []

  func record(_ stage: CryptoStatePersistenceStage) {
    stages.append(stage)
  }

  func reset() {
    stages.removeAll()
  }

  func snapshot() -> [CryptoStatePersistenceStage] {
    stages
  }
}

private actor CoordinatorMemoryKeyStore: KeyStore {
  private var values: [KeyStoreKey: Data] = [:]

  func load(_ key: KeyStoreKey) async throws -> Data? {
    values[key]
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let current = values[key] {
      guard current == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values[key] = replacement
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values.removeValue(forKey: key)
  }

  func value(for key: KeyStoreKey) -> Data? {
    values[key]
  }

  func force(_ data: Data, for key: KeyStoreKey) {
    values[key] = data
  }
}

private final class CoordinatorReservationSequence: @unchecked Sendable {
  private let lock = NSLock()
  private var nextByte: UInt8 = 1

  func next() -> Data {
    lock.lock()
    defer { lock.unlock() }
    let byte = nextByte
    nextByte = nextByte == UInt8.max ? 1 : nextByte + 1
    return Data(repeating: byte, count: 16)
  }
}

private struct CoordinatorTestEnvironment {
  static let fixedTimeMS: UInt64 = 1_750_000_000_000

  let rootURL: URL
  let identity: CryptoStateIdentity
  let storageKey: DeviceStorageKEK
  let stateStore: FileCryptoStateStore
  let keyStore: CoordinatorMemoryKeyStore
  let guardKey: KeyStoreKey
  let initialSnapshot: CryptoStateSnapshot

  private let reservationSequence = CoordinatorReservationSequence()

  init(
    includeConversation: Bool = false,
    initialState override: DeviceCryptoStateV1? = nil,
    identity identityOverride: CryptoStateIdentity? = nil
  ) throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckDurableCoordinatorTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    identity = try identityOverride ?? CoordinatorTestFixture.identity()
    storageKey = try DeviceStorageKEK(
      rawRepresentation: Data(repeating: 0x5A, count: 32)
    )
    stateStore = try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: storageKey,
      testHooks: .none,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    keyStore = CoordinatorMemoryKeyStore()
    guardKey = try KeyStoreKey.paired(
      clientKind: identity.clientKind,
      installationID: identity.installationID,
      rootFingerprint: identity.machineRootFingerprint,
      machineRoute: identity.machineRoute,
      purpose: .counterGuard
    )
    initialSnapshot = try CryptoStateSnapshot(
      override
        ?? CoordinatorTestFixture.initialState(
          includeConversation: includeConversation
        )
    )
  }

  func bootstrapPermit() throws -> CounterBootstrapPermit {
    try CounterBootstrapPermit(
      snapshot: initialSnapshot,
      promotionID: Data(repeating: 0xC1, count: 32)
    )
  }

  func makeStateStore() throws -> FileCryptoStateStore {
    try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: storageKey,
      testHooks: .none,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
  }

  func makeCoordinator(
    stateStore override: FileCryptoStateStore? = nil,
    observer: CryptoStatePersistenceObserver? = nil,
    clock: @escaping CryptoStateClock = { CoordinatorTestEnvironment.fixedTimeMS }
  ) throws -> DurableCryptoStateCoordinator {
    let sequence = reservationSequence
    return try DurableCryptoStateCoordinator(
      rootURL: rootURL,
      identity: identity,
      stateStore: override ?? stateStore,
      keyStore: keyStore,
      guardKey: guardKey,
      observer: observer,
      reservationIDGenerator: { sequence.next() },
      clock: clock
    )
  }

  func persistInitialAndBootstrap() async throws {
    let commit = try await stateStore.commitInitial(initialSnapshot)
    guard commit == .created else {
      throw CoordinatorTestHarnessError.unexpectedInitialCommit
    }
    _ = try await makeCoordinator().bootstrap(bootstrapPermit())
  }

  func removeSandbox() {
    try? FileManager.default.removeItem(at: rootURL)
  }
}

private enum CoordinatorTestHarnessError: Error {
  case unexpectedInitialCommit
  case invalidGuardFixture
}

private struct RetiredReplayFixture {
  let state: DeviceCryptoStateV1
  let scope: DeviceCryptoKeyScopeV1
  let deleteAfterMS: UInt64
}

private struct RetiredCryptoDeliveryFixture {
  let state: DeviceCryptoStateV1
  let identity: CryptoStateIdentity
  let verifier: MachineDataVerifier
  let candidate: VerifiedRetiredMachineDataCandidate
  let payload: Data
  let retiredAtMS: UInt64
}

private struct StagedEpochBarrierDeliveryFixture {
  let state: DeviceCryptoStateV1
  let identity: CryptoStateIdentity
  let verifier: MachineDataVerifier
  let candidate: VerifiedStagedKeyControlCandidate
  let barrier: DeviceEpochBarrierV1
}

private struct StagedDirectoryAdvanceDeliveryFixture {
  let state: DeviceCryptoStateV1
  let identity: CryptoStateIdentity
  let verifier: MachineDataVerifier
  let candidate: VerifiedStagedKeyControlCandidate
  let advance: DeviceDirectoryRevisionAdvanceV1
  let newConversationScope: DeviceCryptoKeyScopeV1
}

private func retiredReplayFixture(ciphertextHash: Data) throws -> RetiredReplayFixture {
  let base = try CoordinatorTestFixture.initialState()
  let scope = base.replayStates[0].scope
  let deleteAfterMS =
    CoordinatorTestEnvironment.fixedTimeMS
    + ReplayWindow.retiredWindowRetentionMilliseconds
  let replay = try DeviceReplayStateV1(
    scope: scope,
    window: ReplayWindowSnapshot(
      highWater: ReplayWindow.windowSize,
      floor: 1,
      entries: [
        ReplayWindowEntry(
          counter: ReplayWindow.windowSize,
          ciphertextHash: ciphertextHash
        )
      ]
    ),
    status: .retired(
      retiredAtMS: CoordinatorTestEnvironment.fixedTimeMS,
      deleteAfterMS: deleteAfterMS
    )
  )
  return try RetiredReplayFixture(
    state: replacingState(
      base,
      stateRevision: base.stateRevision,
      replayStates: [replay]
    ),
    scope: scope,
    deleteAfterMS: deleteAfterMS
  )
}

private func retiredCryptoDeliveryFixture() throws -> RetiredCryptoDeliveryFixture {
  let fixture = try KeyUpdateSetCryptoFixture()
  let streamRoute = Data(repeating: 0xE1, count: 16)
  let generation = Data(repeating: 0xE2, count: 16)
  let retiredAtMS: UInt64 = 1_000
  let bootstrap = try fixture.signedDirectory(
    revision: 7,
    materials: lifecycleBootstrapMaterials()
  )
  let base = try lifecycleState(
    fixture: fixture,
    directory: bootstrap.directory,
    streamStates: [
      try DeviceStreamCursorStateV1(
        streamRoute: streamRoute,
        generation: generation,
        outerCursor: .at(40),
        innerCursor: .catalog(.at(39))
      )
    ]
  )
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: generation,
    streamCursor: .at(39),
    streamSeq: 40,
    messageKeyEpoch: 1
  )
  let payload = Data("retained-catalog-frame".utf8)
  let oldSendingKey = try AeadSendingKey(
    keyID: KeyIDV1(purpose: .catalog, epoch: 1),
    epoch: 1,
    keyDirectoryRevision: 7,
    payloadKind: .catalogDelta,
    rawKey: Data(repeating: 0x41, count: 32)
  )
  let unsigned = try RelayCrypto.sealSymmetric(
    payload,
    key: oldSendingKey,
    context: context,
    counter: ReplayWindow.windowSize
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: fixture.dataSigningKey,
    context: context
  )
  let oldScope = base.replayStates[0].scope
  let recordedReplay = try DeviceReplayStateV1(
    scope: oldScope,
    window: ReplayWindowSnapshot(
      highWater: ReplayWindow.windowSize,
      floor: 1,
      entries: [
        ReplayWindowEntry(
          counter: ReplayWindow.windowSize,
          ciphertextHash: CanonicalCodec.sha256(unsigned.ciphertext)
        )
      ]
    ),
    status: .active
  )
  let recorded = try base.replacingReplayState(recordedReplay)
  let staged = try fixture.setVerifier.prepareDurableStage(
    state: recorded,
    canonicalBytes: fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(
          purpose: .catalog,
          epoch: 2,
          streamRoute: nil,
          rawKeyByte: 0x51
        ),
        LifecycleTestMaterial(
          purpose: .deviceCommandTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x42
        ),
        LifecycleTestMaterial(
          purpose: .deviceReplyTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x43
        ),
      ]
    ),
    expectedConversationRoutes: []
  )
  let barrier = try DeviceEpochBarrierV1(
    streamRoute: streamRoute,
    streamGeneration: generation,
    streamCursor: .at(40),
    innerCursor: .catalog(.at(39)),
    oldEpoch: 1,
    newEpoch: 2,
    keyDirectoryRevision: 8
  )
  let activated = try staged.applyingEpochBarrier(
    barrier,
    activatedAtMS: retiredAtMS
  )
  let normalized = try DeviceCryptoStateV1(
    stateRevision: 1,
    trustScope: activated.trustScope,
    keyDirectory: activated.keyDirectory,
    senderCounter: activated.senderCounter,
    securityState: activated.securityState,
    replayStates: activated.replayStates,
    streamStates: activated.streamStates,
    keyLifecycle: activated.keyLifecycle
  )
  let inventory = try fixture.setVerifier.auditColdOpen(
    state: normalized,
    expectedConversationRoutes: []
  )
  let retained = try inventory.resolveReceivingKey(
    keyID: oldSendingKey.keyID,
    keyDirectoryRevision: 7,
    streamRoute: streamRoute,
    nowMS: retiredAtMS + 1
  )
  let verifier = try MachineDataVerifier(
    machineRoute: fixture.machineRoute,
    deviceRoute: fixture.deviceRoute,
    verifiedCertificate: VerifiedMachineDataCertificate(
      certificate: RelayV2SignedCertificate(
        subjectPubkey: fixture.dataSigningKey.publicKey.rawRepresentation,
        certRole: .data,
        generation: 4,
        rootKeyId: fixture.rootKeyID,
        trustEpoch: 3,
        notAfterMs: nil,
        signature: Data(repeating: 0xE3, count: 64)
      ),
      signingKey: fixture.dataSigningKey.publicKey
    ),
    currentKeyDirectoryRevision: inventory.activeRevision,
    maximumKeySyncAdvance: 1
  )
  let wire = try RelayV2SignedSealedBlobCodec.encode(
    signed,
    maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
  )
  let candidate = try verifier.verifyRetiredMachineData(
    wireBytes: wire,
    context: context,
    capability: retained
  )
  return RetiredCryptoDeliveryFixture(
    state: normalized,
    identity: try CryptoStateIdentity(
      clientKind: .macOSApp,
      installationID: UUID(uuidString: "E1000000-0000-0000-0000-000000000001")!,
      machineID: "retired-crypto-delivery",
      machineRootFingerprint: normalized.trustScope.machineRootFingerprint,
      machineRoute: normalized.trustScope.machineRoute
    ),
    verifier: verifier,
    candidate: candidate,
    payload: payload,
    retiredAtMS: retiredAtMS
  )
}

private func stagedEpochBarrierDeliveryFixture() throws -> StagedEpochBarrierDeliveryFixture {
  let fixture = try KeyUpdateSetCryptoFixture()
  let streamRoute = Data(repeating: 0xF1, count: 16)
  let generation = Data(repeating: 0xF2, count: 16)
  let bootstrap = try fixture.signedDirectory(
    revision: 7,
    materials: lifecycleBootstrapMaterials()
  )
  let base = try lifecycleState(
    fixture: fixture,
    directory: bootstrap.directory,
    streamStates: [
      try DeviceStreamCursorStateV1(
        streamRoute: streamRoute,
        generation: generation,
        outerCursor: .at(40),
        innerCursor: .catalog(.at(39))
      )
    ]
  )
  let staged = try fixture.setVerifier.prepareDurableStage(
    state: base,
    canonicalBytes: fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(purpose: .catalog, epoch: 2, streamRoute: nil, rawKeyByte: 0x51),
        LifecycleTestMaterial(
          purpose: .deviceCommandTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x42
        ),
        LifecycleTestMaterial(
          purpose: .deviceReplyTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x43
        ),
      ]
    ),
    expectedConversationRoutes: []
  )
  let normalized = try normalizedCoordinatorInitialState(staged)
  let inventory = try fixture.setVerifier.auditColdOpen(
    state: normalized,
    expectedConversationRoutes: []
  )
  let capability = try inventory.resolveReceivingKey(
    keyID: KeyIDV1(purpose: .catalog, epoch: 2),
    keyDirectoryRevision: 8,
    streamRoute: streamRoute,
    nowMS: CoordinatorTestEnvironment.fixedTimeMS
  )
  XCTAssertEqual(capability.lifecycle, .staged)
  let barrier = try DeviceEpochBarrierV1(
    streamRoute: streamRoute,
    streamGeneration: generation,
    streamCursor: .at(40),
    innerCursor: .catalog(.at(39)),
    oldEpoch: 1,
    newEpoch: 2,
    keyDirectoryRevision: 8
  )
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: generation,
    streamCursor: nil,
    streamSeq: barrier.appliedStreamSequence,
    messageKeyEpoch: 2
  )
  let candidate = try stagedControlCandidate(
    fixture: fixture,
    inventory: inventory,
    capability: capability,
    context: context,
    headerRevision: 8,
    keyID: KeyIDV1(purpose: .catalog, epoch: 2),
    rawKeyByte: 0x51,
    counter: 17,
    control: .epochBarrier(barrier)
  )
  return StagedEpochBarrierDeliveryFixture(
    state: normalized,
    identity: try coordinatorIdentity(
      state: normalized,
      installationID: "F1000000-0000-0000-0000-000000000001",
      machineID: "staged-epoch-barrier"
    ),
    verifier: try machineDataVerifier(fixture: fixture, currentRevision: 7),
    candidate: candidate,
    barrier: barrier
  )
}

private func stagedDirectoryAdvanceDeliveryFixture() throws
  -> StagedDirectoryAdvanceDeliveryFixture
{
  let fixture = try KeyUpdateSetCryptoFixture()
  let catalogRoute = Data(repeating: 0xF3, count: 16)
  let conversationRoute = Data(repeating: 0xF4, count: 16)
  let generation = Data(repeating: 0xF5, count: 16)
  let bootstrap = try fixture.signedDirectory(
    revision: 7,
    materials: lifecycleBootstrapMaterials()
  )
  let base = try lifecycleState(
    fixture: fixture,
    directory: bootstrap.directory,
    streamStates: [
      try DeviceStreamCursorStateV1(
        streamRoute: catalogRoute,
        generation: generation,
        outerCursor: .at(70),
        innerCursor: .catalog(.at(69))
      )
    ]
  )
  let staged = try fixture.setVerifier.prepareDurableStage(
    state: base,
    canonicalBytes: fixture.signedUpdateSet(
      revision: 8,
      materials: [
        LifecycleTestMaterial(purpose: .catalog, epoch: 1, streamRoute: nil, rawKeyByte: 0x41),
        LifecycleTestMaterial(
          purpose: .conversationDEK,
          epoch: 1,
          streamRoute: conversationRoute,
          rawKeyByte: 0x61
        ),
        LifecycleTestMaterial(
          purpose: .deviceCommandTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x42
        ),
        LifecycleTestMaterial(
          purpose: .deviceReplyTx,
          epoch: 1,
          streamRoute: nil,
          rawKeyByte: 0x43
        ),
      ]
    ),
    expectedConversationRoutes: [conversationRoute]
  )
  let normalized = try normalizedCoordinatorInitialState(staged)
  let inventory = try fixture.setVerifier.auditColdOpen(
    state: normalized,
    expectedConversationRoutes: [conversationRoute]
  )
  let capability = try inventory.resolveReceivingKey(
    keyID: KeyIDV1(purpose: .catalog, epoch: 1),
    keyDirectoryRevision: 8,
    streamRoute: catalogRoute,
    nowMS: CoordinatorTestEnvironment.fixedTimeMS
  )
  let daemonAdvance = try DaemonDirectoryRevisionAdvanceV1(
    fromRevision: 7,
    toRevision: 8
  )
  let context = OuterContextV1(
    frameKind: .catalogPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: fixture.machineRoute,
    deviceRoute: nil,
    streamRoute: catalogRoute,
    requestRoute: nil,
    streamGeneration: generation,
    streamCursor: nil,
    streamSeq: 71,
    messageKeyEpoch: 1
  )
  let candidate = try stagedControlCandidate(
    fixture: fixture,
    inventory: inventory,
    capability: capability,
    context: context,
    headerRevision: 7,
    keyID: KeyIDV1(purpose: .catalog, epoch: 1),
    rawKeyByte: 0x41,
    counter: 27,
    control: .directoryRevisionAdvance(daemonAdvance)
  )
  return StagedDirectoryAdvanceDeliveryFixture(
    state: normalized,
    identity: try coordinatorIdentity(
      state: normalized,
      installationID: "F3000000-0000-0000-0000-000000000001",
      machineID: "staged-directory-advance"
    ),
    verifier: try machineDataVerifier(fixture: fixture, currentRevision: 7),
    candidate: candidate,
    advance: try daemonAdvance.binding(to: context),
    newConversationScope: DeviceCryptoKeyScopeV1(
      keyID: KeyIDV1(purpose: .conversationDEK, epoch: 1),
      streamRoute: conversationRoute
    )
  )
}

private func stagedControlCandidate(
  fixture: KeyUpdateSetCryptoFixture,
  inventory: AuditedDeviceKeyInventoryV1,
  capability: AuditedReceivingKeyCapabilityV1,
  context: OuterContextV1,
  headerRevision: UInt64,
  keyID: KeyIDV1,
  rawKeyByte: UInt8,
  counter: UInt64,
  control: DaemonKeyControlV1
) throws -> VerifiedStagedKeyControlCandidate {
  let unsigned = try RelayCrypto.sealSymmetric(
    try DaemonKeyControlCanonicalCodec.encode(control),
    key: AeadSendingKey(
      keyID: keyID,
      epoch: keyID.epoch,
      keyDirectoryRevision: headerRevision,
      payloadKind: .keyUpdate,
      rawKey: Data(repeating: rawKeyByte, count: 32)
    ),
    context: context,
    counter: counter
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: fixture.dataSigningKey,
    context: context
  )
  return try machineDataVerifier(
    fixture: fixture,
    currentRevision: inventory.activeRevision
  ).verifyStagedKeyControl(
    wireBytes: RelayV2SignedSealedBlobCodec.encode(
      signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    ),
    context: context,
    capability: capability
  )
}

private func machineDataVerifier(
  fixture: KeyUpdateSetCryptoFixture,
  currentRevision: UInt64
) throws -> MachineDataVerifier {
  try MachineDataVerifier(
    machineRoute: fixture.machineRoute,
    deviceRoute: fixture.deviceRoute,
    verifiedCertificate: VerifiedMachineDataCertificate(
      certificate: RelayV2SignedCertificate(
        subjectPubkey: fixture.dataSigningKey.publicKey.rawRepresentation,
        certRole: .data,
        generation: 4,
        rootKeyId: fixture.rootKeyID,
        trustEpoch: 3,
        notAfterMs: nil,
        signature: Data(repeating: 0xF6, count: 64)
      ),
      signingKey: fixture.dataSigningKey.publicKey
    ),
    currentKeyDirectoryRevision: currentRevision,
    maximumKeySyncAdvance: 1
  )
}

private func normalizedCoordinatorInitialState(
  _ state: DeviceCryptoStateV1
) throws -> DeviceCryptoStateV1 {
  try DeviceCryptoStateV1(
    stateRevision: 1,
    trustScope: state.trustScope,
    keyDirectory: state.keyDirectory,
    senderCounter: state.senderCounter,
    securityState: state.securityState,
    replayStates: state.replayStates,
    streamStates: state.streamStates,
    keyLifecycle: state.keyLifecycle
  )
}

private func coordinatorIdentity(
  state: DeviceCryptoStateV1,
  installationID: String,
  machineID: String
) throws -> CryptoStateIdentity {
  try CryptoStateIdentity(
    clientKind: .macOSApp,
    installationID: XCTUnwrap(UUID(uuidString: installationID)),
    machineID: machineID,
    machineRootFingerprint: state.trustScope.machineRootFingerprint,
    machineRoute: state.trustScope.machineRoute
  )
}

private enum CoordinatorTestFixture {
  static let installationID = UUID(
    uuidString: "70000000-0000-0000-0000-000000000001"
  )!
  static let relayServerID = Data(repeating: 0x11, count: 16)
  static let rootFingerprint = Data(repeating: 0x22, count: 32)
  static let machineRoute = Data(repeating: 0x33, count: 16)
  static let deviceRoute = Data(repeating: 0x44, count: 16)
  static let streamRoute = Data(repeating: 0x55, count: 16)
  static let generation = Data(repeating: 0x66, count: 16)
  static let directoryRevision: UInt64 = 7
  static let senderKeyID = KeyIDV1(purpose: .deviceCommandTx, epoch: 11)
  static let replayKeyID = KeyIDV1(purpose: .catalog, epoch: 12)
  static let replyKeyID = KeyIDV1(purpose: .deviceReplyTx, epoch: 13)
  static let conversationKeyID = KeyIDV1(purpose: .conversationDEK, epoch: 20)
  static let conversationRoute = Data(repeating: 0x57, count: 16)

  static func identity() throws -> CryptoStateIdentity {
    try CryptoStateIdentity(
      clientKind: .macOSApp,
      installationID: installationID,
      machineID: "coordinator-machine",
      machineRootFingerprint: rootFingerprint,
      machineRoute: machineRoute
    )
  }

  static func initialState(includeConversation: Bool = false) throws -> DeviceCryptoStateV1 {
    let trust = try DeviceCryptoTrustScopeV1(
      relayServerID: relayServerID,
      machineRootFingerprint: rootFingerprint,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: 5,
      trustEpoch: 3
    )
    var entries = [
      try DeviceWrappedKeyV1(
        keyID: replayKeyID,
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xA1, count: 32),
        wrappedKey: Data(repeating: 0xB1, count: 48)
      )
    ]
    if includeConversation {
      entries.append(
        try DeviceWrappedKeyV1(
          keyID: conversationKeyID,
          deviceRoute: deviceRoute,
          streamRoute: conversationRoute,
          enc: Data(repeating: 0xA4, count: 32),
          wrappedKey: Data(repeating: 0xB4, count: 48)
        ))
    }
    entries.append(
      try DeviceWrappedKeyV1(
        keyID: senderKeyID,
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xA2, count: 32),
        wrappedKey: Data(repeating: 0xB2, count: 48)
      ))
    entries.append(
      try DeviceWrappedKeyV1(
        keyID: replyKeyID,
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xA3, count: 32),
        wrappedKey: Data(repeating: 0xB3, count: 48)
      ))
    let directory = try DeviceKeyDirectoryV1(
      revision: directoryRevision,
      entries: entries,
      signature: Data(repeating: 0x91, count: 64)
    )
    let sender = try DeviceSenderCounterV1(
      keyID: senderKeyID,
      keyDirectoryRevision: directoryRevision,
      noncePrefix: Data([0x10, 0x20, 0x30, 0x40]),
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    )
    var replays = [
      try DeviceReplayStateV1(
        scope: DeviceCryptoKeyScopeV1(keyID: replayKeyID, streamRoute: nil),
        window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
        status: .active
      )
    ]
    if includeConversation {
      replays.append(
        try DeviceReplayStateV1(
          scope: DeviceCryptoKeyScopeV1(
            keyID: conversationKeyID,
            streamRoute: conversationRoute
          ),
          window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
          status: .active
        ))
    }
    let cursor = try DeviceStreamCursorStateV1(
      streamRoute: streamRoute,
      generation: generation,
      outerCursor: .beforeFirst,
      innerCursor: .catalog(.beforeFirst)
    )
    return try DeviceCryptoStateV1(
      stateRevision: 1,
      trustScope: trust,
      keyDirectory: directory,
      senderCounter: sender,
      securityState: .active,
      replayStates: replays,
      streamStates: [cursor]
    )
  }

  static func replayCapacityState() throws -> DeviceCryptoStateV1 {
    let base = try initialState()
    var replays = base.replayStates
    replays.reserveCapacity(DeviceCryptoStateV1.maximumReplayStates)
    let retiredRoute = Data(repeating: 0x58, count: 16)
    let retiredAtMS: UInt64 = 1
    let deleteAfterMS = retiredAtMS + ReplayWindow.retiredWindowRetentionMilliseconds
    for epoch in 1..<UInt64(DeviceCryptoStateV1.maximumReplayStates) {
      replays.append(
        try DeviceReplayStateV1(
          scope: DeviceCryptoKeyScopeV1(
            keyID: KeyIDV1(purpose: .conversationDEK, epoch: epoch),
            streamRoute: retiredRoute
          ),
          window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
          status: .retired(
            retiredAtMS: retiredAtMS,
            deleteAfterMS: deleteAfterMS
          )
        ))
    }
    return try DeviceCryptoStateV1(
      stateRevision: base.stateRevision,
      trustScope: base.trustScope,
      keyDirectory: base.keyDirectory,
      senderCounter: base.senderCounter,
      securityState: base.securityState,
      replayStates: replays,
      streamStates: base.streamStates
    )
  }

  static func directory(
    revision: UInt64,
    catalogEpoch: UInt64 = replayKeyID.epoch,
    senderEpoch: UInt64 = senderKeyID.epoch,
    replyEpoch: UInt64 = replyKeyID.epoch,
    marker: UInt8 = 0xC0,
    conversationEpochs: [UInt64] = []
  ) throws -> DeviceKeyDirectoryV1 {
    var entries = [
      try DeviceWrappedKeyV1(
        keyID: KeyIDV1(purpose: .catalog, epoch: catalogEpoch),
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: marker, count: 32),
        wrappedKey: Data(repeating: marker &+ 1, count: 48)
      )
    ]
    for (index, epoch) in conversationEpochs.enumerated() {
      let offset = UInt8(index * 2)
      entries.append(
        try DeviceWrappedKeyV1(
          keyID: KeyIDV1(purpose: .conversationDEK, epoch: epoch),
          deviceRoute: deviceRoute,
          streamRoute: conversationRoute,
          enc: Data(repeating: marker &+ 6 &+ offset, count: 32),
          wrappedKey: Data(repeating: marker &+ 7 &+ offset, count: 48)
        ))
    }
    entries.append(
      try DeviceWrappedKeyV1(
        keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: senderEpoch),
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: marker &+ 2, count: 32),
        wrappedKey: Data(repeating: marker &+ 3, count: 48)
      ))
    entries.append(
      try DeviceWrappedKeyV1(
        keyID: KeyIDV1(purpose: .deviceReplyTx, epoch: replyEpoch),
        deviceRoute: deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: marker &+ 4, count: 32),
        wrappedKey: Data(repeating: marker &+ 5, count: 48)
      ))
    return try DeviceKeyDirectoryV1(
      revision: revision,
      entries: entries,
      signature: Data(repeating: marker &+ 6, count: 64)
    )
  }

  static func sender(
    from state: DeviceCryptoStateV1,
    directoryRevision: UInt64,
    epoch: UInt64? = nil,
    noncePrefix: Data? = nil,
    reservedHighWater: UInt64? = nil,
    reservationID: Data? = nil
  ) throws -> DeviceSenderCounterV1 {
    try DeviceSenderCounterV1(
      keyID: KeyIDV1(
        purpose: .deviceCommandTx,
        epoch: epoch ?? state.senderCounter.keyID.epoch
      ),
      keyDirectoryRevision: directoryRevision,
      noncePrefix: noncePrefix ?? state.senderCounter.noncePrefix,
      reservedHighWater: reservedHighWater ?? state.senderCounter.reservedHighWater,
      reservationID: reservationID ?? state.senderCounter.reservationID
    )
  }
}

private func replacingState(
  _ state: DeviceCryptoStateV1,
  stateRevision: UInt64,
  keyDirectory: DeviceKeyDirectoryV1? = nil,
  senderCounter: DeviceSenderCounterV1? = nil,
  securityState: DeviceMachineSecurityStateV1? = nil,
  replayStates: [DeviceReplayStateV1]? = nil,
  streamStates: [DeviceStreamCursorStateV1]? = nil
) throws -> DeviceCryptoStateV1 {
  try DeviceCryptoStateV1(
    stateRevision: stateRevision,
    trustScope: state.trustScope,
    keyDirectory: keyDirectory ?? state.keyDirectory,
    senderCounter: senderCounter ?? state.senderCounter,
    securityState: securityState ?? state.securityState,
    replayStates: replayStates ?? state.replayStates,
    streamStates: streamStates ?? state.streamStates
  )
}

private func stateWithActiveKeySyncEpisode(
  _ state: DeviceCryptoStateV1
) throws -> DeviceCryptoStateV1 {
  let activeRevision = state.keyLifecycle?.activeRevision ?? state.keyDirectory.revision
  let target = activeRevision.addingReportingOverflow(1)
  let startedAtMS = CoordinatorTestEnvironment.fixedTimeMS - 1
  let expiresAtMS = startedAtMS.addingReportingOverflow(
    DeviceKeySyncEpisodeV1.deadlineMilliseconds
  )
  guard !target.overflow, !expiresAtMS.overflow else {
    throw DeviceCryptoStateError.invalidKeySyncEpisode
  }
  return try DeviceCryptoStateV1(
    stateRevision: state.stateRevision,
    trustScope: state.trustScope,
    keyDirectory: state.keyDirectory,
    senderCounter: state.senderCounter,
    securityState: state.securityState,
    replayStates: state.replayStates,
    streamStates: state.streamStates,
    keyLifecycle: state.keyLifecycle,
    pendingStreamBindings: state.pendingStreamBindings,
    keySyncEpisode: DeviceKeySyncEpisodeV1(
      targetRevision: target.partialValue,
      observedKeyID: KeyIDV1(purpose: .catalog, epoch: 2),
      streamRoute: nil,
      attempt: 1,
      startedAtMS: startedAtMS,
      expiresAtMS: expiresAtMS.partialValue
    )
  )
}
