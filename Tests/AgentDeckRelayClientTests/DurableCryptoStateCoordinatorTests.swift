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
    XCTAssertEqual(firstDisposition, .fresh)
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
    XCTAssertEqual(freshDisposition, .fresh)
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
    XCTAssertEqual(duplicateDisposition, .exactDuplicate)
    let staleDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: 0,
      ciphertextHash: Data(repeating: 0x82, count: 32),
      observedAtMS: 700
    )
    XCTAssertEqual(staleDisposition, .stale)

    let nonMutationStages = await recorder.snapshot()
    XCTAssertEqual(nonMutationStages, [])
    let stateAfterNonMutations = try await environment.stateStore.load()
    XCTAssertEqual(stateAfterNonMutations, afterFresh)
    let guardAfterNonMutations = await environment.keyStore.value(for: environment.guardKey)
    XCTAssertEqual(guardAfterNonMutations, guardAfterFresh)
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
    XCTAssertEqual(disposition, .fresh)
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
    XCTAssertEqual(disposition, .fresh)
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
    XCTAssertEqual(disposition, .exactDuplicate)
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
    case .stateGuardPendingDurable, .securityQuarantineDurable:
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
    XCTAssertEqual(data[5], 2, file: file, line: line)
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

private enum TestGuardPhase: UInt8 {
  case stable = 0
  case pending = 1
  case retired = 2
  case statePending = 3
}

private enum StatePendingGuardMutation: CaseIterable {
  case invalidVersion
  case trailingByte
  case zeroNextCommitment

  func apply(to data: inout Data) {
    switch self {
    case .invalidVersion:
      data[5] = 3
    case .trailingByte:
      data.append(0)
    case .zeroNextCommitment:
      data.replaceSubrange((data.count - 32)..<data.count, with: repeatElement(0, count: 32))
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

  init() throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckDurableCoordinatorTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    identity = try CoordinatorTestFixture.identity()
    storageKey = try DeviceStorageKEK(
      rawRepresentation: Data(repeating: 0x5A, count: 32)
    )
    stateStore = try FileCryptoStateStore(
      rootURL: rootURL,
      identity: identity,
      storageKey: storageKey
    )
    keyStore = CoordinatorMemoryKeyStore()
    guardKey = try KeyStoreKey.paired(
      clientKind: identity.clientKind,
      installationID: identity.installationID,
      rootFingerprint: identity.machineRootFingerprint,
      machineRoute: identity.machineRoute,
      purpose: .counterGuard
    )
    initialSnapshot = try CryptoStateSnapshot(CoordinatorTestFixture.initialState())
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
      storageKey: storageKey
    )
  }

  func makeCoordinator(
    stateStore override: FileCryptoStateStore? = nil,
    observer: CryptoStatePersistenceObserver? = nil
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
      clock: { Self.fixedTimeMS }
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

  static func identity() throws -> CryptoStateIdentity {
    try CryptoStateIdentity(
      clientKind: .macOSApp,
      installationID: installationID,
      machineID: "coordinator-machine",
      machineRootFingerprint: rootFingerprint,
      machineRoute: machineRoute
    )
  }

  static func initialState() throws -> DeviceCryptoStateV1 {
    let trust = try DeviceCryptoTrustScopeV1(
      relayServerID: relayServerID,
      machineRootFingerprint: rootFingerprint,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: 5,
      trustEpoch: 3
    )
    let directory = try DeviceKeyDirectoryV1(
      revision: directoryRevision,
      entries: [
        DeviceWrappedKeyV1(
          keyID: replayKeyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: 0xA1, count: 32),
          wrappedKey: Data(repeating: 0xB1, count: 48)
        ),
        DeviceWrappedKeyV1(
          keyID: senderKeyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: 0xA2, count: 32),
          wrappedKey: Data(repeating: 0xB2, count: 48)
        ),
        DeviceWrappedKeyV1(
          keyID: replyKeyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: 0xA3, count: 32),
          wrappedKey: Data(repeating: 0xB3, count: 48)
        ),
      ],
      signature: Data(repeating: 0x91, count: 64)
    )
    let sender = try DeviceSenderCounterV1(
      keyID: senderKeyID,
      keyDirectoryRevision: directoryRevision,
      noncePrefix: Data([0x10, 0x20, 0x30, 0x40]),
      reservedHighWater: 0,
      reservationID: Data(repeating: 0, count: 16)
    )
    let replay = try DeviceReplayStateV1(
      scope: DeviceCryptoKeyScopeV1(keyID: replayKeyID, streamRoute: nil),
      window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
      status: .active
    )
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
      replayStates: [replay],
      streamStates: [cursor]
    )
  }
}

private func replacingState(
  _ state: DeviceCryptoStateV1,
  stateRevision: UInt64,
  securityState: DeviceMachineSecurityStateV1? = nil,
  replayStates: [DeviceReplayStateV1]? = nil,
  streamStates: [DeviceStreamCursorStateV1]? = nil
) throws -> DeviceCryptoStateV1 {
  try DeviceCryptoStateV1(
    stateRevision: stateRevision,
    trustScope: state.trustScope,
    keyDirectory: state.keyDirectory,
    senderCounter: state.senderCounter,
    securityState: securityState ?? state.securityState,
    replayStates: replayStates ?? state.replayStates,
    streamStates: streamStates ?? state.streamStates
  )
}
