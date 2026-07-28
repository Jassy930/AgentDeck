import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeck

final class SessionSourceRegistryTests: XCTestCase {
  func testCapabilityMatrixIsExplicitAndLocalNeverCallsRemoteFactory() async throws {
    let local = RegistrySessionSourceSpy()
    let remote = RegistrySessionSourceSpy()
    let fixture = RegistrySessionSourceSpy()
    let remoteRegistration = try makeRemoteRegistration(machineID: "remote-1", source: remote)
    let factory = RegistryRemoteFactorySpy(
      steps: ["remote-1": [.success(remoteRegistration)]]
    )
    let registry = try SessionSourceRegistry(
      local: makeLocalRegistration(source: local),
      remoteFactory: { machineID in
        try await factory.make(machineID: machineID)
      }
    )
    try await registry.registerFixture(
      makeFixtureRegistration(id: "preview-a", source: fixture)
    )

    let firstLocal = try await registry.open(.local)
    let secondLocal = try await registry.open(.local)
    XCTAssertEqual(firstLocal.scope, .local)
    XCTAssertTrue(sameSource(firstLocal.source, as: local))
    XCTAssertTrue(sameSource(secondLocal.source, as: local))
    XCTAssertNotNil(firstLocal.localPairingAdministration)
    XCTAssertNotNil(firstLocal.localConversationAdministration)
    let callsBeforeRemoteOpen = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(callsBeforeRemoteOpen, 0)

    let fixtureHandle = try await registry.open(.fixture(id: "preview-a"))
    XCTAssertTrue(sameSource(fixtureHandle.source, as: fixture))
    XCTAssertNil(fixtureHandle.localPairingAdministration)
    XCTAssertNil(fixtureHandle.localConversationAdministration)

    let remoteHandle = try await registry.open(.remote(machineID: "remote-1"))
    XCTAssertTrue(sameSource(remoteHandle.source, as: remote))
    XCTAssertNil(remoteHandle.localPairingAdministration)
    XCTAssertNil(remoteHandle.localConversationAdministration)
    let callsAfterRemoteOpen = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(callsAfterRemoteOpen, 1)

    await registry.shutdown()
  }

  func testRegistrationRejectsMissingOrForeignLocalCapabilities() throws {
    let source = RegistrySessionSourceSpy()

    XCTAssertThrowsError(
      try SessionSourceRegistration(
        scope: .local,
        source: source,
        capabilities: SessionSourceCapabilities(),
        lifecycle: source
      )
    ) { error in
      XCTAssertEqual(error as? SessionSourceRegistryError, .localCapabilitiesRequired)
    }

    XCTAssertThrowsError(
      try SessionSourceRegistration(
        scope: .remote(machineID: "remote-1"),
        source: source,
        capabilities: SessionSourceCapabilities(
          localPairingAdministration: source,
          localConversationAdministration: source
        ),
        lifecycle: source
      )
    ) { error in
      XCTAssertEqual(
        error as? SessionSourceRegistryError,
        .localCapabilitiesForbidden(scope: .remote(machineID: "remote-1"))
      )
    }

    XCTAssertThrowsError(
      try SessionSourceRegistration(
        scope: .fixture(id: "preview-a"),
        source: source,
        capabilities: SessionSourceCapabilities(
          localPairingAdministration: source
        ),
        lifecycle: source
      )
    ) { error in
      XCTAssertEqual(
        error as? SessionSourceRegistryError,
        .localCapabilitiesForbidden(scope: .fixture(id: "preview-a"))
      )
    }
  }

  func testConcurrentOpenForSameRemoteIsSingleFlightAndCached() async throws {
    let gate = RegistryManualGate()
    let remote = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .success(
            try makeRemoteRegistration(machineID: "remote-1", source: remote),
            gate: gate
          )
        ]
      ]
    )
    let registry = try makeRegistry(factory: factory)
    let callers = RegistryCallerProbe()

    let first = Task {
      await callers.arrive()
      return try await registry.open(.remote(machineID: "remote-1"))
    }
    let second = Task {
      await callers.arrive()
      return try await registry.open(.remote(machineID: "remote-1"))
    }
    let third = Task {
      await callers.arrive()
      return try await registry.open(.remote(machineID: "remote-1"))
    }

    await callers.waitForArrivals(3)
    await factory.waitForCalls(1, machineID: "remote-1")
    let blockedFactoryCalls = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(blockedFactoryCalls, 1)
    await gate.release()

    let handles = try await [first.value, second.value, third.value]
    XCTAssertTrue(handles.allSatisfy { sameSource($0.source, as: remote) })
    _ = try await registry.open(.remote(machineID: "remote-1"))
    let cachedFactoryCalls = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(cachedFactoryCalls, 1)

    await registry.shutdown()
  }

  func testDifferentRemoteIDsOpenIndependently() async throws {
    let gateA = RegistryManualGate()
    let gateB = RegistryManualGate()
    let remoteA = RegistrySessionSourceSpy()
    let remoteB = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-a": [
          .success(
            try makeRemoteRegistration(machineID: "remote-a", source: remoteA),
            gate: gateA
          )
        ],
        "remote-b": [
          .success(
            try makeRemoteRegistration(machineID: "remote-b", source: remoteB),
            gate: gateB
          )
        ],
      ]
    )
    let registry = try makeRegistry(factory: factory)

    let openA = Task { try await registry.open(.remote(machineID: "remote-a")) }
    await factory.waitForCalls(1, machineID: "remote-a")
    let openB = Task { try await registry.open(.remote(machineID: "remote-b")) }
    await factory.waitForCalls(1, machineID: "remote-b")

    await gateB.release()
    let handleB = try await openB.value
    XCTAssertTrue(sameSource(handleB.source, as: remoteB))

    await gateA.release()
    let handleA = try await openA.value
    XCTAssertTrue(sameSource(handleA.source, as: remoteA))
    let callsA = await factory.callCount(machineID: "remote-a")
    let callsB = await factory.callCount(machineID: "remote-b")
    XCTAssertEqual(callsA, 1)
    XCTAssertEqual(callsB, 1)

    await registry.shutdown()
  }

  func testInvalidAndUnknownScopesFailClosedWithTypedErrors() async throws {
    let factory = RegistryRemoteFactorySpy(steps: [:])
    let registry = try makeRegistry(factory: factory)
    let source = RegistrySessionSourceSpy()

    await assertRegistryError(.invalidRemoteMachineID) {
      _ = try await registry.open(.remote(machineID: ""))
    }
    await assertRegistryError(.invalidRemoteMachineID) {
      _ = try await registry.open(.remote(machineID: " \n"))
    }
    await assertRegistryError(.invalidFixtureID) {
      _ = try await registry.open(.fixture(id: ""))
    }
    await assertRegistryError(.unknownFixture(id: "missing")) {
      _ = try await registry.open(.fixture(id: "missing"))
    }
    await assertRegistryError(.unknownRemote(machineID: "missing")) {
      try await registry.invalidateRemote(machineID: "missing")
    }

    XCTAssertThrowsError(
      try makeRemoteRegistration(machineID: "", source: source)
    ) { error in
      XCTAssertEqual(error as? SessionSourceRegistryError, .invalidRemoteMachineID)
    }
    XCTAssertThrowsError(
      try makeFixtureRegistration(id: "\t", source: source)
    ) { error in
      XCTAssertEqual(error as? SessionSourceRegistryError, .invalidFixtureID)
    }

    await registry.shutdown()
  }

  func testInvalidateJoinsExactGenerationBeforeColdOpenAndLeavesLocalUntouched() async throws {
    let oldJoinGate = RegistryManualGate()
    let local = RegistrySessionSourceSpy()
    let oldRemote = RegistrySessionSourceSpy(joinGate: oldJoinGate)
    let newRemote = RegistrySessionSourceSpy()
    let firstRegistration = try makeRemoteRegistration(
      machineID: "remote-1",
      source: oldRemote
    )
    let secondRegistration = try makeRemoteRegistration(
      machineID: "remote-1",
      source: newRemote
    )
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .success(firstRegistration),
          .checkedSuccess(secondRegistration) {
            await oldRemote.joinCompletionCount() == 1
          },
        ]
      ]
    )
    let registry = try SessionSourceRegistry(
      local: makeLocalRegistration(source: local),
      remoteFactory: { machineID in
        try await factory.make(machineID: machineID)
      }
    )

    let localBefore = try await registry.open(.local)
    let oldHandle = try await registry.open(.remote(machineID: "remote-1"))
    XCTAssertTrue(sameSource(oldHandle.source, as: oldRemote))

    let invalidation = Task {
      try await registry.invalidateRemote(machineID: "remote-1")
    }
    await oldRemote.waitForJoinCalls(1)

    let reopen = Task {
      try await registry.open(.remote(machineID: "remote-1"))
    }
    await oldJoinGate.release()
    try await invalidation.value
    let newHandle = try await reopen.value

    XCTAssertTrue(sameSource(newHandle.source, as: newRemote))
    let factoryCalls = await factory.callCount(machineID: "remote-1")
    let oldShutdowns = await oldRemote.shutdownCount()
    let oldJoins = await oldRemote.joinCount()
    let oldJoinCompletions = await oldRemote.joinCompletionCount()
    XCTAssertEqual(factoryCalls, 2)
    XCTAssertEqual(oldShutdowns, 1)
    XCTAssertEqual(oldJoins, 1)
    XCTAssertEqual(oldJoinCompletions, 1)

    let localAfter = try await registry.open(.local)
    XCTAssertTrue(sameSource(localBefore.source, as: local))
    XCTAssertTrue(sameSource(localAfter.source, as: local))
    let localShutdowns = await local.shutdownCount()
    let localJoins = await local.joinCount()
    XCTAssertEqual(localShutdowns, 0)
    XCTAssertEqual(localJoins, 0)

    await registry.shutdown()
  }

  func testInvalidateWhileOpeningJoinsOldFactoryResultBeforeColdOpen() async throws {
    let firstFactoryGate = RegistryManualGate()
    let oldJoinGate = RegistryManualGate()
    let local = RegistrySessionSourceSpy()
    let oldRemote = RegistrySessionSourceSpy(joinGate: oldJoinGate)
    let newRemote = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .success(
            try makeRemoteRegistration(machineID: "remote-1", source: oldRemote),
            gate: firstFactoryGate
          ),
          .checkedSuccess(
            try makeRemoteRegistration(machineID: "remote-1", source: newRemote)
          ) {
            await oldRemote.joinCompletionCount() == 1
          },
        ]
      ]
    )
    let registry = try SessionSourceRegistry(
      local: makeLocalRegistration(source: local),
      remoteFactory: { machineID in
        try await factory.make(machineID: machineID)
      }
    )

    let oldWaiter = Task {
      try await registry.open(.remote(machineID: "remote-1"))
    }
    await factory.waitForCalls(1, machineID: "remote-1")

    // MainActor submission barrier：先提交 invalidate actor call 并让 launcher 在该 await
    // 处挂起，再允许旧 factory 完成，避免靠 priority/yield 猜测调度顺序。
    let submission = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
    let invalidation = Task { @MainActor in
      _ = submission.continuation.yield(())
      try await registry.invalidateRemote(machineID: "remote-1")
    }
    var submissionIterator = submission.stream.makeAsyncIterator()
    _ = await submissionIterator.next()
    await MainActor.run {
      precondition(Thread.isMainThread)
    }
    submission.continuation.finish()

    await firstFactoryGate.release()
    await oldRemote.waitForJoinCalls(1)

    // invalidate 的 exact join 尚未放行时提交同 ID open；第二 factory 自身还会检查
    // join completion，因此任何提前 cold-open 都以 typed test failure 收口。
    let concurrentReopen = Task {
      try await registry.open(.remote(machineID: "remote-1"))
    }
    await oldJoinGate.release()

    try await invalidation.value
    let oldWaiterHandle = try await oldWaiter.value
    let reopenedHandle = try await concurrentReopen.value
    XCTAssertTrue(sameSource(oldWaiterHandle.source, as: newRemote))
    XCTAssertTrue(sameSource(reopenedHandle.source, as: newRemote))
    XCTAssertFalse(sameSource(oldWaiterHandle.source, as: oldRemote))

    let factoryCalls = await factory.callCount(machineID: "remote-1")
    let oldShutdowns = await oldRemote.shutdownCount()
    let oldJoins = await oldRemote.joinCount()
    let oldJoinCompletions = await oldRemote.joinCompletionCount()
    XCTAssertEqual(factoryCalls, 2)
    XCTAssertEqual(oldShutdowns, 1)
    XCTAssertEqual(oldJoins, 1)
    XCTAssertEqual(oldJoinCompletions, 1)

    await registry.shutdown()
  }

  func testShutdownJoinsEveryOwnedScopeAndBlocksNewWork() async throws {
    let local = RegistrySessionSourceSpy()
    let remote = RegistrySessionSourceSpy()
    let fixture = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .success(try makeRemoteRegistration(machineID: "remote-1", source: remote))
        ]
      ]
    )
    let registry = try SessionSourceRegistry(
      local: makeLocalRegistration(source: local),
      remoteFactory: { machineID in
        try await factory.make(machineID: machineID)
      }
    )
    try await registry.registerFixture(
      makeFixtureRegistration(id: "preview-a", source: fixture)
    )
    _ = try await registry.open(.remote(machineID: "remote-1"))

    async let firstShutdown: Void = registry.shutdown()
    async let secondShutdown: Void = registry.shutdown()
    _ = await (firstShutdown, secondShutdown)

    for source in [local, remote, fixture] {
      let shutdowns = await source.shutdownCount()
      let joins = await source.joinCount()
      XCTAssertEqual(shutdowns, 1)
      XCTAssertEqual(joins, 1)
    }
    await assertRegistryError(.shutDown) {
      _ = try await registry.open(.local)
    }
    await assertRegistryError(.shutDown) {
      _ = try await registry.open(.remote(machineID: "never-open"))
    }
    await assertRegistryError(.shutDown) {
      try await registry.registerFixture(
        makeFixtureRegistration(id: "late", source: RegistrySessionSourceSpy())
      )
    }
    let unopenedFactoryCalls = await factory.callCount(machineID: "never-open")
    XCTAssertEqual(unopenedFactoryCalls, 0)
  }

  func testShutdownNotifiesAllKnownOwnersBeforeWaitingForOneOwner() async throws {
    let unblockLocalShutdown = RegistryManualGate()
    let local = RegistrySessionSourceSpy(shutdownGate: unblockLocalShutdown)
    let remote = RegistrySessionSourceSpy(shutdownReleaseGate: unblockLocalShutdown)
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .success(try makeRemoteRegistration(machineID: "remote-1", source: remote))
        ]
      ]
    )
    let registry = try SessionSourceRegistry(
      local: makeLocalRegistration(source: local),
      remoteFactory: { machineID in
        try await factory.make(machineID: machineID)
      }
    )
    _ = try await registry.open(.remote(machineID: "remote-1"))

    // local shutdown 会等 remote shutdown 释放 gate；只有 registry 先并发通知全部
    // 已知 owner，shutdown 才能完成，不能被列表中的第一个 owner 串行卡住。
    await registry.shutdown()

    let localShutdowns = await local.shutdownCount()
    let remoteShutdowns = await remote.shutdownCount()
    let localJoins = await local.joinCount()
    let remoteJoins = await remote.joinCount()
    XCTAssertEqual(localShutdowns, 1)
    XCTAssertEqual(remoteShutdowns, 1)
    XCTAssertEqual(localJoins, 1)
    XCTAssertEqual(remoteJoins, 1)
  }

  func testFactoryFailureIsNotCachedAndExplicitRetryColdOpens() async throws {
    let failureGate = RegistryManualGate()
    let remote = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .failure(.planned, gate: failureGate),
          .success(try makeRemoteRegistration(machineID: "remote-1", source: remote)),
        ]
      ]
    )
    let registry = try makeRegistry(factory: factory)

    let first = Task {
      return await capturedRegistryOpen(registry, machineID: "remote-1")
    }
    await factory.waitForCalls(1, machineID: "remote-1")
    await failureGate.release()

    let firstError = await first.value
    XCTAssertEqual(firstError as? RegistryFactoryFailure, .planned)
    let failedFactoryCalls = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(failedFactoryCalls, 1)

    let retryHandle = try await registry.open(.remote(machineID: "remote-1"))
    XCTAssertTrue(sameSource(retryHandle.source, as: remote))
    let retriedFactoryCalls = await factory.callCount(machineID: "remote-1")
    let prematureShutdowns = await remote.shutdownCount()
    let prematureJoins = await remote.joinCount()
    XCTAssertEqual(retriedFactoryCalls, 2)
    XCTAssertEqual(prematureShutdowns, 0)
    XCTAssertEqual(prematureJoins, 0)

    await registry.shutdown()
  }

  func testCancelledOnlyWaiterStillClearsFailedFactoryBeforeExplicitRetry() async throws {
    let failureGate = RegistryManualGate()
    let remote = RegistrySessionSourceSpy()
    let factory = RegistryRemoteFactorySpy(
      steps: [
        "remote-1": [
          .failure(.planned, gate: failureGate),
          .success(try makeRemoteRegistration(machineID: "remote-1", source: remote)),
        ]
      ]
    )
    let registry = try makeRegistry(factory: factory)

    let cancelledWaiter = Task {
      await capturedRegistryOpen(registry, machineID: "remote-1")
    }
    await factory.waitForCalls(1, machineID: "remote-1")
    cancelledWaiter.cancel()
    await failureGate.release()

    let cancelledError = await cancelledWaiter.value
    XCTAssertTrue(cancelledError is CancellationError)

    let retryHandle = try await registry.open(.remote(machineID: "remote-1"))
    XCTAssertTrue(sameSource(retryHandle.source, as: remote))
    let factoryCalls = await factory.callCount(machineID: "remote-1")
    XCTAssertEqual(factoryCalls, 2)

    await registry.shutdown()
  }
}

private enum RegistryFactoryFailure: Error, Equatable, Sendable {
  case planned
  case unexpectedCall(machineID: String)
  case lifecycleNotJoined
}

private actor RegistryManualGate {
  private var isReleased = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    guard !isReleased else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !isReleased else { return }
    isReleased = true
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    for continuation in pending {
      continuation.resume()
    }
  }
}

private actor RegistryCallerProbe {
  private struct Waiter {
    let expected: Int
    let continuation: CheckedContinuation<Void, Never>
  }

  private var arrivals = 0
  private var waiters: [Waiter] = []

  func arrive() {
    arrivals += 1
    resumeWaiters()
  }

  func waitForArrivals(_ expected: Int) async {
    guard arrivals < expected else { return }
    await withCheckedContinuation { continuation in
      waiters.append(Waiter(expected: expected, continuation: continuation))
    }
  }

  private func resumeWaiters() {
    var pending: [Waiter] = []
    for waiter in waiters {
      if arrivals >= waiter.expected {
        waiter.continuation.resume()
      } else {
        pending.append(waiter)
      }
    }
    waiters = pending
  }
}

private actor RegistryRemoteFactorySpy {
  typealias AsyncCheck = @Sendable () async -> Bool

  enum Outcome: Sendable {
    case registration(SessionSourceRegistration)
    case failure(RegistryFactoryFailure)
  }

  struct Step: Sendable {
    let gate: RegistryManualGate?
    let check: AsyncCheck?
    let outcome: Outcome

    static func success(
      _ registration: SessionSourceRegistration,
      gate: RegistryManualGate? = nil
    ) -> Step {
      Step(gate: gate, check: nil, outcome: .registration(registration))
    }

    static func checkedSuccess(
      _ registration: SessionSourceRegistration,
      check: @escaping AsyncCheck
    ) -> Step {
      Step(gate: nil, check: check, outcome: .registration(registration))
    }

    static func failure(
      _ error: RegistryFactoryFailure,
      gate: RegistryManualGate? = nil
    ) -> Step {
      Step(gate: gate, check: nil, outcome: .failure(error))
    }
  }

  private struct CallWaiter {
    let machineID: String
    let expected: Int
    let continuation: CheckedContinuation<Void, Never>
  }

  private let steps: [String: [Step]]
  private var calls: [String: Int] = [:]
  private var waiters: [CallWaiter] = []

  init(steps: [String: [Step]]) {
    self.steps = steps
  }

  func make(machineID: String) async throws -> SessionSourceRegistration {
    let index = calls[machineID, default: 0]
    calls[machineID] = index + 1
    resumeCallWaiters()

    guard let configured = steps[machineID], configured.indices.contains(index) else {
      throw RegistryFactoryFailure.unexpectedCall(machineID: machineID)
    }
    let step = configured[index]
    if let gate = step.gate {
      await gate.wait()
    }
    if let check = step.check, !(await check()) {
      throw RegistryFactoryFailure.lifecycleNotJoined
    }
    switch step.outcome {
    case .registration(let registration):
      return registration
    case .failure(let error):
      throw error
    }
  }

  func callCount(machineID: String) -> Int {
    calls[machineID, default: 0]
  }

  func waitForCalls(_ expected: Int, machineID: String) async {
    guard calls[machineID, default: 0] < expected else { return }
    await withCheckedContinuation { continuation in
      waiters.append(
        CallWaiter(
          machineID: machineID,
          expected: expected,
          continuation: continuation
        )
      )
    }
  }

  private func resumeCallWaiters() {
    var pending: [CallWaiter] = []
    for waiter in waiters {
      if calls[waiter.machineID, default: 0] >= waiter.expected {
        waiter.continuation.resume()
      } else {
        pending.append(waiter)
      }
    }
    waiters = pending
  }
}

private actor RegistrySessionSourceSpy:
  SessionSourceLifecycle,
  LocalPairingAdministration,
  LocalConversationAdministration
{
  private struct JoinWaiter {
    let expected: Int
    let continuation: CheckedContinuation<Void, Never>
  }

  private let shutdownGate: RegistryManualGate?
  private let shutdownReleaseGate: RegistryManualGate?
  private let joinGate: RegistryManualGate?
  private var shutdowns = 0
  private var joins = 0
  private var joinCompletions = 0
  private var joinWaiters: [JoinWaiter] = []

  init(
    shutdownGate: RegistryManualGate? = nil,
    shutdownReleaseGate: RegistryManualGate? = nil,
    joinGate: RegistryManualGate? = nil
  ) {
    self.shutdownGate = shutdownGate
    self.shutdownReleaseGate = shutdownReleaseGate
    self.joinGate = joinGate
  }

  func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
    finishedStream()
  }

  func conversations(
    machineID: String
  ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
    _ = machineID
    return finishedStream()
  }

  func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
    _ = conversationID
    return finishedStream()
  }

  func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
    finishedStream()
  }

  func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
    _ = encoded
    throw RegistryFactoryFailure.planned
  }

  func pair(
    _ encodedInvite: String
  ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    _ = encodedInvite
    return finishedThrowingStream()
  }

  func revokeSelf(machineID: String) async throws -> RevocationReceipt {
    _ = machineID
    throw RegistryFactoryFailure.planned
  }

  func sendPrompt(
    conversationID: String,
    text: String,
    idempotencyKey: UUID
  ) async throws -> CommandReceipt {
    _ = (conversationID, text, idempotencyKey)
    throw RegistryFactoryFailure.planned
  }

  func resolveApproval(
    conversationID: String,
    turnID: String,
    approvalID: String,
    decision: ActionDecisionKind,
    idempotencyKey: UUID
  ) async throws -> ApprovalReceipt {
    _ = (conversationID, turnID, approvalID, decision, idempotencyKey)
    throw RegistryFactoryFailure.planned
  }

  func retryApprovalDelivery(
    conversationID: String,
    approvalID: String
  ) async throws -> ApprovalReceipt {
    _ = (conversationID, approvalID)
    throw RegistryFactoryFailure.planned
  }

  func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>> {
    finishedStream()
  }

  func confirmPairing(id: String) async throws -> PairingAdministrationReceipt {
    _ = id
    throw RegistryFactoryFailure.planned
  }

  func cancelPairing(id: String) async throws -> PairingAdministrationReceipt {
    _ = id
    throw RegistryFactoryFailure.planned
  }

  func connectionLease() async throws -> LocalConversationConnectionLease {
    throw RegistryFactoryFailure.planned
  }

  func requireCurrentConnection(
    _ lease: LocalConversationConnectionLease
  ) async throws {
    _ = lease
    throw RegistryFactoryFailure.planned
  }

  func requiresFreshConnection(
    _ lease: LocalConversationConnectionLease
  ) async -> Bool {
    _ = lease
    return true
  }

  func invalidateConnection(
    _ lease: LocalConversationConnectionLease,
    reason: LocalConversationConnectionInvalidationReason
  ) async -> Bool {
    _ = (lease, reason)
    return false
  }

  func describeAgents(
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeAgentDescriptionsV2 {
    _ = lease
    throw RegistryFactoryFailure.planned
  }

  func startConversation(
    _ draft: RuntimeConversationDraft,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeConversationStartResult {
    _ = (draft, lease)
    throw RegistryFactoryFailure.planned
  }

  func configureConversation(
    _ configuration: RuntimeConfigureConversationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConfigurationReceiptV2 {
    _ = (configuration, lease)
    throw RegistryFactoryFailure.planned
  }

  func updateConversationMetadata(
    _ mutation: RuntimeConversationMetadataMutationRequestV2,
    using lease: LocalConversationConnectionLease
  ) async throws -> RuntimeConversationMetadataReceiptV2 {
    _ = (mutation, lease)
    throw RegistryFactoryFailure.planned
  }

  func resolveApproval(
    conversationID: RuntimeConversationID,
    turnID: RuntimeTurnID,
    approvalID: RuntimeApprovalID,
    decision: RuntimeActionDecisionV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> ApprovalReceiptV1 {
    _ = (conversationID, turnID, approvalID, decision, lease)
    throw RegistryFactoryFailure.planned
  }

  func loadCatalog(
    using lease: LocalConversationConnectionLease
  ) async throws -> [RuntimeCatalogSnapshotV2] {
    _ = lease
    throw RegistryFactoryFailure.planned
  }

  func synchronizeCatalog(
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    _ = (cursor, lease)
    throw RegistryFactoryFailure.planned
  }

  func backfillCatalog(
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    _ = (cursor, lease)
    throw RegistryFactoryFailure.planned
  }

  func synchronizeConversation(
    conversationID: RuntimeConversationID,
    cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    _ = (conversationID, cursor, lease)
    throw RegistryFactoryFailure.planned
  }

  func backfillConversation(
    conversationID: RuntimeConversationID,
    after cursor: RuntimeStreamCursorV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> AppRuntimeSynchronizationResult {
    _ = (conversationID, cursor, lease)
    throw RegistryFactoryFailure.planned
  }

  func unsubscribeConversation(
    _ conversationID: RuntimeConversationID,
    using lease: LocalConversationConnectionLease
  ) async throws {
    _ = (conversationID, lease)
    throw RegistryFactoryFailure.planned
  }

  func sendPrompt(
    conversationID: RuntimeConversationID,
    idempotencyKey: RuntimeIdempotencyKey,
    expectedConfigurationRevision: UInt64,
    prompt: RuntimePromptPayloadV1,
    using lease: LocalConversationConnectionLease
  ) async throws -> CommandReceiptV2 {
    _ = (conversationID, idempotencyKey, expectedConfigurationRevision, prompt, lease)
    throw RegistryFactoryFailure.planned
  }

  func shutdown() async {
    shutdowns += 1
    if let shutdownReleaseGate {
      await shutdownReleaseGate.release()
    }
    if let shutdownGate {
      await shutdownGate.wait()
    }
  }

  func join() async {
    joins += 1
    resumeJoinWaiters()
    if let joinGate {
      await joinGate.wait()
    }
    joinCompletions += 1
  }

  func shutdownCount() -> Int { shutdowns }
  func joinCount() -> Int { joins }
  func joinCompletionCount() -> Int { joinCompletions }

  func waitForJoinCalls(_ expected: Int) async {
    guard joins < expected else { return }
    await withCheckedContinuation { continuation in
      joinWaiters.append(JoinWaiter(expected: expected, continuation: continuation))
    }
  }

  private func resumeJoinWaiters() {
    var pending: [JoinWaiter] = []
    for waiter in joinWaiters {
      if joins >= waiter.expected {
        waiter.continuation.resume()
      } else {
        pending.append(waiter)
      }
    }
    joinWaiters = pending
  }
}

private func makeRegistry(
  factory: RegistryRemoteFactorySpy
) throws -> SessionSourceRegistry {
  let local = RegistrySessionSourceSpy()
  return try SessionSourceRegistry(
    local: makeLocalRegistration(source: local),
    remoteFactory: { machineID in
      try await factory.make(machineID: machineID)
    }
  )
}

private func makeLocalRegistration(
  source: RegistrySessionSourceSpy
) throws -> SessionSourceRegistration {
  try SessionSourceRegistration(
    scope: .local,
    source: source,
    capabilities: SessionSourceCapabilities(
      localPairingAdministration: source,
      localConversationAdministration: source
    ),
    lifecycle: source
  )
}

private func makeRemoteRegistration(
  machineID: String,
  source: RegistrySessionSourceSpy
) throws -> SessionSourceRegistration {
  try SessionSourceRegistration(
    scope: .remote(machineID: machineID),
    source: source,
    capabilities: SessionSourceCapabilities(),
    lifecycle: source
  )
}

private func makeFixtureRegistration(
  id: String,
  source: RegistrySessionSourceSpy
) throws -> SessionSourceRegistration {
  try SessionSourceRegistration(
    scope: .fixture(id: id),
    source: source,
    capabilities: SessionSourceCapabilities(),
    lifecycle: source
  )
}

private func sameSource(
  _ source: any SessionSource,
  as expected: RegistrySessionSourceSpy
) -> Bool {
  (source as AnyObject) === expected
}

private func capturedRegistryOpen(
  _ registry: SessionSourceRegistry,
  machineID: String
) async -> (any Error)? {
  do {
    _ = try await registry.open(.remote(machineID: machineID))
    return nil
  } catch {
    return error
  }
}

private func assertRegistryError(
  _ expected: SessionSourceRegistryError,
  operation: () async throws -> Void,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    try await operation()
    XCTFail("操作意外成功，预期错误：\(expected)", file: file, line: line)
  } catch let error as SessionSourceRegistryError {
    XCTAssertEqual(error, expected, file: file, line: line)
  } catch {
    XCTFail("错误类型不匹配：\(error)", file: file, line: line)
  }
}

private func finishedStream<Element: Sendable>() -> AsyncStream<Element> {
  AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
    continuation.finish()
  }
}

private func finishedThrowingStream<Element: Sendable>() -> AsyncThrowingStream<Element, Error> {
  AsyncThrowingStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
    continuation.finish()
  }
}
