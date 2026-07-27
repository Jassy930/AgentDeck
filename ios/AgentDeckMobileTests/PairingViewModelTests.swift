import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeckMobile

@MainActor
final class PairingViewModelTests: XCTestCase {
  private let invite = "agentdeck-pair:v1:YWJjZA"

  func testRejectsEmptyShortPINAndOversizedInviteWithoutInspectingOrPairing() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.inspectInvite("   ")
    await waitForMainActorState {
      viewModel.pairingState
        == .failed(
          SessionSourceFailure(code: .invalidPairInvite), retryable: false)
    }
    viewModel.inspectInvite("123456")
    await waitForMainActorState {
      viewModel.pairingState
        == .failed(
          SessionSourceFailure(code: .invalidPairInvite), retryable: false)
    }
    viewModel.inspectInvite(
      PairInviteInput.prefix
        + String(repeating: "A", count: PairInviteInput.maximumUTF8Bytes)
    )
    await waitForMainActorState {
      viewModel.pairingState
        == .failed(
          SessionSourceFailure(code: .invalidPairInvite), retryable: false)
    }

    let inspectionCalls = await source.recordedInspectionCalls()
    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(inspectionCalls, [])
    XCTAssertEqual(pairingCalls, [])
  }

  func testInspectionShowsFullTrustPreviewAndMakesNoPairingRequestBeforeConfirmation() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let preview = makePreview()
    await source.setInspectionBehavior(.immediate(preview))
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.inspectInvite("\n\(invite)  ")
    await source.waitForInspectionCalls(1)
    await waitForMainActorState {
      viewModel.pairingState == .awaitingConfirmation(preview)
    }

    let inspectionCalls = await source.recordedInspectionCalls()
    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(inspectionCalls, [invite])
    XCTAssertEqual(pairingCalls, [])
    XCTAssertEqual(viewModel.inspectedInvite, invite)
    XCTAssertEqual(viewModel.preview?.relayServerID, Data(repeating: 0x33, count: 16))
    XCTAssertEqual(viewModel.preview?.currentSPKIPin, Data(repeating: 0x44, count: 32))
    XCTAssertEqual(viewModel.preview?.nextSPKIPin, Data(repeating: 0x55, count: 32))
  }

  func testConfirmationUsesExactInspectedInviteAndPublishesProgressInOrder() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let preview = makePreview()
    let paired = makePairedMachine()
    await source.setInspectionBehavior(.immediate(preview))
    await source.setPairingBehavior(
      .finished([.preparing, .waitingForLocalConfirmation, .paired(paired)]))
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    var observed: [PairingViewState] = []
    viewModel.onUpdate = { observed.append(viewModel.pairingState) }

    viewModel.inspectInvite(invite)
    await waitForMainActorState {
      viewModel.pairingState == .awaitingConfirmation(preview)
    }
    viewModel.confirmPairing()
    await source.waitForPairingCalls(1)
    await waitForMainActorState { viewModel.pairingState == .paired(paired) }

    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(pairingCalls, [invite])
    XCTAssertTrue(observed.contains(.pairing(.preparing)))
    XCTAssertTrue(observed.contains(.pairing(.waitingForLocalConfirmation)))
    XCTAssertEqual(observed.last, .paired(paired))
  }

  func testTransportFailureRetryReusesExactInviteAndNeverStartsSecondConcurrentPairing() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setInspectionBehavior(.immediate(makePreview()))
    await source.setPairingBehavior(.suspended)
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.inspectInvite(invite)
    await waitForMainActorState {
      if case .awaitingConfirmation = viewModel.pairingState { return true }
      return false
    }
    viewModel.confirmPairing()
    viewModel.confirmPairing()
    await source.waitForPairingCalls(1)
    await source.failPairing(
      with: SessionSourceFailure(code: .transportUnavailable))
    await waitForMainActorState {
      viewModel.pairingState
        == .failed(
          SessionSourceFailure(code: .transportUnavailable), retryable: true)
    }

    await source.setPairingBehavior(.finished([.paired(makePairedMachine())]))
    viewModel.retryPairing()
    await source.waitForPairingCalls(2)
    await waitForMainActorState {
      viewModel.pairingState == .paired(self.makePairedMachine())
    }
    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(pairingCalls, [invite, invite])
  }

  func testCanceledAndExpiredAreExplicitNonSuccessTerminalStates() async {
    for (progress, expected) in [
      (PairingProgress.canceled, PairingViewState.canceled),
      (.expired, .expired),
    ] {
      let source = SessionSourceSpy()
      let localStore = LocalPairedMachineStoreSpy()
      await source.setInspectionBehavior(.immediate(makePreview()))
      await source.setPairingBehavior(.finished([progress]))
      let viewModel = PairingViewModel(source: source, localStore: localStore)
      viewModel.inspectInvite(invite)
      await waitForMainActorState {
        if case .awaitingConfirmation = viewModel.pairingState { return true }
        return false
      }
      viewModel.confirmPairing()
      await waitForMainActorState { viewModel.pairingState == expected }
    }
  }

  func testCancelActiveTasksTerminatesPairingStreamWithoutChangingDurableInvite() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setInspectionBehavior(.immediate(makePreview()))
    await source.setPairingBehavior(.suspended)
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.inspectInvite(invite)
    await waitForMainActorState {
      if case .awaitingConfirmation = viewModel.pairingState { return true }
      return false
    }
    viewModel.confirmPairing()
    await source.waitForPairingCalls(1)

    viewModel.cancelActiveTasks()
    await source.waitForPairingTerminations(1)

    XCTAssertEqual(viewModel.inspectedInvite, invite)
    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(pairingCalls, [invite])
  }

  func testInvalidReplacementInputCancelsExistingPairingBeforePublishingFailure() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setInspectionBehavior(.immediate(makePreview()))
    await source.setPairingBehavior(.suspended)
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.inspectInvite(invite)
    await waitForMainActorState {
      if case .awaitingConfirmation = viewModel.pairingState { return true }
      return false
    }
    viewModel.confirmPairing()
    await source.waitForPairingCalls(1)

    viewModel.inspectInvite("123456")
    await source.waitForPairingTerminations(1)

    XCTAssertEqual(
      viewModel.pairingState,
      .failed(SessionSourceFailure(code: .invalidPairInvite), retryable: false)
    )
    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(pairingCalls, [invite])
  }

  func testLatePreStreamCancellationCannotClearReplacementPairingTask() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let replacementInvite = "agentdeck-pair:v1:ZWZnaA"
    await source.setInspectionBehavior(.immediate(makePreview()))
    await source.setPairingBehavior(.suspendedBeforeStream)
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.inspectInvite(invite)
    await waitForMainActorState {
      if case .awaitingConfirmation = viewModel.pairingState { return true }
      return false
    }
    viewModel.confirmPairing()
    await source.waitForPairingCalls(1)

    viewModel.inspectInvite(replacementInvite)
    await waitForMainActorState {
      viewModel.inspectedInvite == replacementInvite
        && viewModel.pairingState == .awaitingConfirmation(self.makePreview())
    }
    await source.setPairingBehavior(.suspended)
    viewModel.confirmPairing()
    await source.waitForPairingCalls(2)

    await source.failPairingBeforeStream(
      encodedInvite: invite,
      with: CancellationError()
    )
    await Task.yield()
    await source.emitPairing(.waitingForLocalConfirmation)
    await waitForMainActorState {
      viewModel.pairingState == .pairing(.waitingForLocalConfirmation)
    }

    viewModel.cancelActiveTasks()
    await source.waitForPairingTerminations(1)

    let pairingCalls = await source.recordedPairingCalls()
    XCTAssertEqual(pairingCalls, [invite, replacementInvite])
    XCTAssertEqual(viewModel.inspectedInvite, replacementInvite)
  }

  func testCommittedRevocationWaitsForVerifiedTerminalBeforeDeletingLocalMachine() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setRevocationBehavior(
      .immediate(.committed(RuntimeGrantSerial(rawValue: 7))))
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.revoke(machineID: "machine-1")
    await source.waitForRevocationCalls(1)
    await waitForMainActorState {
      viewModel.machineActionState == .waitingForVerifiedRevocation(machineID: "machine-1")
    }

    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  func testRevocationTransportFailureDoesNotDeleteLocalMaterial() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setRevocationBehavior(
      .failure(SessionSourceFailure(code: .transportUnavailable)))
    let viewModel = PairingViewModel(source: source, localStore: localStore)

    viewModel.revoke(machineID: "machine-1")
    await source.waitForRevocationCalls(1)
    await waitForMainActorState {
      viewModel.machineActionState
        == .failed(
          machineID: "machine-1",
          error: SessionSourceFailure(code: .transportUnavailable),
          retryable: true
        )
    }

    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  func testVerifiedRevocationCleanupIsNotOwnedByPresentationViewModel() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.start()
    await source.waitForMachineSubscriptions(1)

    await source.emitMachines(.ready(value: [makeMachine(state: .revoked)], revision: 1))
    await waitForMainActorState {
      viewModel.machines.first?.connectionState == .revoked
    }

    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  func testOfflineLocalForgetRequiresTwoExplicitConfirmations() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.start()
    await source.waitForMachineSubscriptions(1)
    await source.emitMachines(
      .ready(value: [makeMachine(state: .machineOffline)], revision: 1)
    )
    await waitForMainActorState {
      viewModel.machines.first?.connectionState == .machineOffline
    }

    viewModel.beginLocalForget(machineID: "machine-1")
    XCTAssertEqual(
      viewModel.machineActionState,
      .confirmLocalForget(machineID: "machine-1", step: .warnResidualGrant))
    viewModel.confirmLocalForget(machineID: "machine-1")
    XCTAssertEqual(
      viewModel.machineActionState,
      .confirmLocalForget(machineID: "machine-1", step: .confirmDestructiveRemoval))
    let firstForgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(firstForgetCalls, [])
    viewModel.confirmLocalForget(machineID: "machine-1")
    await localStore.waitForForgetCalls(1)

    let finalForgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(finalForgetCalls, ["machine-1"])
  }

  func testConnectedMachineCannotBypassOnlineRevocationWithLocalForget() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.start()
    await source.waitForMachineSubscriptions(1)
    await source.emitMachines(
      .ready(value: [makeMachine(state: .connected)], revision: 1)
    )
    await waitForMainActorState {
      viewModel.machines.first?.connectionState == .connected
    }

    viewModel.beginLocalForget(machineID: "machine-1")

    guard
      case .failed(let machineID, let failure, let retryable) =
        viewModel.machineActionState
    else {
      return XCTFail("在线机器必须拒绝 local forget")
    }
    XCTAssertEqual(machineID, "machine-1")
    XCTAssertEqual(failure.code, .commandRejected)
    XCTAssertFalse(retryable)
    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  func testReconnectAfterFirstLocalForgetConfirmationCancelsDestructiveFlow() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.start()
    await source.waitForMachineSubscriptions(1)
    await source.emitMachines(
      .ready(value: [makeMachine(state: .machineOffline)], revision: 1)
    )
    await waitForMainActorState {
      viewModel.machines.first?.connectionState == .machineOffline
    }

    viewModel.beginLocalForget(machineID: "machine-1")
    viewModel.confirmLocalForget(machineID: "machine-1")
    XCTAssertEqual(
      viewModel.machineActionState,
      .confirmLocalForget(
        machineID: "machine-1",
        step: .confirmDestructiveRemoval
      )
    )

    await source.emitMachines(
      .ready(value: [makeMachine(state: .connected)], revision: 2)
    )
    await waitForMainActorState {
      guard
        case .failed(let machineID, let failure, _) =
          viewModel.machineActionState
      else { return false }
      return machineID == "machine-1" && failure.code == .commandRejected
    }
    viewModel.confirmLocalForget(machineID: "machine-1")
    try? await Task.sleep(for: .milliseconds(20))

    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  func testTransportFailureDoesNotEnableLocalForgetWhileMachineIsConnected() async {
    let source = SessionSourceSpy()
    let localStore = LocalPairedMachineStoreSpy()
    await source.setRevocationBehavior(
      .failure(SessionSourceFailure(code: .transportUnavailable))
    )
    let viewModel = PairingViewModel(source: source, localStore: localStore)
    viewModel.start()
    await source.waitForMachineSubscriptions(1)
    await source.emitMachines(
      .ready(value: [makeMachine(state: .connected)], revision: 1)
    )
    await waitForMainActorState {
      viewModel.machines.first?.connectionState == .connected
    }

    viewModel.revoke(machineID: "machine-1")
    await source.waitForRevocationCalls(1)
    await waitForMainActorState {
      guard case .failed(_, let failure, let retryable) = viewModel.machineActionState
      else { return false }
      return failure.code == .transportUnavailable && retryable
    }
    viewModel.beginLocalForget(machineID: "machine-1")

    guard
      case .failed(let machineID, let failure, let retryable) =
        viewModel.machineActionState
    else {
      return XCTFail("连接中的机器不能因一次 transport failure 获得 local forget 资格")
    }
    XCTAssertEqual(machineID, "machine-1")
    XCTAssertEqual(failure.code, .commandRejected)
    XCTAssertFalse(retryable)
    let forgetCalls = await localStore.recordedForgetCalls()
    XCTAssertEqual(forgetCalls, [])
  }

  private func makePreview() -> PairingPreview {
    PairingPreview(
      name: "Mac Studio",
      relayHost: "relay.example.com",
      rootFingerprint: Data(repeating: 0x22, count: 32),
      expiresAtMs: 9_999_999,
      relayServerID: Data(repeating: 0x33, count: 16),
      currentSPKIPin: Data(repeating: 0x44, count: 32),
      nextSPKIPin: Data(repeating: 0x55, count: 32)
    )
  }

  private func makePairedMachine() -> PairedMachine {
    PairedMachine(
      id: "machine-1",
      name: "Mac Studio",
      relayHost: "relay.example.com",
      rootFingerprint: Data(repeating: 0x22, count: 32)
    )
  }

  private func makeMachine(state: SessionConnectionState) -> MachineSummary {
    MachineSummary(
      id: "machine-1",
      name: "Mac Studio",
      connectionState: state,
      lastHeartbeat: nil,
      activeConversationCount: 0,
      pendingApprovalCount: 0
    )
  }
}

actor LocalPairedMachineStoreSpy: LocalPairedMachineManaging {
  private var forgetCalls: [String] = []
  private var failure: SessionSourceFailure?

  func forgetLocal(machineID: String) async throws {
    if let failure { throw failure }
    forgetCalls.append(machineID)
  }

  func setFailure(_ failure: SessionSourceFailure?) {
    self.failure = failure
  }

  func recordedForgetCalls() -> [String] { forgetCalls }

  func waitForForgetCalls(_ count: Int) async {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while clock.now < deadline {
      if forgetCalls.count >= count { return }
      try? await Task.sleep(for: .milliseconds(1))
    }
    XCTFail("等待 local forget 调用超时")
  }
}
