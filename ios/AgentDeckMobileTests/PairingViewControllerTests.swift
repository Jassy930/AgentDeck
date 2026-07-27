import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

final class PairingViewControllerTests: XCTestCase {
  func testQRScannerVisibilityGateRejectsTokenAfterLeaving() {
    var gate = QRScannerVisibilityGate()
    gate.viewWillAppear()
    let visibilityID = try! XCTUnwrap(gate.sceneDidActivate())

    XCTAssertTrue(gate.allowsStart(visibilityID: visibilityID))
    XCTAssertEqual(gate.viewWillDisappear(), visibilityID)

    XCTAssertFalse(gate.isVisible)
    XCTAssertFalse(gate.allowsStart(visibilityID: visibilityID))
  }

  func testQRScannerVisibilityGateRejectsLateMetadataAfterReappearing() {
    var gate = QRScannerVisibilityGate()
    gate.viewWillAppear()
    let previousVisibilityID = try! XCTUnwrap(gate.sceneDidActivate())
    XCTAssertEqual(gate.viewWillDisappear(), previousVisibilityID)
    gate.viewWillAppear()
    let currentVisibilityID = try! XCTUnwrap(gate.sceneDidActivate())

    XCTAssertFalse(gate.allowsCallback(visibilityID: previousVisibilityID))
    XCTAssertTrue(gate.allowsCallback(visibilityID: currentVisibilityID))
  }

  func testQRScannerVisibilityGateStopsOnSceneDeactivationAndRestartsFreshGeneration() {
    var gate = QRScannerVisibilityGate()
    gate.viewWillAppear()
    let previousVisibilityID = try! XCTUnwrap(gate.sceneDidActivate())

    XCTAssertEqual(gate.sceneWillDeactivate(), previousVisibilityID)
    XCTAssertFalse(gate.allowsStart(visibilityID: previousVisibilityID))
    let currentVisibilityID = try! XCTUnwrap(gate.sceneDidActivate())

    XCTAssertNotEqual(currentVisibilityID, previousVisibilityID)
    XCTAssertFalse(gate.allowsCallback(visibilityID: previousVisibilityID))
    XCTAssertTrue(gate.allowsCallback(visibilityID: currentVisibilityID))
  }

  func testQRScannerVisibilityGateDoesNotStartWhileViewIsNotVisible() {
    var gate = QRScannerVisibilityGate()

    XCTAssertNil(gate.sceneDidActivate())
    gate.viewWillAppear()
    let visibilityID = try! XCTUnwrap(gate.sceneDidActivate())
    XCTAssertTrue(gate.consume(visibilityID: visibilityID))

    XCTAssertFalse(gate.allowsCallback(visibilityID: visibilityID))
    XCTAssertNil(gate.sceneDidActivate(), "同一 active 通知不得绕过已消费 generation")
  }

  func testQRScannerCaptureOwnershipRejectsLateStopFromPreviousAppearance() {
    var gate = QRScannerCaptureOwnershipGate()
    let previousVisibilityID = UUID()
    let currentVisibilityID = UUID()
    gate.activate(visibilityID: previousVisibilityID)
    gate.activate(visibilityID: currentVisibilityID)

    XCTAssertFalse(gate.deactivate(visibilityID: previousVisibilityID))
    XCTAssertTrue(gate.owns(visibilityID: currentVisibilityID))
    XCTAssertTrue(gate.deactivate(visibilityID: currentVisibilityID))
    XCTAssertNil(gate.activeVisibilityID)
  }

  func testReconnectReleasesLocalForgetClaimSoSameMachineCanClaimAgain() {
    var gate = LocalForgetFlowPresentationGate()

    guard let firstFlowID = gate.claim(machineID: "machine-1") else {
      return XCTFail("首次 local-forget flow 应成功 claim")
    }
    gate.reconcile(
      with: .confirmLocalForget(
        machineID: "machine-1",
        step: .warnResidualGrant
      )
    )
    XCTAssertNil(gate.claim(machineID: "machine-1"))

    gate.reconcile(
      with: .failed(
        machineID: "machine-1",
        error: SessionSourceFailure(code: .commandRejected),
        retryable: false
      )
    )

    XCTAssertNil(gate.machineID)
    XCTAssertNil(gate.flowID)
    let secondFlowID = gate.claim(machineID: "machine-1")
    XCTAssertNotNil(secondFlowID)
    XCTAssertNotEqual(secondFlowID, firstFlowID)
  }

  func testLateDestructiveConfirmationRetryIsRejectedAfterReconnect() {
    var gate = LocalForgetFlowPresentationGate()
    guard let oldFlowID = gate.claim(machineID: "machine-1") else {
      return XCTFail("首次 local-forget flow 应成功 claim")
    }
    XCTAssertTrue(
      gate.allowsDestructiveConfirmation(
        machineID: "machine-1",
        flowID: oldFlowID,
        state: .confirmLocalForget(
          machineID: "machine-1",
          step: .confirmDestructiveRemoval
        )
      )
    )

    let reconnected = PairingMachineActionState.failed(
      machineID: "machine-1",
      error: SessionSourceFailure(code: .commandRejected),
      retryable: false
    )
    XCTAssertFalse(
      gate.allowsDestructiveConfirmation(
        machineID: "machine-1",
        flowID: oldFlowID,
        state: reconnected
      )
    )
    XCTAssertNil(gate.machineID)

    guard let newFlowID = gate.claim(machineID: "machine-1") else {
      return XCTFail("重连后同一机器的新 flow 应可重新 claim")
    }
    let newFlowState = PairingMachineActionState.confirmLocalForget(
      machineID: "machine-1",
      step: .confirmDestructiveRemoval
    )
    XCTAssertFalse(
      gate.allowsDestructiveConfirmation(
        machineID: "machine-1",
        flowID: oldFlowID,
        state: newFlowState
      )
    )
    XCTAssertTrue(
      gate.allowsDestructiveConfirmation(
        machineID: "machine-1",
        flowID: newFlowID,
        state: newFlowState
      )
    )
  }
}
