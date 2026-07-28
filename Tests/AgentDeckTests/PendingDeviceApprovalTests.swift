import AgentDeckCore
import AgentDeckSessionSource
import AppKit
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class PendingDeviceApprovalTests: XCTestCase {
  func testLoadingViewWithoutPairingsIsStable() async {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)

    controller.loadView()

    XCTAssertTrue(controller.isViewLoaded)
    XCTAssertEqual(controller.rows, [])
    await controller.stopObserving()
  }

  func testFullFingerprintIsVisibleWithoutRequestOrKeyMaterial() async throws {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)
    controller.loadView()
    let pairing = try makePendingPairing(id: "pairing-visible", fingerprintByte: 0xA5)

    await administration.emit(.ready(value: [pairing], revision: 1))
    let rowAppeared = await eventually { controller.rows.count == 1 }
    XCTAssertTrue(rowAppeared)

    let expected = Array(repeating: "A5", count: 32).joined(separator: ":")
    XCTAssertEqual(controller.rows.first?.fingerprint, expected)
    XCTAssertTrue(visibleLabels(in: controller.view).contains(expected))
    XCTAssertFalse(visibleLabels(in: controller.view).contains(pairing.requestHash.hexForTest))
    await controller.stopObserving()
  }

  func testDecisionIsSingleFlightAndAlreadyHandledPreservesWinnerAndState() async throws {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)
    controller.loadView()
    let pairing = try makePendingPairing(id: "pairing-race", fingerprintByte: 0x31)
    await administration.emit(.ready(value: [pairing], revision: 1))
    let rowAppeared = await eventually { controller.rows.count == 1 }
    XCTAssertTrue(rowAppeared)

    XCTAssertTrue(controller.submit(pairingID: pairing.pairingID.rawValue, decision: .confirm))
    XCTAssertFalse(controller.submit(pairingID: pairing.pairingID.rawValue, decision: .confirm))
    XCTAssertFalse(controller.submit(pairingID: pairing.pairingID.rawValue, decision: .cancel))
    let confirmStarted = await eventually {
      await administration.confirmCalls() == [pairing.pairingID.rawValue]
    }
    XCTAssertTrue(confirmStarted)
    XCTAssertTrue(controller.rows.first?.isDecisionInFlight == true)

    await administration.completeConfirm(
      .alreadyHandled(pairing.pairingID, winner: .cancel, state: .canceled)
    )
    let outcomeArrived = await eventually {
      controller.lastOutcome
        == .alreadyHandled(
          pairingID: pairing.pairingID.rawValue,
          winner: "cancel",
          state: "canceled"
        )
    }
    XCTAssertTrue(outcomeArrived)
    XCTAssertFalse(controller.rows.first?.isDecisionInFlight == true)
    XCTAssertFalse(controller.rows.first?.isActionEnabled == true)
    let cancelCalls = await administration.cancelCalls()
    XCTAssertEqual(cancelCalls, [])
    await controller.stopObserving()
  }

  func testCancelRunsOnceAndTerminalReceiptKeepsCurrentRowDisabled() async throws {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)
    controller.loadView()
    let pairing = try makePendingPairing(id: "pairing-cancel", fingerprintByte: 0x35)
    await administration.emit(.ready(value: [pairing], revision: 1))
    let rowAppeared = await eventually { controller.rows.count == 1 }
    XCTAssertTrue(rowAppeared)

    let cancelButton = try XCTUnwrap(button(titled: "拒绝并取消", in: controller.view))
    cancelButton.performClick(nil)
    let canceled = await eventually {
      controller.lastOutcome == .canceled(pairingID: pairing.pairingID.rawValue)
    }
    XCTAssertTrue(canceled)
    XCTAssertFalse(controller.submit(pairingID: pairing.pairingID.rawValue, decision: .cancel))
    XCTAssertFalse(controller.rows.first?.isActionEnabled == true)
    let cancelCalls = await administration.cancelCalls()
    XCTAssertEqual(cancelCalls, [pairing.pairingID.rawValue])
    await controller.stopObserving()
  }

  func testLateResultCannotApplyAfterSameIDRebindsToAnotherFingerprint() async throws {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)
    controller.loadView()
    let original = try makePendingPairing(id: "pairing-rebound", fingerprintByte: 0x41)
    let rebound = try makePendingPairing(id: "pairing-rebound", fingerprintByte: 0x42)
    await administration.emit(.ready(value: [original], revision: 1))
    let originalAppeared = await eventually {
      controller.rows.first?.pairingID == "pairing-rebound"
    }
    XCTAssertTrue(originalAppeared)

    XCTAssertTrue(controller.submit(pairingID: "pairing-rebound", decision: .confirm))
    let confirmStarted = await eventually { await administration.confirmCalls().count == 1 }
    XCTAssertTrue(confirmStarted)
    await administration.emit(.ready(value: [rebound], revision: 2))
    let reboundRejected = await eventually {
      controller.lastOutcome == .securityFailure(pairingID: "pairing-rebound")
        && controller.rows.first?.isActionEnabled == false
    }
    XCTAssertTrue(reboundRejected)

    await administration.completeConfirm(.confirmed(original.pairingID))
    try await Task.sleep(for: .milliseconds(20))
    XCTAssertEqual(controller.lastOutcome, .securityFailure(pairingID: "pairing-rebound"))
    XCTAssertEqual(
      controller.rows.first?.fingerprint,
      Array(repeating: "42", count: 32).joined(separator: ":")
    )
    await controller.stopObserving()
  }

  func testMismatchedReceiptPairingIDFailsClosed() async throws {
    let administration = PendingDeviceAdministrationSpy()
    let controller = PendingDeviceApprovalController(administration: administration)
    controller.loadView()
    let pairing = try makePendingPairing(id: "pairing-expected", fingerprintByte: 0x51)
    await administration.emit(.ready(value: [pairing], revision: 1))
    let rowAppeared = await eventually { controller.rows.count == 1 }
    XCTAssertTrue(rowAppeared)

    XCTAssertTrue(controller.submit(pairingID: pairing.pairingID.rawValue, decision: .confirm))
    let confirmStarted = await eventually { await administration.confirmCalls().count == 1 }
    XCTAssertTrue(confirmStarted)
    await administration.completeConfirm(.confirmed(RuntimePairingID(rawValue: "pairing-other")))

    let mismatchRejected = await eventually {
      controller.lastOutcome == .securityFailure(pairingID: pairing.pairingID.rawValue)
        && controller.rows.first?.isActionEnabled == false
    }
    XCTAssertTrue(mismatchRejected)
    await controller.stopObserving()
  }

  func testTerminalAndFailureStatesRemainTypedAndDistinct() {
    let id = RuntimePairingID(rawValue: "pairing-outcome")
    XCTAssertEqual(
      PendingDeviceApprovalController.outcome(for: .canceled(id)),
      .canceled(pairingID: id.rawValue)
    )
    XCTAssertEqual(
      PendingDeviceApprovalController.outcome(for: .expired(id)),
      .expired(pairingID: id.rawValue)
    )
    XCTAssertEqual(
      PendingDeviceApprovalController.outcome(
        for: SessionSourceFailure(code: .transportUnavailable),
        pairingID: id.rawValue
      ),
      .failed(pairingID: id.rawValue, kind: .transportUnavailable, retryable: true)
    )
    XCTAssertEqual(
      PendingDeviceApprovalController.outcome(
        for: SessionSourceFailure(code: .securityError),
        pairingID: id.rawValue
      ),
      .failed(pairingID: id.rawValue, kind: .securityFailure, retryable: false)
    )
  }

  func testProductionCompositionExposesOnlyLocalAdministrationAndPreviewHasNoEntry()
    async throws
  {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-pending-approval-\(UUID().uuidString.lowercased())",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: home) }

    let production = try AppSessionSourceComposition.production(
      installation: .injectedForTesting(homeDirectory: home),
      remoteLifecycleFactory: { _, _ in throw PreviewCompositionError.remoteScopeUnavailable }
    )
    XCTAssertNotNil(production.localPairingAdministration)
    let productionDelegate = AppDelegate(profile: .dev, composition: production)
    XCTAssertNotNil(
      menuItem(
        titled: AppDelegate.pendingDeviceApprovalMenuTitle,
        in: productionDelegate.makeMainMenu()
      )
    )

    let preview = try PreviewBootstrap.makeComposition()
    XCTAssertNil(preview.localPairingAdministration)
    let previewDelegate = AppDelegate(profile: .dev, composition: preview, preview: true)
    XCTAssertNil(
      menuItem(
        titled: AppDelegate.pendingDeviceApprovalMenuTitle,
        in: previewDelegate.makeMainMenu()
      )
    )

    await production.shutdown()
    await preview.shutdown()
  }

  func testControllerDependsOnFacadeInsteadOfConcreteLocalSource() throws {
    let source = try String(
      contentsOf: repositoryRootForPendingApprovalTest()
        .appendingPathComponent("Sources/AgentDeck/Machines/PendingDeviceApprovalController.swift"),
      encoding: .utf8
    )
    XCTAssertFalse(source.contains("LocalDaemonSessionSource"))
    XCTAssertFalse(source.contains("AgentDeckRelayClient"))
  }
}

private actor PendingDeviceAdministrationSpy: LocalPairingAdministration {
  private let stream: AsyncStream<ResourceState<[PendingPairing]>>
  private let continuation: AsyncStream<ResourceState<[PendingPairing]>>.Continuation
  private var confirmIDs: [String] = []
  private var cancelIDs: [String] = []
  private var confirmContinuation: CheckedContinuation<PairingAdministrationReceipt, any Error>?

  init() {
    let pair = AsyncStream<ResourceState<[PendingPairing]>>.makeStream(
      bufferingPolicy: .bufferingNewest(8)
    )
    stream = pair.stream
    continuation = pair.continuation
  }

  func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>> {
    stream
  }

  func confirmPairing(id: String) async throws -> PairingAdministrationReceipt {
    confirmIDs.append(id)
    return try await withCheckedThrowingContinuation { continuation in
      confirmContinuation = continuation
    }
  }

  func cancelPairing(id: String) async throws -> PairingAdministrationReceipt {
    cancelIDs.append(id)
    return .canceled(RuntimePairingID(rawValue: id))
  }

  func emit(_ state: ResourceState<[PendingPairing]>) {
    continuation.yield(state)
  }

  func completeConfirm(_ receipt: PairingAdministrationReceipt) {
    confirmContinuation?.resume(returning: receipt)
    confirmContinuation = nil
  }

  func confirmCalls() -> [String] { confirmIDs }

  func cancelCalls() -> [String] { cancelIDs }
}

private func makePendingPairing(
  id: String,
  fingerprintByte: UInt8
) throws -> PendingPairing {
  try PendingPairing(
    pairingID: RuntimePairingID(rawValue: id),
    requestHash: Data(repeating: fingerprintByte &+ 1, count: 32),
    deviceSignFingerprint: Data(repeating: fingerprintByte, count: 32),
    requestedAtMs: 1_000,
    expiresAtMs: 9_999_999_999_999
  )
}

@MainActor
private func eventually(
  attempts: Int = 200,
  _ predicate: @escaping @MainActor () async -> Bool
) async -> Bool {
  for _ in 0..<attempts {
    if await predicate() { return true }
    try? await Task.sleep(for: .milliseconds(5))
  }
  return false
}

@MainActor
private func visibleLabels(in view: NSView) -> [String] {
  var labels: [String] = []
  if let label = view as? NSTextField, !label.stringValue.isEmpty {
    labels.append(label.stringValue)
  }
  for subview in view.subviews {
    labels.append(contentsOf: visibleLabels(in: subview))
  }
  return labels
}

@MainActor
private func button(titled title: String, in view: NSView) -> NSButton? {
  if let button = view as? NSButton, button.title == title { return button }
  for subview in view.subviews {
    if let found = button(titled: title, in: subview) { return found }
  }
  return nil
}

@MainActor
private func menuItem(titled title: String, in menu: NSMenu) -> NSMenuItem? {
  for item in menu.items {
    if item.title == title { return item }
    if let submenu = item.submenu, let found = menuItem(titled: title, in: submenu) {
      return found
    }
  }
  return nil
}

private func repositoryRootForPendingApprovalTest() -> URL {
  URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
}

extension Data {
  fileprivate var hexForTest: String {
    map { String(format: "%02X", $0) }.joined()
  }
}
