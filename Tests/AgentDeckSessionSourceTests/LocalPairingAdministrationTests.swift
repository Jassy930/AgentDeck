import AgentDeckCore
import AgentDeckSessionSource
import XCTest

final class LocalPairingAdministrationTests: XCTestCase {
  private actor LocalOnlyStub: LocalPairingAdministration {
    func pendingPairings() async -> AsyncStream<ResourceState<[PendingPairing]>> {
      AsyncStream { continuation in
        continuation.yield(.ready(value: [], revision: 9))
        continuation.finish()
      }
    }

    func confirmPairing(id: String) async throws -> PairingAdministrationReceipt {
      .alreadyHandled(
        RuntimePairingID(rawValue: id),
        winner: .confirm,
        state: .delivered
      )
    }

    func cancelPairing(id: String) async throws -> PairingAdministrationReceipt {
      .alreadyHandled(
        RuntimePairingID(rawValue: id),
        winner: .cancel,
        state: .canceled
      )
    }
  }

  func testLocalAdministrationIsIndependentFromSessionSource() {
    let local: any LocalPairingAdministration = LocalOnlyStub()
    XCTAssertFalse((local as Any) is any SessionSource)
  }

  func testPendingFactoryIsAsyncAndResourceTyped() async {
    let local: any LocalPairingAdministration = LocalOnlyStub()
    var iterator = await local.pendingPairings().makeAsyncIterator()
    guard let state = await iterator.next() else {
      return XCTFail("expected one resource state")
    }
    guard case .ready(let pairings, let revision) = state else {
      return XCTFail("expected ready")
    }
    XCTAssertTrue(pairings.isEmpty)
    XCTAssertEqual(revision, 9)
  }

  func testConfirmAlreadyHandledPreservesWinnerAndState() async throws {
    let local: any LocalPairingAdministration = LocalOnlyStub()
    let receipt = try await local.confirmPairing(id: "pairing")
    guard case .alreadyHandled(let id, let winner, let state) = receipt else {
      return XCTFail("expected already handled")
    }
    XCTAssertEqual(id.rawValue, "pairing")
    XCTAssertEqual(winner, .confirm)
    XCTAssertEqual(state, .delivered)
  }

  func testCancelAlreadyHandledPreservesWinnerAndState() async throws {
    let local: any LocalPairingAdministration = LocalOnlyStub()
    let receipt = try await local.cancelPairing(id: "pairing")
    guard case .alreadyHandled(let id, let winner, let state) = receipt else {
      return XCTFail("expected already handled")
    }
    XCTAssertEqual(id.rawValue, "pairing")
    XCTAssertEqual(winner, .cancel)
    XCTAssertEqual(state, .canceled)
  }
}
