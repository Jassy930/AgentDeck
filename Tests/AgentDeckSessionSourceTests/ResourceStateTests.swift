import AgentDeckSessionSource
import XCTest

final class ResourceStateTests: XCTestCase {
  func testResourceStateHasExactlyFourCases() {
    let values: [ResourceState<[Int]>] = [
      .loading(previous: nil),
      .ready(value: [1], revision: 2),
      .stale(value: [3], reason: .reconnecting),
      .failed(error: SessionSourceFailure(code: .transportUnavailable), retryable: true),
    ]
    XCTAssertEqual(values.map(tag), [0, 1, 2, 3])
  }

  func testEveryStatePreservesTypedPayload() {
    let previous = ResourceState.loading(previous: [1, 2])
    let ready = ResourceState.ready(value: [3], revision: 8)
    let stale = ResourceState.stale(value: [4], reason: .machineOffline)
    let failure = SessionSourceFailure(code: .securityError)
    let failed = ResourceState<[Int]>.failed(error: failure, retryable: false)

    guard case .loading(let value) = previous else { return XCTFail("loading") }
    XCTAssertEqual(value, [1, 2])
    guard case .ready(let value, let revision) = ready else { return XCTFail("ready") }
    XCTAssertEqual(value, [3])
    XCTAssertEqual(revision, 8)
    guard case .stale(let value, let reason) = stale else { return XCTFail("stale") }
    XCTAssertEqual(value, [4])
    XCTAssertEqual(reason, .machineOffline)
    guard case .failed(let error, let retryable) = failed else { return XCTFail("failed") }
    XCTAssertEqual(error, failure)
    XCTAssertFalse(retryable)
  }

  private func tag<Value>(_ state: ResourceState<Value>) -> Int {
    switch state {
    case .loading: 0
    case .ready: 1
    case .stale: 2
    case .failed: 3
    }
  }
}
