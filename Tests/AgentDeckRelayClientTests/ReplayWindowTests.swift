import AgentDeckRelayClient
import Foundation
import XCTest

final class ReplayWindowTests: XCTestCase {
  func testPublicContractIsSendableAndUses4096CounterWindow() {
    requireSendable(ReplayDisposition.self)
    requireSendable(ReplayWindowEntry.self)
    requireSendable(ReplayWindowSnapshot.self)
    requireSendable(ReplayWindow.self)

    XCTAssertEqual(ReplayWindow.windowSize, UInt64(4_096))

    let makeEmpty: () -> ReplayWindow = ReplayWindow.init
    let restore: (ReplayWindowSnapshot) throws -> ReplayWindow = ReplayWindow.init(snapshot:)
    _ = (makeEmpty, restore)
  }

  func testFirstObservationIsFreshAndExactRepeatIsDuplicate() throws {
    var window = ReplayWindow()
    let hash = hash(for: 7)

    XCTAssertEqual(
      try window.observe(counter: 7, ciphertextHash: hash),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: 7, ciphertextHash: hash),
      .exactDuplicate
    )
  }

  func testSameCounterWithDifferentHashIsNonceReuse() throws {
    var window = ReplayWindow()
    let hash = hash(for: 42)
    XCTAssertEqual(
      try window.observe(counter: 42, ciphertextHash: hash),
      .fresh
    )

    XCTAssertThrowsError(
      try window.observe(counter: 42, ciphertextHash: differentHash(from: hash))
    ) { error in
      XCTAssertEqual(error as? RelayCryptoError, .nonceReuse)
    }

    var otherCounterWindow = ReplayWindow()
    XCTAssertEqual(
      try otherCounterWindow.observe(counter: 42, ciphertextHash: hash),
      .fresh
    )
    XCTAssertEqual(
      try otherCounterWindow.observe(counter: 43, ciphertextHash: differentHash(from: hash)),
      .fresh,
      "不同 counter 即使 hash 不同也不是 nonce reuse"
    )
  }

  func testObservationRequiresExactlyOneSHA256DigestWithoutMutatingState() throws {
    var window = ReplayWindow()

    XCTAssertThrowsError(
      try window.observe(counter: 9, ciphertextHash: Data(repeating: 0xAB, count: 31))
    ) { error in
      XCTAssertEqual(
        error as? RelayCryptoError,
        .invalidLength(field: "ciphertextHash", expected: 32, actual: 31)
      )
    }
    XCTAssertEqual(
      try window.observe(counter: 9, ciphertextHash: hash(for: 9)),
      .fresh,
      "非法 hash 不能污染 replay state"
    )
  }

  func testUnseenOutOfOrderCounterInsideWindowIsFresh() throws {
    var window = ReplayWindow()
    let highWater = ReplayWindow.windowSize + 100
    let outOfOrder = highWater - 100

    XCTAssertEqual(
      try window.observe(counter: highWater, ciphertextHash: hash(for: highWater)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: outOfOrder, ciphertextHash: hash(for: outOfOrder)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: outOfOrder, ciphertextHash: hash(for: outOfOrder)),
      .exactDuplicate
    )
  }

  func testWindowIncludesHighWaterAndPrevious4095Counters() throws {
    var window = ReplayWindow()
    let highWater: UInt64 = 10_000
    let floor = highWater - (ReplayWindow.windowSize - 1)

    XCTAssertEqual(
      try window.observe(counter: highWater, ciphertextHash: hash(for: highWater)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: floor, ciphertextHash: hash(for: floor)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: floor - 1, ciphertextHash: hash(for: floor - 1)),
      .stale
    )
  }

  func testBelowFloorIsStaleBeforeHistoricalHashComparison() throws {
    var window = ReplayWindow()
    let originalHash = hash(for: 0)

    XCTAssertEqual(
      try window.observe(counter: 0, ciphertextHash: originalHash),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(
        counter: ReplayWindow.windowSize,
        ciphertextHash: hash(for: ReplayWindow.windowSize)
      ),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: 0, ciphertextHash: differentHash(from: originalHash)),
      .stale,
      "floor 以下必须先判 stale，不能再把历史 hash 差异误报为 nonce reuse"
    )
  }

  func testAdvancingHighWaterEvictsOnlyCountersBelowNewFloor() throws {
    var window = ReplayWindow()

    for counter in UInt64(0)..<ReplayWindow.windowSize {
      XCTAssertEqual(
        try window.observe(counter: counter, ciphertextHash: hash(for: counter)),
        .fresh
      )
    }

    XCTAssertEqual(
      try window.observe(
        counter: ReplayWindow.windowSize,
        ciphertextHash: hash(for: ReplayWindow.windowSize)
      ),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: 0, ciphertextHash: hash(for: 0)),
      .stale
    )
    XCTAssertEqual(
      try window.observe(counter: 1, ciphertextHash: hash(for: 1)),
      .exactDuplicate
    )

    let snapshot = window.snapshot
    XCTAssertEqual(snapshot.floor, 1)
    XCTAssertEqual(snapshot.highWater, ReplayWindow.windowSize)
    XCTAssertEqual(snapshot.entries.count, Int(ReplayWindow.windowSize))
    XCTAssertEqual(snapshot.entries.first?.counter, 1)
    XCTAssertEqual(snapshot.entries.last?.counter, ReplayWindow.windowSize)
  }

  func testUInt64MaxBoundaryDoesNotOverflow() throws {
    var window = ReplayWindow()
    let floorAtMax = UInt64.max - (ReplayWindow.windowSize - 1)

    XCTAssertEqual(
      try window.observe(counter: UInt64.max, ciphertextHash: hash(for: UInt64.max)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: floorAtMax, ciphertextHash: hash(for: floorAtMax)),
      .fresh
    )
    XCTAssertEqual(
      try window.observe(counter: floorAtMax - 1, ciphertextHash: hash(for: floorAtMax - 1)),
      .stale
    )
    XCTAssertEqual(
      try window.observe(counter: UInt64.max, ciphertextHash: hash(for: UInt64.max)),
      .exactDuplicate
    )
  }

  func testSnapshotCodableRoundTripRestoresReplaySemantics() throws {
    var original = ReplayWindow()
    XCTAssertEqual(
      try original.observe(counter: 5_000, ciphertextHash: hash(for: 5_000)),
      .fresh
    )
    XCTAssertEqual(
      try original.observe(counter: 4_999, ciphertextHash: hash(for: 4_999)),
      .fresh
    )

    let encoded = try JSONEncoder().encode(original.snapshot)
    let decoded = try JSONDecoder().decode(ReplayWindowSnapshot.self, from: encoded)
    XCTAssertEqual(decoded, original.snapshot)

    var restored = try ReplayWindow(snapshot: decoded)
    XCTAssertEqual(
      try restored.observe(counter: 5_000, ciphertextHash: hash(for: 5_000)),
      .exactDuplicate
    )
    XCTAssertEqual(
      try restored.observe(counter: 4_998, ciphertextHash: hash(for: 4_998)),
      .fresh
    )
  }

  func testSnapshotValidationRejectsMalformedState() {
    let validHighWater: UInt64 = 5_000
    let validFloor = validHighWater - (ReplayWindow.windowSize - 1)
    let validHighEntry = ReplayWindowEntry(
      counter: validHighWater,
      ciphertextHash: hash(for: validHighWater)
    )

    var malformedSnapshots: [ReplayWindowSnapshot] = []
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: nil,
        floor: 0,
        entries: [ReplayWindowEntry(counter: 0, ciphertextHash: hash(for: 0))]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(highWater: validHighWater, floor: validFloor, entries: []),
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: validHighWater,
        floor: validFloor - 1,
        entries: [validHighEntry]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: validHighWater,
        floor: validFloor,
        entries: [
          validHighEntry,
          ReplayWindowEntry(counter: validHighWater - 1, ciphertextHash: hash(for: 4_999)),
        ]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: validHighWater,
        floor: validFloor,
        entries: [
          ReplayWindowEntry(counter: validHighWater, ciphertextHash: hash(for: validHighWater)),
          ReplayWindowEntry(counter: validHighWater, ciphertextHash: hash(for: validHighWater)),
        ]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: validHighWater,
        floor: validFloor,
        entries: [
          ReplayWindowEntry(
            counter: validHighWater,
            ciphertextHash: Data(repeating: 0xAB, count: 31)
          )
        ]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: validHighWater,
        floor: validFloor,
        entries: [
          ReplayWindowEntry(counter: validFloor - 1, ciphertextHash: hash(for: validFloor - 1)),
          validHighEntry,
        ]
      )
    )
    malformedSnapshots.append(
      ReplayWindowSnapshot(
        highWater: ReplayWindow.windowSize,
        floor: 1,
        entries: (UInt64(0)...ReplayWindow.windowSize).map {
          ReplayWindowEntry(counter: $0, ciphertextHash: hash(for: $0))
        }
      )
    )

    for snapshot in malformedSnapshots {
      XCTAssertThrowsError(try ReplayWindow(snapshot: snapshot))
    }
  }

  private func hash(for counter: UInt64) -> Data {
    var bigEndian = counter.bigEndian
    let prefix = withUnsafeBytes(of: &bigEndian) { Data($0) }
    var hash = Data(repeating: 0, count: 32)
    hash.replaceSubrange(0..<8, with: prefix)
    return hash
  }

  private func differentHash(from hash: Data) -> Data {
    var changed = hash
    changed[changed.startIndex] ^= 1
    return changed
  }

  private func requireSendable<Value: Sendable>(_: Value.Type) {}
}
