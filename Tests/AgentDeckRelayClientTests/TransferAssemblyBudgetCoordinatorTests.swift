import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class TransferAssemblyBudgetCoordinatorTests: XCTestCase {
  func testPublicConstantsAndCoordinatorAreSendable() {
    requireSendable(TransferAssemblyBudgetCoordinator.self)

    XCTAssertEqual(
      TransferAssemblyBudgetCoordinator.maximumReassemblyBytes,
      512 * 1_024 * 1_024
    )
    XCTAssertEqual(
      TransferAssemblyBudgetCoordinator.maximumCompletedTombstones,
      8_192
    )
  }

  func testFiveNearMaximumOwnersFailClosedWithoutEvictionAndReuseExactRelease() throws {
    let coordinator = TransferAssemblyBudgetCoordinator()
    let scopes = (0..<5).map(makeScope)
    let nearMaximumTransferBytes = UInt64(64 * 1_024 * 1_024 - 1)
    let nearMaximumConnectionPeak = nearMaximumTransferBytes * 2

    for scope in scopes.prefix(4) {
      _ = try coordinator.reservePartBytes(
        scope: scope,
        reservation: nil,
        additionalBytes: nearMaximumTransferBytes
      )
      _ = try coordinator.reserveAssemblyBytes(
        scope: scope,
        bytes: nearMaximumTransferBytes
      )
    }

    XCTAssertEqual(
      coordinator.usage.reassemblyBytes,
      nearMaximumConnectionPeak * 4
    )
    XCTAssertEqual(coordinator.usage.completedTombstones, 0)

    assertAssemblerError(.reassemblyFull) {
      _ = try coordinator.reservePartBytes(
        scope: scopes[4],
        reservation: nil,
        additionalBytes: nearMaximumTransferBytes
      )
    }
    XCTAssertEqual(
      coordinator.usage.reassemblyBytes,
      nearMaximumConnectionPeak * 4,
      "第五个 owner 被拒绝时不得驱逐或改写前四个 owner 的预算"
    )

    coordinator.releaseAll(scope: scopes[0])
    XCTAssertEqual(
      coordinator.usage.reassemblyBytes,
      nearMaximumConnectionPeak * 3
    )

    _ = try coordinator.reservePartBytes(
      scope: scopes[4],
      reservation: nil,
      additionalBytes: nearMaximumTransferBytes
    )
    _ = try coordinator.reserveAssemblyBytes(
      scope: scopes[4],
      bytes: nearMaximumTransferBytes
    )
    XCTAssertEqual(
      coordinator.usage.reassemblyBytes,
      nearMaximumConnectionPeak * 4,
      "释放一个 exact owner 后，第五个 near-128 MiB owner 才能完整准入"
    )

    for scope in scopes {
      coordinator.releaseAll(scope: scope)
    }
    assertEmpty(coordinator)
  }

  func testConcurrentReserveIsAtomicAtExactGlobalSeam() async {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 4,
      maximumCompletedTombstones: 8
    )
    let scopes = (0..<8).map(makeScope)

    let outcomes = await withTaskGroup(of: Int.self, returning: [Int].self) { group in
      for scope in scopes {
        group.addTask {
          do {
            _ = try coordinator.reserveAssemblyBytes(scope: scope, bytes: 1)
            return 1
          } catch TransferAssemblerError.reassemblyFull {
            return 0
          } catch {
            return -1
          }
        }
      }

      var values: [Int] = []
      for await value in group {
        values.append(value)
      }
      return values
    }

    XCTAssertEqual(outcomes.filter { $0 == 1 }.count, 4)
    XCTAssertEqual(outcomes.filter { $0 == 0 }.count, 4)
    XCTAssertFalse(outcomes.contains(-1))
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 4)

    for scope in scopes {
      coordinator.releaseAll(scope: scope)
    }
    assertEmpty(coordinator)
  }

  func testEightThousandOneHundredNinetyTwoTombstonesRejectPlusOneWithoutEviction()
    throws
  {
    let coordinator = TransferAssemblyBudgetCoordinator()
    let scopes = (0..<33).map(makeScope)
    let firstReservation = try coordinator.reserveTombstone(scope: scopes[0])

    for ownerIndex in 0..<32 {
      let start = ownerIndex == 0 ? 1 : 0
      for _ in start..<TransferAssembler.maximumCompletedTombstones {
        _ = try coordinator.reserveTombstone(scope: scopes[ownerIndex])
      }
    }

    XCTAssertEqual(coordinator.usage.reassemblyBytes, 0)
    XCTAssertEqual(coordinator.usage.completedTombstones, 8_192)

    assertAssemblerError(.reassemblyFull) {
      _ = try coordinator.reserveTombstone(scope: scopes[32])
    }
    XCTAssertEqual(
      coordinator.usage.completedTombstones,
      8_192,
      "8192/+1 seam 必须拒绝新 tombstone，不能淘汰 TTL 内旧 dedup"
    )

    coordinator.release(firstReservation)
    XCTAssertEqual(
      coordinator.usage.completedTombstones,
      8_191,
      "最早 reservation 必须仍然存在，证明 +1 失败没有偷偷驱逐"
    )
    _ = try coordinator.reserveTombstone(scope: scopes[32])
    XCTAssertEqual(coordinator.usage.completedTombstones, 8_192)

    for scope in scopes {
      coordinator.releaseAll(scope: scope)
    }
    assertEmpty(coordinator)
  }

  func testPartCacheIsAdmittedBeforeItCanBecomeRetainedAssemblerState() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 1,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)
    let payload = Data("abcd".utf8)

    assertAssemblerError(.reassemblyFull) {
      _ = try assembler.accept(
        makeCarrier(
          transferID: "part-preallocation",
          index: 0,
          count: 2,
          totalHash: digest(payload),
          totalBytes: UInt64(payload.count),
          part: Data("ab".utf8)
        ),
        scope: scope,
        nowMS: 0
      )
    }

    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)
    assertEmpty(coordinator)
  }

  func testFinalAssemblyIsAdmittedBeforeAllocationAndFailureDropsOffendingParts() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 6,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)
    let payload = Data("abcd".utf8)
    let hash = digest(payload)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "assembly-preallocation",
        index: 0,
        count: 2,
        totalHash: hash,
        totalBytes: 4,
        part: Data("ab".utf8)
      ),
      scope: scope,
      nowMS: 0
    )
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 2)

    assertAssemblerError(.reassemblyFull) {
      _ = try assembler.accept(
        makeCarrier(
          transferID: "assembly-preallocation",
          index: 1,
          count: 2,
          totalHash: hash,
          totalBytes: 4,
          part: Data("cd".utf8)
        ),
        scope: scope,
        nowMS: 1
      )
    }

    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.completedTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)
    assertEmpty(coordinator)
  }

  func testTombstoneIsAdmittedBeforeCompletedStateAllocation() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 1
    )
    let firstScope = makeScope(0)
    let secondScope = makeScope(1)
    var first = TransferAssembler(scope: firstScope, budgetCoordinator: coordinator)
    var second = TransferAssembler(scope: secondScope, budgetCoordinator: coordinator)

    guard
      case .complete = try first.accept(
        onePartCarrier(transferID: "tombstone-first", payload: Data("a".utf8)),
        scope: firstScope,
        nowMS: 0
      )
    else {
      return XCTFail("第一个 completion 应占用唯一 global tombstone")
    }
    XCTAssertEqual(coordinator.usage.completedTombstones, 1)

    assertAssemblerError(.reassemblyFull) {
      _ = try second.accept(
        onePartCarrier(transferID: "tombstone-overflow", payload: Data("b".utf8)),
        scope: secondScope,
        nowMS: 1
      )
    }
    XCTAssertEqual(second.activeTransferCount, 0)
    XCTAssertEqual(second.completedTransferCount, 0)
    XCTAssertEqual(second.bufferedBytes, 0)
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 0)
    XCTAssertEqual(coordinator.usage.completedTombstones, 1)

    guard
      case .alreadyComplete = try first.accept(
        onePartCarrier(transferID: "tombstone-first", payload: Data("a".utf8)),
        scope: firstScope,
        nowMS: 2
      )
    else {
      return XCTFail("失败的 +1 completion 不得驱逐既有 dedup")
    }
  }

  func testCompleteReleasesPartAndAssemblyBytesButRetainsTombstoneUntilTTL() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)
    let carrier = try onePartCarrier(
      transferID: "complete-release",
      payload: Data("done".utf8)
    )

    guard case .complete = try assembler.accept(carrier, scope: scope, nowMS: 10) else {
      return XCTFail("完整 transfer 应完成")
    }
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 0)
    XCTAssertEqual(coordinator.usage.completedTombstones, 1)

    _ = try assembler.sweepExpired(
      scope: scope,
      nowMS: 10 + TransferAssembler.transferTTLMilliseconds
    )
    assertEmpty(coordinator)
  }

  func testHashFailureReleasesPartAndAssemblyReservationsExactly() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)

    assertAssemblerError(.hashMismatch) {
      _ = try assembler.accept(
        makeCarrier(
          transferID: "hash-release",
          index: 0,
          count: 1,
          totalHash: Data(repeating: 0, count: SHA256.byteCount),
          totalBytes: 3,
          part: Data("bad".utf8)
        ),
        scope: scope,
        nowMS: 0
      )
    }

    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.completedTransferCount, 0)
    assertEmpty(coordinator)
  }

  func testSilentTTLReleasesPartialReservationWithoutAnotherFrame() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)
    let payload = Data("ab".utf8)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "silent-ttl-release",
        index: 0,
        count: 2,
        totalHash: digest(payload),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      scope: scope,
      nowMS: 5
    )
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 1)

    _ = try assembler.sweepExpired(
      scope: scope,
      nowMS: 5 + TransferAssembler.transferTTLMilliseconds
    )
    assertEmpty(coordinator)
  }

  func testResetReleasesAllActiveAndCompletedReservationsExactly() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "reset-active-budget",
        index: 0,
        count: 2,
        totalHash: digest(Data("ab".utf8)),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      scope: scope,
      nowMS: 0
    )
    _ = try assembler.accept(
      onePartCarrier(transferID: "reset-tombstone-budget", payload: Data("z".utf8)),
      scope: scope,
      nowMS: 0
    )
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 1)
    XCTAssertEqual(coordinator.usage.completedTombstones, 1)

    try assembler.reset(scope: scope)
    assertEmpty(coordinator)
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.completedTransferCount, 0)
  }

  func testOwnerTeardownReleaseAllIsExactAndLateResetCannotUnderflow() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "teardown-active-budget",
        index: 0,
        count: 2,
        totalHash: digest(Data("ab".utf8)),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      scope: scope,
      nowMS: 0
    )
    _ = try assembler.accept(
      onePartCarrier(transferID: "teardown-tombstone-budget", payload: Data("z".utf8)),
      scope: scope,
      nowMS: 0
    )

    coordinator.releaseAll(scope: scope)
    assertEmpty(coordinator)

    try assembler.reset(scope: scope)
    assertEmpty(coordinator)
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.completedTransferCount, 0)
  }

  func testNoncopyableOwnerDestructionReleasesExactScopeWithoutExplicitReset() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "destroy-active-budget",
        index: 0,
        count: 2,
        totalHash: digest(Data("ab".utf8)),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      scope: scope,
      nowMS: 0
    )
    _ = try assembler.accept(
      onePartCarrier(transferID: "destroy-tombstone-budget", payload: Data("z".utf8)),
      scope: scope,
      nowMS: 0
    )
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 1)
    XCTAssertEqual(coordinator.usage.completedTombstones, 1)

    destroyAssembler(consume assembler)
    assertEmpty(coordinator)
  }

  func testZeroByteActiveTokenIsReleasedByOwnerTeardownAndLateResetIsIdempotent() throws {
    let coordinator = TransferAssemblyBudgetCoordinator(
      maximumReassemblyBytes: 32,
      maximumCompletedTombstones: 8
    )
    let scope = makeScope(0)
    var assembler = TransferAssembler(scope: scope, budgetCoordinator: coordinator)

    _ = try assembler.accept(
      makeCarrier(
        transferID: "zero-byte-owner-token",
        index: 0,
        count: 2,
        totalHash: digest(Data([0x01])),
        totalBytes: 1,
        part: Data()
      ),
      scope: scope,
      nowMS: 0
    )
    XCTAssertEqual(assembler.activeTransferCount, 1)
    XCTAssertEqual(assembler.bufferedBytes, 0)
    XCTAssertEqual(coordinator.usage.reassemblyBytes, 0)
    XCTAssertEqual(
      coordinator.usage.reservationCount,
      1,
      "零字节 part 仍必须拥有 exact token，不能绕过 owner teardown 记账"
    )

    coordinator.releaseAll(scope: scope)
    assertEmpty(coordinator)

    try assembler.reset(scope: scope)
    assertEmpty(coordinator)
    XCTAssertEqual(assembler.activeTransferCount, 0)
  }
}

private func makeScope(_ index: Int) -> TransferAssemblyScope {
  TransferAssemblyScope(
    connectionID: UUID(
      uuid: (
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, UInt8(truncatingIfNeeded: index >> 8), UInt8(truncatingIfNeeded: index)
      )
    ),
    generation: RelayTransportGeneration(rawValue: 1)
  )
}

private func onePartCarrier(
  transferID: String,
  payload: Data
) throws -> RuntimeTransferCarrierV2 {
  try makeCarrier(
    transferID: transferID,
    index: 0,
    count: 1,
    totalHash: digest(payload),
    totalBytes: UInt64(payload.count),
    part: payload
  )
}

private func makeCarrier(
  messageID: String = "budget-message",
  channel: RuntimeTransferChannelV2 = .stream,
  transferID: String,
  index: UInt32,
  count: UInt32,
  totalHash: Data,
  totalBytes: UInt64,
  part: Data
) throws -> RuntimeTransferCarrierV2 {
  try RuntimeTransferCarrierV2(
    messageID: RuntimeMessageID(rawValue: messageID),
    channel: channel,
    transferID: RuntimeTransferID(rawValue: transferID),
    partIndex: index,
    partCount: count,
    totalSHA256: totalHash,
    totalBytes: totalBytes,
    part: part
  )
}

private func digest(_ data: Data) -> Data {
  Data(SHA256.hash(data: data))
}

private func assertAssemblerError<T>(
  _ expected: TransferAssemblerError,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ operation: () throws -> T
) {
  XCTAssertThrowsError(try operation(), file: file, line: line) { error in
    XCTAssertEqual(error as? TransferAssemblerError, expected, file: file, line: line)
  }
}

private func assertEmpty(
  _ coordinator: TransferAssemblyBudgetCoordinator,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertEqual(coordinator.usage.reassemblyBytes, 0, file: file, line: line)
  XCTAssertEqual(coordinator.usage.completedTombstones, 0, file: file, line: line)
  XCTAssertEqual(coordinator.usage.reservationCount, 0, file: file, line: line)
}

private func requireSendable<T: Sendable>(_: T.Type) {}

private func destroyAssembler(_ assembler: consuming TransferAssembler) {}
