import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class TransferAssemblerTests: XCTestCase {
  func testPublicContractConstantsAndStableFailureCodes() {
    requireSendable(TransferAssembler.self)
    requireSendable(TransferAssembly.self)
    requireSendable(TransferAssemblyProgress.self)
    requireSendable(TransferAssemblerError.self)

    XCTAssertEqual(TransferAssembler.maximumActiveTransfers, 64)
    XCTAssertEqual(TransferAssembler.maximumReassemblyBytes, 128 * 1024 * 1024)
    XCTAssertEqual(TransferAssembler.transferTTLMilliseconds, 300_000)
    XCTAssertEqual(TransferAssembler.maximumCompletedTombstones, 256)

    XCTAssertEqual(TransferAssemblerError.tooLarge.code, "remote.transfer.too_large")
    XCTAssertEqual(
      TransferAssemblerError.hashMismatch.code,
      "remote.transfer.hash_mismatch"
    )
    XCTAssertEqual(TransferAssemblerError.expired.code, "remote.transfer.expired")
    XCTAssertEqual(
      TransferAssemblerError.reassemblyFull.code,
      "remote.transfer.reassembly_full"
    )
    XCTAssertEqual(TransferAssemblerError.staleScope.code, "remote.transfer.stale_scope")
  }

  func testPublicScopeRejectsLateCarrierSweepAndResetFromOldGeneration() throws {
    let connectionID = UUID()
    let current = TransferAssemblyScope(
      connectionID: connectionID,
      generation: RelayTransportGeneration(rawValue: 2)
    )
    let stale = TransferAssemblyScope(
      connectionID: connectionID,
      generation: RelayTransportGeneration(rawValue: 1)
    )
    let payload = Data("scope".utf8)
    let carrier = try makeCarrier(
      transferID: "scope-bound",
      index: 0,
      count: 1,
      totalHash: digest(payload),
      totalBytes: UInt64(payload.count),
      part: payload
    )
    var assembler = TransferAssembler(scope: current)

    assertAssemblerError(.staleScope) {
      try assembler.accept(carrier, scope: stale, nowMS: 0)
    }
    XCTAssertThrowsError(try assembler.sweepExpired(scope: stale, nowMS: 1))
    XCTAssertThrowsError(try assembler.reset(scope: stale))
    guard
      case .complete(let completed) = try assembler.accept(
        carrier,
        scope: current,
        nowMS: 2
      )
    else {
      return XCTFail("current scope should complete")
    }
    XCTAssertEqual(completed.payload, payload)
    XCTAssertNoThrow(try assembler.reset(scope: current))
  }

  func testRustCurrentCompactFixtureDecodesAndCompletesExactly() throws {
    let fixture = try compactTransferFixture()
    let carrier = try RuntimeWireCodec.decodeTransferCarrier(fixture)
    var assembler = TransferAssembler()

    guard case .complete(let completion) = try assembler.accept(carrier, nowMS: 10) else {
      return XCTFail("Rust compact transfer fixture should complete")
    }
    XCTAssertEqual(completion.messageID.rawValue, "message-transfer-compact-1")
    XCTAssertEqual(completion.channel, .stream)
    XCTAssertEqual(completion.transferID.rawValue, "transfer-stable-1")
    XCTAssertEqual(completion.payload, Data("runtime-transfer-fixture".utf8))
    XCTAssertEqual(assembler.bufferedBytes, 0)
  }

  func testSixtyFourPartsCompleteInIndexOrderDespiteReverseArrival() throws {
    let payload = Data((0..<64).map(UInt8.init))
    let hash = digest(payload)
    var assembler = TransferAssembler()
    var completion: TransferAssembly?

    for index in stride(from: 63, through: 0, by: -1) {
      let progress = try assembler.accept(
        makeCarrier(
          transferID: "reverse-64",
          index: UInt32(index),
          count: 64,
          totalHash: hash,
          totalBytes: 64,
          part: Data([UInt8(index)])
        ),
        nowMS: 100
      )
      switch progress {
      case .inProgress:
        break
      case .complete(let value):
        completion = value
      case .alreadyComplete:
        XCTFail("fresh transfer cannot already be complete")
      }
    }

    XCTAssertEqual(completion?.payload, payload)
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)
  }

  func testCompactBoundsRejectSixtyFivePartsAndAcceptExactMaximumPart() throws {
    let jsonProfileTransfer = try TransferEnvelopeV2(
      transferID: RuntimeTransferID(rawValue: "parts-65"),
      partIndex: 0,
      partCount: 65,
      totalSHA256: digest(Data()),
      totalBytes: 0,
      part: Data()
    )
    let invalidCompactCarrier = RuntimeTransferCarrierV2(
      messageID: RuntimeMessageID(rawValue: "message"),
      channel: .stream,
      transfer: jsonProfileTransfer
    )
    var boundsAssembler = TransferAssembler()
    assertAssemblerError(.tooLarge) {
      try boundsAssembler.accept(invalidCompactCarrier, nowMS: 0)
    }
    XCTAssertEqual(boundsAssembler.activeTransferCount, 0)

    let maximumPart = Data(
      repeating: 0x5A,
      count: TransferEnvelopeV2.maxCompactPartBytes
    )
    let carrier = try makeCarrier(
      transferID: "maximum-part",
      index: 0,
      count: 1,
      totalHash: digest(maximumPart),
      totalBytes: UInt64(maximumPart.count),
      part: maximumPart
    )
    var assembler = TransferAssembler()
    guard case .complete(let completion) = try assembler.accept(carrier, nowMS: 0) else {
      return XCTFail("exact 3.5 MiB compact part should complete")
    }
    XCTAssertEqual(completion.payload.count, TransferEnvelopeV2.maxCompactPartBytes)
  }

  func testDuplicateSameIsIdempotentAndDuplicateConflictAbortsTransfer() throws {
    let payload = Data("ab".utf8)
    let hash = digest(payload)
    let first = try makeCarrier(
      transferID: "duplicate-same",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("a".utf8)
    )
    let second = try makeCarrier(
      transferID: "duplicate-same",
      index: 1,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("b".utf8)
    )
    var assembler = TransferAssembler()

    _ = try assembler.accept(first, nowMS: 0)
    guard
      case .inProgress(let receivedParts, let partCount) = try assembler.accept(
        first,
        nowMS: 1
      )
    else {
      return XCTFail("exact duplicate should remain in progress")
    }
    XCTAssertEqual(receivedParts, 1)
    XCTAssertEqual(partCount, 2)
    XCTAssertEqual(assembler.bufferedBytes, 1)
    guard case .complete(let completion) = try assembler.accept(second, nowMS: 2) else {
      return XCTFail("second unique part should complete")
    }
    XCTAssertEqual(completion.payload, payload)

    let conflictFirst = try makeCarrier(
      transferID: "duplicate-conflict",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("a".utf8)
    )
    let conflict = try makeCarrier(
      transferID: "duplicate-conflict",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("x".utf8)
    )
    _ = try assembler.accept(conflictFirst, nowMS: 3)
    assertAssemblerError(.hashMismatch) {
      try assembler.accept(conflict, nowMS: 4)
    }
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)
  }

  func testEveryBindingAxisMismatchAbortsAndReleasesActiveTransfer() throws {
    let payload = Data("ab".utf8)
    let hash = digest(payload)
    let first = try makeCarrier(
      transferID: "binding",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("a".utf8)
    )
    let mismatches = [
      try makeCarrier(
        messageID: "other-message",
        transferID: "binding",
        index: 1,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("b".utf8)
      ),
      try makeCarrier(
        channel: .reply,
        transferID: "binding",
        index: 1,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("b".utf8)
      ),
      try makeCarrier(
        transferID: "binding",
        index: 1,
        count: 3,
        totalHash: hash,
        totalBytes: 2,
        part: Data("b".utf8)
      ),
      try makeCarrier(
        transferID: "binding",
        index: 1,
        count: 2,
        totalHash: hash,
        totalBytes: 3,
        part: Data("b".utf8)
      ),
      try makeCarrier(
        transferID: "binding",
        index: 1,
        count: 2,
        totalHash: Data(repeating: 0xAA, count: 32),
        totalBytes: 2,
        part: Data("b".utf8)
      ),
    ]

    for mismatch in mismatches {
      var assembler = TransferAssembler()
      _ = try assembler.accept(first, nowMS: 0)
      assertAssemblerError(.hashMismatch) {
        try assembler.accept(mismatch, nowMS: 1)
      }
      XCTAssertEqual(assembler.activeTransferCount, 0)
      XCTAssertEqual(assembler.bufferedBytes, 0)
    }
  }

  func testLengthAndTotalHashMismatchFailBeforeReturningPayloadAndReleaseBudget() throws {
    var lengthAssembler = TransferAssembler()
    let shortPayload = Data("ab".utf8)
    let shortHash = digest(shortPayload)
    _ = try lengthAssembler.accept(
      makeCarrier(
        transferID: "length-mismatch",
        index: 0,
        count: 2,
        totalHash: shortHash,
        totalBytes: 3,
        part: Data("a".utf8)
      ),
      nowMS: 0
    )
    assertAssemblerError(.hashMismatch) {
      try lengthAssembler.accept(
        makeCarrier(
          transferID: "length-mismatch",
          index: 1,
          count: 2,
          totalHash: shortHash,
          totalBytes: 3,
          part: Data("b".utf8)
        ),
        nowMS: 1
      )
    }
    XCTAssertEqual(lengthAssembler.bufferedBytes, 0)
    XCTAssertEqual(lengthAssembler.completedTransferCount, 0)

    var hashAssembler = TransferAssembler()
    assertAssemblerError(.hashMismatch) {
      try hashAssembler.accept(
        makeCarrier(
          transferID: "hash-mismatch",
          index: 0,
          count: 1,
          totalHash: Data(repeating: 0, count: 32),
          totalBytes: 3,
          part: Data("bad".utf8)
        ),
        nowMS: 0
      )
    }
    XCTAssertEqual(hashAssembler.bufferedBytes, 0)
    XCTAssertEqual(hashAssembler.completedTransferCount, 0)
  }

  func testAssemblyPeakChargesCachedPartsAndFullAssemblyCopy() throws {
    let payload = Data("abcdefgh".utf8)
    let hash = digest(payload)
    let first = try makeCarrier(
      transferID: "peak",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 8,
      part: Data("abcd".utf8)
    )
    let second = try makeCarrier(
      transferID: "peak",
      index: 1,
      count: 2,
      totalHash: hash,
      totalBytes: 8,
      part: Data("efgh".utf8)
    )

    var tooSmall = TransferAssembler(maxReassemblyBytes: 12)
    _ = try tooSmall.accept(first, nowMS: 0)
    XCTAssertEqual(tooSmall.bufferedBytes, 4)
    assertAssemblerError(.reassemblyFull) {
      try tooSmall.accept(second, nowMS: 1)
    }
    XCTAssertEqual(tooSmall.activeTransferCount, 0)
    XCTAssertEqual(tooSmall.bufferedBytes, 0)

    var exactPeak = TransferAssembler(maxReassemblyBytes: 16)
    _ = try exactPeak.accept(first, nowMS: 0)
    guard case .complete(let completion) = try exactPeak.accept(second, nowMS: 1) else {
      return XCTFail("exact parts + assembly peak should complete")
    }
    XCTAssertEqual(completion.payload, payload)
    XCTAssertEqual(exactPeak.bufferedBytes, 0)
  }

  func testConnectionBudgetIsSharedAcrossTransfersWithoutEvictingExistingWork() throws {
    var assembler = TransferAssembler(maxReassemblyBytes: 5)
    let firstPayload = Data("abcdef".utf8)
    _ = try assembler.accept(
      makeCarrier(
        transferID: "budget-a",
        index: 0,
        count: 2,
        totalHash: digest(firstPayload),
        totalBytes: 6,
        part: Data("abc".utf8)
      ),
      nowMS: 0
    )
    XCTAssertEqual(assembler.bufferedBytes, 3)

    let secondPayload = Data("wxyz".utf8)
    assertAssemblerError(.reassemblyFull) {
      try assembler.accept(
        makeCarrier(
          transferID: "budget-b",
          index: 0,
          count: 2,
          totalHash: digest(secondPayload),
          totalBytes: 4,
          part: Data("wxy".utf8)
        ),
        nowMS: 1
      )
    }
    XCTAssertEqual(assembler.activeTransferCount, 1)
    XCTAssertEqual(assembler.bufferedBytes, 3)
  }

  func testAbsoluteTTLDoesNotRenewOnDuplicateAndExpiresAtBoundary() throws {
    let payload = Data("ab".utf8)
    let hash = digest(payload)
    let first = try makeCarrier(
      transferID: "ttl",
      index: 0,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("a".utf8)
    )
    let second = try makeCarrier(
      transferID: "ttl",
      index: 1,
      count: 2,
      totalHash: hash,
      totalBytes: 2,
      part: Data("b".utf8)
    )
    var assembler = TransferAssembler()

    _ = try assembler.accept(first, nowMS: 1_000)
    _ = try assembler.accept(first, nowMS: 300_999)
    assertAssemblerError(.expired) {
      try assembler.accept(second, nowMS: 301_000)
    }
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)

    let complete = try makeCarrier(
      transferID: "tombstone-ttl",
      index: 0,
      count: 1,
      totalHash: digest(Data("z".utf8)),
      totalBytes: 1,
      part: Data("z".utf8)
    )
    guard case .complete = try assembler.accept(complete, nowMS: 500_000) else {
      return XCTFail("fresh transfer should complete")
    }
    guard case .alreadyComplete = try assembler.accept(complete, nowMS: 799_999) else {
      return XCTFail("unexpired tombstone should suppress duplicate completion")
    }
    guard case .complete = try assembler.accept(complete, nowMS: 800_000) else {
      return XCTFail("tombstone should expire at the exact TTL boundary")
    }
  }

  func testExplicitSweepReleasesSilentPartialAtAbsoluteTTL() throws {
    let payload = Data("ab".utf8)
    var assembler = TransferAssembler()
    _ = try assembler.accept(
      makeCarrier(
        transferID: "silent-ttl",
        index: 0,
        count: 2,
        totalHash: digest(payload),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      nowMS: 10
    )
    XCTAssertEqual(assembler.bufferedBytes, 1)
    XCTAssertTrue(assembler.sweepExpired(nowMS: 300_009).isEmpty)

    let expired = assembler.sweepExpired(nowMS: 300_010)
    XCTAssertEqual(expired.map(\.rawValue), ["silent-ttl"])
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)
  }

  func testZeroBytePartsStillConsumeTheSixtyFourActiveTransferSlots() throws {
    var assembler = TransferAssembler()
    for index in 0..<TransferAssembler.maximumActiveTransfers {
      _ = try assembler.accept(
        makeCarrier(
          transferID: "active-\(index)",
          index: 0,
          count: 2,
          totalHash: digest(Data([UInt8(truncatingIfNeeded: index)])),
          totalBytes: 1,
          part: Data()
        ),
        nowMS: 0
      )
    }
    XCTAssertEqual(assembler.activeTransferCount, 64)
    XCTAssertEqual(assembler.bufferedBytes, 0)

    assertAssemblerError(.reassemblyFull) {
      try assembler.accept(
        makeCarrier(
          transferID: "active-overflow",
          index: 0,
          count: 2,
          totalHash: digest(Data([0xFF])),
          totalBytes: 1,
          part: Data()
        ),
        nowMS: 0
      )
    }
    XCTAssertEqual(assembler.activeTransferCount, 64)
  }

  func testCompletedTombstonesFailClosedAtCapWithoutEvictingLiveDedup() throws {
    var assembler = TransferAssembler()
    var carriers: [RuntimeTransferCarrierV2] = []

    for index in 0..<TransferAssembler.maximumCompletedTombstones {
      let payload = Data([UInt8(truncatingIfNeeded: index)])
      let carrier = try makeCarrier(
        transferID: "completed-\(index)",
        index: 0,
        count: 1,
        totalHash: digest(payload),
        totalBytes: 1,
        part: payload
      )
      carriers.append(carrier)
      guard case .complete = try assembler.accept(carrier, nowMS: UInt64(index)) else {
        return XCTFail("fresh tombstone fixture should complete")
      }
    }
    XCTAssertEqual(assembler.completedTransferCount, 256)

    let overflowPayload = Data([0xFF])
    let overflow = try makeCarrier(
      transferID: "completed-overflow",
      index: 0,
      count: 1,
      totalHash: digest(overflowPayload),
      totalBytes: 1,
      part: overflowPayload
    )
    assertAssemblerError(.reassemblyFull) {
      try assembler.accept(overflow, nowMS: 1_000)
    }
    guard case .alreadyComplete = try assembler.accept(carriers[0], nowMS: 1_001) else {
      return XCTFail("oldest unexpired tombstone must remain")
    }
    guard case .alreadyComplete = try assembler.accept(carriers.last!, nowMS: 1_002) else {
      return XCTFail("newest tombstone should remain")
    }

    var conflictAssembler = TransferAssembler()

    let original = Data("ok".utf8)
    let originalHash = digest(original)
    let completed = try makeCarrier(
      transferID: "completed-conflict",
      index: 0,
      count: 1,
      totalHash: originalHash,
      totalBytes: 2,
      part: original
    )
    guard case .complete = try conflictAssembler.accept(completed, nowMS: 2_000) else {
      return XCTFail("fresh transfer should complete")
    }
    let conflictingReplay = try makeCarrier(
      transferID: "completed-conflict",
      index: 0,
      count: 1,
      totalHash: originalHash,
      totalBytes: 2,
      part: Data("no".utf8)
    )
    assertAssemblerError(.hashMismatch) {
      try conflictAssembler.accept(conflictingReplay, nowMS: 2_001)
    }
  }

  func testResetReleasesActivePartsAndCompletedTombstones() throws {
    var assembler = TransferAssembler()
    let activePayload = Data("ab".utf8)
    _ = try assembler.accept(
      makeCarrier(
        transferID: "reset-active",
        index: 0,
        count: 2,
        totalHash: digest(activePayload),
        totalBytes: 2,
        part: Data("a".utf8)
      ),
      nowMS: 0
    )
    let completed = try makeCarrier(
      transferID: "reset-completed",
      index: 0,
      count: 1,
      totalHash: digest(Data("z".utf8)),
      totalBytes: 1,
      part: Data("z".utf8)
    )
    _ = try assembler.accept(completed, nowMS: 0)

    XCTAssertEqual(assembler.activeTransferCount, 1)
    XCTAssertEqual(assembler.completedTransferCount, 1)
    XCTAssertEqual(assembler.bufferedBytes, 1)
    assembler.reset()
    XCTAssertEqual(assembler.activeTransferCount, 0)
    XCTAssertEqual(assembler.completedTransferCount, 0)
    XCTAssertEqual(assembler.bufferedBytes, 0)

    guard case .complete = try assembler.accept(completed, nowMS: 1) else {
      return XCTFail("reset must remove the completed tombstone")
    }
  }
}

private func makeCarrier(
  messageID: String = "message",
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

private func assertAssemblerError(
  _ expected: TransferAssemblerError,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ body: () throws -> Any
) {
  XCTAssertThrowsError(try body(), file: file, line: line) { error in
    XCTAssertEqual(error as? TransferAssemblerError, expected, file: file, line: line)
  }
}

private func compactTransferFixture() throws -> Data {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let fixtureURL =
    repositoryRoot
    .appendingPathComponent("protocol/agentdeck/fixtures/runtime-v5-wire.jsonl")
  let contents = try String(contentsOf: fixtureURL, encoding: .utf8)

  for line in contents.split(separator: "\n") {
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
    )
    if object["case"] as? String == "compactTransferCarrier" {
      return try decodeHex(try XCTUnwrap(object["value"] as? String))
    }
  }
  throw FixtureError.compactTransferCarrierMissing
}

private func decodeHex(_ value: String) throws -> Data {
  guard value.count.isMultiple(of: 2) else { throw FixtureError.invalidHex }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let end = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<end], radix: 16) else {
      throw FixtureError.invalidHex
    }
    output.append(byte)
    index = end
  }
  return output
}

private enum FixtureError: Error {
  case compactTransferCarrierMissing
  case invalidHex
}

private func requireSendable<T: Sendable>(_: T.Type) {}
