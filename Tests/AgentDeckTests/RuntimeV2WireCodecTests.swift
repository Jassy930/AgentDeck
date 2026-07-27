import Foundation
import XCTest

@testable import AgentDeckCore

final class RuntimeV2WireCodecTests: XCTestCase {
  func testCurrentFacadeIsV5AndRejectsV1IngressAndEgress() throws {
    XCTAssertEqual(runtimeProtocolVersionV2, 2)
    XCTAssertEqual(runtimeProtocolVersionV3, 3)
    XCTAssertEqual(runtimeProtocolVersionV4, 4)
    XCTAssertEqual(runtimeProtocolVersionV5, 5)
    XCTAssertEqual(runtimeProtocolVersionCurrent, runtimeProtocolVersionV5)
    requireV2Codec(RuntimeWireCodec.self)

    let hello = try fixture(named: "requestHello")
    let currentData = try jsonData(hello.value)
    _ = try RuntimeWireCodec.decodeEnvelope(currentData)
    XCTAssertThrowsError(try RuntimeV1WireCodec.decodeEnvelope(currentData))

    var v1Object = try objectValue(hello.value)
    v1Object["version"] = 1
    var body = try dictionary(v1Object["body"])
    var payload = try dictionary(body["payload"])
    payload["runtimeProtocolVersion"] = 1
    body["payload"] = payload
    v1Object["body"] = body
    let v1Data = try jsonData(v1Object)
    _ = try RuntimeV1WireCodec.decodeEnvelope(v1Data)
    XCTAssertThrowsError(try RuntimeWireCodec.decodeEnvelope(v1Data))

    let v1Egress = RuntimeEnvelopeV2(
      version: 1,
      messageID: RuntimeMessageID(rawValue: "v1-egress"),
      body: .request(.hello(runtimeProtocolVersion: 1))
    )
    XCTAssertThrowsError(try RuntimeWireCodec.encode(v1Egress))
  }
  func testCurrentCodecReadsAll110RustFixturesAndCompactIsByteExact() throws {
    let fixtures = try loadFixtures()
    XCTAssertEqual(fixtures.count, 110)
    XCTAssertEqual(Set(fixtures.map(\.name)).count, 110)

    let envelopes = fixtures.filter { $0.wireType == "runtimeEnvelope" }
    let transfers = fixtures.filter { $0.wireType == "transferEnvelope" }
    let compact = fixtures.filter { $0.wireType == "runtimeTransferCarrierV1" }
    XCTAssertEqual(envelopes.count, 108)
    XCTAssertEqual(transfers.count, 1)
    XCTAssertEqual(compact.count, 1)

    var counts = ["request": 0, "reply": 0, "stream": 0]
    for fixture in envelopes {
      let input = try jsonData(fixture.value)
      let decoded = try RuntimeWireCodec.decodeEnvelope(input)
      switch decoded.body {
      case .request: counts["request", default: 0] += 1
      case .reply: counts["reply", default: 0] += 1
      case .stream: counts["stream", default: 0] += 1
      }
      try assertJSONSemanticallyEqual(
        input,
        RuntimeWireCodec.encode(decoded),
        caseName: fixture.name
      )
    }
    XCTAssertEqual(counts, ["request": 29, "reply": 52, "stream": 27])

    let transferFixture = try XCTUnwrap(transfers.first)
    let transferInput = try jsonData(transferFixture.value)
    let transfer = try RuntimeWireCodec.decodeTransferEnvelope(transferInput)
    try assertJSONSemanticallyEqual(
      transferInput,
      RuntimeWireCodec.encode(transfer),
      caseName: transferFixture.name
    )

    let compactFixture = try XCTUnwrap(compact.first)
    let compactHex = try XCTUnwrap(compactFixture.value as? String)
    let compactInput = try Data(hex: compactHex)
    let carrier = try RuntimeWireCodec.decodeTransferCarrier(compactInput)
    XCTAssertEqual(carrier.runtimeVersion, 5)
    XCTAssertEqual(try RuntimeWireCodec.encode(carrier), compactInput)
  }

  func testJSONEnvelopeAndRequestRejectExactOneMiBInBothDirections() throws {
    XCTAssertEqual(RuntimeV2WireCodec.maxRequestBytes, 1024 * 1024)
    XCTAssertEqual(RuntimeV2WireCodec.maxJSONFrameBytes, 1024 * 1024)
    for kind in SizedEnvelopeKind.allCases {
      let below = try makeSizedEnvelope(
        kind: kind, byteCount: RuntimeV2WireCodec.maxJSONFrameBytes - 1)
      let belowRaw = try JSONEncoder().encode(below)
      XCTAssertEqual(belowRaw.count, RuntimeV2WireCodec.maxJSONFrameBytes - 1)
      XCTAssertEqual(try RuntimeWireCodec.encode(below).count, belowRaw.count)
      _ = try RuntimeWireCodec.decodeEnvelope(belowRaw)

      let exact = try makeSizedEnvelope(kind: kind, byteCount: RuntimeV2WireCodec.maxJSONFrameBytes)
      let exactRaw = try JSONEncoder().encode(exact)
      XCTAssertEqual(exactRaw.count, RuntimeV2WireCodec.maxJSONFrameBytes)
      XCTAssertThrowsError(try RuntimeWireCodec.encode(exact))
      XCTAssertThrowsError(try RuntimeWireCodec.decodeEnvelope(exactRaw))
    }

    let transferFixture = try fixture(named: "transferEnvelope")
    let transferRaw = try jsonData(transferFixture.value)
    var exactTransferFrame = transferRaw
    exactTransferFrame.append(
      Data(repeating: 0x20, count: RuntimeV2WireCodec.maxJSONFrameBytes - transferRaw.count)
    )
    XCTAssertEqual(exactTransferFrame.count, RuntimeV2WireCodec.maxJSONFrameBytes)
    XCTAssertThrowsError(try RuntimeWireCodec.decodeTransferEnvelope(exactTransferFrame))
  }

  func testCompactProfileRepresents64MiBWith19PartsAndFitsBelowFourMiB() throws {
    XCTAssertEqual(RuntimeTransferCarrierV2.maxBytes, 4 * 1024 * 1024)
    let hash = Data(repeating: 0x5a, count: 32)
    let total = TransferEnvelopeV2.maxTotalBytes
    XCTAssertThrowsError(
      try compactCarrier(partCount: 18, totalBytes: total, hash: hash, part: Data([1]))
    )
    XCTAssertNoThrow(
      try compactCarrier(partCount: 19, totalBytes: total, hash: hash, part: Data([1]))
    )
    XCTAssertNoThrow(
      try compactCarrier(partCount: 64, totalBytes: total, hash: hash, part: Data([1]))
    )
    XCTAssertThrowsError(
      try compactCarrier(partCount: 65, totalBytes: total, hash: hash, part: Data([1]))
    )
    for invalidHash in [Data(repeating: 0, count: 31), Data(repeating: 0, count: 33)] {
      XCTAssertThrowsError(
        try compactCarrier(
          partCount: 19,
          totalBytes: total,
          hash: invalidHash,
          part: Data([1])
        )
      )
    }

    let maxPart = Data(repeating: 0x41, count: TransferEnvelopeV2.maxCompactPartBytes)
    let carrier = try compactCarrier(
      messageID: String(repeating: "m", count: 1024),
      transferID: String(repeating: "t", count: 1024),
      partCount: 19,
      totalBytes: total,
      hash: hash,
      part: maxPart
    )
    let encoded = try RuntimeWireCodec.encode(carrier)
    XCTAssertLessThan(encoded.count, RuntimeTransferCarrierV2.maxBytes)
    XCTAssertEqual(
      try RuntimeWireCodec.encode(RuntimeWireCodec.decodeTransferCarrier(encoded)), encoded)

    let reply = try compactCarrier(
      channel: .reply,
      partIndex: 1,
      partCount: 2,
      totalBytes: 2,
      hash: hash,
      part: Data([0x42])
    )
    let decodedReply = try RuntimeWireCodec.decodeTransferCarrier(
      RuntimeWireCodec.encode(reply)
    )
    XCTAssertEqual(decodedReply.channel, .reply)
    XCTAssertEqual(decodedReply.transfer.partIndex, 1)

    let badMessage = RuntimeTransferCarrierV2(
      messageID: RuntimeMessageID(rawValue: String(repeating: "中", count: 342)),
      channel: .reply,
      transfer: carrier.transfer
    )
    XCTAssertThrowsError(try RuntimeWireCodec.encode(badMessage))
    for invalidMessage in ["", String(repeating: "m", count: 1025)] {
      XCTAssertThrowsError(
        try compactCarrier(
          messageID: invalidMessage,
          partCount: 1,
          totalBytes: 1,
          hash: hash,
          part: Data([1])
        )
      )
    }
    for invalidTransferID in ["", String(repeating: "t", count: 1025)] {
      XCTAssertThrowsError(
        try compactCarrier(
          transferID: invalidTransferID,
          partCount: 1,
          totalBytes: 1,
          hash: hash,
          part: Data([1])
        )
      )
    }
    XCTAssertThrowsError(
      try compactCarrier(
        partCount: 2,
        totalBytes: UInt64(TransferEnvelopeV2.maxCompactPartBytes + 1),
        hash: hash,
        part: Data(
          repeating: 1,
          count: TransferEnvelopeV2.maxCompactPartBytes + 1
        )
      )
    )
  }

  func testCompactCarrierRejectsTransferBoundsOnIngressAndEgress() throws {
    let hash = Data(repeating: 0x5a, count: 32)
    let total = TransferEnvelopeV2.maxTotalBytes
    XCTAssertThrowsError(
      try compactCarrier(
        partIndex: 19,
        partCount: 19,
        totalBytes: total,
        hash: hash,
        part: Data([1])
      )
    )
    XCTAssertThrowsError(
      try compactCarrier(
        partCount: 1,
        totalBytes: 0,
        hash: hash,
        part: Data([1])
      )
    )
    XCTAssertThrowsError(
      try compactCarrier(
        partCount: 19,
        totalBytes: total + 1,
        hash: hash,
        part: Data([1])
      )
    )

    let fixture = try fixture(named: "compactTransferCarrier")
    let original = try Data(hex: try XCTUnwrap(fixture.value as? String))
    let layout = try compactLayout(original)

    var indexEqualsCount = original
    writeUInt32(1, to: &indexEqualsCount, at: layout.partIndex)
    var zeroParts = original
    writeUInt32(0, to: &zeroParts, at: layout.partCount)
    var tooManyParts = original
    writeUInt32(65, to: &tooManyParts, at: layout.partCount)
    var cannotRepresentTotal = original
    writeUInt32(18, to: &cannotRepresentTotal, at: layout.partCount)
    writeUInt64(total, to: &cannotRepresentTotal, at: layout.totalBytes)
    var totalTooLarge = original
    writeUInt64(total + 1, to: &totalTooLarge, at: layout.totalBytes)
    var partExceedsTotal = original
    writeUInt64(UInt64(layout.partLength - 1), to: &partExceedsTotal, at: layout.totalBytes)
    var declaredPartTooLong = original
    writeUInt32(UInt32(layout.partLength + 1), to: &declaredPartTooLong, at: layout.partLengthField)
    var oversizedPart = original.prefix(layout.partStart)
    writeUInt32(2, to: &oversizedPart, at: layout.partCount)
    writeUInt64(
      UInt64(TransferEnvelopeV2.maxCompactPartBytes + 1),
      to: &oversizedPart,
      at: layout.totalBytes
    )
    writeUInt32(
      UInt32(TransferEnvelopeV2.maxCompactPartBytes + 1),
      to: &oversizedPart,
      at: layout.partLengthField
    )
    oversizedPart.append(
      Data(repeating: 1, count: TransferEnvelopeV2.maxCompactPartBytes + 1)
    )

    for candidate in [
      indexEqualsCount,
      zeroParts,
      tooManyParts,
      cannotRepresentTotal,
      totalTooLarge,
      partExceedsTotal,
      declaredPartTooLong,
      oversizedPart,
    ] {
      XCTAssertThrowsError(try RuntimeWireCodec.decodeTransferCarrier(candidate))
    }
  }

  func testCompactCarrierRejectsMalformedAndVersionMismatchedFrames() throws {
    let fixture = try fixture(named: "compactTransferCarrier")
    let original = try Data(hex: try XCTUnwrap(fixture.value as? String))
    let decoded = try RuntimeWireCodec.decodeTransferCarrier(original)
    XCTAssertThrowsError(try RuntimeV1WireCodec.decodeTransferCarrier(original))

    var v1 = original
    v1[5] = 0
    v1[6] = 1
    _ = try RuntimeV1WireCodec.decodeTransferCarrier(v1)
    XCTAssertThrowsError(try RuntimeWireCodec.decodeTransferCarrier(v1)) { error in
      XCTAssertEqual(error as? RuntimeV2WireError, .unsupportedVersion)
    }
    let v1Egress = RuntimeTransferCarrierV2(
      runtimeVersion: 1,
      messageID: decoded.messageID,
      channel: decoded.channel,
      transfer: decoded.transfer
    )
    XCTAssertThrowsError(try RuntimeWireCodec.encode(v1Egress)) { error in
      XCTAssertEqual(error as? RuntimeV2WireError, .unsupportedVersion)
    }

    var badMagic = original
    badMagic[0] ^= 0xff
    var badChannel = original
    badChannel[7] = 2
    var trailing = original
    trailing.append(0)
    var truncated = original
    truncated.removeLast()
    var badLength = original
    badLength[8] = 0xff
    badLength[9] = 0xff
    var badUTF8 = original
    badUTF8[10] = 0xff
    for candidate in [badMagic, badChannel, trailing, truncated, badLength, badUTF8] {
      XCTAssertThrowsError(try RuntimeWireCodec.decodeTransferCarrier(candidate))
    }

    XCTAssertThrowsError(
      try RuntimeWireCodec.decodeTransferCarrier(
        Data(repeating: 0, count: RuntimeTransferCarrierV2.maxBytes)
      )
    ) { error in
      XCTAssertEqual(error as? RuntimeV2WireError, .transferTooLarge)
    }
  }

  func testCurrentProductionSourcesContainNoV1OuterOrPrivateHandleReferences() throws {
    let roots = [
      "Sources/AgentDeck",
      "Sources/AgentDeckRelayClient",
      "ios/AgentDeckMobile",
      "Sources/AgentDeckCore",
    ]
    let frozen =
      repositoryRoot
      .appendingPathComponent("Sources/AgentDeckCore/Protocol/RuntimeWireTypes.swift")
      .standardizedFileURL.path
    let forbidden: Set<String> = [
      "runtimeProtocolVersionV1", "RuntimeV1MirrorError", "RuntimeRequestV1",
      "RuntimeReplyV1", "RuntimeStreamItemV1", "RuntimeMessageV1", "RuntimeEnvelopeV1",
      "RuntimeV1WireCodec", "TransferEnvelopeV1", "RuntimeTransferChannelV1",
      "RuntimeTransferCarrierV1", "CommandReceiptV1", "CommandStatusReceiptV1",
      "ConversationStartReceiptV1", "RuntimeConversationEntryV1", "RuntimeCatalogSnapshotV1",
      "RuntimeCatalogChangeV1", "RuntimeCatalogDeltaV1", "RuntimeEventV1",
      "RuntimeEventBodyV1", "ConversationSnapshotV1", "RuntimeBackfillChunkV1",
    ]
    let privateHandlePrefix = ["Runtime", "Adapter", "State", "Key"].joined()

    for relativeRoot in roots {
      let root = repositoryRoot.appendingPathComponent(relativeRoot)
      var isDirectory: ObjCBool = false
      XCTAssertTrue(FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory))
      XCTAssertTrue(isDirectory.boolValue)
      let files = try swiftFiles(below: root).filter { $0.standardizedFileURL.path != frozen }
      XCTAssertFalse(files.isEmpty, "source gate root must not be empty: \(relativeRoot)")
      for file in files {
        let source = try String(contentsOf: file, encoding: .utf8)
        let identifiers = Set(sourceIdentifierTokens(source))
        XCTAssertTrue(
          identifiers.isDisjoint(with: forbidden), "v1 current reference in \(file.path)")
        XCTAssertFalse(
          identifiers.contains { $0.hasPrefix(privateHandlePrefix) },
          "private adapter handle reference in \(file.path)"
        )
      }
    }

    let noPrivateHandleFiles = [
      "Sources/AgentDeckCore/Protocol/RuntimeV2Types.swift",
      "Sources/AgentDeckCore/Protocol/RuntimeV2StreamTypes.swift",
      "Sources/AgentDeckCore/Protocol/RuntimeV2WireCodec.swift",
      "protocol/agentdeck/runtime-protocol.schema.json",
      "protocol/agentdeck/fixtures/runtime-v5-wire.jsonl",
    ]
    for relativePath in noPrivateHandleFiles {
      let source = try String(
        contentsOf: repositoryRoot.appendingPathComponent(relativePath),
        encoding: .utf8
      )
      XCTAssertFalse(source.contains("adapterStateKey"), relativePath)
    }

    for file in try swiftFiles(
      below: repositoryRoot.appendingPathComponent("Sources/AgentDeckCore")
    ) {
      let source = try String(contentsOf: file, encoding: .utf8)
      let importedModules = Set(importedModuleNames(source))
      XCTAssertTrue(
        importedModules.isDisjoint(with: ["AppKit", "UIKit", "Network", "CryptoKit"]),
        "platform/network/crypto import in shared Core: \(file.path)"
      )
    }

    let legalImportForms = """
      import AppKit
      @preconcurrency import Network
      internal import UIKit // access-level import
      import class CryptoKit.SHA256
      """
    XCTAssertEqual(
      Set(importedModuleNames(legalImportForms)),
      ["AppKit", "Network", "UIKit", "CryptoKit"]
    )
  }

  // MARK: - Helpers

  private enum SizedEnvelopeKind: CaseIterable {
    case request
    case reply
    case stream
  }

  private struct Fixture {
    let name: String
    let wireType: String
    let value: Any
  }

  func testAssembledTransferDecodeAllowsLargeReplyButRejectsChannelMismatch() throws {
    let message = String(repeating: "x", count: RuntimeWireCodec.maxJSONFrameBytes)
    let envelope = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "large-transfer-reply"),
      body: .reply(
        .failure(
          RuntimeFailureV1(
            code: "remote.large",
            message: message
          )
        )
      )
    )
    let encoded = try JSONEncoder().encode(envelope)
    XCTAssertGreaterThan(encoded.count, RuntimeWireCodec.maxJSONFrameBytes)
    XCTAssertThrowsError(try RuntimeWireCodec.decodeEnvelope(encoded)) { error in
      XCTAssertEqual(error as? RuntimeV2WireError, .frameTooLarge)
    }

    let decoded = try RuntimeWireCodec.decodeAssembledTransferEnvelope(
      encoded,
      channel: .reply
    )
    guard case .reply(.failure(let failure)) = decoded.body else {
      return XCTFail("assembled reply must preserve its typed payload")
    }
    XCTAssertEqual(failure.message.count, message.count)
    XCTAssertThrowsError(
      try RuntimeWireCodec.decodeAssembledTransferEnvelope(encoded, channel: .stream)
    ) { error in
      XCTAssertEqual(error as? RuntimeV2WireError, .invalidTransferCarrier)
    }
  }

  private func requireV2Codec(_: RuntimeV2WireCodec.Type) {}

  private func makeSizedEnvelope(
    kind: SizedEnvelopeKind,
    byteCount: Int
  ) throws -> RuntimeEnvelopeV2 {
    func envelope(text: String) throws -> RuntimeEnvelopeV2 {
      switch kind {
      case .request:
        return RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "sized-request"),
          body: .request(
            .start(
              agentKind: .codex,
              idempotencyKey: RuntimeIdempotencyKey(rawValue: "sized-key"),
              cwd: text,
              title: nil
            )
          )
        )
      case .reply:
        return RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "sized-reply"),
          body: .reply(
            .failure(RuntimeFailureV1(code: "sized", message: text))
          )
        )
      case .stream:
        return RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "sized-stream"),
          body: .stream(
            .event(
              try RuntimeEventV2(
                conversationID: RuntimeConversationID(rawValue: "sized-conversation"),
                eventID: RuntimeEventID(rawValue: "sized-event"),
                eventSeq: 1,
                commandID: nil,
                itemID: nil,
                entityID: nil,
                body: .error(
                  RuntimeFailureV1(code: "sized", message: text)
                )
              )
            )
          )
        )
      }
    }
    let empty = try envelope(text: "")
    let overhead = try JSONEncoder().encode(empty).count
    return try envelope(text: String(repeating: "x", count: byteCount - overhead))
  }

  private func compactCarrier(
    messageID: String = "compact-message",
    channel: RuntimeTransferChannelV2 = .stream,
    transferID: String = "compact-profile",
    partIndex: UInt32 = 0,
    partCount: UInt32,
    totalBytes: UInt64,
    hash: Data,
    part: Data
  ) throws -> RuntimeTransferCarrierV2 {
    try RuntimeTransferCarrierV2(
      messageID: RuntimeMessageID(rawValue: messageID),
      channel: channel,
      transferID: RuntimeTransferID(rawValue: transferID),
      partIndex: partIndex,
      partCount: partCount,
      totalSHA256: hash,
      totalBytes: totalBytes,
      part: part
    )
  }

  private struct CompactLayout {
    let partIndex: Int
    let partCount: Int
    let totalBytes: Int
    let partLengthField: Int
    let partStart: Int
    let partLength: Int
  }

  private func compactLayout(_ data: Data) throws -> CompactLayout {
    guard data.count >= 10 else { throw RuntimeV2WireError.invalidTransferCarrier }
    let messageLength = (Int(data[8]) << 8) | Int(data[9])
    let transferLengthOffset = 10 + messageLength
    guard transferLengthOffset + 2 <= data.count else {
      throw RuntimeV2WireError.invalidTransferCarrier
    }
    let transferLength =
      (Int(data[transferLengthOffset]) << 8)
      | Int(data[transferLengthOffset + 1])
    let partIndex = transferLengthOffset + 2 + transferLength
    let partCount = partIndex + 4
    let totalBytes = partCount + 4 + 32
    let partLengthField = totalBytes + 8
    guard partLengthField + 4 <= data.count else {
      throw RuntimeV2WireError.invalidTransferCarrier
    }
    let partLength = Int(readUInt32(from: data, at: partLengthField))
    let partStart = partLengthField + 4
    guard partStart + partLength == data.count else {
      throw RuntimeV2WireError.invalidTransferCarrier
    }
    return CompactLayout(
      partIndex: partIndex,
      partCount: partCount,
      totalBytes: totalBytes,
      partLengthField: partLengthField,
      partStart: partStart,
      partLength: partLength
    )
  }

  private func readUInt32(from data: Data, at offset: Int) -> UInt32 {
    data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
  }

  private func writeUInt32(_ value: UInt32, to data: inout Data, at offset: Int) {
    data.replaceSubrange(
      offset..<(offset + 4),
      with: [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
      ]
    )
  }

  private func writeUInt64(_ value: UInt64, to data: inout Data, at offset: Int) {
    data.replaceSubrange(
      offset..<(offset + 8),
      with: (0..<8).map { shift in
        UInt8(truncatingIfNeeded: value >> UInt64((7 - shift) * 8))
      }
    )
  }

  private func fixture(named name: String) throws -> Fixture {
    try XCTUnwrap(loadFixtures().first { $0.name == name })
  }

  private func loadFixtures() throws -> [Fixture] {
    let data = try Data(
      contentsOf:
        repositoryRoot
        .appendingPathComponent("protocol/agentdeck/fixtures/runtime-v5-wire.jsonl"))
    let text = try XCTUnwrap(String(data: data, encoding: .utf8))
    return try text.split(separator: "\n").map { line in
      let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
      )
      return Fixture(
        name: try XCTUnwrap(object["case"] as? String),
        wireType: try XCTUnwrap(object["wireType"] as? String),
        value: try XCTUnwrap(object["value"])
      )
    }
  }

  private var repositoryRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  private func swiftFiles(below root: URL) throws -> [URL] {
    let enumerator = try XCTUnwrap(
      FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey],
        options: [.skipsHiddenFiles]
      )
    )
    return enumerator.compactMap { item in
      guard let url = item as? URL, url.pathExtension == "swift" else { return nil }
      return url
    }
  }

  private func sourceIdentifierTokens(_ source: String) -> [String] {
    let regex = try! NSRegularExpression(pattern: #"[A-Za-z_][A-Za-z0-9_]*"#)
    let range = NSRange(source.startIndex..<source.endIndex, in: source)
    return regex.matches(in: source, range: range).compactMap { match in
      guard let swiftRange = Range(match.range, in: source) else { return nil }
      return String(source[swiftRange])
    }
  }

  private func importedModuleNames(_ source: String) -> [String] {
    let pattern =
      #"(?m)^\s*(?:(?:@[A-Za-z_][A-Za-z0-9_]*(?:\([^\n)]*\))?|public|internal|package|private|fileprivate)\s+)*import\s+(?:(?:typealias|struct|class|enum|protocol|let|var|func|operator)\s+)?([A-Za-z_][A-Za-z0-9_]*)"#
    let regex = try! NSRegularExpression(pattern: pattern)
    let range = NSRange(source.startIndex..<source.endIndex, in: source)
    return regex.matches(in: source, range: range).compactMap { match in
      guard let swiftRange = Range(match.range(at: 1), in: source) else { return nil }
      return String(source[swiftRange])
    }
  }

  private func jsonData(_ value: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
  }

  private func objectValue(_ value: Any) throws -> [String: Any] {
    try XCTUnwrap(value as? [String: Any])
  }

  private func dictionary(_ value: Any?) throws -> [String: Any] {
    try XCTUnwrap(value as? [String: Any])
  }

  private func assertJSONSemanticallyEqual(
    _ lhs: Data,
    _ rhs: Data,
    caseName: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let left = try JSONSerialization.jsonObject(with: lhs) as? NSObject
    let right = try JSONSerialization.jsonObject(with: rhs) as? NSObject
    XCTAssertEqual(left, right, "fixture \(caseName)", file: file, line: line)
  }
}

extension Data {
  fileprivate init(hex: String) throws {
    guard hex.count.isMultiple(of: 2) else {
      throw RuntimeV2WireError.invalidTransferCarrier
    }
    self.init()
    reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else {
        throw RuntimeV2WireError.invalidTransferCarrier
      }
      append(byte)
      index = next
    }
  }
}
