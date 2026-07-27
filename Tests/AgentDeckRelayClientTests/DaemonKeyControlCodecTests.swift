import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class DaemonKeyControlCodecTests: XCTestCase {
  func testRustGoldenUpdateSetEpochBarrierAndStreamBindingHashesMatch() throws {
    let updateControl = DaemonKeyControlV1.updateSet(try updateSet())
    let updateBytes = try DaemonKeyControlCanonicalCodec.encode(updateControl)
    XCTAssertEqual(
      CanonicalCodec.sha256(updateBytes).keyControlHex,
      "cfbe703b14e67da6a820fbcca39832a6f7864a668276c6158248b89087441c3b"
    )
    XCTAssertEqual(try DaemonKeyControlCanonicalCodec.decode(updateBytes), updateControl)

    let barrierControl = DaemonKeyControlV1.epochBarrier(
      try DeviceEpochBarrierV1(
        streamRoute: streamRoute(7),
        streamGeneration: Data(repeating: 0x71, count: 16),
        streamCursor: .at(40),
        innerCursor: .conversation(id: "conversation-key-control", cursor: .at(39)),
        oldEpoch: 3,
        newEpoch: 4,
        keyDirectoryRevision: 12
      ))
    let barrierBytes = try DaemonKeyControlCanonicalCodec.encode(barrierControl)
    XCTAssertEqual(
      CanonicalCodec.sha256(barrierBytes).keyControlHex,
      "73f848b39e0845c78c1081ed437f5892dca6a52e9865505c886875f14e1cd297"
    )
    XCTAssertEqual(try DaemonKeyControlCanonicalCodec.decode(barrierBytes), barrierControl)

    let bindingControl = DaemonKeyControlV1.streamBinding(try catalogBinding())
    let bindingBytes = try DaemonKeyControlCanonicalCodec.encode(bindingControl)
    XCTAssertEqual(
      CanonicalCodec.sha256(bindingBytes).keyControlHex,
      "0c9e57159872adb26a7c4c40dcb24de54ee666c8f0e7ea1db7546d16acb423cd"
    )
    XCTAssertEqual(try DaemonKeyControlCanonicalCodec.decode(bindingBytes), bindingControl)
  }

  func testAllFiveTagsRoundTripAndStrictDecoderRejectsDrift() throws {
    let authority = try keyControlAuthority()
    let values: [DaemonKeyControlV1] = [
      .updateSet(try updateSet()),
      .epochBarrier(
        try DeviceEpochBarrierV1(
          streamRoute: streamRoute(7),
          streamGeneration: Data(repeating: 0x71, count: 16),
          streamCursor: .at(40),
          innerCursor: .catalog(.at(39)),
          oldEpoch: 3,
          newEpoch: 4,
          keyDirectoryRevision: 12
        )),
      .directoryCurrent(
        try DaemonDirectoryCurrentV1(
          authority: authority,
          currentKeyDirectoryRevision: 12,
          requestedKeyDirectoryRevision: 13
        )),
      .streamBinding(try catalogBinding()),
      .directoryRevisionAdvance(
        try DaemonDirectoryRevisionAdvanceV1(fromRevision: 12, toRevision: 13)
      ),
    ]
    let tagOffset = Data("AgentDeck/KeyControlV1\0".utf8).count

    for (expectedTag, value) in values.enumerated() {
      let canonical = try DaemonKeyControlCanonicalCodec.encode(value)
      XCTAssertEqual(canonical[tagOffset], UInt8(expectedTag))
      XCTAssertEqual(try DaemonKeyControlCanonicalCodec.decode(canonical), value)

      var trailing = canonical
      trailing.append(0)
      XCTAssertThrowsError(try DaemonKeyControlCanonicalCodec.decode(trailing))

      var wrongVersion = canonical
      wrongVersion[tagOffset + 1] = 0
      wrongVersion[tagOffset + 2] = 2
      XCTAssertThrowsError(try DaemonKeyControlCanonicalCodec.decode(wrongVersion))
    }

    var unknownTag = try DaemonKeyControlCanonicalCodec.encode(values[0])
    unknownTag[tagOffset] = 0xFF
    XCTAssertThrowsError(try DaemonKeyControlCanonicalCodec.decode(unknownTag))
    XCTAssertThrowsError(
      try DaemonKeyControlCanonicalCodec.decode(
        Data(repeating: 0, count: DaemonKeyControlCanonicalCodec.maximumCanonicalBytes + 1)
      )
    )
  }

  func testDirectoryAdvanceBindsOnlyAuthenticatedCatalogOuterAxes() throws {
    let advance = try DaemonDirectoryRevisionAdvanceV1(fromRevision: 12, toRevision: 13)
    let context = OuterContextV1(
      frameKind: .catalogPublish,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: Data(repeating: 0x11, count: 16),
      deviceRoute: nil,
      streamRoute: Data(repeating: 0x21, count: 16),
      requestRoute: nil,
      streamGeneration: Data(repeating: 0x22, count: 16),
      streamCursor: .at(40),
      streamSeq: 41,
      messageKeyEpoch: 5
    )
    let proof = try advance.binding(to: context)
    XCTAssertEqual(proof.streamRoute, context.streamRoute)
    XCTAssertEqual(proof.streamGeneration, context.streamGeneration)
    XCTAssertEqual(proof.streamSequence, context.streamSeq)
    XCTAssertEqual(proof.canonicalBytes, advance.canonicalBytes)

    var wrongFamily = context
    wrongFamily.frameKind = .conversationPublish
    XCTAssertThrowsError(try advance.binding(to: wrongFamily))
    var missingGeneration = context
    missingGeneration.streamGeneration = nil
    XCTAssertThrowsError(try advance.binding(to: missingGeneration))
  }
}

private func updateSet() throws -> CanonicalKeyUpdateSetV1 {
  let update = try CanonicalKeyUpdateV1(
    keyDirectoryRevision: 12,
    keyID: KeyIDV1(purpose: .catalog, epoch: 4),
    deviceRoute: Data(repeating: 0x22, count: 16),
    streamRoute: nil,
    enc: Data(repeating: 0x61, count: 32),
    wrappedKey: Data(repeating: 0x62, count: 48),
    signature: Data(repeating: 0x63, count: 64)
  )
  return try CanonicalKeyUpdateSetV1(
    keyDirectoryRevision: 12,
    deviceRoute: Data(repeating: 0x22, count: 16),
    updates: [update]
  )
}

private func keyControlAuthority() throws -> DeviceKeyControlAuthorityV1 {
  try DeviceKeyControlAuthorityV1(
    machineRoute: Data(repeating: 0x11, count: 16),
    deviceRoute: Data(repeating: 0x12, count: 16),
    grantSerial: 7,
    rootTrustEpoch: 3
  )
}

private func catalogBinding() throws -> DaemonStreamBindingV1 {
  try DaemonStreamBindingV1(
    authority: keyControlAuthority(),
    streamRoute: Data(repeating: 0x21, count: 16),
    streamGeneration: Data(repeating: 0x22, count: 16),
    streamCursor: .at(41),
    innerCursor: .catalog(cursor: .at(19)),
    keyDirectoryRevision: 9,
    keyID: KeyIDV1(purpose: .catalog, epoch: 5)
  )
}

private func streamRoute(_ index: UInt16) -> Data {
  var value = Data(repeating: 0x31, count: 16)
  value[14] = UInt8(index >> 8)
  value[15] = UInt8(index & 0xFF)
  return value
}

extension Data {
  fileprivate var keyControlHex: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
