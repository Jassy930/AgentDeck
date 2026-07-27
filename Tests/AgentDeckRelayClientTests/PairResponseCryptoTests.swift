import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PairResponseCryptoTests: XCTestCase {
  func testPairResponseCodecInfoAndTBSMatchRustGoldenVector() throws {
    let vector = try pairingVector()
    let canonical = try pairingHex(vector, "pairResponseCanonicalHex")
    let response = try PairResponseCanonicalCodec.decode(canonical)

    XCTAssertEqual(try PairResponseCanonicalCodec.encode(response), canonical)
    XCTAssertEqual(
      try response.info.canonicalBytes(),
      try hpkeInfoVector("pairResponseInfoHex")
    )
    XCTAssertEqual(CanonicalCodec.sha256(canonical), try pairingHex(vector, "pairResponseHashHex"))
    XCTAssertEqual(
      try PairResponseCrypto.responseSignatureTBS(
        response,
        context: pairingCryptoContext(.pairResponse),
        signingKeyFingerprint: Data(repeating: 0xA4, count: 32),
        signingKeyGeneration: 2,
        signingCredentialSHA256: Data(repeating: 0xA5, count: 32)
      ),
      try pairingHex(vector, "pairResponseTbsHex")
    )
  }

  func testPairPendingAndReceiptCodecsAndTBSMatchRustGoldenVector() throws {
    let vector = try pairingVector()
    let pendingBytes = try pairingHex(vector, "pairPendingCanonicalHex")
    let pending = try PairPendingCanonicalCodec.decode(pendingBytes)
    XCTAssertEqual(try PairPendingCanonicalCodec.encode(pending), pendingBytes)
    XCTAssertEqual(
      try PairResponseCrypto.pairPendingSignatureTBS(
        pending,
        info: try pairingRequestInfo(),
        context: pairingCryptoContext(.pairPending),
        signingKeyFingerprint: Data(repeating: 0xA4, count: 32),
        signingKeyGeneration: 2,
        signingCredentialSHA256: Data(repeating: 0xA5, count: 32)
      ),
      try pairingHex(vector, "pairPendingTbsHex")
    )

    let receiptBytes = try pairingHex(vector, "pairResponseReceivedCanonicalHex")
    let receipt = try PairResponseReceivedCanonicalCodec.decode(receiptBytes)
    XCTAssertEqual(try PairResponseReceivedCanonicalCodec.encode(receipt), receiptBytes)
    XCTAssertEqual(
      try PairResponseCrypto.responseReceivedTBS(
        receipt,
        info: try pairingResponseInfo(),
        context: pairingCryptoContext(.pairResponseReceived),
        deviceSignFingerprint: Data(repeating: 0xB5, count: 32)
      ),
      try pairingHex(vector, "pairResponseReceivedTbsHex")
    )
  }

  func testPairResponseCodecsRejectTrailingTruncatedAndWrongDomains() throws {
    let canonical = try pairingHex(try pairingVector(), "pairResponseCanonicalHex")
    XCTAssertThrowsError(try PairResponseCanonicalCodec.decode(canonical + Data([0])))
    XCTAssertThrowsError(try PairResponseCanonicalCodec.decode(canonical.dropLastData()))

    let pending = try pairingHex(try pairingVector(), "pairPendingCanonicalHex")
    XCTAssertThrowsError(try PairPendingCanonicalCodec.decode(pending + Data([0])))
    XCTAssertThrowsError(try PairResponseReceivedCanonicalCodec.decode(pending))

    let receipt = try pairingHex(try pairingVector(), "pairResponseReceivedCanonicalHex")
    XCTAssertThrowsError(try PairResponseReceivedCanonicalCodec.decode(receipt.dropLastData()))
    XCTAssertThrowsError(
      try PairResponseCanonicalCodec.decode(
        Data(repeating: 1, count: CanonicalPairResponseV1.maximumCanonicalBytes + 1)
      )
    )
  }
}

private func pairingRequestInfo() throws -> PairRequestInfoV1 {
  try PairRequestInfoV1(
    relayServerID: Data(repeating: 0x88, count: 16),
    pairRoute: Data(repeating: 0x55, count: 16),
    inviteHash: Data(repeating: 0x01, count: 32),
    expiryMilliseconds: 1_700_000_000_000
  )
}

private func pairingResponseInfo() throws -> PairResponseInfoV1 {
  try PairResponseInfoV1(
    relayServerID: Data(repeating: 0x88, count: 16),
    pairRoute: Data(repeating: 0x55, count: 16),
    inviteHash: Data(repeating: 0x01, count: 32),
    expiryMilliseconds: 1_700_000_000_000,
    requestHash: Data(repeating: 0x02, count: 32),
    machineRoute: Data(repeating: 0x11, count: 16),
    deviceRoute: Data(repeating: 0x22, count: 16),
    grantSerial: 9,
    rootTrustEpoch: 3
  )
}

private func pairingCryptoContext(_ kind: OuterFrameKind) -> OuterContextV1 {
  OuterContextV1(
    frameKind: kind,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: nil,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: 0,
    pairRoute: Data(repeating: 0x55, count: 16)
  )
}

private func pairingVector() throws -> [String: Any] {
  try cryptoVectorSection("pairing_canonical")
}

private func hpkeInfoVector(_ key: String) throws -> Data {
  try pairingHex(try cryptoVectorSection("hpke_infos"), key)
}

private func cryptoVectorSection(_ key: String) throws -> [String: Any] {
  let url = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("protocol/agentdeck/crypto-vectors-v1.json")
  let root = try XCTUnwrap(
    try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
  )
  return try XCTUnwrap(root[key] as? [String: Any])
}

private func pairingHex(_ vector: [String: Any], _ key: String) throws -> Data {
  let value = try XCTUnwrap(vector[key] as? String)
  guard value.count.isMultiple(of: 2) else { throw PairResponseCryptoTestError.invalidHex }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let end = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<end], radix: 16) else {
      throw PairResponseCryptoTestError.invalidHex
    }
    output.append(byte)
    index = end
  }
  return output
}

private enum PairResponseCryptoTestError: Error { case invalidHex }

extension Data {
  fileprivate func dropLastData() -> Data { Data(dropLast()) }
}
