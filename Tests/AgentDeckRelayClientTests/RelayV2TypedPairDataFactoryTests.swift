import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class RelayV2TypedPairDataFactoryTests: XCTestCase {
  func testPairDataFactorySurfaceAcceptsOnlyOpaqueCarrierTypes() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("Sources/AgentDeckRelayClient/Wire/RelayV2Types.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)
    let expression = try NSRegularExpression(
      pattern: #"(?m)^\s*static func pairData\s*\(([^)]*)\)"#
    )
    let matches = expression.matches(
      in: source,
      range: NSRange(source.startIndex..<source.endIndex, in: source)
    )
    let signatures = matches.compactMap { match -> String? in
      guard let range = Range(match.range(at: 1), in: source) else { return nil }
      return source[range].trimmingCharacters(in: .whitespacesAndNewlines)
    }

    XCTAssertEqual(
      Set(signatures),
      [
        "_ carrier: OpaquePairRequestCarrier",
        "_ carrier: OpaquePairResponseReceivedCarrier",
      ]
    )
    XCTAssertFalse(signatures.contains { $0.contains("Data") })
  }

  func testPairRequestFactoryPreservesValidatedCarrierExactly() throws {
    let pairRoute = Data(repeating: 0x55, count: 16)
    let request = try PairRequestV1(
      encapsulatedKey: Data(repeating: 0x91, count: 32),
      ciphertext: Data(repeating: 0x92, count: 48),
      deviceProofSignature: Data(repeating: 0x93, count: 64)
    )
    let canonical = try PairRequestCanonicalCodec.encode(request)
    let carrier = try OpaquePairRequestCarrier(
      pairRoute: pairRoute,
      canonicalBytes: canonical,
      requestHash: CanonicalCodec.sha256(canonical)
    )

    let decoded = try RelayWireCodecV2.decode(
      RelayWireCodecV2.encode(RelayV2OutboundFrame.pairData(carrier))
    )

    XCTAssertEqual(
      decoded.body,
      .pairData(pairRoute: pairRoute, sealedBlob: canonical)
    )
  }

  func testPairResponseReceivedFactoryPreservesValidatedCarrierExactly() throws {
    let pairRoute = Data(repeating: 0x66, count: 16)
    let canonical = try PairTerminalEnvelopeCodec.encode(
      CanonicalPairingControlEnvelopeV1(
        formatVersion: 1,
        encapsulatedKey: Data(repeating: 0xA1, count: 32),
        ciphertext: Data(repeating: 0xA2, count: 64)
      )
    )
    let carrier = try OpaquePairResponseReceivedCarrier(
      pairRoute: pairRoute,
      canonicalBytes: canonical
    )

    let decoded = try RelayWireCodecV2.decode(
      RelayWireCodecV2.encode(RelayV2OutboundFrame.pairData(carrier))
    )

    XCTAssertEqual(
      decoded.body,
      .pairData(pairRoute: pairRoute, sealedBlob: canonical)
    )
  }
}
