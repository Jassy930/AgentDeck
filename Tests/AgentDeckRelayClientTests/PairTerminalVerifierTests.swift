import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PairTerminalVerifierTests: XCTestCase {
  func testRustGoldenCanonicalTBSHPKEAndSignatureOpenInSwift() throws {
    let vector = try loadPairTerminalVector()
    let canonical = try pairTerminalData("canonicalHex", vector)
    let terminal = try PairTerminalCanonicalCodec.decode(canonical)
    XCTAssertEqual(terminal.machineRoute, Data(repeating: 0x11, count: 16))
    XCTAssertEqual(terminal.requestHash, Data(repeating: 0x02, count: 32))
    XCTAssertEqual(terminal.outcome, .canceled)
    XCTAssertEqual(terminal.signature, try pairTerminalData("signatureHex", vector))
    XCTAssertEqual(try PairTerminalCanonicalCodec.encode(terminal), canonical)
    XCTAssertEqual(
      try PairTerminalCanonicalCodec.unsignedCanonicalBytes(terminal),
      try pairTerminalData("unsignedCanonicalHex", vector)
    )
    XCTAssertEqual(
      CanonicalCodec.sha256(canonical),
      try pairTerminalData("sha256Hex", vector)
    )

    let info = try goldenInfo()
    XCTAssertEqual(try info.canonicalBytes(), try pairTerminalData("infoHex", vector))
    let context = goldenContext(info: info)
    XCTAssertEqual(
      try CanonicalCodec.encodeAAD(context),
      try pairTerminalData("aadHex", vector)
    )

    let certificate = try SignedCertificateCanonicalCodec.decode(
      pairTerminalData("dataCertificateCanonicalHex", vector)
    )
    let signingKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: pairTerminalData("dataSigningSeedHex", vector)
    )
    let verifiedCertificate = VerifiedMachineDataCertificate(
      certificate: certificate,
      signingKey: signingKey.publicKey
    )
    XCTAssertEqual(
      try PairTerminalVerifier.signatureTBS(
        terminal,
        info: info,
        context: context,
        verifiedCertificate: verifiedCertificate
      ),
      try pairTerminalData("tbsHex", vector)
    )

    let envelopeCanonical = try pairTerminalData("envelopeCanonicalHex", vector)
    let envelope = try PairTerminalEnvelopeCodec.decode(envelopeCanonical)
    XCTAssertEqual(envelope.encapsulatedKey, try pairTerminalData("envelopeEncHex", vector))
    XCTAssertEqual(envelope.ciphertext, try pairTerminalData("envelopeCiphertextHex", vector))
    XCTAssertEqual(try PairTerminalEnvelopeCodec.encode(envelope), envelopeCanonical)
    let recipient = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: pairTerminalData("recipientPrivHex", vector)
    )
    let opened = try PairTerminalVerifier.open(
      canonicalEnvelope: envelopeCanonical,
      recipientDeviceHPKEPrivateKey: recipient,
      info: info,
      context: context,
      expected: PairTerminalExpectedV1(
        machineRoute: terminal.machineRoute,
        requestHash: terminal.requestHash
      ),
      verifiedCertificate: verifiedCertificate
    )
    XCTAssertEqual(opened, terminal)
  }

  func testPairTerminalRejectsWrongIdentityRouteSignerAndCiphertext() throws {
    let vector = try loadPairTerminalVector()
    let info = try goldenInfo()
    let context = goldenContext(info: info)
    let certificate = try SignedCertificateCanonicalCodec.decode(
      pairTerminalData("dataCertificateCanonicalHex", vector)
    )
    let signingKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: pairTerminalData("dataSigningSeedHex", vector)
    )
    let verifiedCertificate = VerifiedMachineDataCertificate(
      certificate: certificate,
      signingKey: signingKey.publicKey
    )
    let recipient = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: pairTerminalData("recipientPrivHex", vector)
    )
    let canonicalEnvelope = try pairTerminalData("envelopeCanonicalHex", vector)

    XCTAssertThrowsError(
      try PairTerminalVerifier.open(
        canonicalEnvelope: canonicalEnvelope,
        recipientDeviceHPKEPrivateKey: recipient,
        info: info,
        context: context,
        expected: PairTerminalExpectedV1(
          machineRoute: Data(repeating: 0x12, count: 16),
          requestHash: Data(repeating: 0x02, count: 32)
        ),
        verifiedCertificate: verifiedCertificate
      )
    ) { error in
      XCTAssertEqual(error as? PairTerminalVerifierError, .identityMismatch)
    }

    var wrongContext = context
    wrongContext.pairRoute = Data(repeating: 0x56, count: 16)
    XCTAssertThrowsError(
      try PairTerminalVerifier.open(
        canonicalEnvelope: canonicalEnvelope,
        recipientDeviceHPKEPrivateKey: recipient,
        info: info,
        context: wrongContext,
        expected: PairTerminalExpectedV1(
          machineRoute: Data(repeating: 0x11, count: 16),
          requestHash: Data(repeating: 0x02, count: 32)
        ),
        verifiedCertificate: verifiedCertificate
      )
    ) { error in
      XCTAssertEqual(error as? PairTerminalVerifierError, .invalidContext)
    }

    let wrongKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x73, count: 32)
    )
    XCTAssertThrowsError(
      try PairTerminalVerifier.open(
        canonicalEnvelope: canonicalEnvelope,
        recipientDeviceHPKEPrivateKey: recipient,
        info: info,
        context: context,
        expected: PairTerminalExpectedV1(
          machineRoute: Data(repeating: 0x11, count: 16),
          requestHash: Data(repeating: 0x02, count: 32)
        ),
        verifiedCertificate: VerifiedMachineDataCertificate(
          certificate: certificate,
          signingKey: wrongKey.publicKey
        )
      )
    ) { error in
      XCTAssertEqual(error as? PairTerminalVerifierError, .invalidSigner)
    }

    let envelope = try PairTerminalEnvelopeCodec.decode(canonicalEnvelope)
    var ciphertext = envelope.ciphertext
    ciphertext[0] ^= 1
    let tampered = try PairTerminalEnvelopeCodec.encode(
      CanonicalPairingControlEnvelopeV1(
        formatVersion: envelope.formatVersion,
        encapsulatedKey: envelope.encapsulatedKey,
        ciphertext: ciphertext
      )
    )
    XCTAssertThrowsError(
      try PairTerminalVerifier.open(
        canonicalEnvelope: tampered,
        recipientDeviceHPKEPrivateKey: recipient,
        info: info,
        context: context,
        expected: PairTerminalExpectedV1(
          machineRoute: Data(repeating: 0x11, count: 16),
          requestHash: Data(repeating: 0x02, count: 32)
        ),
        verifiedCertificate: verifiedCertificate
      )
    ) { error in
      XCTAssertEqual(error as? PairTerminalVerifierError, .hpkeOpenFailed)
    }
  }

  func testPairTerminalCodecRejectsUnknownOutcomeTrailingZeroAndOversize() throws {
    let vector = try loadPairTerminalVector()
    let canonical = try pairTerminalData("canonicalHex", vector)
    var trailing = canonical
    trailing.append(0)
    XCTAssertThrowsError(try PairTerminalCanonicalCodec.decode(trailing))

    var unsigned = try pairTerminalData("unsignedCanonicalHex", vector)
    unsigned[unsigned.index(before: unsigned.endIndex)] = 0xFF
    var malformed = Data("AgentDeck/PairTerminalV1\0".utf8)
    appendPairTerminalBytes(unsigned, to: &malformed)
    appendPairTerminalBytes(Data(repeating: 1, count: 64), to: &malformed)
    XCTAssertThrowsError(try PairTerminalCanonicalCodec.decode(malformed))
    XCTAssertThrowsError(
      try PairTerminalCanonicalCodec.decode(
        Data(repeating: 1, count: PairTerminalCanonicalCodec.maximumCanonicalBytes + 1)
      )
    ) { error in
      XCTAssertEqual(error as? PairTerminalVerifierError, .sizeLimit)
    }

    let expired = try CanonicalPairTerminalV1(
      machineRoute: Data(repeating: 0x11, count: 16),
      requestHash: Data(repeating: 0x22, count: 32),
      outcome: .expired,
      signature: Data(repeating: 0x33, count: 64)
    )
    XCTAssertEqual(
      try PairTerminalCanonicalCodec.decode(PairTerminalCanonicalCodec.encode(expired)),
      expired
    )
  }
}

private func goldenInfo() throws -> PairRequestInfoV1 {
  try PairRequestInfoV1(
    relayServerID: Data(repeating: 0x88, count: 16),
    pairRoute: Data(repeating: 0x55, count: 16),
    inviteHash: Data(repeating: 0x01, count: 32),
    expiryMilliseconds: 1_700_000_000_000
  )
}

private func goldenContext(info: PairRequestInfoV1) -> OuterContextV1 {
  OuterContextV1(
    frameKind: .pairTerminal,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: info.e2eeFormatVersion,
    machineRoute: nil,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    streamSeq: nil,
    messageKeyEpoch: 0,
    pairRoute: info.pairRoute
  )
}

private func loadPairTerminalVector() throws -> [String: Any] {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let data = try Data(
    contentsOf: root.appendingPathComponent("protocol/agentdeck/crypto-vectors-v1.json")
  )
  let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
  return try XCTUnwrap(object["pair_terminal"] as? [String: Any])
}

private func pairTerminalData(_ key: String, _ vector: [String: Any]) throws -> Data {
  try decodePairTerminalHex(try XCTUnwrap(vector[key] as? String))
}

private func decodePairTerminalHex(_ value: String) throws -> Data {
  guard value.count.isMultiple(of: 2) else {
    throw PairTerminalTestError.invalidHex
  }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw PairTerminalTestError.invalidHex
    }
    output.append(byte)
    index = next
  }
  return output
}

private func appendPairTerminalBytes(_ value: Data, to output: inout Data) {
  var count = UInt32(value.count).bigEndian
  Swift.withUnsafeBytes(of: &count) { output.append(contentsOf: $0) }
  output.append(value)
}

private enum PairTerminalTestError: Error {
  case invalidHex
}
