import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PairRequestCryptoTests: XCTestCase {
  private let nowMilliseconds: UInt64 = 1_700_000_000_000

  func testRustGoldenRequestCanonicalHashAndTBSMatchSwift() throws {
    let vector = try loadPairingCanonicalVector()
    let request = try PairRequestV1(
      formatVersion: 1,
      encapsulatedKey: Data(repeating: 0x91, count: 32),
      ciphertext: Data(repeating: 0x92, count: 48),
      deviceProofSignature: Data(repeating: 0x93, count: 64)
    )
    let canonical = try PairRequestCanonicalCodec.encode(request)

    XCTAssertEqual(canonical, try pairingVectorData("pairRequestCanonicalHex", vector))
    XCTAssertEqual(
      CanonicalCodec.sha256(canonical),
      try pairingVectorData("pairRequestHashHex", vector)
    )
    XCTAssertEqual(try PairRequestCanonicalCodec.decode(canonical), request)

    let info = try PairRequestInfoV1(
      relayServerID: Data(repeating: 0x88, count: 16),
      pairRoute: Data(repeating: 0x55, count: 16),
      inviteHash: Data(repeating: 0x01, count: 32),
      expiryMilliseconds: 1_700_000_000_000
    )
    let context = exactPairRequestContext(info: info)
    XCTAssertEqual(
      try PairRequestCrypto.signatureTBS(
        request,
        info: info,
        context: context,
        deviceSignFingerprint: Data(repeating: 0x94, count: 32)
      ),
      try pairingVectorData("pairRequestTbsHex", vector)
    )
  }

  func testInviteCanonicalURIAndTTLBoundaryAreStrict() throws {
    let invite = try makeInvite()
    let canonical = try PairInviteCanonicalCodec.encode(invite)
    XCTAssertEqual(try PairInviteCanonicalCodec.decode(canonical), invite)

    let uri = try invite.encodeURI(nowMilliseconds: nowMilliseconds)
    XCTAssertTrue(uri.hasPrefix("agentdeck-pair:v1:"))
    XCTAssertFalse(uri.contains("="))
    XCTAssertEqual(
      try PairInviteV1.decodeURI(uri, nowMilliseconds: nowMilliseconds),
      invite
    )

    XCTAssertThrowsError(
      try PairInviteV1.decodeURI(uri, nowMilliseconds: invite.expiresAtMilliseconds)
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .expired)
    }
    let tooFar = try makeInvite(expiresAtMilliseconds: nowMilliseconds + 300_001)
    XCTAssertThrowsError(try tooFar.validate(nowMilliseconds: nowMilliseconds)) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .expiryOutOfBounds)
    }
    let expired = try makeInvite(expiresAtMilliseconds: nowMilliseconds - 1)
    XCTAssertThrowsError(try expired.validate(nowMilliseconds: nowMilliseconds)) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .expired)
    }

    XCTAssertThrowsError(
      try PairInviteV1.decodeURI(uri + "=", nowMilliseconds: nowMilliseconds)
    )
    XCTAssertThrowsError(
      try PairInviteV1.decodeURI(
        String(repeating: "a", count: PairInviteCanonicalCodec.maximumURIBytes + 1),
        nowMilliseconds: nowMilliseconds
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .sizeLimit("pair invite URI"))
    }
  }

  func testInviteRejectsURLDisplayNameFingerprintAndCertificateShape() throws {
    let invalidURLs = [
      "ws://relay.example.test/",
      "WSS://relay.example.test/",
      "wss://relay.example.test",
      "wss://user@relay.example.test/",
      "wss://relay.example.test/path",
      "wss://relay.example.test/?secret=1",
      "wss://relay.example.test/#fragment",
      "wss://relay.example.test:0/",
      "wss://relay.example.test:443/",
      "wss://RELAY.example.test/",
    ]
    for url in invalidURLs {
      XCTAssertThrowsError(try makeInvite(wssURL: url), "accepted invalid URL: \(url)")
    }

    for name in ["", " Remote", "Remote ", "Remote\n", String(repeating: "é", count: 65)] {
      XCTAssertThrowsError(
        try makeInvite(machineDisplayName: name),
        "accepted invalid display name: \(name.debugDescription)"
      )
    }

    XCTAssertThrowsError(
      try makeInvite(machineRootFingerprint: Data(repeating: 0xFF, count: 32))
    )

    var certificate = validCertificate()
    certificate.certRole = .link
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.generation = 0
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.rootKeyId = Data(repeating: 0, count: 16)
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.trustEpoch = 0
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.notAfterMs = 0
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.subjectPubkey = Data(repeating: 0, count: 32)
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))
    certificate = validCertificate()
    certificate.signature = Data(repeating: 0, count: 64)
    XCTAssertThrowsError(try makeInvite(dataSignCertificate: certificate))

    certificate = validCertificate(notAfterMilliseconds: nowMilliseconds)
    let certExpiresNow = try makeInvite(dataSignCertificate: certificate)
    XCTAssertThrowsError(try certExpiresNow.validate(nowMilliseconds: nowMilliseconds))
  }

  func testAuthorizationIsSortedUniqueBoundedAndPermissionCovered() throws {
    let valid = try validAuthorization()
    let canonical = try AuthorizationRequestCanonicalCodec.encode(valid)
    XCTAssertEqual(try AuthorizationRequestCanonicalCodec.decode(canonical), valid)

    XCTAssertThrowsError(
      try AuthorizationRequestV1(
        deviceDisplayName: "Remote",
        capabilities: [.conversation, .catalog],
        permissions: [.catalogRead]
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .duplicateAuthorization)
    }
    XCTAssertThrowsError(
      try AuthorizationRequestV1(
        deviceDisplayName: "Remote",
        capabilities: [.catalog, .catalog],
        permissions: [.catalogRead]
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .duplicateAuthorization)
    }
    XCTAssertThrowsError(
      try AuthorizationRequestV1(
        deviceDisplayName: "Remote",
        capabilities: [.catalog],
        permissions: [.approvalResolve]
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .permissionWithoutCapability)
    }
    XCTAssertThrowsError(
      try AuthorizationRequestV1(
        deviceDisplayName: "Remote",
        capabilities: [],
        permissions: []
      )
    )
  }

  func testStrictCodecsRejectUnknownTagTrailingTruncationAndOversize() throws {
    let inviteCanonical = try PairInviteCanonicalCodec.encode(makeInvite())
    let authorizationCanonical = try AuthorizationRequestCanonicalCodec.encode(
      validAuthorization()
    )
    let plaintextCanonical = try PairRequestPlaintextCanonicalCodec.encode(
      try PairRequestPlaintextV1(
        inviteSecret: Data(repeating: 0x61, count: 32),
        deviceSignPublicKey: Data(repeating: 0x71, count: 32),
        deviceHPKEPublicKey: Data(repeating: 0x72, count: 32),
        authorizationRequest: validAuthorization()
      )
    )
    let requestCanonical = try PairRequestCanonicalCodec.encode(
      try PairRequestV1(
        encapsulatedKey: Data(repeating: 0x81, count: 32),
        ciphertext: Data(repeating: 0x82, count: 96),
        deviceProofSignature: Data(repeating: 0x83, count: 64)
      )
    )

    XCTAssertThrowsError(try PairInviteCanonicalCodec.decode(inviteCanonical + Data([0])))
    XCTAssertThrowsError(
      try AuthorizationRequestCanonicalCodec.decode(authorizationCanonical.dropLastData())
    )
    XCTAssertThrowsError(
      try PairRequestPlaintextCanonicalCodec.decode(plaintextCanonical + Data([0]))
    )
    XCTAssertThrowsError(try PairRequestCanonicalCodec.decode(requestCanonical + Data([0])))
    XCTAssertThrowsError(try PairRequestCanonicalCodec.decode(requestCanonical.dropLastData()))

    XCTAssertThrowsError(
      try AuthorizationRequestCanonicalCodec.decode(
        rawAuthorization(capabilityTag: 0xFF, permissionTag: 0)
      )
    )
    XCTAssertThrowsError(
      try AuthorizationRequestCanonicalCodec.decode(
        rawAuthorization(capabilityTag: 0, permissionTag: 0xFF)
      )
    )
    XCTAssertThrowsError(
      try PairRequestCanonicalCodec.decode(
        Data(repeating: 0, count: PairRequestCanonicalCodec.maximumCanonicalBytes + 1)
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .sizeLimit("pair request envelope"))
    }
    XCTAssertThrowsError(
      try PairRequestV1(
        encapsulatedKey: Data(repeating: 0x81, count: 32),
        ciphertext: Data(
          repeating: 0x82,
          count: PairRequestCanonicalCodec.maximumCiphertextBytes + 1
        ),
        deviceProofSignature: Data(repeating: 0x83, count: 64)
      )
    )
  }

  func testSealPairRequestProducesOpaqueCanonicalCarrierAndValidProof() throws {
    let invitePrivate = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x41, count: 32)
    )
    let invite = try makeInvite(inviteHPKEPublicKey: invitePrivate.publicKey.rawRepresentation)
    let deviceSigningKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x71, count: 32)
    )
    let deviceHPKEKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x72, count: 32)
    )
    let authorization = try validAuthorization()

    let carrier = try PairRequestCrypto.sealPairRequest(
      invite: invite,
      authorizationRequest: authorization,
      deviceSigningKey: deviceSigningKey,
      deviceHPKEPublicKey: deviceHPKEKey.publicKey,
      nowMilliseconds: nowMilliseconds
    )

    XCTAssertEqual(carrier.pairRoute, invite.pairRoute)
    XCTAssertEqual(carrier.requestHash, CanonicalCodec.sha256(carrier.canonicalBytes))
    XCTAssertFalse(carrier.canonicalBytes.containsSubsequence(invite.inviteSecret))
    XCTAssertEqual(
      Set(Mirror(reflecting: carrier).children.compactMap(\.label)),
      ["pairRoute", "canonicalBytes", "requestHash"]
    )

    let envelope = try PairRequestCanonicalCodec.decode(carrier.canonicalBytes)
    let info = try requestInfo(for: invite)
    let context = exactPairRequestContext(info: info)
    let opened = try RelayCrypto.openHPKE(
      HPKEEnvelopeV1(enc: envelope.encapsulatedKey, ciphertext: envelope.ciphertext),
      recipient: invitePrivate,
      info: info.canonicalBytes(),
      aad: CanonicalCodec.encodeAAD(context)
    )
    let plaintext = try PairRequestPlaintextCanonicalCodec.decode(opened)
    XCTAssertEqual(plaintext.inviteSecret, invite.inviteSecret)
    XCTAssertEqual(
      plaintext.deviceSignPublicKey,
      deviceSigningKey.publicKey.rawRepresentation
    )
    XCTAssertEqual(plaintext.deviceHPKEPublicKey, deviceHPKEKey.publicKey.rawRepresentation)
    XCTAssertEqual(plaintext.authorizationRequest, authorization)

    let tbs = try PairRequestCrypto.signatureTBS(
      envelope,
      info: info,
      context: context,
      deviceSignFingerprint: CanonicalCodec.sha256(
        deviceSigningKey.publicKey.rawRepresentation
      )
    )
    XCTAssertTrue(
      deviceSigningKey.publicKey.isValidSignature(
        envelope.deviceProofSignature,
        for: tbs
      )
    )
  }

  func testPairRequestTamperFailsClosedForCiphertextSignatureInfoAndPairRoute() throws {
    let invitePrivate = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x31, count: 32)
    )
    let invite = try makeInvite(inviteHPKEPublicKey: invitePrivate.publicKey.rawRepresentation)
    let deviceSigningKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x32, count: 32)
    )
    let deviceHPKEKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x33, count: 32)
    )
    let carrier = try PairRequestCrypto.sealPairRequest(
      invite: invite,
      authorizationRequest: validAuthorization(),
      deviceSigningKey: deviceSigningKey,
      deviceHPKEPublicKey: deviceHPKEKey.publicKey,
      nowMilliseconds: nowMilliseconds
    )
    let envelope = try PairRequestCanonicalCodec.decode(carrier.canonicalBytes)
    let info = try requestInfo(for: invite)
    let context = exactPairRequestContext(info: info)

    var tamperedCiphertext = envelope.ciphertext
    tamperedCiphertext[0] ^= 1
    let ciphertextEnvelope = try PairRequestV1(
      encapsulatedKey: envelope.encapsulatedKey,
      ciphertext: tamperedCiphertext,
      deviceProofSignature: envelope.deviceProofSignature
    )
    XCTAssertThrowsError(
      try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(
          enc: ciphertextEnvelope.encapsulatedKey,
          ciphertext: ciphertextEnvelope.ciphertext
        ),
        recipient: invitePrivate,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    )

    var tamperedSignature = envelope.deviceProofSignature
    tamperedSignature[0] ^= 1
    let signatureEnvelope = try PairRequestV1(
      encapsulatedKey: envelope.encapsulatedKey,
      ciphertext: envelope.ciphertext,
      deviceProofSignature: tamperedSignature
    )
    let validTBS = try PairRequestCrypto.signatureTBS(
      signatureEnvelope,
      info: info,
      context: context,
      deviceSignFingerprint: CanonicalCodec.sha256(
        deviceSigningKey.publicKey.rawRepresentation
      )
    )
    XCTAssertFalse(
      deviceSigningKey.publicKey.isValidSignature(
        signatureEnvelope.deviceProofSignature,
        for: validTBS
      )
    )

    let wrongInfo = try PairRequestInfoV1(
      relayServerID: info.relayServerID,
      pairRoute: info.pairRoute,
      inviteHash: Data(repeating: 0xEE, count: 32),
      expiryMilliseconds: info.expiryMilliseconds
    )
    XCTAssertThrowsError(
      try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(enc: envelope.encapsulatedKey, ciphertext: envelope.ciphertext),
        recipient: invitePrivate,
        info: wrongInfo.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    )

    var wrongRouteContext = context
    wrongRouteContext.pairRoute = Data(repeating: 0x56, count: 16)
    XCTAssertThrowsError(
      try PairRequestCrypto.signatureTBS(
        envelope,
        info: info,
        context: wrongRouteContext,
        deviceSignFingerprint: CanonicalCodec.sha256(
          deviceSigningKey.publicKey.rawRepresentation
        )
      )
    ) { error in
      XCTAssertEqual(error as? PairRequestCryptoError, .invalidContext)
    }

    var wrongKindContext = context
    wrongKindContext.frameKind = .pairResponse
    XCTAssertThrowsError(
      try PairRequestCrypto.signatureTBS(
        envelope,
        info: info,
        context: wrongKindContext,
        deviceSignFingerprint: CanonicalCodec.sha256(
          deviceSigningKey.publicKey.rawRepresentation
        )
      )
    )
  }

  func testSensitiveDebugDescriptionsAreRedacted() throws {
    let invite = try makeInvite()
    let authorization = try validAuthorization()
    let plaintext = try PairRequestPlaintextV1(
      inviteSecret: invite.inviteSecret,
      deviceSignPublicKey: Data(repeating: 0x71, count: 32),
      deviceHPKEPublicKey: Data(repeating: 0x72, count: 32),
      authorizationRequest: authorization
    )
    let envelope = try PairRequestV1(
      encapsulatedKey: Data(repeating: 0x81, count: 32),
      ciphertext: Data(repeating: 0x82, count: 32),
      deviceProofSignature: Data(repeating: 0x83, count: 64)
    )

    for value in [
      invite.debugDescription,
      authorization.debugDescription,
      plaintext.debugDescription,
      envelope.debugDescription,
    ] {
      XCTAssertTrue(value.contains("<redacted>"))
      XCTAssertFalse(value.contains("61616161"))
      XCTAssertFalse(value.contains("Remote CLI"))
    }
  }

  private func requestInfo(for invite: PairInviteV1) throws -> PairRequestInfoV1 {
    try PairRequestInfoV1(
      relayServerID: invite.relayServerID,
      pairRoute: invite.pairRoute,
      inviteHash: invite.canonicalSHA256(),
      expiryMilliseconds: invite.expiresAtMilliseconds
    )
  }

  private func exactPairRequestContext(info: PairRequestInfoV1) -> OuterContextV1 {
    OuterContextV1(
      frameKind: .pairRequest,
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

  private func validAuthorization() throws -> AuthorizationRequestV1 {
    try AuthorizationRequestV1(
      deviceDisplayName: "Remote CLI",
      capabilities: [
        .catalog,
        .conversation,
        .prompt,
        .command,
        .approval,
        .metadata,
        .selfRevocation,
      ],
      permissions: [
        .catalogRead,
        .conversationRead,
        .conversationStart,
        .promptSend,
        .commandCancel,
        .approvalResolve,
        .approvalRetry,
        .metadataWrite,
        .revokeSelf,
      ]
    )
  }

  private func makeInvite(
    inviteHPKEPublicKey: Data? = nil,
    wssURL: String = "wss://relay.example.test/",
    expiresAtMilliseconds: UInt64? = nil,
    machineRootFingerprint: Data? = nil,
    dataSignCertificate: RelayV2SignedCertificate? = nil,
    machineDisplayName: String = "Fixture Mac"
  ) throws -> PairInviteV1 {
    let rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x51, count: 32)
    )
    let rootPublicKey = rootKey.publicKey.rawRepresentation
    return try PairInviteV1(
      pairRoute: Data(repeating: 0x55, count: 16),
      inviteSecret: Data(repeating: 0x61, count: 32),
      inviteHPKEPublicKey: inviteHPKEPublicKey ?? Data(repeating: 0x62, count: 32),
      wssURL: wssURL,
      relayServerID: Data(repeating: 0x33, count: 16),
      currentSPKIPin: Data(repeating: 0x63, count: 32),
      nextSPKIPin: Data(repeating: 0x64, count: 32),
      expiresAtMilliseconds: expiresAtMilliseconds ?? nowMilliseconds + 300_000,
      machineRootPublicKey: rootPublicKey,
      machineRootFingerprint: machineRootFingerprint ?? CanonicalCodec.sha256(rootPublicKey),
      dataSignCertificate: dataSignCertificate ?? validCertificate(),
      machineDisplayName: machineDisplayName
    )
  }

  private func validCertificate(
    notAfterMilliseconds: UInt64? = nil
  ) -> RelayV2SignedCertificate {
    RelayV2SignedCertificate(
      subjectPubkey: Data(repeating: 0x65, count: 32),
      certRole: .data,
      generation: 1,
      rootKeyId: Data(repeating: 0x44, count: 16),
      trustEpoch: 1,
      notAfterMs: notAfterMilliseconds,
      signature: Data(repeating: 0x66, count: 64)
    )
  }

  private func rawAuthorization(capabilityTag: UInt8, permissionTag: UInt8) -> Data {
    var output = Data("AgentDeck/AuthorizationRequestV1\0".utf8)
    appendPairRequestInteger(UInt16(1), to: &output)
    appendPairRequestBytes(Data("Remote".utf8), to: &output)
    output.append(1)
    output.append(capabilityTag)
    output.append(1)
    output.append(permissionTag)
    return output
  }
}

private func loadPairingCanonicalVector() throws -> [String: Any] {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let data = try Data(
    contentsOf: root.appendingPathComponent("protocol/agentdeck/crypto-vectors-v1.json")
  )
  let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
  return try XCTUnwrap(object["pairing_canonical"] as? [String: Any])
}

private func pairingVectorData(_ key: String, _ vector: [String: Any]) throws -> Data {
  try decodePairRequestHex(try XCTUnwrap(vector[key] as? String))
}

private func decodePairRequestHex(_ value: String) throws -> Data {
  guard value.count.isMultiple(of: 2) else {
    throw PairRequestCryptoTestError.invalidHex
  }
  var output = Data()
  output.reserveCapacity(value.count / 2)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: 2)
    guard let byte = UInt8(value[index..<next], radix: 16) else {
      throw PairRequestCryptoTestError.invalidHex
    }
    output.append(byte)
    index = next
  }
  return output
}

private func appendPairRequestBytes(_ value: Data, to output: inout Data) {
  appendPairRequestInteger(UInt32(value.count), to: &output)
  output.append(value)
}

private func appendPairRequestInteger<T: FixedWidthInteger>(
  _ value: T,
  to output: inout Data
) {
  var encoded = value.bigEndian
  Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
}

private enum PairRequestCryptoTestError: Error {
  case invalidHex
}

extension Data {
  fileprivate func dropLastData() -> Data {
    Data(dropLast())
  }

  fileprivate func containsSubsequence(_ value: Data) -> Bool {
    range(of: value) != nil
  }
}
