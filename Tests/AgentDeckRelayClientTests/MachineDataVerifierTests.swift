import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class MachineDataVerifierTests: XCTestCase {
  func testSignedSealedWireDecoderIsStrictCanonicalAndBounded() throws {
    let fixture = try makeMachineDataFixture()
    let canonical = try RelayV2SignedSealedBlobCodec.encode(
      fixture.signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )

    let decoded = try RelayV2SignedSealedBlobCodec.decode(
      canonical,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    XCTAssertEqual(decoded, fixture.signed)
    XCTAssertEqual(
      try RelayV2SignedSealedBlobCodec.encode(
        decoded,
        maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
      ),
      canonical
    )

    let domainBytes = Data("AgentDeck/SealedBlobV1\0".utf8).count
    let versionOffset = domainBytes
    let purposeOffset = versionOffset + 2
    let keyIDEpochOffset = purposeOffset + 1
    let keyEpochOffset = keyIDEpochOffset + 8
    let revisionOffset = keyEpochOffset + 8
    let nonceLengthOffset = revisionOffset + 8

    var malformed: [Data] = [Data(), Data(canonical.dropLast())]
    malformed.append(mutating(canonical, at: 0) { $0 ^= 0xFF })
    malformed.append(
      replacing(
        canonical,
        range: versionOffset..<(versionOffset + 2),
        with: [0, 2]
      )
    )
    malformed.append(mutating(canonical, at: purposeOffset) { $0 = 0xFF })
    malformed.append(
      replacing(canonical, range: keyIDEpochOffset..<(keyIDEpochOffset + 8), with: zeroes(8))
    )
    malformed.append(
      replacing(canonical, range: keyEpochOffset..<(keyEpochOffset + 8), with: bigEndian(10))
    )
    malformed.append(
      replacing(canonical, range: revisionOffset..<(revisionOffset + 8), with: zeroes(8))
    )
    malformed.append(
      replacing(
        canonical,
        range: nonceLengthOffset..<(nonceLengthOffset + 4),
        with: [0, 0, 0, 11]
      )
    )
    malformed.append(
      replacing(
        canonical,
        range: (canonical.count - 64)..<canonical.count,
        with: zeroes(64)
      )
    )
    var trailing = canonical
    trailing.append(0)
    malformed.append(trailing)

    for bytes in malformed {
      XCTAssertThrowsError(
        try RelayV2SignedSealedBlobCodec.decode(
          bytes,
          maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
        ),
        "strict decoder accepted malformed sealed blob of \(bytes.count) bytes"
      )
    }

    XCTAssertThrowsError(
      try RelayV2SignedSealedBlobCodec.decode(
        canonical,
        maxEncodedBytes: canonical.count - 1
      )
    )
  }

  func testTrustCertificateAndRevisionGatesRunBeforeMachineDataSignature() throws {
    let fixture = try makeMachineDataFixture()
    let verifier = try MachineDataVerifier(
      relayServerID: fixture.relayServerID,
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.dataCertificate.rootKeyId,
      expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
      dataCertificate: fixture.dataCertificate,
      minimumDataCertificateGeneration: fixture.dataCertificate.generation,
      currentKeyDirectoryRevision: fixture.keyDirectoryRevision,
      maximumKeySyncAdvance: 1
    )
    let wire = try RelayV2SignedSealedBlobCodec.encode(
      fixture.signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    let key = try MachineDataReceivingKeyBinding(
      key: fixture.receivingKey,
      streamRoute: fixture.streamRoute,
      noncePrefix: fixture.sendingKey.noncePrefix,
      keyDirectoryRevision: fixture.keyDirectoryRevision
    )

    guard
      case .current(let candidate) = try verifier.verify(
        wireBytes: wire,
        context: fixture.context,
        receivingKey: key
      )
    else {
      return XCTFail("current signed frame should mint a verified candidate")
    }
    XCTAssertEqual(candidate.counter, fixture.counter)
    XCTAssertEqual(candidate.keyDirectoryRevision, fixture.keyDirectoryRevision)
    let opened = try verifier.open(candidate, receivingKey: key)
    XCTAssertEqual(opened.payloadKind, .conversationEvent)
    XCTAssertEqual(opened.payload, Data("runtime-event".utf8))

    let lower = try signedWire(
      fixture: fixture,
      keyDirectoryRevision: fixture.keyDirectoryRevision - 1
    )
    XCTAssertThrowsError(
      try verifier.verify(wireBytes: lower, context: fixture.context, receivingKey: key)
    )

    let next = try signedWire(
      fixture: fixture,
      keyDirectoryRevision: fixture.keyDirectoryRevision + 1
    )
    guard
      case .keySyncRequired(let observedRevision) = try verifier.verify(
        wireBytes: next,
        context: fixture.context,
        receivingKey: key
      )
    else {
      return XCTFail("exact next revision must request bounded key sync")
    }
    XCTAssertEqual(observedRevision, fixture.keyDirectoryRevision + 1)

    let skipped = try signedWire(
      fixture: fixture,
      keyDirectoryRevision: fixture.keyDirectoryRevision + 2
    )
    XCTAssertThrowsError(
      try verifier.verify(wireBytes: skipped, context: fixture.context, receivingKey: key)
    )

    var forged = fixture.signed.signature
    forged[0] ^= 1
    let forgedWire = try RelayV2SignedSealedBlobCodec.encode(
      SignedSealedBlobV1(inner: fixture.signed.inner, signature: forged),
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    XCTAssertThrowsError(
      try verifier.verify(wireBytes: forgedWire, context: fixture.context, receivingKey: key)
    )

    var wrongContext = fixture.context
    wrongContext.streamSeq = fixture.context.streamSeq.map { $0 + 1 }
    XCTAssertThrowsError(
      try verifier.verify(wireBytes: wire, context: wrongContext, receivingKey: key)
    )
  }

  func testSignatureOnlyProbeAcceptsNewKeyIDAtExactNextAndRejectsLowerOrSkippedRevision()
    throws
  {
    let fixture = try makeMachineDataFixture()
    let verifier = try MachineDataVerifier(
      relayServerID: fixture.relayServerID,
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.dataCertificate.rootKeyId,
      expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
      dataCertificate: fixture.dataCertificate,
      minimumDataCertificateGeneration: fixture.dataCertificate.generation,
      currentKeyDirectoryRevision: fixture.keyDirectoryRevision,
      maximumKeySyncAdvance: 1
    )
    let newKeyID = KeyIDV1(purpose: .conversationDEK, epoch: 10)
    let exactNext = try higherRevisionProbeFrame(
      fixture: fixture,
      keyID: newKeyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision + 1
    )

    let probe = try verifier.verifyExactNextHigherRevisionProbe(
      wireBytes: exactNext.wire,
      context: exactNext.context
    )
    XCTAssertEqual(probe.keyID, newKeyID)
    XCTAssertEqual(probe.keyDirectoryRevision, fixture.keyDirectoryRevision + 1)
    XCTAssertEqual(probe.frameKind, .conversationPublish)
    XCTAssertEqual(probe.streamRoute, fixture.streamRoute)
    XCTAssertNil(probe.requestRoute)

    for revision in [
      fixture.keyDirectoryRevision - 1,
      fixture.keyDirectoryRevision,
      fixture.keyDirectoryRevision + 2,
    ] {
      let rejected = try higherRevisionProbeFrame(
        fixture: fixture,
        keyID: newKeyID,
        keyDirectoryRevision: revision
      )
      XCTAssertThrowsError(
        try verifier.verifyExactNextHigherRevisionProbe(
          wireBytes: rejected.wire,
          context: rejected.context
        )
      )
    }

    var wrongRoute = exactNext.context
    wrongRoute.streamRoute = Data(repeating: 0xEE, count: 16)
    XCTAssertThrowsError(
      try verifier.verifyExactNextHigherRevisionProbe(
        wireBytes: exactNext.wire,
        context: wrongRoute
      )
    )

    let forged = try higherRevisionProbeFrame(
      fixture: fixture,
      keyID: newKeyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision + 1,
      signingKey: Curve25519.Signing.PrivateKey()
    )
    XCTAssertThrowsError(
      try verifier.verifyExactNextHigherRevisionProbe(
        wireBytes: forged.wire,
        context: forged.context
      )
    ) { error in
      XCTAssertEqual(error as? RelayCryptoError, .badSignature)
    }
  }

  func testReceivingCapabilityBindsKeyPurposeOuterFamilyAndPlaintextKind() throws {
    let fixture = try makeMachineDataFixture()
    let verifier = try MachineDataVerifier(
      relayServerID: fixture.relayServerID,
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.dataCertificate.rootKeyId,
      expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
      dataCertificate: fixture.dataCertificate,
      minimumDataCertificateGeneration: fixture.dataCertificate.generation,
      currentKeyDirectoryRevision: fixture.keyDirectoryRevision,
      maximumKeySyncAdvance: 1
    )
    let binding = try MachineDataReceivingKeyBinding(
      key: fixture.receivingKey,
      streamRoute: fixture.streamRoute,
      noncePrefix: fixture.sendingKey.noncePrefix,
      keyDirectoryRevision: fixture.keyDirectoryRevision
    )

    var wrongFamily = fixture.context
    wrongFamily.frameKind = .catalogPublish
    let wire = try RelayV2SignedSealedBlobCodec.encode(
      fixture.signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    XCTAssertThrowsError(
      try verifier.verify(wireBytes: wire, context: wrongFamily, receivingKey: binding)
    )

    let wrongKindKey = try AeadSendingKey(
      keyID: fixture.sendingKey.keyID,
      epoch: fixture.sendingKey.epoch,
      keyDirectoryRevision: fixture.keyDirectoryRevision,
      payloadKind: .catalogDelta,
      rawKey: Data(repeating: 0x81, count: 32)
    )
    let wrongKindUnsigned = try RelayCrypto.sealSymmetric(
      Data("catalog-on-conversation-key".utf8),
      key: wrongKindKey,
      context: fixture.context,
      counter: fixture.counter + 1
    )
    let wrongKindSigned = try RelayCrypto.signSealed(
      wrongKindUnsigned,
      key: fixture.dataSigningKey,
      context: fixture.context
    )
    let wrongKindWire = try RelayV2SignedSealedBlobCodec.encode(
      wrongKindSigned,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
    guard
      case .current(let candidate) = try verifier.verify(
        wireBytes: wrongKindWire,
        context: fixture.context,
        receivingKey: binding
      )
    else {
      return XCTFail("签名和 outer 合法时应在 AEAD payload admission 阶段拒绝")
    }
    XCTAssertThrowsError(try verifier.open(candidate, receivingKey: binding)) { error in
      XCTAssertEqual(error as? MachineDataVerifierError, .payloadKindMismatch)
    }

    XCTAssertThrowsError(
      try MachineDataReceivingKeyBinding(
        key: fixture.receivingKey,
        streamRoute: fixture.streamRoute,
        noncePrefix: fixture.sendingKey.noncePrefix,
        keyDirectoryRevision: fixture.keyDirectoryRevision,
        capability: .catalogPublication
      )
    )
  }

  func testInvalidRootBindingRoleGenerationEpochAndCertificateSignatureFailClosed() throws {
    let fixture = try makeMachineDataFixture()
    let rootPublic = fixture.rootSigningKey.publicKey.rawRepresentation
    let rootFingerprint = CanonicalCodec.sha256(rootPublic)

    XCTAssertThrowsError(
      try MachineDataVerifier(
        relayServerID: fixture.relayServerID,
        machineRoute: fixture.machineRoute,
        deviceRoute: fixture.deviceRoute,
        machineRootPublicKey: rootPublic,
        machineRootFingerprint: Data(repeating: 0xFF, count: 32),
        expectedRootKeyID: fixture.dataCertificate.rootKeyId,
        expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
        dataCertificate: fixture.dataCertificate,
        minimumDataCertificateGeneration: fixture.dataCertificate.generation,
        currentKeyDirectoryRevision: fixture.keyDirectoryRevision,
        maximumKeySyncAdvance: 1
      )
    )

    for certificate in [
      replacingCertificate(fixture.dataCertificate, role: .link),
      replacingCertificate(fixture.dataCertificate, generation: 0),
      replacingCertificate(
        fixture.dataCertificate,
        trustEpoch: fixture.dataCertificate.trustEpoch + 1
      ),
      replacingCertificate(
        fixture.dataCertificate,
        signature: Data(repeating: 0xA5, count: 64)
      ),
    ] {
      XCTAssertThrowsError(
        try MachineDataVerifier(
          relayServerID: fixture.relayServerID,
          machineRoute: fixture.machineRoute,
          deviceRoute: fixture.deviceRoute,
          machineRootPublicKey: rootPublic,
          machineRootFingerprint: rootFingerprint,
          expectedRootKeyID: fixture.dataCertificate.rootKeyId,
          expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
          dataCertificate: certificate,
          minimumDataCertificateGeneration: fixture.dataCertificate.generation,
          currentKeyDirectoryRevision: fixture.keyDirectoryRevision,
          maximumKeySyncAdvance: 1
        )
      )
    }
  }

  func testSignedCertificateCanonicalCodecAndReusableTrustVerifier() throws {
    let rustGolden = RelayV2SignedCertificate(
      subjectPubkey: Data(repeating: 0x11, count: 32),
      certRole: .link,
      generation: 7,
      rootKeyId: Data(repeating: 0x22, count: 16),
      trustEpoch: 3,
      notAfterMs: 9,
      signature: Data(repeating: 0x33, count: 64)
    )
    let goldenBytes = try SignedCertificateCanonicalCodec.encode(rustGolden)
    XCTAssertEqual(goldenBytes.count, 222)
    XCTAssertEqual(
      try SignedCertificateCanonicalCodec.canonicalSHA256(rustGolden).certificateHexString,
      "b0b95841d7484b28fc133bfcdb16677878023e361b3e8784079b5ff0fce3e204"
    )
    XCTAssertEqual(
      try SignedCertificateCanonicalCodec.decode(goldenBytes),
      rustGolden
    )
    var trailing = goldenBytes
    trailing.append(0)
    XCTAssertThrowsError(try SignedCertificateCanonicalCodec.decode(trailing))

    let fixture = try makeMachineDataFixture()
    let canonical = try SignedCertificateCanonicalCodec.encode(
      fixture.dataCertificate
    )
    let verified = try MachineDataCertificateVerifier.verify(
      canonicalBytes: canonical,
      relayServerID: fixture.relayServerID,
      machineRoute: fixture.machineRoute,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.dataCertificate.rootKeyId,
      expectedTrustEpoch: fixture.dataCertificate.trustEpoch,
      minimumDataCertificateGeneration: fixture.dataCertificate.generation,
      nowMilliseconds: 1
    )
    requireSendable(VerifiedMachineDataCertificate.self)
    XCTAssertEqual(verified.certificate, fixture.dataCertificate)
  }

  private func requireSendable<Value: Sendable>(_: Value.Type) {}
}

private struct MachineDataFixture {
  let relayServerID: Data
  let machineRoute: Data
  let deviceRoute: Data
  let streamRoute: Data
  let keyDirectoryRevision: UInt64
  let counter: UInt64
  let rootSigningKey: Curve25519.Signing.PrivateKey
  let dataSigningKey: Curve25519.Signing.PrivateKey
  let dataCertificate: RelayV2SignedCertificate
  let sendingKey: AeadSendingKey
  let receivingKey: AeadReceivingKey
  let context: OuterContextV1
  let signed: SignedSealedBlobV1
}

private struct HigherRevisionProbeFrame {
  let context: OuterContextV1
  let wire: Data
}

private func higherRevisionProbeFrame(
  fixture: MachineDataFixture,
  keyID: KeyIDV1,
  keyDirectoryRevision: UInt64,
  signingKey: Curve25519.Signing.PrivateKey? = nil
) throws -> HigherRevisionProbeFrame {
  var context = fixture.context
  context.deviceRoute = nil
  context.requestRoute = nil
  context.streamCursor = nil
  context.messageKeyEpoch = keyID.epoch
  let unsigned = try RelayCrypto.sealSymmetric(
    Data("unknown-higher-revision".utf8),
    key: AeadSendingKey(
      keyID: keyID,
      epoch: keyID.epoch,
      keyDirectoryRevision: keyDirectoryRevision,
      payloadKind: .conversationEvent,
      rawKey: Data(repeating: 0x91, count: 32)
    ),
    context: context,
    counter: 7
  )
  let signed = try RelayCrypto.signSealed(
    unsigned,
    key: signingKey ?? fixture.dataSigningKey,
    context: context
  )
  return HigherRevisionProbeFrame(
    context: context,
    wire: try RelayV2SignedSealedBlobCodec.encode(
      signed,
      maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
    )
  )
}

private func makeMachineDataFixture() throws -> MachineDataFixture {
  let relayServerID = Data(repeating: 0x11, count: 16)
  let machineRoute = Data(repeating: 0x22, count: 16)
  let deviceRoute = Data(repeating: 0x33, count: 16)
  let streamRoute = Data(repeating: 0x44, count: 16)
  let generation = Data(repeating: 0x55, count: 16)
  let rootKeyID = Data(repeating: 0x66, count: 16)
  let root = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x71, count: 32))
  let data = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x72, count: 32))
  let unsignedCertificate = RelayV2SignedCertificate(
    subjectPubkey: data.publicKey.rawRepresentation,
    certRole: .data,
    generation: 4,
    rootKeyId: rootKeyID,
    trustEpoch: 3,
    notAfterMs: 4_000_000_000_000,
    signature: Data(repeating: 1, count: 64)
  )
  let certificateTBS = ToBeSignedV1(
    objectType: .dataCert,
    signatureFormatVersion: 1,
    relayProtocolVersion: relayProtocolVersionV2,
    runtimeProtocolVersion: runtimeProtocolVersionCurrent,
    e2eeFormatVersion: 1,
    relayServerID: relayServerID,
    machineRoute: machineRoute,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    roleScope: "machine-data",
    signingKeyFingerprint: CanonicalCodec.sha256(root.publicKey.rawRepresentation),
    rootKeyID: rootKeyID,
    trustEpoch: 3,
    serialOrGeneration: 4,
    notAfterMS: 4_000_000_000_000,
    signedObjectSHA256: CanonicalCodec.sha256(
      signedCertificateUnsignedCanonicalBytes(unsignedCertificate)
    )
  )
  let certificate = RelayV2SignedCertificate(
    subjectPubkey: unsignedCertificate.subjectPubkey,
    certRole: unsignedCertificate.certRole,
    generation: unsignedCertificate.generation,
    rootKeyId: unsignedCertificate.rootKeyId,
    trustEpoch: unsignedCertificate.trustEpoch,
    notAfterMs: unsignedCertificate.notAfterMs,
    signature: try RelayCrypto.sign(certificateTBS, key: root)
  )

  let keyDirectoryRevision: UInt64 = 7
  let keyID = KeyIDV1(purpose: .conversationDEK, epoch: 9)
  let rawKey = Data(repeating: 0x81, count: 32)
  let sending = try AeadSendingKey(
    keyID: keyID,
    epoch: keyID.epoch,
    keyDirectoryRevision: keyDirectoryRevision,
    payloadKind: .conversationEvent,
    rawKey: rawKey
  )
  let receiving = try AeadReceivingKey(keyID: keyID, epoch: keyID.epoch, rawKey: rawKey)
  let context = OuterContextV1(
    frameKind: .conversationPublish,
    relayProtocolVersion: relayProtocolVersionV2,
    e2eeFormatVersion: 1,
    machineRoute: machineRoute,
    deviceRoute: nil,
    streamRoute: streamRoute,
    requestRoute: nil,
    streamGeneration: generation,
    streamCursor: .at(40),
    streamSeq: 41,
    messageKeyEpoch: keyID.epoch
  )
  let counter: UInt64 = 42
  let unsigned = try RelayCrypto.sealSymmetric(
    Data("runtime-event".utf8),
    key: sending,
    context: context,
    counter: counter
  )
  let signed = try RelayCrypto.signSealed(unsigned, key: data, context: context)
  return MachineDataFixture(
    relayServerID: relayServerID,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    streamRoute: streamRoute,
    keyDirectoryRevision: keyDirectoryRevision,
    counter: counter,
    rootSigningKey: root,
    dataSigningKey: data,
    dataCertificate: certificate,
    sendingKey: sending,
    receivingKey: receiving,
    context: context,
    signed: signed
  )
}

private func signedWire(
  fixture: MachineDataFixture,
  keyDirectoryRevision: UInt64
) throws -> Data {
  let unsigned = UnsignedSealedBlobV1(
    formatVersion: fixture.signed.inner.formatVersion,
    keyID: fixture.signed.inner.keyID,
    keyEpoch: fixture.signed.inner.keyEpoch,
    keyDirectoryRevision: keyDirectoryRevision,
    nonce: fixture.signed.inner.nonce,
    ciphertext: fixture.signed.inner.ciphertext
  )
  return try RelayV2SignedSealedBlobCodec.encode(
    RelayCrypto.signSealed(unsigned, key: fixture.dataSigningKey, context: fixture.context),
    maxEncodedBytes: RelayWireCodecV2.maxFrameBytes
  )
}

private func replacingCertificate(
  _ source: RelayV2SignedCertificate,
  role: RelayV2CertRole? = nil,
  generation: UInt64? = nil,
  trustEpoch: UInt64? = nil,
  signature: Data? = nil
) -> RelayV2SignedCertificate {
  RelayV2SignedCertificate(
    subjectPubkey: source.subjectPubkey,
    certRole: role ?? source.certRole,
    generation: generation ?? source.generation,
    rootKeyId: source.rootKeyId,
    trustEpoch: trustEpoch ?? source.trustEpoch,
    notAfterMs: source.notAfterMs,
    signature: signature ?? source.signature
  )
}

private func signedCertificateUnsignedCanonicalBytes(
  _ certificate: RelayV2SignedCertificate
) -> Data {
  var output = Data("AgentDeck/SignedCertificateUnsignedV1\0".utf8)
  appendLengthPrefixed(certificate.subjectPubkey, to: &output)
  output.append(certificate.certRole == .link ? 0 : 1)
  output.append(contentsOf: bigEndian(certificate.generation))
  appendLengthPrefixed(certificate.rootKeyId, to: &output)
  output.append(contentsOf: bigEndian(certificate.trustEpoch))
  if let expiry = certificate.notAfterMs {
    output.append(1)
    output.append(contentsOf: bigEndian(expiry))
  } else {
    output.append(0)
  }
  return output
}

private func appendLengthPrefixed(_ value: Data, to output: inout Data) {
  output.append(contentsOf: bigEndian(UInt32(value.count)))
  output.append(value)
}

private func bigEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
  var encoded = value.bigEndian
  return Swift.withUnsafeBytes(of: &encoded) { Array($0) }
}

private func zeroes(_ count: Int) -> [UInt8] {
  Array(repeating: 0, count: count)
}

private func mutating(_ source: Data, at offset: Int, _ body: (inout UInt8) -> Void) -> Data {
  var copy = source
  body(&copy[offset])
  return copy
}

private func replacing(_ source: Data, range: Range<Int>, with bytes: [UInt8]) -> Data {
  var copy = source
  copy.replaceSubrange(range, with: bytes)
  return copy
}

extension Data {
  fileprivate var certificateHexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
