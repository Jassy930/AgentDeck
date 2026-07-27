import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class DeviceRequestSignerTests: XCTestCase {
  func testRuntimeEncodePrecedesCounterAndSignerOnlyReturnsSignedSealedBlob() async throws {
    let fixture = try makeDeviceRequestFixture()
    let coordinator = RequestCounterCoordinator()
    let signer = try DeviceRequestSigner(
      expectedRelayServerID: fixture.relayServerID,
      expectedGrant: fixture.grant,
      expectedMachineRoute: fixture.machineRoute,
      expectedDeviceRoute: fixture.deviceRoute,
      expectedGrantSerial: fixture.grant.grantSerial,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.grant.rootKeyId,
      expectedTrustEpoch: fixture.grant.trustEpoch,
      deviceSigningKey: fixture.deviceSigningKey,
      commandKeyID: fixture.keyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision,
      rawCommandKey: fixture.rawCommandKey,
      counterAllocator: CounterAllocator(coordinator: coordinator)
    )

    let invalid = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent + 1,
      messageID: RuntimeMessageID(rawValue: "invalid-version"),
      body: .request(.catalog(pageCursor: nil))
    )
    do {
      _ = try await signer.signRuntimeRequest(
        invalid,
        machineRoute: fixture.machineRoute,
        deviceRoute: fixture.deviceRoute,
        requestRoute: fixture.requestRoute
      )
      XCTFail("invalid Runtime envelope must fail before reserving a counter")
    } catch {
      let reservations = await coordinator.reservationCount
      XCTAssertEqual(reservations, 0)
    }

    let signed = try await signer.signRuntimeRequest(
      fixture.envelope,
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      requestRoute: fixture.requestRoute
    )
    let reservations = await coordinator.reservationCount
    XCTAssertEqual(reservations, 1)
    XCTAssertEqual(signed.requestRoute, fixture.requestRoute)
    XCTAssertEqual(signed.context.frameKind, .uplinkSend)
    XCTAssertEqual(signed.context.machineRoute, fixture.machineRoute)
    XCTAssertEqual(signed.context.deviceRoute, fixture.deviceRoute)
    XCTAssertEqual(signed.context.requestRoute, fixture.requestRoute)
    XCTAssertEqual(signed.context.messageKeyEpoch, fixture.keyID.epoch)

    let verified = try RelayCrypto.verifySealed(
      signed.sealedBlob,
      key: fixture.deviceSigningKey.publicKey,
      context: signed.context
    )
    let opened = try RelayCrypto.openSealedPayload(
      verified,
      key: AeadReceivingKey(
        keyID: fixture.keyID,
        epoch: fixture.keyID.epoch,
        rawKey: fixture.rawCommandKey
      ),
      context: signed.context
    )
    XCTAssertEqual(opened.payloadKind, .commandRequest)
    let decoded = try RuntimeWireCodec.decodeEnvelope(opened.payload)
    XCTAssertEqual(decoded.version, runtimeProtocolVersionCurrent)
    XCTAssertEqual(decoded.messageID.rawValue, fixture.envelope.messageID.rawValue)
    guard case .request(.catalog(pageCursor: nil)) = decoded.body else {
      return XCTFail("opened payload must be the exact Runtime request")
    }
  }

  func testOuterContextTamperBreaksDeviceSignatureAndAEAD() async throws {
    let fixture = try makeDeviceRequestFixture()
    let signer = try DeviceRequestSigner(
      expectedRelayServerID: fixture.relayServerID,
      expectedGrant: fixture.grant,
      expectedMachineRoute: fixture.machineRoute,
      expectedDeviceRoute: fixture.deviceRoute,
      expectedGrantSerial: fixture.grant.grantSerial,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.grant.rootKeyId,
      expectedTrustEpoch: fixture.grant.trustEpoch,
      deviceSigningKey: fixture.deviceSigningKey,
      commandKeyID: fixture.keyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision,
      rawCommandKey: fixture.rawCommandKey,
      counterAllocator: CounterAllocator(coordinator: RequestCounterCoordinator())
    )
    let signed = try await signer.signRuntimeRequest(
      fixture.envelope,
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      requestRoute: fixture.requestRoute
    )

    let tamperedContexts = [
      OuterContextV1(
        frameKind: .directedReply,
        relayProtocolVersion: signed.context.relayProtocolVersion,
        e2eeFormatVersion: signed.context.e2eeFormatVersion,
        machineRoute: signed.context.machineRoute,
        deviceRoute: signed.context.deviceRoute,
        streamRoute: signed.context.streamRoute,
        requestRoute: signed.context.requestRoute,
        streamGeneration: signed.context.streamGeneration,
        streamCursor: signed.context.streamCursor,
        streamSeq: signed.context.streamSeq,
        messageKeyEpoch: signed.context.messageKeyEpoch
      ),
      OuterContextV1(
        frameKind: signed.context.frameKind,
        relayProtocolVersion: signed.context.relayProtocolVersion,
        e2eeFormatVersion: signed.context.e2eeFormatVersion,
        machineRoute: Data(repeating: 0xEE, count: 16),
        deviceRoute: signed.context.deviceRoute,
        streamRoute: signed.context.streamRoute,
        requestRoute: signed.context.requestRoute,
        streamGeneration: signed.context.streamGeneration,
        streamCursor: signed.context.streamCursor,
        streamSeq: signed.context.streamSeq,
        messageKeyEpoch: signed.context.messageKeyEpoch
      ),
      OuterContextV1(
        frameKind: signed.context.frameKind,
        relayProtocolVersion: signed.context.relayProtocolVersion,
        e2eeFormatVersion: signed.context.e2eeFormatVersion,
        machineRoute: signed.context.machineRoute,
        deviceRoute: signed.context.deviceRoute,
        streamRoute: signed.context.streamRoute,
        requestRoute: Data(repeating: 0xEF, count: 16),
        streamGeneration: signed.context.streamGeneration,
        streamCursor: signed.context.streamCursor,
        streamSeq: signed.context.streamSeq,
        messageKeyEpoch: signed.context.messageKeyEpoch
      ),
    ]

    for context in tamperedContexts {
      XCTAssertThrowsError(
        try RelayCrypto.verifySealed(
          signed.sealedBlob,
          key: fixture.deviceSigningKey.publicKey,
          context: context
        )
      )
    }
  }

  func testTypedKeyControlCodecAndSignerUseKeyUpdatePayloadAndExactRevision() async throws {
    let fixture = try makeDeviceRequestFixture()
    let authority = try DeviceKeyControlAuthorityV1(
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      grantSerial: fixture.grant.grantSerial,
      rootTrustEpoch: fixture.grant.trustEpoch
    )
    let probe = try DeviceKeySyncRequestV1(
      authority: authority,
      knownKeyDirectoryRevision: fixture.keyDirectoryRevision,
      requestedKeyDirectoryRevision: fixture.keyDirectoryRevision + 1,
      keyID: KeyIDV1(purpose: .conversationDEK, epoch: 12),
      streamRoute: Data(repeating: 0xA1, count: 16),
      attempt: 2
    )
    let request = DeviceKeyControlRequestV1.keySync(probe)
    let canonical = try KeyControlCanonicalCodec.encode(request)
    XCTAssertEqual(try KeyControlCanonicalCodec.decode(canonical), request)
    var trailing = canonical
    trailing.append(0)
    XCTAssertThrowsError(try KeyControlCanonicalCodec.decode(trailing))
    var unknownKind = canonical
    unknownKind[Data("AgentDeck/KeyControlRequestV1\0".utf8).count] = 0xFF
    XCTAssertThrowsError(try KeyControlCanonicalCodec.decode(unknownKind))

    let coordinator = RequestCounterCoordinator()
    let signer = try makeDeviceRequestSigner(fixture, coordinator: coordinator)
    let signed = try await signer.signKeyControlRequest(
      request,
      requestRoute: fixture.requestRoute
    )
    XCTAssertEqual(
      signed.sealedBlob.inner.keyDirectoryRevision,
      fixture.keyDirectoryRevision + 1
    )
    XCTAssertEqual(signed.sealedBlob.inner.keyID, fixture.keyID)
    let verified = try RelayCrypto.verifySealed(
      signed.sealedBlob,
      key: fixture.deviceSigningKey.publicKey,
      context: signed.context
    )
    let opened = try RelayCrypto.openSealedPayload(
      verified,
      key: AeadReceivingKey(
        keyID: fixture.keyID,
        epoch: fixture.keyID.epoch,
        rawKey: fixture.rawCommandKey
      ),
      context: signed.context
    )
    XCTAssertEqual(opened.payloadKind, .keyUpdate)
    XCTAssertEqual(opened.payload, canonical)
    XCTAssertEqual(try KeyControlCanonicalCodec.decode(opened.payload), request)
    let reservationCount = await coordinator.reservationCount
    XCTAssertEqual(reservationCount, 1)

    let acknowledgement = DeviceKeyControlRequestV1.keyUpdateAck(
      try DeviceKeyUpdateAckV1(
        authority: authority,
        keyDirectoryRevision: fixture.keyDirectoryRevision,
        updateSetSHA256: Data(repeating: 0xA2, count: 32)
      )
    )
    do {
      _ = try await signer.signKeyControlRequest(
        acknowledgement,
        requestRoute: Data(repeating: 0xA3, count: 16)
      )
      XCTFail("raw ACK DTO must be rejected before counter reservation")
    } catch {
      XCTAssertEqual(error as? DeviceRequestSignerError, .invalidConfiguration)
    }
    let countAfterRejectedRawAck = await coordinator.reservationCount
    XCTAssertEqual(countAfterRejectedRawAck, 1)
  }

  func testKeyControlCanonicalBytesMatchRustContractHash() throws {
    var streamRoute = Data(repeating: 0x31, count: 16)
    streamRoute[14] = 0
    streamRoute[15] = 1
    let request = DeviceKeyControlRequestV1.keySync(
      try DeviceKeySyncRequestV1(
        authority: DeviceKeyControlAuthorityV1(
          machineRoute: Data(repeating: 0x21, count: 16),
          deviceRoute: Data(repeating: 0x22, count: 16),
          grantSerial: 9,
          rootTrustEpoch: 3
        ),
        knownKeyDirectoryRevision: 11,
        requestedKeyDirectoryRevision: 12,
        keyID: KeyIDV1(purpose: .conversationDEK, epoch: 4),
        streamRoute: streamRoute,
        attempt: 1
      )
    )
    let canonical = try KeyControlCanonicalCodec.encode(request)
    XCTAssertEqual(
      CanonicalCodec.sha256(canonical).grantHexString,
      "389ab57550d739c035e0b2a8e8cb5347d2a44ac16b32943a9f9990255d895909"
    )
    XCTAssertEqual(try KeyControlCanonicalCodec.decode(canonical), request)
  }

  func testPairingOuterContextUsesAppendOnlyPairRouteAndRejectsMixedAxes() throws {
    let route = Data(repeating: 0xA7, count: 16)
    let context = OuterContextV1(
      frameKind: .pairTerminal,
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
      pairRoute: route
    )
    let aad = try CanonicalCodec.encodeAAD(context)
    var expectedSuffix = Data("AgentDeck/OuterContextPairRouteV1\0".utf8)
    expectedSuffix.append(contentsOf: [0, 0, 0, 16])
    expectedSuffix.append(route)
    XCTAssertTrue(aad.suffix(expectedSuffix.count) == expectedSuffix)

    var missingRoute = context
    missingRoute.pairRoute = nil
    XCTAssertThrowsError(try CanonicalCodec.encodeAAD(missingRoute))
    var mixed = context
    mixed.machineRoute = Data(repeating: 0xA8, count: 16)
    XCTAssertThrowsError(try CanonicalCodec.encodeAAD(mixed))
    var nonPairing = context
    nonPairing.frameKind = .uplinkSend
    XCTAssertThrowsError(try CanonicalCodec.encodeAAD(nonPairing))
  }

  func testKeySyncMustBeExactNextAndFailsBeforeCounterReservation() async throws {
    let fixture = try makeDeviceRequestFixture()
    let authority = try DeviceKeyControlAuthorityV1(
      machineRoute: fixture.machineRoute,
      deviceRoute: fixture.deviceRoute,
      grantSerial: fixture.grant.grantSerial,
      rootTrustEpoch: fixture.grant.trustEpoch
    )
    let skipped = DeviceKeyControlRequestV1.keySync(
      try DeviceKeySyncRequestV1(
        authority: authority,
        knownKeyDirectoryRevision: fixture.keyDirectoryRevision,
        requestedKeyDirectoryRevision: fixture.keyDirectoryRevision + 2,
        keyID: KeyIDV1(purpose: .catalog, epoch: 12),
        streamRoute: nil,
        attempt: 1
      )
    )
    let coordinator = RequestCounterCoordinator()
    let signer = try makeDeviceRequestSigner(fixture, coordinator: coordinator)
    do {
      _ = try await signer.signKeyControlRequest(skipped, requestRoute: fixture.requestRoute)
      XCTFail("KeySync 只能声明 current 的 exact-next revision")
    } catch let error as DeviceRequestSignerError {
      XCTAssertEqual(error, .invalidConfiguration)
    }
    let reservationCount = await coordinator.reservationCount
    XCTAssertEqual(reservationCount, 0)
  }

  func testAuthenticationTranscriptBindsEveryChallengeGrantAndTrustAxis() async throws {
    let fixture = try makeDeviceRequestFixture()
    let signer = try DeviceRequestSigner(
      expectedRelayServerID: fixture.relayServerID,
      expectedGrant: fixture.grant,
      expectedMachineRoute: fixture.machineRoute,
      expectedDeviceRoute: fixture.deviceRoute,
      expectedGrantSerial: fixture.grant.grantSerial,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.grant.rootKeyId,
      expectedTrustEpoch: fixture.grant.trustEpoch,
      deviceSigningKey: fixture.deviceSigningKey,
      commandKeyID: fixture.keyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision,
      rawCommandKey: fixture.rawCommandKey,
      counterAllocator: CounterAllocator(coordinator: RequestCounterCoordinator())
    )
    let challenge = try RelayDeviceAuthenticationChallenge(
      relayServerID: fixture.relayServerID,
      connectionInstance: Data(repeating: 0x91, count: 16),
      challengeNonce: Data(repeating: 0x92, count: 32)
    )
    let frame = try await signer.authenticationFrame(
      challenge: challenge,
      grant: fixture.grant
    )
    let encoded = try RelayWireCodecV2.encode(frame)
    guard
      case .authenticate(.device(let encodedGrant), let signature) = try RelayWireCodecV2.decode(
        encoded
      ).body
    else {
      return XCTFail("authentication must use the typed device proof")
    }
    XCTAssertEqual(encodedGrant, fixture.grant)

    let expectedTranscript = authenticationTranscript(
      challenge: challenge,
      grant: fixture.grant
    )
    XCTAssertTrue(
      fixture.deviceSigningKey.publicKey.isValidSignature(signature, for: expectedTranscript)
    )

    var tampered = expectedTranscript
    tampered[tampered.index(before: tampered.endIndex)] ^= 1
    XCTAssertFalse(fixture.deviceSigningKey.publicKey.isValidSignature(signature, for: tampered))

    XCTAssertThrowsError(
      try RelayDeviceAuthenticationChallenge(
        relayServerID: Data(repeating: 0, count: 16),
        connectionInstance: challenge.connectionInstance,
        challengeNonce: challenge.challengeNonce
      )
    )
    XCTAssertThrowsError(
      try RelayDeviceAuthenticationChallenge(
        relayServerID: challenge.relayServerID,
        connectionInstance: Data(repeating: 0, count: 16),
        challengeNonce: challenge.challengeNonce
      )
    )
  }

  func testAuthenticationRejectsRelayOrGrantMismatchBeforePrivateSigning() async throws {
    let fixture = try makeDeviceRequestFixture()
    let producer = CountingDeviceSignatureProducer(key: fixture.deviceSigningKey)
    let signer = try DeviceRequestSigner(
      expectedRelayServerID: fixture.relayServerID,
      expectedGrant: fixture.grant,
      expectedMachineRoute: fixture.machineRoute,
      expectedDeviceRoute: fixture.deviceRoute,
      expectedGrantSerial: fixture.grant.grantSerial,
      machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
      machineRootFingerprint: CanonicalCodec.sha256(
        fixture.rootSigningKey.publicKey.rawRepresentation
      ),
      expectedRootKeyID: fixture.grant.rootKeyId,
      expectedTrustEpoch: fixture.grant.trustEpoch,
      signatureProducer: producer,
      commandKeyID: fixture.keyID,
      keyDirectoryRevision: fixture.keyDirectoryRevision,
      rawCommandKey: fixture.rawCommandKey,
      counterAllocator: CounterAllocator(coordinator: RequestCounterCoordinator())
    )

    let wrongRelayChallenge = try RelayDeviceAuthenticationChallenge(
      relayServerID: Data(repeating: 0xFE, count: 16),
      connectionInstance: Data(repeating: 0x91, count: 16),
      challengeNonce: Data(repeating: 0x92, count: 32)
    )
    do {
      _ = try await signer.authenticationFrame(
        challenge: wrongRelayChallenge,
        grant: fixture.grant
      )
      XCTFail("challenge from another Relay trust domain must fail")
    } catch let error as DeviceRequestSignerError {
      XCTAssertEqual(error, .trustBindingMismatch)
    }
    let afterRelayMismatch = await producer.signatureCount
    XCTAssertEqual(afterRelayMismatch, 0)

    let exactChallenge = try RelayDeviceAuthenticationChallenge(
      relayServerID: fixture.relayServerID,
      connectionInstance: Data(repeating: 0x91, count: 16),
      challengeNonce: Data(repeating: 0x92, count: 32)
    )
    let wrongGrant = RelayV2Grant(
      machineRoute: fixture.grant.machineRoute,
      deviceRoute: fixture.grant.deviceRoute,
      deviceSignPubkey: fixture.grant.deviceSignPubkey,
      grantSerial: fixture.grant.grantSerial + 1,
      rootKeyId: fixture.grant.rootKeyId,
      trustEpoch: fixture.grant.trustEpoch,
      signature: fixture.grant.signature
    )
    do {
      _ = try await signer.authenticationFrame(
        challenge: exactChallenge,
        grant: wrongGrant
      )
      XCTFail("non-exact grant/serial must fail")
    } catch let error as DeviceRequestSignerError {
      XCTAssertEqual(error, .trustBindingMismatch)
    }
    let afterGrantMismatch = await producer.signatureCount
    XCTAssertEqual(afterGrantMismatch, 0)
  }

  func testRelayGrantCanonicalCodecMatchesRustGoldenAndIsStrictBounded() throws {
    let grant = RelayV2Grant(
      machineRoute: Data(repeating: 0x44, count: 16),
      deviceRoute: Data(repeating: 0x55, count: 16),
      deviceSignPubkey: Data(repeating: 0x66, count: 32),
      grantSerial: 8,
      rootKeyId: Data(repeating: 0x77, count: 16),
      trustEpoch: 4,
      signature: Data(repeating: 0x88, count: 64)
    )
    let canonical = try RelayGrantCanonicalCodec.encode(grant)
    XCTAssertEqual(canonical.count, 238)
    XCTAssertEqual(try RelayGrantCanonicalCodec.decode(canonical), grant)
    XCTAssertEqual(
      try RelayGrantCanonicalCodec.canonicalSHA256(grant).grantHexString,
      "4d7f552fa647dbe4611943756f4481ee99580d712445f70b5c1d0fe5bbb877dd"
    )
    let transcript = try AuthenticationTranscriptV1.encode(
      challenge: RelayDeviceAuthenticationChallenge(
        relayServerID: Data(repeating: 0xBB, count: 16),
        connectionInstance: Data(repeating: 0xAA, count: 16),
        challengeNonce: Data(repeating: 0x99, count: 32)
      ),
      grant: grant
    )
    XCTAssertEqual(
      transcript.grantHexString,
      "4167656e744465636b2f41757468656e7469636174696f6e5472616e7363726970745631"
        + "000100000020999999999999999999999999999999999999999999999999999999999999"
        + "999900000010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000010bbbbbbbbbbbbbbbbbbbb"
        + "bbbbbbbbbbbb000200000010444444444444444444444444444444440100000010555555"
        + "555555555555555555555555550000000000000008000000204d7f552fa647dbe4611943"
        + "756f4481ee99580d712445f70b5c1d0fe5bbb877dd"
    )

    var trailing = canonical
    trailing.append(0)
    XCTAssertThrowsError(try RelayGrantCanonicalCodec.decode(trailing))
    XCTAssertThrowsError(
      try RelayGrantCanonicalCodec.decode(
        canonical,
        maxEncodedBytes: canonical.count - 1
      )
    )
    XCTAssertThrowsError(
      try RelayGrantCanonicalCodec.decode(
        Data(repeating: 0, count: RelayGrantCanonicalCodec.maximumCanonicalBytes + 1)
      )
    )
  }

  func testRelayGrantCredentialVerifierBindsRootAndEveryPersistedAxis() throws {
    let fixture = try makeDeviceRequestFixture()
    let rootPublic = fixture.rootSigningKey.publicKey.rawRepresentation
    let rootFingerprint = CanonicalCodec.sha256(rootPublic)
    let canonical = try RelayGrantCanonicalCodec.encode(fixture.grant)
    let verified = try RelayGrantCredentialVerifier.verify(
      canonicalBytes: canonical,
      relayServerID: fixture.relayServerID,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: rootFingerprint,
      expectedMachineRoute: fixture.machineRoute,
      expectedDeviceRoute: fixture.deviceRoute,
      expectedDeviceSignPublicKey: fixture.deviceSigningKey.publicKey.rawRepresentation,
      expectedGrantSerial: fixture.grant.grantSerial,
      expectedRootKeyID: fixture.grant.rootKeyId,
      expectedTrustEpoch: fixture.grant.trustEpoch
    )
    XCTAssertEqual(verified.grant, fixture.grant)
    XCTAssertEqual(verified.canonicalBytes, canonical)

    var forgedSignature = fixture.grant.signature
    forgedSignature[0] ^= 1
    let forged = RelayV2Grant(
      machineRoute: fixture.grant.machineRoute,
      deviceRoute: fixture.grant.deviceRoute,
      deviceSignPubkey: fixture.grant.deviceSignPubkey,
      grantSerial: fixture.grant.grantSerial,
      rootKeyId: fixture.grant.rootKeyId,
      trustEpoch: fixture.grant.trustEpoch,
      signature: forgedSignature
    )
    XCTAssertThrowsError(
      try RelayGrantCredentialVerifier.verify(
        forged,
        relayServerID: fixture.relayServerID,
        machineRootPublicKey: rootPublic,
        machineRootFingerprint: rootFingerprint,
        expectedMachineRoute: fixture.machineRoute,
        expectedDeviceRoute: fixture.deviceRoute,
        expectedDeviceSignPublicKey: fixture.deviceSigningKey.publicKey.rawRepresentation,
        expectedGrantSerial: fixture.grant.grantSerial,
        expectedRootKeyID: fixture.grant.rootKeyId,
        expectedTrustEpoch: fixture.grant.trustEpoch
      )
    )
    XCTAssertThrowsError(
      try RelayGrantCredentialVerifier.verify(
        fixture.grant,
        relayServerID: fixture.relayServerID,
        machineRootPublicKey: rootPublic,
        machineRootFingerprint: rootFingerprint,
        expectedMachineRoute: fixture.machineRoute,
        expectedDeviceRoute: fixture.deviceRoute,
        expectedDeviceSignPublicKey: fixture.deviceSigningKey.publicKey.rawRepresentation,
        expectedGrantSerial: fixture.grant.grantSerial + 1,
        expectedRootKeyID: fixture.grant.rootKeyId,
        expectedTrustEpoch: fixture.grant.trustEpoch
      )
    )
  }
}

private func makeDeviceRequestSigner(
  _ fixture: DeviceRequestFixture,
  coordinator: RequestCounterCoordinator
) throws -> DeviceRequestSigner {
  try DeviceRequestSigner(
    expectedRelayServerID: fixture.relayServerID,
    expectedGrant: fixture.grant,
    expectedMachineRoute: fixture.machineRoute,
    expectedDeviceRoute: fixture.deviceRoute,
    expectedGrantSerial: fixture.grant.grantSerial,
    machineRootPublicKey: fixture.rootSigningKey.publicKey.rawRepresentation,
    machineRootFingerprint: CanonicalCodec.sha256(
      fixture.rootSigningKey.publicKey.rawRepresentation
    ),
    expectedRootKeyID: fixture.grant.rootKeyId,
    expectedTrustEpoch: fixture.grant.trustEpoch,
    deviceSigningKey: fixture.deviceSigningKey,
    commandKeyID: fixture.keyID,
    keyDirectoryRevision: fixture.keyDirectoryRevision,
    rawCommandKey: fixture.rawCommandKey,
    counterAllocator: CounterAllocator(coordinator: coordinator)
  )
}

private actor RequestCounterCoordinator: CounterBlockReserving {
  private(set) var reservationCount = 0

  func reserveCounterBlock() async throws -> CounterBlock {
    let start = UInt64(reservationCount) * CounterBlock.size
    reservationCount += 1
    return try CounterBlock(start: start, endExclusive: start + CounterBlock.size)
  }
}

private actor CountingDeviceSignatureProducer: DeviceSignatureProducing {
  nonisolated let publicKeyRawRepresentation: Data
  private let key: Curve25519.Signing.PrivateKey
  private(set) var signatureCount = 0

  init(key: Curve25519.Signing.PrivateKey) {
    self.key = key
    publicKeyRawRepresentation = key.publicKey.rawRepresentation
  }

  func signature(for message: Data) async throws -> Data {
    signatureCount += 1
    return try key.signature(for: message)
  }
}

private struct DeviceRequestFixture {
  let relayServerID: Data
  let machineRoute: Data
  let deviceRoute: Data
  let requestRoute: Data
  let rootSigningKey: Curve25519.Signing.PrivateKey
  let deviceSigningKey: Curve25519.Signing.PrivateKey
  let grant: RelayV2Grant
  let keyID: KeyIDV1
  let keyDirectoryRevision: UInt64
  let rawCommandKey: Data
  let envelope: RuntimeEnvelopeV2
}

private func makeDeviceRequestFixture() throws -> DeviceRequestFixture {
  let relayServerID = Data(repeating: 0x31, count: 16)
  let machineRoute = Data(repeating: 0x32, count: 16)
  let deviceRoute = Data(repeating: 0x33, count: 16)
  let requestRoute = Data(repeating: 0x34, count: 16)
  let rootSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x39, count: 32)
  )
  let deviceSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x35, count: 32)
  )
  let unsignedGrant = RelayV2Grant(
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignPubkey: deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: 6,
    rootKeyId: Data(repeating: 0x36, count: 16),
    trustEpoch: 7,
    signature: Data(repeating: 0, count: 64)
  )
  let rootFingerprint = CanonicalCodec.sha256(
    rootSigningKey.publicKey.rawRepresentation
  )
  let grant = RelayV2Grant(
    machineRoute: unsignedGrant.machineRoute,
    deviceRoute: unsignedGrant.deviceRoute,
    deviceSignPubkey: unsignedGrant.deviceSignPubkey,
    grantSerial: unsignedGrant.grantSerial,
    rootKeyId: unsignedGrant.rootKeyId,
    trustEpoch: unsignedGrant.trustEpoch,
    signature: try RelayCrypto.sign(
      RelayGrantCredentialVerifier.toBeSigned(
        unsignedGrant,
        relayServerID: relayServerID,
        machineRootFingerprint: rootFingerprint
      ),
      key: rootSigningKey
    )
  )
  return DeviceRequestFixture(
    relayServerID: relayServerID,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    requestRoute: requestRoute,
    rootSigningKey: rootSigningKey,
    deviceSigningKey: deviceSigningKey,
    grant: grant,
    keyID: KeyIDV1(purpose: .deviceCommandTx, epoch: 8),
    keyDirectoryRevision: 9,
    rawCommandKey: Data(repeating: 0x38, count: 32),
    envelope: RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "request-message-1"),
      body: .request(.catalog(pageCursor: nil))
    )
  )
}

private func authenticationTranscript(
  challenge: RelayDeviceAuthenticationChallenge,
  grant: RelayV2Grant
) -> Data {
  var output = Data("AgentDeck/AuthenticationTranscriptV1\0".utf8)
  output.append(1)
  requestAppendBytes(challenge.challengeNonce, to: &output)
  requestAppendBytes(challenge.connectionInstance, to: &output)
  requestAppendBytes(challenge.relayServerID, to: &output)
  output.append(contentsOf: requestBigEndian(relayProtocolVersionV2))
  requestAppendBytes(grant.machineRoute, to: &output)
  output.append(1)
  requestAppendBytes(grant.deviceRoute, to: &output)
  output.append(contentsOf: requestBigEndian(grant.grantSerial))
  requestAppendBytes(CanonicalCodec.sha256(relayGrantCanonicalBytes(grant)), to: &output)
  return output
}

private func relayGrantCanonicalBytes(_ grant: RelayV2Grant) -> Data {
  var unsigned = Data("AgentDeck/RelayGrantUnsignedV1\0".utf8)
  requestAppendBytes(grant.machineRoute, to: &unsigned)
  requestAppendBytes(grant.deviceRoute, to: &unsigned)
  requestAppendBytes(grant.deviceSignPubkey, to: &unsigned)
  unsigned.append(contentsOf: requestBigEndian(grant.grantSerial))
  requestAppendBytes(grant.rootKeyId, to: &unsigned)
  unsigned.append(contentsOf: requestBigEndian(grant.trustEpoch))

  var canonical = Data("AgentDeck/RelayGrantV1\0".utf8)
  requestAppendBytes(unsigned, to: &canonical)
  requestAppendBytes(grant.signature, to: &canonical)
  return canonical
}

private func requestAppendBytes(_ value: Data, to output: inout Data) {
  output.append(contentsOf: requestBigEndian(UInt32(value.count)))
  output.append(value)
}

private func requestBigEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
  var encoded = value.bigEndian
  return Swift.withUnsafeBytes(of: &encoded) { Array($0) }
}

extension Data {
  fileprivate var grantHexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
