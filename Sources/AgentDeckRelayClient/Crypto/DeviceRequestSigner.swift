import AgentDeckCore
import CryptoKit
import Foundation

enum DeviceRequestSignerError: Error, Equatable, Sendable {
  case invalidConfiguration
  case trustBindingMismatch
  case invalidRoute
  case signingFailed
}

struct RelayDeviceAuthenticationChallenge: Equatable, Sendable {
  let relayServerID: Data
  let connectionInstance: Data
  let challengeNonce: Data

  init(
    relayServerID: Data,
    connectionInstance: Data,
    challengeNonce: Data
  ) throws {
    guard Self.isNonzero(relayServerID, count: 16),
      Self.isNonzero(connectionInstance, count: 16),
      Self.isNonzero(challengeNonce, count: 32)
    else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    self.relayServerID = relayServerID
    self.connectionInstance = connectionInstance
    self.challengeNonce = challengeNonce
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct SignedDeviceRequest: Equatable, Sendable {
  let requestRoute: Data
  let context: OuterContextV1
  let sealedBlob: SignedSealedBlobV1
}

protocol DeviceSignatureProducing: Sendable {
  var publicKeyRawRepresentation: Data { get }

  func signature(for message: Data) async throws -> Data
}

private struct CryptoKitDeviceSignatureProducer: DeviceSignatureProducing {
  let privateKey: Curve25519.Signing.PrivateKey

  var publicKeyRawRepresentation: Data {
    privateKey.publicKey.rawRepresentation
  }

  func signature(for message: Data) async throws -> Data {
    try privateKey.signature(for: message)
  }
}

struct DeviceRequestSigner: Sendable {
  private let expectedRelayServerID: Data
  private let expectedGrant: RelayV2Grant
  private let signatureProducer: any DeviceSignatureProducing
  private let commandKey: AeadSendingKey
  private let keyControlKey: AeadSendingKey
  private let keySyncProbeKey: AeadSendingKey?
  private let counterAllocator: CounterAllocator

  init(
    expectedRelayServerID: Data,
    expectedGrant: RelayV2Grant,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedGrantSerial: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    deviceSigningKey: Curve25519.Signing.PrivateKey,
    commandKeyID: KeyIDV1,
    keyDirectoryRevision: UInt64,
    rawCommandKey: Data,
    counterAllocator: CounterAllocator
  ) throws {
    try self.init(
      expectedRelayServerID: expectedRelayServerID,
      expectedGrant: expectedGrant,
      expectedMachineRoute: expectedMachineRoute,
      expectedDeviceRoute: expectedDeviceRoute,
      expectedGrantSerial: expectedGrantSerial,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch,
      signatureProducer: CryptoKitDeviceSignatureProducer(privateKey: deviceSigningKey),
      commandKeyID: commandKeyID,
      keyDirectoryRevision: keyDirectoryRevision,
      rawCommandKey: rawCommandKey,
      counterAllocator: counterAllocator
    )
  }

  init(
    expectedRelayServerID: Data,
    expectedGrant: RelayV2Grant,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedGrantSerial: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    deviceSigningKey: Curve25519.Signing.PrivateKey,
    commandKey: AeadSendingKey,
    counterAllocator: CounterAllocator
  ) throws {
    try self.init(
      expectedRelayServerID: expectedRelayServerID,
      expectedGrant: expectedGrant,
      expectedMachineRoute: expectedMachineRoute,
      expectedDeviceRoute: expectedDeviceRoute,
      expectedGrantSerial: expectedGrantSerial,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch,
      signatureProducer: CryptoKitDeviceSignatureProducer(privateKey: deviceSigningKey),
      commandKey: commandKey,
      counterAllocator: counterAllocator
    )
  }

  init(
    expectedRelayServerID: Data,
    expectedGrant: RelayV2Grant,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedGrantSerial: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    signatureProducer: any DeviceSignatureProducing,
    commandKey: AeadSendingKey,
    counterAllocator: CounterAllocator
  ) throws {
    let verifiedGrant = try RelayGrantCredentialVerifier.verify(
      expectedGrant,
      relayServerID: expectedRelayServerID,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedMachineRoute: expectedMachineRoute,
      expectedDeviceRoute: expectedDeviceRoute,
      expectedDeviceSignPublicKey: signatureProducer.publicKeyRawRepresentation,
      expectedGrantSerial: expectedGrantSerial,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch
    )
    guard commandKey.keyID.purpose == .deviceCommandTx,
      commandKey.keyID.epoch > 0,
      commandKey.epoch == commandKey.keyID.epoch,
      commandKey.keyDirectoryRevision > 0,
      commandKey.payloadKind == .commandRequest
    else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    self.expectedRelayServerID = expectedRelayServerID
    self.expectedGrant = verifiedGrant.grant
    self.signatureProducer = signatureProducer
    self.commandKey = commandKey
    keyControlKey = try commandKey.rebinding(
      keyDirectoryRevision: commandKey.keyDirectoryRevision,
      payloadKind: .keyUpdate
    )
    let nextRevision = commandKey.keyDirectoryRevision.addingReportingOverflow(1)
    keySyncProbeKey =
      !nextRevision.overflow
      ? try commandKey.rebinding(
        keyDirectoryRevision: nextRevision.partialValue,
        payloadKind: .keyUpdate
      )
      : nil
    self.counterAllocator = counterAllocator
  }

  init(
    expectedRelayServerID: Data,
    expectedGrant: RelayV2Grant,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedGrantSerial: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64,
    signatureProducer: any DeviceSignatureProducing,
    commandKeyID: KeyIDV1,
    keyDirectoryRevision: UInt64,
    rawCommandKey: Data,
    counterAllocator: CounterAllocator
  ) throws {
    let verifiedGrant = try RelayGrantCredentialVerifier.verify(
      expectedGrant,
      relayServerID: expectedRelayServerID,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedMachineRoute: expectedMachineRoute,
      expectedDeviceRoute: expectedDeviceRoute,
      expectedDeviceSignPublicKey: signatureProducer.publicKeyRawRepresentation,
      expectedGrantSerial: expectedGrantSerial,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch
    )
    guard commandKeyID.purpose == .deviceCommandTx,
      commandKeyID.epoch > 0,
      keyDirectoryRevision > 0,
      Self.isNonzero(rawCommandKey, count: 32)
    else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    self.expectedRelayServerID = expectedRelayServerID
    self.expectedGrant = verifiedGrant.grant
    self.signatureProducer = signatureProducer
    commandKey = try AeadSendingKey(
      keyID: commandKeyID,
      epoch: commandKeyID.epoch,
      keyDirectoryRevision: keyDirectoryRevision,
      payloadKind: .commandRequest,
      rawKey: rawCommandKey
    )
    keyControlKey = try AeadSendingKey(
      keyID: commandKeyID,
      epoch: commandKeyID.epoch,
      keyDirectoryRevision: keyDirectoryRevision,
      payloadKind: .keyUpdate,
      rawKey: rawCommandKey
    )
    let nextRevision = keyDirectoryRevision.addingReportingOverflow(1)
    if !nextRevision.overflow {
      keySyncProbeKey = try AeadSendingKey(
        keyID: commandKeyID,
        epoch: commandKeyID.epoch,
        keyDirectoryRevision: nextRevision.partialValue,
        payloadKind: .keyUpdate,
        rawKey: rawCommandKey
      )
    } else {
      keySyncProbeKey = nil
    }
    self.counterAllocator = counterAllocator
  }

  func signRuntimeRequest(
    _ envelope: RuntimeEnvelopeV2,
    machineRoute: Data,
    deviceRoute: Data,
    requestRoute: Data
  ) async throws -> SignedDeviceRequest {
    guard machineRoute == expectedGrant.machineRoute,
      deviceRoute == expectedGrant.deviceRoute,
      Self.isNonzero(requestRoute, count: 16)
    else {
      throw DeviceRequestSignerError.invalidRoute
    }

    // Runtime validation/encoding is intentionally before durable counter reservation.
    let runtimeBytes = try RuntimeWireCodec.encode(envelope)
    let counter = try await counterAllocator.nextCounter()
    let context = OuterContextV1(
      frameKind: .uplinkSend,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: expectedGrant.machineRoute,
      deviceRoute: expectedGrant.deviceRoute,
      streamRoute: nil,
      requestRoute: requestRoute,
      streamGeneration: nil,
      streamCursor: nil,
      streamSeq: nil,
      messageKeyEpoch: commandKey.epoch
    )
    let unsigned = try RelayCrypto.sealSymmetric(
      runtimeBytes,
      key: commandKey,
      context: context,
      counter: counter
    )
    let signature = try await signatureProducer.signature(
      for: CanonicalCodec.sealedBlobTBS(unsigned, context: context)
    )
    guard Self.isNonzero(signature, count: 64) else {
      throw DeviceRequestSignerError.signingFailed
    }
    let signed = SignedSealedBlobV1(inner: unsigned, signature: signature)
    return SignedDeviceRequest(
      requestRoute: requestRoute,
      context: context,
      sealedBlob: signed
    )
  }

  /// 使用 DeviceCommandTx capability 发送 Runtime 之外的 typed key-control。
  /// raw DTO 入口只允许 KeySync；ACK 必须消费 durable coordinator mint 的 opaque permit。
  func signKeyControlRequest(
    _ request: DeviceKeyControlRequestV1,
    requestRoute: Data
  ) async throws -> SignedDeviceRequest {
    let authority = request.authority
    guard authority.machineRoute == expectedGrant.machineRoute,
      authority.deviceRoute == expectedGrant.deviceRoute,
      authority.grantSerial == expectedGrant.grantSerial,
      authority.rootTrustEpoch == expectedGrant.trustEpoch,
      Self.isNonzero(requestRoute, count: 16)
    else {
      throw DeviceRequestSignerError.trustBindingMismatch
    }

    guard case .keySync(let probe) = request else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    let next = commandKey.keyDirectoryRevision.addingReportingOverflow(1)
    guard !next.overflow,
      probe.knownKeyDirectoryRevision == commandKey.keyDirectoryRevision,
      probe.requestedKeyDirectoryRevision == next.partialValue,
      let keySyncProbeKey,
      keySyncProbeKey.keyDirectoryRevision == probe.requestedKeyDirectoryRevision
    else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    return try await signAuthorizedKeyControl(
      request,
      requestRoute: requestRoute,
      sealingKey: keySyncProbeKey
    )
  }

  func signKeyUpdateAcknowledgement(
    permit: DurableKeyUpdateAckPermit,
    authority: DeviceKeyControlAuthorityV1,
    requestRoute: Data
  ) async throws -> SignedDeviceRequest {
    try validate(permit.trustScope, authority: authority)
    let request = DeviceKeyControlRequestV1.keyUpdateAck(
      try DeviceKeyUpdateAckV1(
        authority: authority,
        keyDirectoryRevision: permit.keyDirectoryRevision,
        updateSetSHA256: permit.updateSetSHA256
      ))
    return try await signAuthorizedKeyControl(
      request,
      requestRoute: requestRoute,
      sealingKey: try acknowledgementKey(revision: permit.keyDirectoryRevision)
    )
  }

  func signStreamAppliedAcknowledgement(
    permit: DurableStreamAppliedAckPermit,
    authority: DeviceKeyControlAuthorityV1,
    requestRoute: Data
  ) async throws -> SignedDeviceRequest {
    try validate(permit.trustScope, authority: authority)
    let request = DeviceKeyControlRequestV1.streamAppliedAck(
      try DeviceStreamAppliedAckV1(
        authority: authority,
        streamRoute: permit.streamRoute,
        streamGeneration: permit.streamGeneration,
        appliedStreamSequence: permit.appliedStreamSequence,
        innerCursor: try runtimeInnerCursor(permit.innerCursor),
        keyDirectoryRevision: permit.keyDirectoryRevision,
        keyEpoch: permit.keyEpoch,
        epochBarrierSHA256: permit.epochBarrierSHA256
      ))
    return try await signAuthorizedKeyControl(
      request,
      requestRoute: requestRoute,
      sealingKey: try acknowledgementKey(revision: permit.keyDirectoryRevision)
    )
  }

  private func signAuthorizedKeyControl(
    _ request: DeviceKeyControlRequestV1,
    requestRoute: Data,
    sealingKey: AeadSendingKey
  ) async throws -> SignedDeviceRequest {
    let authority = request.authority
    guard authority.machineRoute == expectedGrant.machineRoute,
      authority.deviceRoute == expectedGrant.deviceRoute,
      authority.grantSerial == expectedGrant.grantSerial,
      authority.rootTrustEpoch == expectedGrant.trustEpoch,
      request.declaredKeyDirectoryRevision == sealingKey.keyDirectoryRevision,
      Self.isNonzero(requestRoute, count: 16)
    else {
      throw DeviceRequestSignerError.trustBindingMismatch
    }

    let canonical = try KeyControlCanonicalCodec.encode(request)
    let counter = try await counterAllocator.nextCounter()
    let context = OuterContextV1(
      frameKind: .uplinkSend,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: 1,
      machineRoute: expectedGrant.machineRoute,
      deviceRoute: expectedGrant.deviceRoute,
      streamRoute: nil,
      requestRoute: requestRoute,
      streamGeneration: nil,
      streamCursor: nil,
      streamSeq: nil,
      messageKeyEpoch: sealingKey.epoch
    )
    let unsigned = try RelayCrypto.sealSymmetric(
      canonical,
      key: sealingKey,
      context: context,
      counter: counter
    )
    let signature: Data
    do {
      signature = try await signatureProducer.signature(
        for: CanonicalCodec.sealedBlobTBS(unsigned, context: context)
      )
    } catch {
      throw DeviceRequestSignerError.signingFailed
    }
    guard Self.isNonzero(signature, count: 64) else {
      throw DeviceRequestSignerError.signingFailed
    }
    return SignedDeviceRequest(
      requestRoute: requestRoute,
      context: context,
      sealedBlob: SignedSealedBlobV1(inner: unsigned, signature: signature)
    )
  }

  private func acknowledgementKey(revision: UInt64) throws -> AeadSendingKey {
    if revision == keyControlKey.keyDirectoryRevision { return keyControlKey }
    guard let keySyncProbeKey,
      revision == keySyncProbeKey.keyDirectoryRevision
    else {
      throw DeviceRequestSignerError.invalidConfiguration
    }
    return keySyncProbeKey
  }

  private func validate(
    _ trustScope: DeviceCryptoTrustScopeV1,
    authority: DeviceKeyControlAuthorityV1
  ) throws {
    guard trustScope.relayServerID == expectedRelayServerID,
      trustScope.machineRoute == expectedGrant.machineRoute,
      trustScope.deviceRoute == expectedGrant.deviceRoute,
      trustScope.grantSerial == expectedGrant.grantSerial,
      trustScope.trustEpoch == expectedGrant.trustEpoch,
      authority.machineRoute == trustScope.machineRoute,
      authority.deviceRoute == trustScope.deviceRoute,
      authority.grantSerial == trustScope.grantSerial,
      authority.rootTrustEpoch == trustScope.trustEpoch
    else {
      throw DeviceRequestSignerError.trustBindingMismatch
    }
  }

  private func runtimeInnerCursor(
    _ cursor: DeviceInnerCursorV1
  ) throws -> RuntimeInnerCursorV1 {
    switch cursor {
    case .catalog(let value):
      return .catalog(cursor: runtimeCursor(value))
    case .conversation(let id, let value):
      return .conversation(
        conversationID: RuntimeConversationID(rawValue: id),
        cursor: runtimeCursor(value)
      )
    }
  }

  private func runtimeCursor(_ cursor: StreamCursor) -> RuntimeStreamCursorV1 {
    switch cursor {
    case .beforeFirst: .beforeFirst
    case .at(let value): .at(value)
    }
  }

  func authenticationFrame(
    challenge: RelayDeviceAuthenticationChallenge,
    grant: RelayV2Grant
  ) async throws -> RelayV2OutboundFrame {
    // Every trust axis is checked before the private signing operation.
    guard challenge.relayServerID == expectedRelayServerID,
      grant == expectedGrant,
      grant.machineRoute == expectedGrant.machineRoute,
      grant.deviceRoute == expectedGrant.deviceRoute,
      grant.grantSerial == expectedGrant.grantSerial
    else {
      throw DeviceRequestSignerError.trustBindingMismatch
    }
    let transcript = try AuthenticationTranscriptV1.encode(
      challenge: challenge,
      grant: expectedGrant
    )
    let signature: Data
    do {
      signature = try await signatureProducer.signature(for: transcript)
    } catch {
      throw DeviceRequestSignerError.signingFailed
    }
    guard Self.isNonzero(signature, count: 64) else {
      throw DeviceRequestSignerError.signingFailed
    }
    return RelayV2OutboundFrame.control(
      .authenticate(
        proof: .device(relayGrant: expectedGrant),
        signature: signature
      )
    )
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum AuthenticationTranscriptV1 {
  static func encode(
    challenge: RelayDeviceAuthenticationChallenge,
    grant: RelayV2Grant
  ) throws -> Data {
    var output = Data("AgentDeck/AuthenticationTranscriptV1\0".utf8)
    output.append(1)
    appendBytes(challenge.challengeNonce, to: &output)
    appendBytes(challenge.connectionInstance, to: &output)
    appendBytes(challenge.relayServerID, to: &output)
    appendBigEndian(relayProtocolVersionV2, to: &output)
    appendBytes(grant.machineRoute, to: &output)
    output.append(1)
    appendBytes(grant.deviceRoute, to: &output)
    appendBigEndian(grant.grantSerial, to: &output)
    appendBytes(
      try RelayGrantCanonicalCodec.canonicalSHA256(grant),
      to: &output
    )
    return output
  }

  private static func appendBytes(_ value: Data, to output: inout Data) {
    appendBigEndian(UInt32(value.count), to: &output)
    output.append(value)
  }

  private static func appendBigEndian<T: FixedWidthInteger>(
    _ value: T,
    to output: inout Data
  ) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }
}
