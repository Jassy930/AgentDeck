import AgentDeckCore
import CryptoKit
import Foundation

enum KeyDirectoryVerifierError: Error, Equatable, Sendable {
  case invalidEncoding
  case sizeLimit
  case invalidTrustBinding
  case invalidContext
  case revisionMismatch
  case badSignature
  case hpkeOpenFailed
  case invalidKeyMaterial
  case missingRequiredKey
  case invalidBootstrapRoster
}

/// Rust `KeyUpdateV1` 的严格、canonical Swift mirror。
struct CanonicalKeyUpdateV1: Equatable, Sendable, CustomDebugStringConvertible {
  static let encapsulatedKeyBytes = 32
  static let wrappedKeyBytes = 48
  static let signatureBytes = 64

  let keyDirectoryRevision: UInt64
  let keyID: KeyIDV1
  let deviceRoute: Data
  let streamRoute: Data?
  let enc: Data
  let wrappedKey: Data
  let signature: Data

  init(
    keyDirectoryRevision: UInt64,
    keyID: KeyIDV1,
    deviceRoute: Data,
    streamRoute: Data?,
    enc: Data,
    wrappedKey: Data,
    signature: Data,
    requireSignature: Bool = true
  ) throws {
    guard keyDirectoryRevision > 0,
      keyID.epoch > 0,
      Self.isNonzero(deviceRoute, count: 16),
      Self.streamShapeIsValid(purpose: keyID.purpose, streamRoute: streamRoute),
      Self.isNonzero(enc, count: Self.encapsulatedKeyBytes),
      Self.isNonzero(wrappedKey, count: Self.wrappedKeyBytes),
      signature.count == Self.signatureBytes,
      requireSignature == !signature.allSatisfy({ $0 == 0 })
    else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    self.keyDirectoryRevision = keyDirectoryRevision
    self.keyID = keyID
    self.deviceRoute = deviceRoute
    self.streamRoute = streamRoute
    self.enc = enc
    self.wrappedKey = wrappedKey
    self.signature = signature
  }

  var debugDescription: String {
    "CanonicalKeyUpdateV1(revision: \(keyDirectoryRevision), material: <redacted>)"
  }

  fileprivate static func streamShapeIsValid(
    purpose: KeyPurpose,
    streamRoute: Data?
  ) -> Bool {
    switch purpose {
    case .conversationDEK:
      return streamRoute.map({ isNonzero($0, count: 16) }) ?? false
    case .catalog, .deviceCommandTx, .deviceReplyTx:
      return streamRoute == nil
    }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum KeyDirectoryCanonicalCodec {
  static let maximumUnsignedBytes = 512 * 1_024
  static let maximumCanonicalBytes = maximumUnsignedBytes + 128

  private static let domain = Data("AgentDeck/KeyDirectoryV1\0".utf8)
  private static let unsignedDomain = Data("AgentDeck/KeyDirectoryUnsignedV1\0".utf8)

  static func unsignedCanonicalBytes(_ directory: DeviceKeyDirectoryV1) throws -> Data {
    var encoder = KeyCanonicalEncoder(maximumBytes: maximumUnsignedBytes)
    try encoder.domain(unsignedDomain)
    try encoder.u64(directory.revision)
    try encoder.u16Count(directory.entries.count)
    for entry in directory.entries {
      try encoder.u8(entry.keyID.purpose.canonicalTag)
      try encoder.u64(entry.keyID.epoch)
      try encoder.bytes(entry.deviceRoute, exact: 16)
      try encoder.optionalID16(entry.streamRoute)
      try encoder.bytes(entry.enc, exact: DeviceWrappedKeyV1.encapsulatedKeyBytes)
      try encoder.bytes(entry.wrappedKey, exact: DeviceWrappedKeyV1.wrappedKeyBytes)
    }
    return try encoder.finish()
  }

  static func encode(_ directory: DeviceKeyDirectoryV1) throws -> Data {
    let unsigned = try unsignedCanonicalBytes(directory)
    var encoder = KeyCanonicalEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(domain)
    try encoder.bytes(unsigned, maximum: maximumUnsignedBytes)
    try encoder.bytes(directory.signature, exact: 64)
    return try encoder.finish()
  }

  static func decode(
    _ bytes: Data,
    maximumEncodedBytes: Int = maximumCanonicalBytes
  ) throws -> DeviceKeyDirectoryV1 {
    guard maximumEncodedBytes >= 0 else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    guard bytes.count <= maximumCanonicalBytes,
      bytes.count <= maximumEncodedBytes
    else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    var outer = KeyCanonicalDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumUnsignedBytes)
    let signature = try outer.bytes(exact: 64)
    try outer.finish()

    var decoder = KeyCanonicalDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let revision = try decoder.u64()
    let count = try decoder.u16Count(maximum: DeviceKeyDirectoryV1.maximumEntries)
    var entries: [DeviceWrappedKeyV1] = []
    entries.reserveCapacity(count)
    for _ in 0..<count {
      guard let purpose = decodeKeyPurpose(canonicalTag: try decoder.u8()) else {
        throw KeyDirectoryVerifierError.invalidEncoding
      }
      let keyID = KeyIDV1(purpose: purpose, epoch: try decoder.u64())
      let deviceRoute = try decoder.bytes(exact: 16)
      let streamRoute = try decoder.optionalID16()
      let enc = try decoder.bytes(exact: DeviceWrappedKeyV1.encapsulatedKeyBytes)
      let wrappedKey = try decoder.bytes(exact: DeviceWrappedKeyV1.wrappedKeyBytes)
      do {
        entries.append(
          try DeviceWrappedKeyV1(
            keyID: keyID,
            deviceRoute: deviceRoute,
            streamRoute: streamRoute,
            enc: enc,
            wrappedKey: wrappedKey
          ))
      } catch {
        throw KeyDirectoryVerifierError.invalidEncoding
      }
    }
    try decoder.finish()
    let directory: DeviceKeyDirectoryV1
    do {
      directory = try DeviceKeyDirectoryV1(
        revision: revision,
        entries: entries,
        signature: signature
      )
    } catch {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    guard try encode(directory) == bytes else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    return directory
  }

  static func unsignedCanonicalSHA256(_ directory: DeviceKeyDirectoryV1) throws -> Data {
    CanonicalCodec.sha256(try unsignedCanonicalBytes(directory))
  }
}

enum KeyUpdateCanonicalCodec {
  static let maximumCanonicalBytes = 1_024

  private static let domain = Data("AgentDeck/KeyUpdateV1\0".utf8)
  private static let unsignedDomain = Data("AgentDeck/KeyUpdateUnsignedV1\0".utf8)

  static func unsignedCanonicalBytes(_ update: CanonicalKeyUpdateV1) throws -> Data {
    var encoder = KeyCanonicalEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(unsignedDomain)
    try encoder.u64(update.keyDirectoryRevision)
    try encoder.u8(update.keyID.purpose.canonicalTag)
    try encoder.u64(update.keyID.epoch)
    try encoder.bytes(update.deviceRoute, exact: 16)
    try encoder.optionalID16(update.streamRoute)
    try encoder.bytes(update.enc, exact: CanonicalKeyUpdateV1.encapsulatedKeyBytes)
    try encoder.bytes(update.wrappedKey, exact: CanonicalKeyUpdateV1.wrappedKeyBytes)
    return try encoder.finish()
  }

  static func encode(_ update: CanonicalKeyUpdateV1) throws -> Data {
    guard !update.signature.allSatisfy({ $0 == 0 }) else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    var encoder = KeyCanonicalEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(domain)
    try encoder.bytes(
      unsignedCanonicalBytes(update),
      maximum: maximumCanonicalBytes
    )
    try encoder.bytes(update.signature, exact: CanonicalKeyUpdateV1.signatureBytes)
    return try encoder.finish()
  }

  static func decode(
    _ bytes: Data,
    maximumEncodedBytes: Int = maximumCanonicalBytes
  ) throws -> CanonicalKeyUpdateV1 {
    guard maximumEncodedBytes >= 0 else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    guard bytes.count <= maximumCanonicalBytes,
      bytes.count <= maximumEncodedBytes
    else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    var outer = KeyCanonicalDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumCanonicalBytes)
    let signature = try outer.bytes(exact: CanonicalKeyUpdateV1.signatureBytes)
    try outer.finish()

    var decoder = KeyCanonicalDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let revision = try decoder.u64()
    guard let purpose = decodeKeyPurpose(canonicalTag: try decoder.u8()) else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    let update = try CanonicalKeyUpdateV1(
      keyDirectoryRevision: revision,
      keyID: KeyIDV1(purpose: purpose, epoch: try decoder.u64()),
      deviceRoute: try decoder.bytes(exact: 16),
      streamRoute: try decoder.optionalID16(),
      enc: try decoder.bytes(exact: CanonicalKeyUpdateV1.encapsulatedKeyBytes),
      wrappedKey: try decoder.bytes(exact: CanonicalKeyUpdateV1.wrappedKeyBytes),
      signature: signature
    )
    try decoder.finish()
    guard try encode(update) == bytes else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    return update
  }
}

private struct MachineDataSignerCredential: Sendable {
  let verifyingKey: Curve25519.Signing.PublicKey
  let fingerprint: Data
  let generation: UInt64
  let certificateSHA256: Data

  init(_ verified: VerifiedMachineDataCertificate) throws {
    let certificate = verified.certificate
    let observedFingerprint = CanonicalCodec.sha256(
      verified.signingKey.rawRepresentation
    )
    guard certificate.certRole == .data,
      certificate.subjectPubkey == verified.signingKey.rawRepresentation,
      observedFingerprint == CanonicalCodec.sha256(certificate.subjectPubkey),
      observedFingerprint.contains(where: { $0 != 0 }),
      certificate.generation > 0
    else {
      throw KeyDirectoryVerifierError.invalidTrustBinding
    }
    verifyingKey = verified.signingKey
    fingerprint = observedFingerprint
    generation = certificate.generation
    do {
      certificateSHA256 = try SignedCertificateCanonicalCodec.canonicalSHA256(certificate)
    } catch {
      throw KeyDirectoryVerifierError.invalidTrustBinding
    }
    guard certificateSHA256.contains(where: { $0 != 0 }) else {
      throw KeyDirectoryVerifierError.invalidTrustBinding
    }
  }
}

private struct KeyUpdateTrustContext: Sendable {
  let relayServerID: Data
  let machineRootFingerprint: Data
  let machineRoute: Data
  let deviceRoute: Data
  let grantSerial: UInt64
  let rootTrustEpoch: UInt64

  init(record: StoredPairedMachineRecordV1) throws {
    guard Self.isNonzero(record.relayServerID, count: 16),
      Self.isNonzero(record.machineRootFingerprint, count: 32),
      Self.isNonzero(record.machineRoute, count: 16),
      Self.isNonzero(record.deviceRoute, count: 16),
      record.grantSerial > 0,
      record.trustEpoch > 0
    else {
      throw KeyDirectoryVerifierError.invalidTrustBinding
    }
    relayServerID = record.relayServerID
    machineRootFingerprint = record.machineRootFingerprint
    machineRoute = record.machineRoute
    deviceRoute = record.deviceRoute
    grantSerial = record.grantSerial
    rootTrustEpoch = record.trustEpoch
  }

  private static func isNonzero(_ data: Data, count: Int) -> Bool {
    data.count == count && data.contains(where: { $0 != 0 })
  }
}

struct KeyUpdateSealingContextV1: Equatable, Sendable {
  let info: Data
  let outerContext: OuterContextV1
}

struct VerifiedKeyDirectoryV1: Sendable, CustomDebugStringConvertible {
  let directory: DeviceKeyDirectoryV1
  let canonicalBytes: Data

  var debugDescription: String {
    "VerifiedKeyDirectoryV1(revision: \(directory.revision), material: <redacted>)"
  }
}

struct OpenedKeyUpdateV1: Sendable, CustomDebugStringConvertible {
  let keyDirectoryRevision: UInt64
  let keyID: KeyIDV1
  let streamRoute: Data?
  let material: OpenedKeyMaterialCapabilityV1

  var debugDescription: String {
    "OpenedKeyUpdateV1(revision: \(keyDirectoryRevision), material: <redacted>)"
  }

  func makeReceivingKey() throws -> InstalledReceivingKeyV1 {
    guard keyID.purpose != .deviceCommandTx else {
      throw KeyDirectoryVerifierError.invalidContext
    }
    return try material.makeReceivingKey(
      keyDirectoryRevision: keyDirectoryRevision
    )
  }

  func makeCommandSendingKey() throws -> AeadSendingKey {
    guard keyID.purpose == .deviceCommandTx else {
      throw KeyDirectoryVerifierError.invalidContext
    }
    return try material.makeSendingKey(
      keyDirectoryRevision: keyDirectoryRevision,
      payloadKind: .commandRequest
    )
  }
}

struct InstalledReceivingKeyV1: Sendable, CustomDebugStringConvertible {
  let streamRoute: Data?
  let keyDirectoryRevision: UInt64
  let noncePrefix: Data
  let key: AeadReceivingKey

  fileprivate init(
    streamRoute: Data?,
    keyDirectoryRevision: UInt64,
    noncePrefix: Data,
    key: AeadReceivingKey
  ) throws {
    guard streamRoute.map({ $0.count == 16 && $0.contains(where: { $0 != 0 }) }) ?? true,
      keyDirectoryRevision > 0,
      noncePrefix.count == 4
    else {
      throw KeyDirectoryVerifierError.invalidKeyMaterial
    }
    self.streamRoute = streamRoute
    self.keyDirectoryRevision = keyDirectoryRevision
    self.noncePrefix = noncePrefix
    self.key = key
  }

  var debugDescription: String {
    "InstalledReceivingKeyV1(material: <redacted>)"
  }
}

/// bootstrap / cold-open 全量验签、HPKE open 与 authenticated roster 对账后的封闭能力。
///
/// 该 carrier 只代表 immutable pairing directory；live key sync 必须消费逐项签名的
/// `KeyUpdateSetV1` 并等待 `EpochBarrierV1`，禁止把 updates 合成为新的整体 directory。
struct AuditedBootstrapKeyDirectoryV1: Sendable, CustomDebugStringConvertible {
  let directory: DeviceKeyDirectoryV1
  let commandKey: AeadSendingKey
  let receivingKeys: [InstalledReceivingKeyV1]
  fileprivate let materials: [OpenedKeyMaterialCapabilityV1]

  var debugDescription: String {
    "AuditedBootstrapKeyDirectoryV1(revision: \(directory.revision), material: <redacted>)"
  }

  func material(
    keyID: KeyIDV1,
    streamRoute: Data?
  ) -> OpenedKeyMaterialCapabilityV1? {
    materials.first(where: { $0.keyID == keyID && $0.streamRoute == streamRoute })
  }
}

struct KeyDirectoryVerifier: Sendable {
  private static let e2eeFormatVersion: UInt16 = 1

  private let trust: KeyUpdateTrustContext
  private let signer: MachineDataSignerCredential
  private let deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey

  init(material: PairedMachineConnectionMaterial) throws {
    try self.init(
      record: material.record,
      verifiedCertificate: material.machineDataCertificate,
      deviceHPKEPrivateKey: material.deviceHPKEPrivateKey
    )
  }

  init(
    record: StoredPairedMachineRecordV1,
    verifiedCertificate: VerifiedMachineDataCertificate,
    deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey
  ) throws {
    guard record.machineDataCertificate == verifiedCertificate.certificate else {
      throw KeyDirectoryVerifierError.invalidTrustBinding
    }
    trust = try KeyUpdateTrustContext(record: record)
    signer = try MachineDataSignerCredential(verifiedCertificate)
    self.deviceHPKEPrivateKey = deviceHPKEPrivateKey
  }

  func trustMatches(_ scope: DeviceCryptoTrustScopeV1) -> Bool {
    trust.relayServerID == scope.relayServerID
      && trust.machineRootFingerprint == scope.machineRootFingerprint
      && trust.machineRoute == scope.machineRoute
      && trust.deviceRoute == scope.deviceRoute
      && trust.grantSerial == scope.grantSerial
      && trust.rootTrustEpoch == scope.trustEpoch
  }

  func verifyDirectory(
    canonicalBytes: Data,
    expectedRevision: UInt64
  ) throws -> VerifiedKeyDirectoryV1 {
    let directory = try KeyDirectoryCanonicalCodec.decode(canonicalBytes)
    guard expectedRevision > 0,
      directory.revision == expectedRevision,
      directory.entries.allSatisfy({ $0.deviceRoute == trust.deviceRoute })
    else {
      throw KeyDirectoryVerifierError.revisionMismatch
    }
    let tbs = try directorySignatureTBS(directory)
    guard signer.verifyingKey.isValidSignature(directory.signature, for: tbs) else {
      throw KeyDirectoryVerifierError.badSignature
    }
    return VerifiedKeyDirectoryV1(
      directory: directory,
      canonicalBytes: canonicalBytes
    )
  }

  fileprivate func openDirectory(
    _ verified: VerifiedKeyDirectoryV1
  ) throws -> OpenedKeyDirectoryV1 {
    var opened: [OpenedKeyMaterialCapabilityV1] = []
    opened.reserveCapacity(verified.directory.entries.count)
    for entry in verified.directory.entries {
      let sealing = try sealingContext(
        keyDirectoryRevision: verified.directory.revision,
        keyID: entry.keyID,
        streamRoute: entry.streamRoute
      )
      let raw = try openHPKE(
        enc: entry.enc,
        wrappedKey: entry.wrappedKey,
        sealing: sealing
      )
      opened.append(
        OpenedKeyMaterialCapabilityV1(
          keyID: entry.keyID,
          streamRoute: entry.streamRoute,
          rawKey: raw
        ))
    }
    return OpenedKeyDirectoryV1(
      directory: verified.directory,
      materials: opened
    )
  }

  func openKeyUpdate(
    canonicalBytes: Data,
    expectedRevision: UInt64
  ) throws -> OpenedKeyUpdateV1 {
    let update = try KeyUpdateCanonicalCodec.decode(canonicalBytes)
    guard expectedRevision > 0,
      update.keyDirectoryRevision == expectedRevision,
      update.deviceRoute == trust.deviceRoute
    else {
      throw KeyDirectoryVerifierError.revisionMismatch
    }
    let sealing = try sealingContext(
      keyDirectoryRevision: update.keyDirectoryRevision,
      keyID: update.keyID,
      streamRoute: update.streamRoute
    )
    let tbs = try keyUpdateSignatureTBS(update, sealing: sealing)
    guard signer.verifyingKey.isValidSignature(update.signature, for: tbs) else {
      throw KeyDirectoryVerifierError.badSignature
    }
    let raw = try openHPKE(
      enc: update.enc,
      wrappedKey: update.wrappedKey,
      sealing: sealing
    )
    return OpenedKeyUpdateV1(
      keyDirectoryRevision: update.keyDirectoryRevision,
      keyID: update.keyID,
      streamRoute: update.streamRoute,
      material: OpenedKeyMaterialCapabilityV1(
        keyID: update.keyID,
        streamRoute: update.streamRoute,
        rawKey: raw
      )
    )
  }

  func auditBootstrapDirectory(
    canonicalBytes: Data,
    expectedRevision: UInt64,
    expectedConversationRoutes: [Data]
  ) throws -> AuditedBootstrapKeyDirectoryV1 {
    let verified = try verifyDirectory(
      canonicalBytes: canonicalBytes,
      expectedRevision: expectedRevision
    )
    try validateBootstrapRoster(
      verified.directory,
      expectedConversationRoutes: expectedConversationRoutes
    )
    let opened = try openDirectory(verified)
    guard
      let command = opened.materials.first(where: {
        $0.keyID.purpose == .deviceCommandTx
      })
    else {
      throw KeyDirectoryVerifierError.missingRequiredKey
    }
    let commandKey = try command.makeSendingKey(
      keyDirectoryRevision: verified.directory.revision,
      payloadKind: .commandRequest
    )
    let receiving = try opened.materials.compactMap {
      material -> InstalledReceivingKeyV1? in
      guard material.keyID.purpose != .deviceCommandTx else { return nil }
      return try material.makeReceivingKey(
        keyDirectoryRevision: verified.directory.revision
      )
    }
    return AuditedBootstrapKeyDirectoryV1(
      directory: verified.directory,
      commandKey: commandKey,
      receivingKeys: receiving,
      materials: opened.materials
    )
  }

  func sealingContext(
    keyDirectoryRevision: UInt64,
    keyID: KeyIDV1,
    streamRoute: Data?
  ) throws -> KeyUpdateSealingContextV1 {
    guard keyDirectoryRevision > 0,
      keyID.epoch > 0,
      CanonicalKeyUpdateV1.streamShapeIsValid(
        purpose: keyID.purpose,
        streamRoute: streamRoute
      )
    else {
      throw KeyDirectoryVerifierError.invalidContext
    }
    var info = KeyCanonicalEncoder(maximumBytes: KeyUpdateCanonicalCodec.maximumCanonicalBytes)
    try info.domain(Data("AgentDeck/KeyUpdateInfoV1\0".utf8))
    try info.u16(Self.e2eeFormatVersion)
    try info.u16(runtimeProtocolVersionCurrent)
    try info.bytes(trust.relayServerID, exact: 16)
    try info.bytes(trust.machineRoute, exact: 16)
    try info.bytes(trust.deviceRoute, exact: 16)
    try info.optionalID16(streamRoute)
    try info.u64(trust.grantSerial)
    try info.u64(trust.rootTrustEpoch)
    try info.u64(keyDirectoryRevision)
    try info.u8(keyID.purpose.canonicalTag)
    try info.u64(keyID.epoch)
    let outer = OuterContextV1(
      frameKind: .keyUpdate,
      relayProtocolVersion: relayProtocolVersionV2,
      e2eeFormatVersion: Self.e2eeFormatVersion,
      machineRoute: trust.machineRoute,
      deviceRoute: trust.deviceRoute,
      streamRoute: streamRoute,
      requestRoute: nil,
      streamGeneration: nil,
      streamCursor: nil,
      streamSeq: nil,
      messageKeyEpoch: keyID.epoch
    )
    return KeyUpdateSealingContextV1(
      info: try info.finish(),
      outerContext: outer
    )
  }

  func directorySignatureTBS(_ directory: DeviceKeyDirectoryV1) throws -> Data {
    guard directory.revision > 0,
      directory.entries.allSatisfy({ $0.deviceRoute == trust.deviceRoute })
    else {
      throw KeyDirectoryVerifierError.invalidContext
    }
    var encoder = KeyCanonicalEncoder(maximumBytes: 1_024)
    try encoder.domain(Data("AgentDeck/KeyDirectoryTbsV1\0".utf8))
    try encoder.u16(Self.e2eeFormatVersion)
    try encoder.u16(runtimeProtocolVersionCurrent)
    try encoder.u16(relayProtocolVersionV2)
    try encoder.bytes(trust.relayServerID, exact: 16)
    try encoder.bytes(trust.machineRoute, exact: 16)
    try encoder.bytes(trust.deviceRoute, exact: 16)
    try encoder.u64(trust.grantSerial)
    try encoder.u64(trust.rootTrustEpoch)
    try encoder.u64(directory.revision)
    try encoder.bytes(signer.fingerprint, exact: 32)
    try encoder.u64(signer.generation)
    try encoder.bytes(signer.certificateSHA256, exact: 32)
    try encoder.bytes(
      KeyDirectoryCanonicalCodec.unsignedCanonicalSHA256(directory),
      exact: 32
    )
    return try encoder.finish()
  }

  func keyUpdateSignatureTBS(
    _ update: CanonicalKeyUpdateV1,
    sealing: KeyUpdateSealingContextV1
  ) throws -> Data {
    guard update.deviceRoute == trust.deviceRoute,
      update.keyDirectoryRevision > 0,
      update.keyID.epoch > 0,
      update.streamRoute == sealing.outerContext.streamRoute,
      sealing.outerContext.frameKind == .keyUpdate,
      sealing.outerContext.relayProtocolVersion == relayProtocolVersionV2,
      sealing.outerContext.e2eeFormatVersion == Self.e2eeFormatVersion,
      sealing.outerContext.machineRoute == trust.machineRoute,
      sealing.outerContext.deviceRoute == trust.deviceRoute,
      sealing.outerContext.requestRoute == nil,
      sealing.outerContext.streamGeneration == nil,
      sealing.outerContext.streamCursor == nil,
      sealing.outerContext.streamSeq == nil,
      sealing.outerContext.messageKeyEpoch == update.keyID.epoch
    else {
      throw KeyDirectoryVerifierError.invalidContext
    }
    var encoder = KeyCanonicalEncoder(maximumBytes: KeyUpdateCanonicalCodec.maximumCanonicalBytes)
    try encoder.domain(Data("AgentDeck/KeyUpdateTbsV1\0".utf8))
    try encoder.u16(Self.e2eeFormatVersion)
    try encoder.u16(runtimeProtocolVersionCurrent)
    try encoder.u16(relayProtocolVersionV2)
    try encoder.bytes(trust.relayServerID, exact: 16)
    try encoder.bytes(trust.machineRoute, exact: 16)
    try encoder.bytes(trust.deviceRoute, exact: 16)
    try encoder.u64(trust.grantSerial)
    try encoder.u64(trust.rootTrustEpoch)
    try encoder.u64(update.keyDirectoryRevision)
    try encoder.u8(update.keyID.purpose.canonicalTag)
    try encoder.u64(update.keyID.epoch)
    try encoder.optionalID16(update.streamRoute)
    try encoder.bytes(signer.fingerprint, exact: 32)
    try encoder.u64(signer.generation)
    try encoder.bytes(signer.certificateSHA256, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(sealing.info), exact: 32)
    try encoder.bytes(
      CanonicalCodec.sha256(try CanonicalCodec.encodeAAD(sealing.outerContext)),
      exact: 32
    )
    try encoder.bytes(update.enc, exact: CanonicalKeyUpdateV1.encapsulatedKeyBytes)
    try encoder.bytes(CanonicalCodec.sha256(update.wrappedKey), exact: 32)
    return try encoder.finish()
  }

  private func openHPKE(
    enc: Data,
    wrappedKey: Data,
    sealing: KeyUpdateSealingContextV1
  ) throws -> Data {
    let plaintext: Data
    do {
      plaintext = try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(enc: enc, ciphertext: wrappedKey),
        recipient: deviceHPKEPrivateKey,
        info: sealing.info,
        aad: CanonicalCodec.encodeAAD(sealing.outerContext)
      )
    } catch {
      throw KeyDirectoryVerifierError.hpkeOpenFailed
    }
    guard plaintext.count == 32 else {
      throw KeyDirectoryVerifierError.invalidKeyMaterial
    }
    return plaintext
  }

  private func validateBootstrapRoster(
    _ directory: DeviceKeyDirectoryV1,
    expectedConversationRoutes: [Data]
  ) throws {
    var previous: Data?
    for route in expectedConversationRoutes {
      guard route.count == 16,
        route.contains(where: { $0 != 0 }),
        previous.map({ $0.lexicographicallyPrecedes(route) }) ?? true
      else {
        throw KeyDirectoryVerifierError.invalidBootstrapRoster
      }
      previous = route
    }
    let observed = directory.entries.compactMap { entry in
      entry.keyID.purpose == .conversationDEK ? entry.streamRoute : nil
    }
    guard directory.entries.allSatisfy({ $0.keyID.epoch == 1 }),
      observed == expectedConversationRoutes
    else {
      throw KeyDirectoryVerifierError.invalidBootstrapRoster
    }
  }
}

private struct OpenedKeyDirectoryV1: Sendable {
  let directory: DeviceKeyDirectoryV1
  let materials: [OpenedKeyMaterialCapabilityV1]
}

/// HPKE open 后的 module-internal opaque key capability；raw bytes 永不提供 getter。
struct OpenedKeyMaterialCapabilityV1: Sendable, CustomDebugStringConvertible {
  let keyID: KeyIDV1
  let streamRoute: Data?
  private let rawKey: Data

  init(keyID: KeyIDV1, streamRoute: Data?, rawKey: Data) {
    self.keyID = keyID
    self.streamRoute = streamRoute
    self.rawKey = rawKey
  }

  var debugDescription: String {
    "OpenedKeyMaterialCapabilityV1(material: <redacted>)"
  }

  func matchesSecret(_ other: Self) -> Bool {
    let challenge = Data("AgentDeck/KeyMaterialLineageProofV1\0".utf8)
    let authenticationCode = HMAC<SHA256>.authenticationCode(
      for: challenge,
      using: SymmetricKey(data: rawKey)
    )
    return HMAC<SHA256>.isValidAuthenticationCode(
      authenticationCode,
      authenticating: challenge,
      using: SymmetricKey(data: other.rawKey)
    )
  }

  func secretFingerprint() -> Data {
    var input = Data("AgentDeck/KeyMaterialFingerprintV1\0".utf8)
    input.append(rawKey)
    return Data(SHA256.hash(data: input))
  }

  func makeSendingKey(
    keyDirectoryRevision: UInt64,
    payloadKind: SealedPayloadKind
  ) throws -> AeadSendingKey {
    do {
      return try AeadSendingKey(
        keyID: keyID,
        epoch: keyID.epoch,
        keyDirectoryRevision: keyDirectoryRevision,
        payloadKind: payloadKind,
        rawKey: rawKey
      )
    } catch {
      throw KeyDirectoryVerifierError.invalidKeyMaterial
    }
  }

  func makeReceivingKey(
    keyDirectoryRevision: UInt64
  ) throws -> InstalledReceivingKeyV1 {
    do {
      let noncePrefix = try AeadSendingKey(
        keyID: keyID,
        epoch: keyID.epoch,
        keyDirectoryRevision: keyDirectoryRevision,
        payloadKind: .keyUpdate,
        rawKey: rawKey
      ).noncePrefix
      return try InstalledReceivingKeyV1(
        streamRoute: streamRoute,
        keyDirectoryRevision: keyDirectoryRevision,
        noncePrefix: noncePrefix,
        key: AeadReceivingKey(keyID: keyID, epoch: keyID.epoch, rawKey: rawKey)
      )
    } catch let error as KeyDirectoryVerifierError {
      throw error
    } catch {
      throw KeyDirectoryVerifierError.invalidKeyMaterial
    }
  }
}

private struct KeyCanonicalEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func domain(_ value: Data) throws {
    try append(value)
  }

  mutating func u8(_ value: UInt8) throws {
    try append(Data([value]))
  }

  mutating func u16(_ value: UInt16) throws {
    try appendInteger(value)
  }

  mutating func u64(_ value: UInt64) throws {
    try appendInteger(value)
  }

  mutating func u16Count(_ count: Int) throws {
    guard let value = UInt16(exactly: count) else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    try u16(value)
  }

  mutating func bytes(
    _ value: Data,
    maximum: Int? = nil,
    exact: Int? = nil
  ) throws {
    if let maximum, value.count > maximum {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    if let exact, value.count != exact {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    guard let count = UInt32(exactly: value.count) else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    try appendInteger(count)
    try append(value)
  }

  mutating func optionalID16(_ value: Data?) throws {
    if let value {
      guard value.count == 16 else {
        throw KeyDirectoryVerifierError.invalidEncoding
      }
      try u8(1)
      try append(value)
    } else {
      try u8(0)
    }
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    return output
  }

  private mutating func append(_ data: Data) throws {
    let next = output.count.addingReportingOverflow(data.count)
    guard !next.overflow,
      next.partialValue <= maximumBytes
    else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    output.append(data)
  }

  private mutating func appendInteger<T: FixedWidthInteger>(_ value: T) throws {
    var encoded = value.bigEndian
    try Swift.withUnsafeBytes(of: &encoded) { buffer in
      try append(Data(buffer))
    }
  }
}

private struct KeyCanonicalDecoder {
  private let bytes: Data
  private var offset = 0

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  mutating func domain(_ expected: Data) throws {
    guard try fixed(count: expected.count) == expected else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
  }

  mutating func u8() throws -> UInt8 {
    try fixed(count: 1)[0]
  }

  mutating func u16Count(maximum: Int) throws -> Int {
    let count = Int(try u16())
    guard count <= maximum else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    return count
  }

  mutating func u16() throws -> UInt16 {
    try integer(count: 2)
  }

  mutating func u64() throws -> UInt64 {
    try integer(count: 8)
  }

  mutating func bytes(maximum: Int) throws -> Data {
    let length = Int(try u32())
    guard length <= maximum else {
      throw KeyDirectoryVerifierError.sizeLimit
    }
    return try fixed(count: length)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    return value
  }

  mutating func optionalID16() throws -> Data? {
    switch try u8() {
    case 0: return nil
    case 1: return try fixed(count: 16)
    default: throw KeyDirectoryVerifierError.invalidEncoding
    }
  }

  func finish() throws {
    guard offset == bytes.count else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
  }

  private mutating func u32() throws -> UInt32 {
    try integer(count: 4)
  }

  private mutating func fixed(count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0,
      !end.overflow,
      end.partialValue <= bytes.count
    else {
      throw KeyDirectoryVerifierError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return bytes.subdata(in: offset..<end.partialValue)
  }

  private mutating func integer<T: FixedWidthInteger>(count: Int) throws -> T {
    try fixed(count: count).reduce(0) { ($0 << 8) | T($1) }
  }
}

private func decodeKeyPurpose(canonicalTag: UInt8) -> KeyPurpose? {
  switch canonicalTag {
  case 0: .catalog
  case 1: .conversationDEK
  case 2: .deviceCommandTx
  case 3: .deviceReplyTx
  default: nil
  }
}
