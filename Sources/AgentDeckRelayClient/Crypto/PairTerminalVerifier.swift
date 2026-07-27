import AgentDeckCore
import CryptoKit
import Foundation

enum PairTerminalVerifierError: Error, Equatable, Sendable {
  case invalidEncoding
  case sizeLimit
  case invalidContext
  case invalidSigner
  case identityMismatch
  case badSignature
  case hpkeOpenFailed
}

enum PairTerminalOutcomeV1: Equatable, Sendable {
  case canceled
  case expired

  fileprivate var canonicalTag: UInt8 {
    switch self {
    case .canceled: 0
    case .expired: 1
    }
  }

  fileprivate init(canonicalTag: UInt8) throws {
    switch canonicalTag {
    case 0: self = .canceled
    case 1: self = .expired
    default: throw PairTerminalVerifierError.invalidEncoding
    }
  }
}

struct PairRequestInfoV1: Equatable, Sendable {
  let e2eeFormatVersion: UInt16
  let runtimeProtocolVersion: UInt16
  let relayServerID: Data
  let pairRoute: Data
  let inviteHash: Data
  let expiryMilliseconds: UInt64

  init(
    e2eeFormatVersion: UInt16 = 1,
    runtimeProtocolVersion: UInt16 = runtimeProtocolVersionCurrent,
    relayServerID: Data,
    pairRoute: Data,
    inviteHash: Data,
    expiryMilliseconds: UInt64
  ) throws {
    guard e2eeFormatVersion == 1,
      runtimeProtocolVersion == runtimeProtocolVersionCurrent,
      Self.isNonzero(relayServerID, count: 16),
      Self.isNonzero(pairRoute, count: 16),
      Self.isNonzero(inviteHash, count: 32),
      expiryMilliseconds > 0
    else {
      throw PairTerminalVerifierError.invalidContext
    }
    self.e2eeFormatVersion = e2eeFormatVersion
    self.runtimeProtocolVersion = runtimeProtocolVersion
    self.relayServerID = relayServerID
    self.pairRoute = pairRoute
    self.inviteHash = inviteHash
    self.expiryMilliseconds = expiryMilliseconds
  }

  func canonicalBytes() throws -> Data {
    var encoder = PairTerminalEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairRequestInfoV1\0".utf8))
    try encoder.u16(e2eeFormatVersion)
    try encoder.u16(runtimeProtocolVersion)
    try encoder.bytes(relayServerID, exact: 16)
    try encoder.bytes(pairRoute, exact: 16)
    try encoder.bytes(inviteHash, exact: 32)
    try encoder.u64(expiryMilliseconds)
    return try encoder.finish()
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct PairTerminalExpectedV1: Equatable, Sendable {
  let machineRoute: Data
  let requestHash: Data

  init(machineRoute: Data, requestHash: Data) throws {
    guard Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(requestHash, count: 32)
    else {
      throw PairTerminalVerifierError.identityMismatch
    }
    self.machineRoute = machineRoute
    self.requestHash = requestHash
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct CanonicalPairTerminalV1: Equatable, Sendable, CustomDebugStringConvertible {
  let machineRoute: Data
  let requestHash: Data
  let outcome: PairTerminalOutcomeV1
  let signature: Data

  init(
    machineRoute: Data,
    requestHash: Data,
    outcome: PairTerminalOutcomeV1,
    signature: Data,
    requireSignature: Bool = true
  ) throws {
    guard Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(requestHash, count: 32),
      signature.count == 64,
      !requireSignature || signature.contains(where: { $0 != 0 })
    else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    self.machineRoute = machineRoute
    self.requestHash = requestHash
    self.outcome = outcome
    self.signature = signature
  }

  var debugDescription: String {
    "CanonicalPairTerminalV1(outcome: \(outcome), material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct CanonicalPairingControlEnvelopeV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let encapsulatedKey: Data
  let ciphertext: Data

  init(formatVersion: UInt16, encapsulatedKey: Data, ciphertext: Data) throws {
    guard formatVersion == 1,
      encapsulatedKey.count == 32,
      encapsulatedKey.contains(where: { $0 != 0 }),
      !ciphertext.isEmpty,
      ciphertext.count <= PairTerminalEnvelopeCodec.maximumCiphertextBytes
    else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    self.formatVersion = formatVersion
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
  }

  var debugDescription: String {
    "CanonicalPairingControlEnvelopeV1(material: <redacted>)"
  }
}

private struct PairTerminalSignerBindingV1: Sendable {
  let signingKeyFingerprint: Data
  let generation: UInt64
  let certificateSHA256: Data

  init(verifiedCertificate: VerifiedMachineDataCertificate) throws {
    let certificate = verifiedCertificate.certificate
    let canonical: Data
    do {
      canonical = try SignedCertificateCanonicalCodec.encode(certificate)
    } catch {
      throw PairTerminalVerifierError.invalidSigner
    }
    let fingerprint = CanonicalCodec.sha256(certificate.subjectPubkey)
    guard certificate.certRole == .data,
      certificate.subjectPubkey == verifiedCertificate.signingKey.rawRepresentation,
      fingerprint.contains(where: { $0 != 0 }),
      certificate.generation > 0
    else {
      throw PairTerminalVerifierError.invalidSigner
    }
    signingKeyFingerprint = fingerprint
    generation = certificate.generation
    certificateSHA256 = CanonicalCodec.sha256(canonical)
  }
}

enum PairTerminalCanonicalCodec {
  static let maximumUnsignedBytes = 256
  static let maximumCanonicalBytes = 512

  private static let unsignedDomain = Data("AgentDeck/PairTerminalUnsignedV1\0".utf8)
  private static let domain = Data("AgentDeck/PairTerminalV1\0".utf8)

  static func unsignedCanonicalBytes(_ value: CanonicalPairTerminalV1) throws -> Data {
    var encoder = PairTerminalEncoder(maximumBytes: maximumUnsignedBytes)
    try encoder.raw(unsignedDomain)
    try encoder.bytes(value.machineRoute, exact: 16)
    try encoder.bytes(value.requestHash, exact: 32)
    try encoder.u8(value.outcome.canonicalTag)
    return try encoder.finish()
  }

  static func encode(_ value: CanonicalPairTerminalV1) throws -> Data {
    guard value.signature.contains(where: { $0 != 0 }) else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    var encoder = PairTerminalEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.bytes(unsignedCanonicalBytes(value))
    try encoder.bytes(value.signature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairTerminalV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairTerminalVerifierError.sizeLimit
    }
    var outer = PairTerminalDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumUnsignedBytes)
    let signature = try outer.bytes(exact: 64)
    try outer.finish()

    var decoder = PairTerminalDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let value = try CanonicalPairTerminalV1(
      machineRoute: decoder.bytes(exact: 16),
      requestHash: decoder.bytes(exact: 32),
      outcome: PairTerminalOutcomeV1(canonicalTag: decoder.u8()),
      signature: signature
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    return value
  }
}

enum PairTerminalEnvelopeCodec {
  static let maximumCiphertextBytes = 256 * 1_024
  static let maximumCanonicalBytes = maximumCiphertextBytes + 1_024

  private static let domain = Data("AgentDeck/PairingControlEnvelopeV1\0".utf8)

  static func encode(_ value: CanonicalPairingControlEnvelopeV1) throws -> Data {
    var encoder = PairTerminalEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.encapsulatedKey, exact: 32)
    try encoder.bytes(value.ciphertext)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairingControlEnvelopeV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairTerminalVerifierError.sizeLimit
    }
    var decoder = PairTerminalDecoder(bytes)
    try decoder.domain(domain)
    let value = try CanonicalPairingControlEnvelopeV1(
      formatVersion: decoder.u16(),
      encapsulatedKey: decoder.bytes(exact: 32),
      ciphertext: decoder.bytes(maximum: maximumCiphertextBytes)
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    return value
  }
}

enum PairTerminalVerifier {
  /// Pairing client 在收到 terminal 前尚不知道 machine route；该 route 必须先从
  /// HPKE plaintext 读取，再用 invite 中的 MachineRoot 与 Data certificate 对
  /// `route + certificate + terminal TBS` 做完整签名验证，不能由未验证 outer data 提供。
  static func openVerifiedFromInvite(
    canonicalEnvelope: Data,
    recipientDeviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey,
    invite: PairInviteV1,
    requestHash: Data,
    nowMilliseconds: UInt64
  ) throws -> CanonicalPairTerminalV1 {
    try invite.validateStatic()
    guard requestHash.count == 32,
      requestHash.contains(where: { $0 != 0 })
    else {
      throw PairTerminalVerifierError.identityMismatch
    }
    let info = try PairRequestInfoV1(
      relayServerID: invite.relayServerID,
      pairRoute: invite.pairRoute,
      inviteHash: invite.canonicalSHA256(),
      expiryMilliseconds: invite.expiresAtMilliseconds
    )
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
      pairRoute: invite.pairRoute
    )
    try validateContext(info: info, context: context)
    let envelope = try PairTerminalEnvelopeCodec.decode(canonicalEnvelope)
    let plaintext: Data
    do {
      plaintext = try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(
          enc: envelope.encapsulatedKey,
          ciphertext: envelope.ciphertext
        ),
        recipient: recipientDeviceHPKEPrivateKey,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairTerminalVerifierError.hpkeOpenFailed
    }
    let terminal = try PairTerminalCanonicalCodec.decode(plaintext)
    guard terminal.requestHash == requestHash else {
      throw PairTerminalVerifierError.identityMismatch
    }
    let verifiedCertificate: VerifiedMachineDataCertificate
    do {
      verifiedCertificate = try MachineDataCertificateVerifier.verify(
        invite.dataSignCertificate,
        relayServerID: invite.relayServerID,
        machineRoute: terminal.machineRoute,
        machineRootPublicKey: invite.machineRootPublicKey,
        machineRootFingerprint: invite.machineRootFingerprint,
        expectedRootKeyID: invite.dataSignCertificate.rootKeyId,
        expectedTrustEpoch: invite.dataSignCertificate.trustEpoch,
        minimumDataCertificateGeneration: invite.dataSignCertificate.generation,
        nowMilliseconds: nowMilliseconds
      )
    } catch {
      throw PairTerminalVerifierError.invalidSigner
    }
    let tbs = try signatureTBS(
      terminal,
      info: info,
      context: context,
      verifiedCertificate: verifiedCertificate
    )
    guard
      verifiedCertificate.signingKey.isValidSignature(
        terminal.signature,
        for: tbs
      )
    else {
      throw PairTerminalVerifierError.badSignature
    }
    return terminal
  }

  static func open(
    canonicalEnvelope: Data,
    recipientDeviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    expected: PairTerminalExpectedV1,
    verifiedCertificate: VerifiedMachineDataCertificate
  ) throws -> CanonicalPairTerminalV1 {
    try validateContext(info: info, context: context)
    let signer = try PairTerminalSignerBindingV1(
      verifiedCertificate: verifiedCertificate
    )
    let envelope = try PairTerminalEnvelopeCodec.decode(canonicalEnvelope)
    let plaintext: Data
    do {
      plaintext = try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(
          enc: envelope.encapsulatedKey,
          ciphertext: envelope.ciphertext
        ),
        recipient: recipientDeviceHPKEPrivateKey,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairTerminalVerifierError.hpkeOpenFailed
    }
    let terminal = try PairTerminalCanonicalCodec.decode(plaintext)
    guard terminal.machineRoute == expected.machineRoute,
      terminal.requestHash == expected.requestHash
    else {
      throw PairTerminalVerifierError.identityMismatch
    }
    let tbs = try signatureTBS(
      terminal,
      info: info,
      context: context,
      signer: signer
    )
    guard
      verifiedCertificate.signingKey.isValidSignature(
        terminal.signature,
        for: tbs
      )
    else {
      throw PairTerminalVerifierError.badSignature
    }
    return terminal
  }

  static func signatureTBS(
    _ terminal: CanonicalPairTerminalV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    verifiedCertificate: VerifiedMachineDataCertificate
  ) throws -> Data {
    try signatureTBS(
      terminal,
      info: info,
      context: context,
      signer: PairTerminalSignerBindingV1(verifiedCertificate: verifiedCertificate)
    )
  }

  private static func signatureTBS(
    _ terminal: CanonicalPairTerminalV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    signer: PairTerminalSignerBindingV1
  ) throws -> Data {
    try validateContext(info: info, context: context)
    var encoder = PairTerminalEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairTerminalTbsV1\0".utf8))
    try encoder.u16(info.e2eeFormatVersion)
    try encoder.u16(info.runtimeProtocolVersion)
    try encoder.u16(context.relayProtocolVersion)
    try encoder.bytes(info.relayServerID, exact: 16)
    try encoder.bytes(info.pairRoute, exact: 16)
    try encoder.bytes(info.inviteHash, exact: 32)
    try encoder.u64(info.expiryMilliseconds)
    try encoder.bytes(terminal.machineRoute, exact: 16)
    try encoder.bytes(terminal.requestHash, exact: 32)
    try encoder.u8(terminal.outcome.canonicalTag)
    try encoder.bytes(signer.signingKeyFingerprint, exact: 32)
    try encoder.u64(signer.generation)
    try encoder.bytes(signer.certificateSHA256, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(info.canonicalBytes()), exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(CanonicalCodec.encodeAAD(context)), exact: 32)
    return try encoder.finish()
  }

  private static func validateContext(
    info: PairRequestInfoV1,
    context: OuterContextV1
  ) throws {
    do {
      try context.validateShape()
    } catch {
      throw PairTerminalVerifierError.invalidContext
    }
    guard context.frameKind == .pairTerminal,
      context.relayProtocolVersion == relayProtocolVersionV2,
      context.e2eeFormatVersion == info.e2eeFormatVersion,
      context.pairRoute == info.pairRoute
    else {
      throw PairTerminalVerifierError.invalidContext
    }
  }
}

private struct PairTerminalEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func raw(_ value: Data) throws { try append(value) }
  mutating func u8(_ value: UInt8) throws { try append(Data([value])) }
  mutating func u16(_ value: UInt16) throws { try integer(value) }
  mutating func u64(_ value: UInt64) throws { try integer(value) }

  mutating func bytes(_ value: Data, exact: Int? = nil) throws {
    if let exact, value.count != exact {
      throw PairTerminalVerifierError.invalidEncoding
    }
    guard let count = UInt32(exactly: value.count) else {
      throw PairTerminalVerifierError.sizeLimit
    }
    try integer(count)
    try append(value)
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else {
      throw PairTerminalVerifierError.sizeLimit
    }
    return output
  }

  private mutating func integer<T: FixedWidthInteger>(_ value: T) throws {
    var value = value.bigEndian
    try Swift.withUnsafeBytes(of: &value) { try append(Data($0)) }
  }

  private mutating func append(_ value: Data) throws {
    let end = output.count.addingReportingOverflow(value.count)
    guard !end.overflow, end.partialValue <= maximumBytes else {
      throw PairTerminalVerifierError.sizeLimit
    }
    output.append(value)
  }
}

private struct PairTerminalDecoder {
  private let input: Data
  private var offset = 0

  init(_ input: Data) {
    self.input = input
  }

  mutating func domain(_ expected: Data) throws {
    guard try take(expected.count) == expected else {
      throw PairTerminalVerifierError.invalidEncoding
    }
  }

  mutating func u8() throws -> UInt8 { try take(1)[0] }
  mutating func u16() throws -> UInt16 { try integer() }
  mutating func u32() throws -> UInt32 { try integer() }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else { throw PairTerminalVerifierError.sizeLimit }
    return try take(count)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    return value
  }

  mutating func finish() throws {
    guard offset == input.count else {
      throw PairTerminalVerifierError.invalidEncoding
    }
  }

  private mutating func integer<T: FixedWidthInteger>() throws -> T {
    try take(MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
  }

  private mutating func take(_ count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= input.count else {
      throw PairTerminalVerifierError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return Data(input[offset..<end.partialValue])
  }
}
