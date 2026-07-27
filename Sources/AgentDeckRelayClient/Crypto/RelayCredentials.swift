import AgentDeckCore
import CryptoKit
import Foundation

enum RelayCredentialError: Error, Equatable, Sendable {
  case sizeLimit
  case invalidEncoding
  case invalidTrustBinding
  case badRootSignature
}

enum RelayGrantCanonicalCodec {
  static let maximumCanonicalBytes = 2 * 1_024

  private static let domain = Data("AgentDeck/RelayGrantV1\0".utf8)
  private static let unsignedDomain = Data("AgentDeck/RelayGrantUnsignedV1\0".utf8)

  static func unsignedCanonicalBytes(_ grant: RelayV2Grant) throws -> Data {
    try validateShape(grant)
    var output = unsignedDomain
    appendBytes(grant.machineRoute, to: &output)
    appendBytes(grant.deviceRoute, to: &output)
    appendBytes(grant.deviceSignPubkey, to: &output)
    appendBigEndian(grant.grantSerial, to: &output)
    appendBytes(grant.rootKeyId, to: &output)
    appendBigEndian(grant.trustEpoch, to: &output)
    return output
  }

  static func encode(_ grant: RelayV2Grant) throws -> Data {
    let unsigned = try unsignedCanonicalBytes(grant)
    var output = domain
    appendBytes(unsigned, to: &output)
    appendBytes(grant.signature, to: &output)
    guard output.count <= maximumCanonicalBytes else {
      throw RelayCredentialError.sizeLimit
    }
    return output
  }

  static func decode(
    _ bytes: Data,
    maxEncodedBytes: Int = maximumCanonicalBytes
  ) throws -> RelayV2Grant {
    guard maxEncodedBytes >= 0 else {
      throw RelayCredentialError.invalidEncoding
    }
    guard bytes.count <= maximumCanonicalBytes,
      bytes.count <= maxEncodedBytes
    else {
      throw RelayCredentialError.sizeLimit
    }

    var outer = RelayCredentialReader(bytes)
    try outer.readDomain(domain)
    let unsigned = try outer.readBytes(maximum: maximumCanonicalBytes)
    let signature = try outer.readFixedBytes(count: 64)
    try outer.finish()

    var inner = RelayCredentialReader(unsigned)
    try inner.readDomain(unsignedDomain)
    let grant = RelayV2Grant(
      machineRoute: try inner.readFixedBytes(count: 16),
      deviceRoute: try inner.readFixedBytes(count: 16),
      deviceSignPubkey: try inner.readFixedBytes(count: 32),
      grantSerial: try inner.readUInt64(),
      rootKeyId: try inner.readFixedBytes(count: 16),
      trustEpoch: try inner.readUInt64(),
      signature: signature
    )
    try inner.finish()
    guard try encode(grant) == bytes else {
      throw RelayCredentialError.invalidEncoding
    }
    return grant
  }

  static func unsignedCanonicalSHA256(_ grant: RelayV2Grant) throws -> Data {
    CanonicalCodec.sha256(try unsignedCanonicalBytes(grant))
  }

  static func canonicalSHA256(_ grant: RelayV2Grant) throws -> Data {
    CanonicalCodec.sha256(try encode(grant))
  }

  private static func validateShape(_ grant: RelayV2Grant) throws {
    guard grant.machineRoute.count == 16,
      grant.deviceRoute.count == 16,
      grant.deviceSignPubkey.count == 32,
      grant.rootKeyId.count == 16,
      grant.signature.count == 64
    else {
      throw RelayCredentialError.invalidEncoding
    }
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

enum SignedCertificateCanonicalCodec {
  static let maximumCanonicalBytes = 1_024

  private static let domain = Data("AgentDeck/SignedCertificateV1\0".utf8)
  private static let unsignedDomain = Data(
    "AgentDeck/SignedCertificateUnsignedV1\0".utf8
  )

  static func unsignedCanonicalBytes(
    _ certificate: RelayV2SignedCertificate
  ) throws -> Data {
    try validateShape(certificate)
    var output = unsignedDomain
    appendBytes(certificate.subjectPubkey, to: &output)
    output.append(certificate.certRole == .link ? 0 : 1)
    appendBigEndian(certificate.generation, to: &output)
    appendBytes(certificate.rootKeyId, to: &output)
    appendBigEndian(certificate.trustEpoch, to: &output)
    if let notAfterMS = certificate.notAfterMs {
      output.append(1)
      appendBigEndian(notAfterMS, to: &output)
    } else {
      output.append(0)
    }
    return output
  }

  static func encode(_ certificate: RelayV2SignedCertificate) throws -> Data {
    let unsigned = try unsignedCanonicalBytes(certificate)
    var output = domain
    appendBytes(unsigned, to: &output)
    appendBytes(certificate.signature, to: &output)
    guard output.count <= maximumCanonicalBytes else {
      throw RelayCredentialError.sizeLimit
    }
    return output
  }

  static func decode(
    _ bytes: Data,
    maxEncodedBytes: Int = maximumCanonicalBytes
  ) throws -> RelayV2SignedCertificate {
    guard maxEncodedBytes >= 0 else {
      throw RelayCredentialError.invalidEncoding
    }
    guard bytes.count <= maximumCanonicalBytes,
      bytes.count <= maxEncodedBytes
    else {
      throw RelayCredentialError.sizeLimit
    }

    var outer = RelayCredentialReader(bytes)
    try outer.readDomain(domain)
    let unsigned = try outer.readBytes(maximum: maximumCanonicalBytes)
    let signature = try outer.readFixedBytes(count: 64)
    try outer.finish()

    var inner = RelayCredentialReader(unsigned)
    try inner.readDomain(unsignedDomain)
    let subjectPubkey = try inner.readFixedBytes(count: 32)
    let role: RelayV2CertRole
    switch try inner.readUInt8() {
    case 0: role = .link
    case 1: role = .data
    default: throw RelayCredentialError.invalidEncoding
    }
    let certificate = RelayV2SignedCertificate(
      subjectPubkey: subjectPubkey,
      certRole: role,
      generation: try inner.readUInt64(),
      rootKeyId: try inner.readFixedBytes(count: 16),
      trustEpoch: try inner.readUInt64(),
      notAfterMs: try inner.readOptionalUInt64(),
      signature: signature
    )
    try inner.finish()
    guard try encode(certificate) == bytes else {
      throw RelayCredentialError.invalidEncoding
    }
    return certificate
  }

  static func unsignedCanonicalSHA256(
    _ certificate: RelayV2SignedCertificate
  ) throws -> Data {
    CanonicalCodec.sha256(try unsignedCanonicalBytes(certificate))
  }

  static func canonicalSHA256(
    _ certificate: RelayV2SignedCertificate
  ) throws -> Data {
    CanonicalCodec.sha256(try encode(certificate))
  }

  private static func validateShape(
    _ certificate: RelayV2SignedCertificate
  ) throws {
    guard certificate.subjectPubkey.count == 32,
      certificate.rootKeyId.count == 16,
      certificate.signature.count == 64
    else {
      throw RelayCredentialError.invalidEncoding
    }
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

struct VerifiedRelayGrantCredential: Sendable, CustomDebugStringConvertible {
  let grant: RelayV2Grant
  let canonicalBytes: Data

  var debugDescription: String {
    "VerifiedRelayGrantCredential(<redacted>)"
  }
}

enum RelayGrantCredentialVerifier {
  static func verify(
    canonicalBytes: Data,
    relayServerID: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedDeviceSignPublicKey: Data,
    expectedGrantSerial: UInt64,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64
  ) throws -> VerifiedRelayGrantCredential {
    let grant = try RelayGrantCanonicalCodec.decode(canonicalBytes)
    return try verify(
      grant,
      relayServerID: relayServerID,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      expectedMachineRoute: expectedMachineRoute,
      expectedDeviceRoute: expectedDeviceRoute,
      expectedDeviceSignPublicKey: expectedDeviceSignPublicKey,
      expectedGrantSerial: expectedGrantSerial,
      expectedRootKeyID: expectedRootKeyID,
      expectedTrustEpoch: expectedTrustEpoch
    )
  }

  static func verify(
    _ grant: RelayV2Grant,
    relayServerID: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    expectedMachineRoute: Data,
    expectedDeviceRoute: Data,
    expectedDeviceSignPublicKey: Data,
    expectedGrantSerial: UInt64,
    expectedRootKeyID: Data,
    expectedTrustEpoch: UInt64
  ) throws -> VerifiedRelayGrantCredential {
    guard isNonzero(relayServerID, count: 16),
      isNonzero(machineRootPublicKey, count: 32),
      isNonzero(machineRootFingerprint, count: 32),
      CanonicalCodec.sha256(machineRootPublicKey) == machineRootFingerprint,
      isNonzero(expectedMachineRoute, count: 16),
      isNonzero(expectedDeviceRoute, count: 16),
      isNonzero(expectedDeviceSignPublicKey, count: 32),
      expectedGrantSerial > 0,
      isNonzero(expectedRootKeyID, count: 16),
      expectedTrustEpoch > 0,
      grant.machineRoute == expectedMachineRoute,
      grant.deviceRoute == expectedDeviceRoute,
      grant.deviceSignPubkey == expectedDeviceSignPublicKey,
      grant.grantSerial == expectedGrantSerial,
      grant.rootKeyId == expectedRootKeyID,
      grant.trustEpoch == expectedTrustEpoch,
      isNonzero(grant.signature, count: 64)
    else {
      throw RelayCredentialError.invalidTrustBinding
    }

    let rootKey: Curve25519.Signing.PublicKey
    do {
      rootKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: machineRootPublicKey
      )
    } catch {
      throw RelayCredentialError.invalidTrustBinding
    }
    guard
      RelayCrypto.verify(
        grant.signature,
        tbs: try toBeSigned(
          grant,
          relayServerID: relayServerID,
          machineRootFingerprint: machineRootFingerprint
        ),
        key: rootKey
      )
    else {
      throw RelayCredentialError.badRootSignature
    }
    return VerifiedRelayGrantCredential(
      grant: grant,
      canonicalBytes: try RelayGrantCanonicalCodec.encode(grant)
    )
  }

  static func toBeSigned(
    _ grant: RelayV2Grant,
    relayServerID: Data,
    machineRootFingerprint: Data
  ) throws -> ToBeSignedV1 {
    ToBeSignedV1(
      objectType: .relayGrant,
      signatureFormatVersion: 1,
      relayProtocolVersion: relayProtocolVersionV2,
      runtimeProtocolVersion: runtimeProtocolVersionCurrent,
      e2eeFormatVersion: 1,
      relayServerID: relayServerID,
      machineRoute: grant.machineRoute,
      deviceRoute: grant.deviceRoute,
      streamRoute: nil,
      requestRoute: nil,
      streamGeneration: nil,
      streamCursor: nil,
      roleScope: "relay-device-grant",
      signingKeyFingerprint: machineRootFingerprint,
      rootKeyID: grant.rootKeyId,
      trustEpoch: grant.trustEpoch,
      serialOrGeneration: grant.grantSerial,
      notAfterMS: nil,
      signedObjectSHA256: try RelayGrantCanonicalCodec.unsignedCanonicalSHA256(grant)
    )
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

private struct RelayCredentialReader {
  private let input: Data
  private var offset = 0

  init(_ input: Data) {
    self.input = input
  }

  mutating func readDomain(_ domain: Data) throws {
    guard try readRaw(count: domain.count) == domain else {
      throw RelayCredentialError.invalidEncoding
    }
  }

  mutating func readUInt8() throws -> UInt8 {
    try readRaw(count: 1)[0]
  }

  mutating func readUInt32() throws -> UInt32 {
    try readRaw(count: 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  }

  mutating func readUInt64() throws -> UInt64 {
    try readRaw(count: 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }

  mutating func readBytes(maximum: Int) throws -> Data {
    guard let count = Int(exactly: try readUInt32()), count <= maximum else {
      throw RelayCredentialError.invalidEncoding
    }
    return try readRaw(count: count)
  }

  mutating func readFixedBytes(count: Int) throws -> Data {
    let value = try readBytes(maximum: count)
    guard value.count == count else {
      throw RelayCredentialError.invalidEncoding
    }
    return value
  }

  mutating func readOptionalUInt64() throws -> UInt64? {
    switch try readUInt8() {
    case 0: return nil
    case 1: return try readUInt64()
    default: throw RelayCredentialError.invalidEncoding
    }
  }

  func finish() throws {
    guard offset == input.count else {
      throw RelayCredentialError.invalidEncoding
    }
  }

  private mutating func readRaw(count: Int) throws -> Data {
    guard count >= 0,
      offset <= input.count,
      count <= input.count - offset
    else {
      throw RelayCredentialError.invalidEncoding
    }
    let start = input.index(input.startIndex, offsetBy: offset)
    let end = input.index(start, offsetBy: count)
    offset += count
    return Data(input[start..<end])
  }
}
