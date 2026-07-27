import AgentDeckCore
import CryptoKit
import Foundation

enum PairResponseCryptoError: Error, Equatable, Sendable {
  case invalidEncoding
  case sizeLimit
  case invalidContext
  case invalidTrustBinding
  case badSignature
  case hpkeOpenFailed
  case hpkeSealFailed
  case authorizationMismatch
  case keyDirectoryInvalid
}

struct PairResponseInfoV1: Equatable, Sendable, CustomDebugStringConvertible {
  static let maximumCanonicalBytes = 1_024

  let e2eeFormatVersion: UInt16
  let runtimeProtocolVersion: UInt16
  let relayServerID: Data
  let pairRoute: Data
  let inviteHash: Data
  let expiryMilliseconds: UInt64
  let requestHash: Data
  let machineRoute: Data
  let deviceRoute: Data
  let grantSerial: UInt64
  let rootTrustEpoch: UInt64

  init(
    e2eeFormatVersion: UInt16 = 1,
    runtimeProtocolVersion: UInt16 = runtimeProtocolVersionCurrent,
    relayServerID: Data,
    pairRoute: Data,
    inviteHash: Data,
    expiryMilliseconds: UInt64,
    requestHash: Data,
    machineRoute: Data,
    deviceRoute: Data,
    grantSerial: UInt64,
    rootTrustEpoch: UInt64
  ) throws {
    guard e2eeFormatVersion == 1,
      runtimeProtocolVersion == runtimeProtocolVersionCurrent,
      Self.isNonzero(relayServerID, count: 16),
      Self.isNonzero(pairRoute, count: 16),
      Self.isNonzero(inviteHash, count: 32),
      expiryMilliseconds > 0,
      Self.isNonzero(requestHash, count: 32),
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      grantSerial > 0,
      rootTrustEpoch > 0
    else {
      throw PairResponseCryptoError.invalidContext
    }
    self.e2eeFormatVersion = e2eeFormatVersion
    self.runtimeProtocolVersion = runtimeProtocolVersion
    self.relayServerID = relayServerID
    self.pairRoute = pairRoute
    self.inviteHash = inviteHash
    self.expiryMilliseconds = expiryMilliseconds
    self.requestHash = requestHash
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.grantSerial = grantSerial
    self.rootTrustEpoch = rootTrustEpoch
  }

  var debugDescription: String {
    "PairResponseInfoV1(material: <redacted>)"
  }

  func canonicalBytes() throws -> Data {
    var encoder = PairResponseEncoder(maximumBytes: Self.maximumCanonicalBytes)
    try encoder.raw(Data("AgentDeck/PairResponseInfoV1\0".utf8))
    try encoder.u16(e2eeFormatVersion)
    try encoder.u16(runtimeProtocolVersion)
    try encoder.bytes(relayServerID, exact: 16)
    try encoder.bytes(pairRoute, exact: 16)
    try encoder.bytes(inviteHash, exact: 32)
    try encoder.u64(expiryMilliseconds)
    try encoder.bytes(requestHash, exact: 32)
    try encoder.bytes(machineRoute, exact: 16)
    try encoder.bytes(deviceRoute, exact: 16)
    try encoder.u64(grantSerial)
    try encoder.u64(rootTrustEpoch)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> Self {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var decoder = PairResponseDecoder(bytes)
    try decoder.domain(Data("AgentDeck/PairResponseInfoV1\0".utf8))
    let value = try Self(
      e2eeFormatVersion: decoder.u16(),
      runtimeProtocolVersion: decoder.u16(),
      relayServerID: decoder.bytes(exact: 16),
      pairRoute: decoder.bytes(exact: 16),
      inviteHash: decoder.bytes(exact: 32),
      expiryMilliseconds: decoder.u64(),
      requestHash: decoder.bytes(exact: 32),
      machineRoute: decoder.bytes(exact: 16),
      deviceRoute: decoder.bytes(exact: 16),
      grantSerial: decoder.u64(),
      rootTrustEpoch: decoder.u64()
    )
    try decoder.finish()
    guard try value.canonicalBytes() == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct CanonicalPairResponseV1: Equatable, Sendable, CustomDebugStringConvertible {
  static let maximumCiphertextBytes = 256 * 1_024
  static let maximumCanonicalBytes = maximumCiphertextBytes + 4 * 1_024

  let formatVersion: UInt16
  let info: PairResponseInfoV1
  let encapsulatedKey: Data
  let ciphertext: Data
  let machineDataSignature: Data

  init(
    formatVersion: UInt16 = 1,
    info: PairResponseInfoV1,
    encapsulatedKey: Data,
    ciphertext: Data,
    machineDataSignature: Data,
    requireSignature: Bool = true
  ) throws {
    guard formatVersion == 1,
      Self.isNonzero(encapsulatedKey, count: 32),
      !ciphertext.isEmpty,
      ciphertext.count <= Self.maximumCiphertextBytes,
      machineDataSignature.count == 64,
      !requireSignature || machineDataSignature.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    self.formatVersion = formatVersion
    self.info = info
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
    self.machineDataSignature = machineDataSignature
  }

  var debugDescription: String {
    "CanonicalPairResponseV1(material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum PairResponseCanonicalCodec {
  private static let unsignedDomain = Data("AgentDeck/PairResponseUnsignedV1\0".utf8)
  private static let domain = Data("AgentDeck/PairResponseV1\0".utf8)

  static func unsignedCanonicalBytes(_ value: CanonicalPairResponseV1) throws -> Data {
    var encoder = PairResponseEncoder(
      maximumBytes: CanonicalPairResponseV1.maximumCanonicalBytes
    )
    try encoder.raw(unsignedDomain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.info.canonicalBytes())
    try encoder.bytes(value.encapsulatedKey, exact: 32)
    try encoder.bytes(
      value.ciphertext,
      maximum: CanonicalPairResponseV1.maximumCiphertextBytes
    )
    return try encoder.finish()
  }

  static func encode(_ value: CanonicalPairResponseV1) throws -> Data {
    guard value.machineDataSignature.contains(where: { $0 != 0 }) else {
      throw PairResponseCryptoError.invalidEncoding
    }
    var encoder = PairResponseEncoder(
      maximumBytes: CanonicalPairResponseV1.maximumCanonicalBytes
    )
    try encoder.raw(domain)
    try encoder.bytes(unsignedCanonicalBytes(value))
    try encoder.bytes(value.machineDataSignature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairResponseV1 {
    guard bytes.count <= CanonicalPairResponseV1.maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var outer = PairResponseDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(
      maximum: CanonicalPairResponseV1.maximumCanonicalBytes
    )
    let signature = try outer.bytes(exact: 64)
    try outer.finish()

    var decoder = PairResponseDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let value = try CanonicalPairResponseV1(
      formatVersion: decoder.u16(),
      info: PairResponseInfoV1.decode(
        decoder.bytes(maximum: PairResponseInfoV1.maximumCanonicalBytes)
      ),
      encapsulatedKey: decoder.bytes(exact: 32),
      ciphertext: decoder.bytes(
        maximum: CanonicalPairResponseV1.maximumCiphertextBytes
      ),
      machineDataSignature: signature
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }
}

struct CanonicalDeviceAuthorizationV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let grantHash: Data
  let machineRoute: Data
  let deviceRoute: Data
  let deviceSignFingerprint: Data
  let grantSerial: UInt64
  let deviceHPKEPublicKey: Data
  let capabilities: [AuthorizationCapabilityV1]
  let permissions: [AuthorizationPermissionV1]
  let rootKeyID: Data
  let trustEpoch: UInt64
  let signature: Data

  init(
    formatVersion: UInt16 = 1,
    grantHash: Data,
    machineRoute: Data,
    deviceRoute: Data,
    deviceSignFingerprint: Data,
    grantSerial: UInt64,
    deviceHPKEPublicKey: Data,
    capabilities: [AuthorizationCapabilityV1],
    permissions: [AuthorizationPermissionV1],
    rootKeyID: Data,
    trustEpoch: UInt64,
    signature: Data,
    requireSignature: Bool = true
  ) throws {
    guard formatVersion == 1,
      Self.isNonzero(grantHash, count: 32),
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      Self.isNonzero(deviceSignFingerprint, count: 32),
      grantSerial > 0,
      Self.isNonzero(deviceHPKEPublicKey, count: 32),
      Self.isStrictlyIncreasing(capabilities.map(\.rawValue)),
      Self.isStrictlyIncreasing(permissions.map(\.rawValue)),
      !capabilities.isEmpty,
      !permissions.isEmpty,
      capabilities.count <= AuthorizationCapabilityV1.allCases.count,
      permissions.count <= AuthorizationPermissionV1.allCases.count,
      permissions.allSatisfy({ capabilities.contains(Self.requiredCapability($0)) }),
      Self.isNonzero(rootKeyID, count: 16),
      trustEpoch > 0,
      signature.count == 64,
      !requireSignature || signature.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    self.formatVersion = formatVersion
    self.grantHash = grantHash
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.deviceSignFingerprint = deviceSignFingerprint
    self.grantSerial = grantSerial
    self.deviceHPKEPublicKey = deviceHPKEPublicKey
    self.capabilities = capabilities
    self.permissions = permissions
    self.rootKeyID = rootKeyID
    self.trustEpoch = trustEpoch
    self.signature = signature
  }

  var debugDescription: String {
    "CanonicalDeviceAuthorizationV1(material: <redacted>)"
  }

  private static func requiredCapability(
    _ permission: AuthorizationPermissionV1
  ) -> AuthorizationCapabilityV1 {
    switch permission {
    case .catalogRead: .catalog
    case .conversationRead, .conversationStart: .conversation
    case .promptSend: .prompt
    case .commandCancel: .command
    case .approvalResolve, .approvalRetry: .approval
    case .metadataWrite: .metadata
    case .revokeSelf: .selfRevocation
    }
  }

  private static func isStrictlyIncreasing(_ values: [UInt8]) -> Bool {
    zip(values, values.dropFirst()).allSatisfy(<)
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum DeviceAuthorizationCanonicalCodec {
  static let maximumCanonicalBytes = 16 * 1_024

  private static let unsignedDomain = Data(
    "AgentDeck/DeviceAuthorizationUnsignedV1\0".utf8
  )
  private static let domain = Data("AgentDeck/DeviceAuthorizationV1\0".utf8)

  static func unsignedCanonicalBytes(
    _ value: CanonicalDeviceAuthorizationV1
  ) throws -> Data {
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(unsignedDomain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.grantHash, exact: 32)
    try encoder.bytes(value.machineRoute, exact: 16)
    try encoder.bytes(value.deviceRoute, exact: 16)
    try encoder.bytes(value.deviceSignFingerprint, exact: 32)
    try encoder.u64(value.grantSerial)
    try encoder.bytes(value.deviceHPKEPublicKey, exact: 32)
    try encoder.u8(UInt8(value.capabilities.count))
    for item in value.capabilities { try encoder.u8(item.rawValue) }
    try encoder.u8(UInt8(value.permissions.count))
    for item in value.permissions { try encoder.u8(item.rawValue) }
    try encoder.bytes(value.rootKeyID, exact: 16)
    try encoder.u64(value.trustEpoch)
    return try encoder.finish()
  }

  static func encode(_ value: CanonicalDeviceAuthorizationV1) throws -> Data {
    guard value.signature.contains(where: { $0 != 0 }) else {
      throw PairResponseCryptoError.invalidEncoding
    }
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.bytes(unsignedCanonicalBytes(value))
    try encoder.bytes(value.signature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalDeviceAuthorizationV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var outer = PairResponseDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumCanonicalBytes)
    let signature = try outer.bytes(exact: 64)
    try outer.finish()

    var decoder = PairResponseDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let formatVersion = try decoder.u16()
    let grantHash = try decoder.bytes(exact: 32)
    let machineRoute = try decoder.bytes(exact: 16)
    let deviceRoute = try decoder.bytes(exact: 16)
    let deviceSignFingerprint = try decoder.bytes(exact: 32)
    let grantSerial = try decoder.u64()
    let deviceHPKEPublicKey = try decoder.bytes(exact: 32)
    let capabilityCount = Int(try decoder.u8())
    guard capabilityCount <= AuthorizationCapabilityV1.allCases.count else {
      throw PairResponseCryptoError.sizeLimit
    }
    var capabilities: [AuthorizationCapabilityV1] = []
    capabilities.reserveCapacity(capabilityCount)
    for _ in 0..<capabilityCount {
      guard let value = AuthorizationCapabilityV1(rawValue: try decoder.u8()) else {
        throw PairResponseCryptoError.invalidEncoding
      }
      capabilities.append(value)
    }
    let permissionCount = Int(try decoder.u8())
    guard permissionCount <= AuthorizationPermissionV1.allCases.count else {
      throw PairResponseCryptoError.sizeLimit
    }
    var permissions: [AuthorizationPermissionV1] = []
    permissions.reserveCapacity(permissionCount)
    for _ in 0..<permissionCount {
      guard let value = AuthorizationPermissionV1(rawValue: try decoder.u8()) else {
        throw PairResponseCryptoError.invalidEncoding
      }
      permissions.append(value)
    }
    let value = try CanonicalDeviceAuthorizationV1(
      formatVersion: formatVersion,
      grantHash: grantHash,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      deviceSignFingerprint: deviceSignFingerprint,
      grantSerial: grantSerial,
      deviceHPKEPublicKey: deviceHPKEPublicKey,
      capabilities: capabilities,
      permissions: permissions,
      rootKeyID: decoder.bytes(exact: 16),
      trustEpoch: decoder.u64(),
      signature: signature
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }

  static func unsignedCanonicalSHA256(
    _ value: CanonicalDeviceAuthorizationV1
  ) throws -> Data {
    CanonicalCodec.sha256(try unsignedCanonicalBytes(value))
  }
}

struct CanonicalPairResponsePlaintextV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let requestHash: Data
  let relayGrant: RelayV2Grant
  let relayGrantCanonicalBytes: Data
  let deviceAuthorization: CanonicalDeviceAuthorizationV1
  let deviceAuthorizationCanonicalBytes: Data
  let keyDirectory: DeviceKeyDirectoryV1
  let keyDirectoryCanonicalBytes: Data

  var debugDescription: String {
    "CanonicalPairResponsePlaintextV1(material: <redacted>)"
  }
}

enum PairResponsePlaintextCanonicalCodec {
  static let maximumCanonicalBytes = 768 * 1_024
  private static let domain = Data("AgentDeck/PairResponsePlaintextV1\0".utf8)

  static func encode(_ value: CanonicalPairResponsePlaintextV1) throws -> Data {
    guard value.formatVersion == 1,
      value.requestHash.count == 32,
      value.requestHash.contains(where: { $0 != 0 }),
      try RelayGrantCanonicalCodec.encode(value.relayGrant) == value.relayGrantCanonicalBytes,
      try DeviceAuthorizationCanonicalCodec.encode(value.deviceAuthorization)
        == value.deviceAuthorizationCanonicalBytes,
      try KeyDirectoryCanonicalCodec.encode(value.keyDirectory)
        == value.keyDirectoryCanonicalBytes
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.requestHash, exact: 32)
    try encoder.bytes(value.relayGrantCanonicalBytes)
    try encoder.bytes(value.deviceAuthorizationCanonicalBytes)
    try encoder.bytes(value.keyDirectoryCanonicalBytes)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairResponsePlaintextV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var decoder = PairResponseDecoder(bytes)
    try decoder.domain(domain)
    let formatVersion = try decoder.u16()
    let requestHash = try decoder.bytes(exact: 32)
    let grantBytes = try decoder.bytes(maximum: RelayGrantCanonicalCodec.maximumCanonicalBytes)
    let authorizationBytes = try decoder.bytes(
      maximum: DeviceAuthorizationCanonicalCodec.maximumCanonicalBytes
    )
    let directoryBytes = try decoder.bytes(
      maximum: KeyDirectoryCanonicalCodec.maximumCanonicalBytes
    )
    try decoder.finish()
    let value = CanonicalPairResponsePlaintextV1(
      formatVersion: formatVersion,
      requestHash: requestHash,
      relayGrant: try RelayGrantCanonicalCodec.decode(grantBytes),
      relayGrantCanonicalBytes: grantBytes,
      deviceAuthorization: try DeviceAuthorizationCanonicalCodec.decode(authorizationBytes),
      deviceAuthorizationCanonicalBytes: authorizationBytes,
      keyDirectory: try KeyDirectoryCanonicalCodec.decode(directoryBytes),
      keyDirectoryCanonicalBytes: directoryBytes
    )
    guard try encode(value) == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }
}

struct CanonicalPairPendingV1: Equatable, Sendable, CustomDebugStringConvertible {
  let requestHash: Data
  let signature: Data

  init(requestHash: Data, signature: Data) throws {
    guard requestHash.count == 32,
      requestHash.contains(where: { $0 != 0 }),
      signature.count == 64,
      signature.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    self.requestHash = requestHash
    self.signature = signature
  }

  var debugDescription: String { "CanonicalPairPendingV1(material: <redacted>)" }
}

enum PairPendingCanonicalCodec {
  static let maximumCanonicalBytes = 256
  private static let domain = Data("AgentDeck/PairPendingV1\0".utf8)

  static func encode(_ value: CanonicalPairPendingV1) throws -> Data {
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.bytes(value.requestHash, exact: 32)
    try encoder.bytes(value.signature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairPendingV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var decoder = PairResponseDecoder(bytes)
    try decoder.domain(domain)
    let value = try CanonicalPairPendingV1(
      requestHash: decoder.bytes(exact: 32),
      signature: decoder.bytes(exact: 64)
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }
}

struct CanonicalPairResponseReceivedV1: Equatable, Sendable, CustomDebugStringConvertible {
  let requestHash: Data
  let grantHash: Data
  let responseHash: Data
  let signature: Data

  init(
    requestHash: Data,
    grantHash: Data,
    responseHash: Data,
    signature: Data,
    requireSignature: Bool = true
  ) throws {
    guard Self.isNonzero(requestHash, count: 32),
      Self.isNonzero(grantHash, count: 32),
      Self.isNonzero(responseHash, count: 32),
      signature.count == 64,
      !requireSignature || signature.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    self.requestHash = requestHash
    self.grantHash = grantHash
    self.responseHash = responseHash
    self.signature = signature
  }

  var debugDescription: String {
    "CanonicalPairResponseReceivedV1(material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum PairResponseReceivedCanonicalCodec {
  static let maximumCanonicalBytes = 1_024
  private static let unsignedDomain = Data(
    "AgentDeck/PairResponseReceivedUnsignedV1\0".utf8
  )
  private static let domain = Data("AgentDeck/PairResponseReceivedV1\0".utf8)

  static func unsignedCanonicalBytes(
    _ value: CanonicalPairResponseReceivedV1
  ) throws -> Data {
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(unsignedDomain)
    try encoder.bytes(value.requestHash, exact: 32)
    try encoder.bytes(value.grantHash, exact: 32)
    try encoder.bytes(value.responseHash, exact: 32)
    return try encoder.finish()
  }

  static func encode(_ value: CanonicalPairResponseReceivedV1) throws -> Data {
    guard value.signature.contains(where: { $0 != 0 }) else {
      throw PairResponseCryptoError.invalidEncoding
    }
    var encoder = PairResponseEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.bytes(unsignedCanonicalBytes(value))
    try encoder.bytes(value.signature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> CanonicalPairResponseReceivedV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairResponseCryptoError.sizeLimit
    }
    var outer = PairResponseDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumCanonicalBytes)
    let signature = try outer.bytes(exact: 64)
    try outer.finish()
    var decoder = PairResponseDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let value = try CanonicalPairResponseReceivedV1(
      requestHash: decoder.bytes(exact: 32),
      grantHash: decoder.bytes(exact: 32),
      responseHash: decoder.bytes(exact: 32),
      signature: signature
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }
}

struct VerifiedPendingPairResponseV1: Sendable, CustomDebugStringConvertible {
  let canonicalResponse: Data
  let responseHash: Data
  let info: PairResponseInfoV1
  let plaintext: CanonicalPairResponsePlaintextV1
  let verifiedCertificate: VerifiedMachineDataCertificate
  let verifiedGrant: VerifiedRelayGrantCredential

  var debugDescription: String {
    "VerifiedPendingPairResponseV1(material: <redacted>)"
  }
}

struct OpaquePairResponseReceivedCarrier: Sendable, CustomDebugStringConvertible {
  let pairRoute: Data
  let canonicalBytes: Data

  init(pairRoute: Data, canonicalBytes: Data) throws {
    guard pairRoute.count == 16,
      pairRoute.contains(where: { $0 != 0 }),
      canonicalBytes.count <= PairTerminalEnvelopeCodec.maximumCanonicalBytes
    else {
      throw PairResponseCryptoError.invalidEncoding
    }
    _ = try PairTerminalEnvelopeCodec.decode(canonicalBytes)
    self.pairRoute = pairRoute
    self.canonicalBytes = canonicalBytes
  }

  var debugDescription: String {
    "OpaquePairResponseReceivedCarrier(material: <redacted>)"
  }
}

enum PairResponseCrypto {
  static func openVerified(
    canonicalResponse: Data,
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1,
    requestHash: Data,
    deviceSigningKey: Curve25519.Signing.PrivateKey,
    deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey,
    nowMilliseconds: UInt64
  ) throws -> VerifiedPendingPairResponseV1 {
    try invite.validate(nowMilliseconds: nowMilliseconds)
    try authorizationRequest.validate()
    let response = try PairResponseCanonicalCodec.decode(canonicalResponse)
    let info = response.info
    guard info.relayServerID == invite.relayServerID,
      info.pairRoute == invite.pairRoute,
      info.inviteHash == (try invite.canonicalSHA256()),
      info.expiryMilliseconds == invite.expiresAtMilliseconds,
      info.requestHash == requestHash,
      deviceHPKEPrivateKey.publicKey.rawRepresentation.count == 32
    else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    let verifiedCertificate: VerifiedMachineDataCertificate
    do {
      verifiedCertificate = try MachineDataCertificateVerifier.verify(
        invite.dataSignCertificate,
        relayServerID: invite.relayServerID,
        machineRoute: info.machineRoute,
        machineRootPublicKey: invite.machineRootPublicKey,
        machineRootFingerprint: invite.machineRootFingerprint,
        expectedRootKeyID: invite.dataSignCertificate.rootKeyId,
        expectedTrustEpoch: info.rootTrustEpoch,
        minimumDataCertificateGeneration: invite.dataSignCertificate.generation,
        nowMilliseconds: nowMilliseconds
      )
    } catch {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    let context = pairingContext(kind: .pairResponse, pairRoute: invite.pairRoute)
    let tbs = try responseSignatureTBS(
      response,
      context: context,
      verifiedCertificate: verifiedCertificate
    )
    guard
      verifiedCertificate.signingKey.isValidSignature(
        response.machineDataSignature,
        for: tbs
      )
    else {
      throw PairResponseCryptoError.badSignature
    }

    let opened: Data
    do {
      opened = try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(
          enc: response.encapsulatedKey,
          ciphertext: response.ciphertext
        ),
        recipient: deviceHPKEPrivateKey,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairResponseCryptoError.hpkeOpenFailed
    }
    let plaintext = try PairResponsePlaintextCanonicalCodec.decode(opened)
    guard plaintext.requestHash == requestHash,
      plaintext.relayGrant.machineRoute == info.machineRoute,
      plaintext.relayGrant.deviceRoute == info.deviceRoute,
      plaintext.relayGrant.grantSerial == info.grantSerial,
      plaintext.relayGrant.deviceSignPubkey
        == deviceSigningKey.publicKey.rawRepresentation,
      plaintext.relayGrant.rootKeyId == invite.dataSignCertificate.rootKeyId,
      plaintext.relayGrant.trustEpoch == info.rootTrustEpoch,
      plaintext.deviceAuthorization.deviceHPKEPublicKey
        == deviceHPKEPrivateKey.publicKey.rawRepresentation,
      plaintext.deviceAuthorization.capabilities == authorizationRequest.capabilities,
      plaintext.deviceAuthorization.permissions == authorizationRequest.permissions
    else {
      throw PairResponseCryptoError.authorizationMismatch
    }
    let verifiedGrant: VerifiedRelayGrantCredential
    do {
      verifiedGrant = try RelayGrantCredentialVerifier.verify(
        plaintext.relayGrant,
        relayServerID: invite.relayServerID,
        machineRootPublicKey: invite.machineRootPublicKey,
        machineRootFingerprint: invite.machineRootFingerprint,
        expectedMachineRoute: info.machineRoute,
        expectedDeviceRoute: info.deviceRoute,
        expectedDeviceSignPublicKey: deviceSigningKey.publicKey.rawRepresentation,
        expectedGrantSerial: info.grantSerial,
        expectedRootKeyID: invite.dataSignCertificate.rootKeyId,
        expectedTrustEpoch: info.rootTrustEpoch
      )
      try verifyDeviceAuthorization(
        plaintext.deviceAuthorization,
        grant: plaintext.relayGrant,
        relayServerID: invite.relayServerID,
        machineRootPublicKey: invite.machineRootPublicKey,
        machineRootFingerprint: invite.machineRootFingerprint
      )
    } catch {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    return VerifiedPendingPairResponseV1(
      canonicalResponse: canonicalResponse,
      responseHash: CanonicalCodec.sha256(canonicalResponse),
      info: info,
      plaintext: plaintext,
      verifiedCertificate: verifiedCertificate,
      verifiedGrant: verifiedGrant
    )
  }

  static func openPairPending(
    canonicalEnvelope: Data,
    invite: PairInviteV1,
    requestHash: Data,
    deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey,
    nowMilliseconds: UInt64
  ) throws -> CanonicalPairPendingV1 {
    try invite.validate(nowMilliseconds: nowMilliseconds)
    let info = try PairRequestInfoV1(
      relayServerID: invite.relayServerID,
      pairRoute: invite.pairRoute,
      inviteHash: invite.canonicalSHA256(),
      expiryMilliseconds: invite.expiresAtMilliseconds
    )
    let context = pairingContext(kind: .pairPending, pairRoute: invite.pairRoute)
    let envelope = try PairTerminalEnvelopeCodec.decode(canonicalEnvelope)
    let opened: Data
    do {
      opened = try RelayCrypto.openHPKE(
        HPKEEnvelopeV1(
          enc: envelope.encapsulatedKey,
          ciphertext: envelope.ciphertext
        ),
        recipient: deviceHPKEPrivateKey,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairResponseCryptoError.hpkeOpenFailed
    }
    let pending = try PairPendingCanonicalCodec.decode(opened)
    guard pending.requestHash == requestHash else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    let key: Curve25519.Signing.PublicKey
    do {
      key = try Curve25519.Signing.PublicKey(
        rawRepresentation: invite.dataSignCertificate.subjectPubkey
      )
    } catch {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    guard
      key.isValidSignature(
        pending.signature,
        for: try pairPendingSignatureTBS(
          pending,
          info: info,
          context: context,
          certificate: invite.dataSignCertificate
        )
      )
    else {
      throw PairResponseCryptoError.badSignature
    }
    return pending
  }

  static func sealPairResponseReceived(
    verified: VerifiedPendingPairResponseV1,
    invite: PairInviteV1,
    deviceSigningKey: Curve25519.Signing.PrivateKey
  ) throws -> OpaquePairResponseReceivedCarrier {
    let context = pairingContext(
      kind: .pairResponseReceived,
      pairRoute: invite.pairRoute
    )
    let grantHash = try RelayGrantCanonicalCodec.canonicalSHA256(
      verified.plaintext.relayGrant
    )
    var receipt = try CanonicalPairResponseReceivedV1(
      requestHash: verified.info.requestHash,
      grantHash: grantHash,
      responseHash: verified.responseHash,
      signature: Data(repeating: 0, count: 64),
      requireSignature: false
    )
    let signature = try deviceSigningKey.signature(
      for: responseReceivedTBS(
        receipt,
        info: verified.info,
        context: context,
        deviceSignFingerprint: CanonicalCodec.sha256(
          deviceSigningKey.publicKey.rawRepresentation
        )
      )
    )
    receipt = try CanonicalPairResponseReceivedV1(
      requestHash: receipt.requestHash,
      grantHash: receipt.grantHash,
      responseHash: receipt.responseHash,
      signature: signature
    )
    let recipient: Curve25519.KeyAgreement.PublicKey
    do {
      recipient = try Curve25519.KeyAgreement.PublicKey(
        rawRepresentation: invite.inviteHPKEPublicKey
      )
    } catch {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    let sealed: HPKEEnvelopeV1
    do {
      sealed = try RelayCrypto.sealHPKE(
        PairResponseReceivedCanonicalCodec.encode(receipt),
        recipient: recipient,
        info: verified.info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairResponseCryptoError.hpkeSealFailed
    }
    let canonical = try PairTerminalEnvelopeCodec.encode(
      CanonicalPairingControlEnvelopeV1(
        formatVersion: 1,
        encapsulatedKey: sealed.enc,
        ciphertext: sealed.ciphertext
      )
    )
    return try OpaquePairResponseReceivedCarrier(
      pairRoute: invite.pairRoute,
      canonicalBytes: canonical
    )
  }

  static func responseSignatureTBS(
    _ response: CanonicalPairResponseV1,
    context: OuterContextV1,
    verifiedCertificate: VerifiedMachineDataCertificate
  ) throws -> Data {
    let info = response.info
    try validatePairingContext(context, kind: .pairResponse, pairRoute: info.pairRoute)
    let certificate = verifiedCertificate.certificate
    let fingerprint = CanonicalCodec.sha256(certificate.subjectPubkey)
    let certificateHash = try SignedCertificateCanonicalCodec.canonicalSHA256(certificate)
    guard certificate.certRole == .data,
      certificate.subjectPubkey == verifiedCertificate.signingKey.rawRepresentation,
      certificate.generation > 0,
      fingerprint.contains(where: { $0 != 0 }),
      certificateHash.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    return try responseSignatureTBS(
      response,
      context: context,
      signingKeyFingerprint: fingerprint,
      signingKeyGeneration: certificate.generation,
      signingCredentialSHA256: certificateHash
    )
  }

  static func responseSignatureTBS(
    _ response: CanonicalPairResponseV1,
    context: OuterContextV1,
    signingKeyFingerprint: Data,
    signingKeyGeneration: UInt64,
    signingCredentialSHA256: Data
  ) throws -> Data {
    let info = response.info
    try validatePairingContext(context, kind: .pairResponse, pairRoute: info.pairRoute)
    guard signingKeyFingerprint.count == 32,
      signingKeyFingerprint.contains(where: { $0 != 0 }),
      signingKeyGeneration > 0,
      signingCredentialSHA256.count == 32,
      signingCredentialSHA256.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    var encoder = PairResponseEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairingEnvelopeTbsV1\0".utf8))
    try encoder.u8(1)
    try encoder.u16(response.formatVersion)
    try encoder.u16(info.runtimeProtocolVersion)
    try encoder.u16(context.relayProtocolVersion)
    try encoder.bytes(info.relayServerID, exact: 16)
    try encoder.bytes(info.pairRoute, exact: 16)
    try encoder.bytes(info.inviteHash, exact: 32)
    try encoder.u64(info.expiryMilliseconds)
    try encoder.optionalBytes(info.requestHash, exact: 32)
    try encoder.optionalID16(info.machineRoute)
    try encoder.optionalID16(info.deviceRoute)
    try encoder.optionalU64(info.grantSerial)
    try encoder.optionalU64(info.rootTrustEpoch)
    try encoder.bytes(signingKeyFingerprint, exact: 32)
    try encoder.optionalU64(signingKeyGeneration)
    try encoder.optionalBytes(signingCredentialSHA256, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(info.canonicalBytes()), exact: 32)
    try encoder.bytes(
      CanonicalCodec.sha256(CanonicalCodec.encodeAAD(context)),
      exact: 32
    )
    try encoder.bytes(response.encapsulatedKey, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(response.ciphertext), exact: 32)
    return try encoder.finish()
  }

  static func pairPendingSignatureTBS(
    _ pending: CanonicalPairPendingV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    certificate: RelayV2SignedCertificate
  ) throws -> Data {
    try validatePairingContext(context, kind: .pairPending, pairRoute: info.pairRoute)
    let fingerprint = CanonicalCodec.sha256(certificate.subjectPubkey)
    let certificateHash = try SignedCertificateCanonicalCodec.canonicalSHA256(certificate)
    guard certificate.certRole == .data,
      certificate.generation > 0,
      fingerprint.contains(where: { $0 != 0 }),
      certificateHash.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    return try pairPendingSignatureTBS(
      pending,
      info: info,
      context: context,
      signingKeyFingerprint: fingerprint,
      signingKeyGeneration: certificate.generation,
      signingCredentialSHA256: certificateHash
    )
  }

  static func pairPendingSignatureTBS(
    _ pending: CanonicalPairPendingV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    signingKeyFingerprint: Data,
    signingKeyGeneration: UInt64,
    signingCredentialSHA256: Data
  ) throws -> Data {
    try validatePairingContext(context, kind: .pairPending, pairRoute: info.pairRoute)
    guard signingKeyFingerprint.count == 32,
      signingKeyFingerprint.contains(where: { $0 != 0 }),
      signingKeyGeneration > 0,
      signingCredentialSHA256.count == 32,
      signingCredentialSHA256.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidTrustBinding
    }
    var encoder = PairResponseEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairPendingTbsV1\0".utf8))
    try encoder.u16(info.e2eeFormatVersion)
    try encoder.u16(info.runtimeProtocolVersion)
    try encoder.u16(context.relayProtocolVersion)
    try encoder.bytes(info.relayServerID, exact: 16)
    try encoder.bytes(info.pairRoute, exact: 16)
    try encoder.bytes(info.inviteHash, exact: 32)
    try encoder.u64(info.expiryMilliseconds)
    try encoder.bytes(pending.requestHash, exact: 32)
    try encoder.bytes(signingKeyFingerprint, exact: 32)
    try encoder.u64(signingKeyGeneration)
    try encoder.bytes(signingCredentialSHA256, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(info.canonicalBytes()), exact: 32)
    try encoder.bytes(
      CanonicalCodec.sha256(CanonicalCodec.encodeAAD(context)),
      exact: 32
    )
    return try encoder.finish()
  }

  static func responseReceivedTBS(
    _ receipt: CanonicalPairResponseReceivedV1,
    info: PairResponseInfoV1,
    context: OuterContextV1,
    deviceSignFingerprint: Data
  ) throws -> Data {
    try validatePairingContext(
      context,
      kind: .pairResponseReceived,
      pairRoute: info.pairRoute
    )
    guard receipt.requestHash == info.requestHash,
      deviceSignFingerprint.count == 32,
      deviceSignFingerprint.contains(where: { $0 != 0 })
    else {
      throw PairResponseCryptoError.invalidContext
    }
    var encoder = PairResponseEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairResponseReceivedTbsV1\0".utf8))
    try encoder.u16(info.e2eeFormatVersion)
    try encoder.u16(info.runtimeProtocolVersion)
    try encoder.u16(context.relayProtocolVersion)
    try encoder.bytes(info.relayServerID, exact: 16)
    try encoder.bytes(info.pairRoute, exact: 16)
    try encoder.bytes(info.inviteHash, exact: 32)
    try encoder.u64(info.expiryMilliseconds)
    try encoder.bytes(receipt.requestHash, exact: 32)
    try encoder.bytes(receipt.grantHash, exact: 32)
    try encoder.bytes(receipt.responseHash, exact: 32)
    try encoder.bytes(info.machineRoute, exact: 16)
    try encoder.bytes(info.deviceRoute, exact: 16)
    try encoder.u64(info.grantSerial)
    try encoder.u64(info.rootTrustEpoch)
    try encoder.bytes(deviceSignFingerprint, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(info.canonicalBytes()), exact: 32)
    try encoder.bytes(
      CanonicalCodec.sha256(CanonicalCodec.encodeAAD(context)),
      exact: 32
    )
    return try encoder.finish()
  }

  private static func verifyDeviceAuthorization(
    _ authorization: CanonicalDeviceAuthorizationV1,
    grant: RelayV2Grant,
    relayServerID: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data
  ) throws {
    guard authorization.grantHash == (try RelayGrantCanonicalCodec.canonicalSHA256(grant)),
      authorization.machineRoute == grant.machineRoute,
      authorization.deviceRoute == grant.deviceRoute,
      authorization.deviceSignFingerprint == CanonicalCodec.sha256(grant.deviceSignPubkey),
      authorization.grantSerial == grant.grantSerial,
      authorization.rootKeyID == grant.rootKeyId,
      authorization.trustEpoch == grant.trustEpoch,
      machineRootFingerprint == CanonicalCodec.sha256(machineRootPublicKey)
    else {
      throw PairResponseCryptoError.authorizationMismatch
    }
    let rootKey = try Curve25519.Signing.PublicKey(
      rawRepresentation: machineRootPublicKey
    )
    let tbs = ToBeSignedV1(
      objectType: .deviceAuthorization,
      signatureFormatVersion: 1,
      relayProtocolVersion: relayProtocolVersionV2,
      runtimeProtocolVersion: runtimeProtocolVersionCurrent,
      e2eeFormatVersion: 1,
      relayServerID: relayServerID,
      machineRoute: authorization.machineRoute,
      deviceRoute: authorization.deviceRoute,
      streamRoute: nil,
      requestRoute: nil,
      streamGeneration: nil,
      streamCursor: nil,
      roleScope: "device-authorization",
      signingKeyFingerprint: machineRootFingerprint,
      rootKeyID: authorization.rootKeyID,
      trustEpoch: authorization.trustEpoch,
      serialOrGeneration: authorization.grantSerial,
      notAfterMS: nil,
      signedObjectSHA256:
        try DeviceAuthorizationCanonicalCodec
        .unsignedCanonicalSHA256(authorization)
    )
    guard RelayCrypto.verify(authorization.signature, tbs: tbs, key: rootKey) else {
      throw PairResponseCryptoError.badSignature
    }
  }

  private static func pairingContext(
    kind: OuterFrameKind,
    pairRoute: Data
  ) -> OuterContextV1 {
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
      pairRoute: pairRoute
    )
  }

  private static func validatePairingContext(
    _ context: OuterContextV1,
    kind: OuterFrameKind,
    pairRoute: Data
  ) throws {
    do { try context.validateShape() } catch {
      throw PairResponseCryptoError.invalidContext
    }
    guard context.frameKind == kind,
      context.relayProtocolVersion == relayProtocolVersionV2,
      context.e2eeFormatVersion == 1,
      context.pairRoute == pairRoute
    else {
      throw PairResponseCryptoError.invalidContext
    }
  }
}

private struct PairResponseEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) { self.maximumBytes = maximumBytes }

  mutating func raw(_ value: Data) throws { try append(value) }
  mutating func u8(_ value: UInt8) throws { try append(Data([value])) }
  mutating func u16(_ value: UInt16) throws { try integer(value) }
  mutating func u64(_ value: UInt64) throws { try integer(value) }

  mutating func bytes(
    _ value: Data,
    exact: Int? = nil,
    maximum: Int? = nil
  ) throws {
    if let exact, value.count != exact {
      throw PairResponseCryptoError.invalidEncoding
    }
    if let maximum, value.count > maximum {
      throw PairResponseCryptoError.sizeLimit
    }
    guard let count = UInt32(exactly: value.count) else {
      throw PairResponseCryptoError.sizeLimit
    }
    try integer(count)
    try append(value)
  }

  mutating func optionalBytes(_ value: Data?, exact: Int) throws {
    guard let value else {
      try u8(0)
      return
    }
    try u8(1)
    try bytes(value, exact: exact)
  }

  mutating func optionalID16(_ value: Data?) throws {
    guard let value else {
      try u8(0)
      return
    }
    guard value.count == 16 else {
      throw PairResponseCryptoError.invalidEncoding
    }
    try u8(1)
    try append(value)
  }

  mutating func optionalU64(_ value: UInt64?) throws {
    guard let value else {
      try u8(0)
      return
    }
    try u8(1)
    try u64(value)
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else {
      throw PairResponseCryptoError.sizeLimit
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
      throw PairResponseCryptoError.sizeLimit
    }
    output.append(value)
  }
}

private struct PairResponseDecoder {
  private let input: Data
  private var offset = 0

  init(_ input: Data) { self.input = input }

  mutating func domain(_ expected: Data) throws {
    guard try take(expected.count) == expected else {
      throw PairResponseCryptoError.invalidEncoding
    }
  }

  mutating func u8() throws -> UInt8 { try take(1)[0] }
  mutating func u16() throws -> UInt16 { try integer() }
  mutating func u32() throws -> UInt32 { try integer() }
  mutating func u64() throws -> UInt64 { try integer() }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else { throw PairResponseCryptoError.sizeLimit }
    return try take(count)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else {
      throw PairResponseCryptoError.invalidEncoding
    }
    return value
  }

  mutating func finish() throws {
    guard offset == input.count else {
      throw PairResponseCryptoError.invalidEncoding
    }
  }

  private mutating func integer<T: FixedWidthInteger>() throws -> T {
    try take(MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
  }

  private mutating func take(_ count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= input.count else {
      throw PairResponseCryptoError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return Data(input[offset..<end.partialValue])
  }
}
