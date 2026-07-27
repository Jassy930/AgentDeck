import AgentDeckCore
import CryptoKit
import Foundation

enum PairRequestCryptoError: Error, Equatable, Sendable {
  case unsupportedVersion
  case expired
  case expiryOutOfBounds
  case invalidEncoding
  case sizeLimit(String)
  case invalidField(String)
  case duplicateAuthorization
  case permissionWithoutCapability
  case invalidContext
  case hpkeSealFailed
  case signingFailed
}

enum AuthorizationCapabilityV1: UInt8, CaseIterable, Equatable, Sendable {
  case catalog = 0
  case conversation = 1
  case prompt = 2
  case command = 3
  case approval = 4
  case metadata = 5
  case selfRevocation = 6
}

enum AuthorizationPermissionV1: UInt8, CaseIterable, Equatable, Sendable {
  case catalogRead = 0
  case conversationRead = 1
  case conversationStart = 2
  case promptSend = 3
  case commandCancel = 4
  case approvalResolve = 5
  case approvalRetry = 6
  case metadataWrite = 7
  case revokeSelf = 8

  fileprivate var requiredCapability: AuthorizationCapabilityV1 {
    switch self {
    case .catalogRead: .catalog
    case .conversationRead, .conversationStart: .conversation
    case .promptSend: .prompt
    case .commandCancel: .command
    case .approvalResolve, .approvalRetry: .approval
    case .metadataWrite: .metadata
    case .revokeSelf: .selfRevocation
    }
  }
}

struct AuthorizationRequestV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let deviceDisplayName: String
  let capabilities: [AuthorizationCapabilityV1]
  let permissions: [AuthorizationPermissionV1]

  init(
    formatVersion: UInt16 = 1,
    deviceDisplayName: String,
    capabilities: [AuthorizationCapabilityV1],
    permissions: [AuthorizationPermissionV1]
  ) throws {
    self.formatVersion = formatVersion
    self.deviceDisplayName = deviceDisplayName
    self.capabilities = capabilities
    self.permissions = permissions
    try validate()
  }

  var debugDescription: String {
    "AuthorizationRequestV1(formatVersion: \(formatVersion), material: <redacted>)"
  }

  func validate() throws {
    guard formatVersion == 1 else {
      throw PairRequestCryptoError.unsupportedVersion
    }
    try PairRequestValidation.validateDisplayName(deviceDisplayName)
    guard !capabilities.isEmpty,
      capabilities.count <= AuthorizationCapabilityV1.allCases.count
    else {
      throw PairRequestCryptoError.sizeLimit("capabilities")
    }
    guard !permissions.isEmpty,
      permissions.count <= AuthorizationPermissionV1.allCases.count
    else {
      throw PairRequestCryptoError.sizeLimit("permissions")
    }
    guard PairRequestValidation.isStrictlyIncreasing(capabilities.map(\.rawValue)),
      PairRequestValidation.isStrictlyIncreasing(permissions.map(\.rawValue))
    else {
      throw PairRequestCryptoError.duplicateAuthorization
    }
    let capabilitySet = Set(capabilities)
    guard permissions.allSatisfy({ capabilitySet.contains($0.requiredCapability) }) else {
      throw PairRequestCryptoError.permissionWithoutCapability
    }
  }
}

enum AuthorizationRequestCanonicalCodec {
  static let maximumCanonicalBytes = 4 * 1_024

  private static let domain = Data("AgentDeck/AuthorizationRequestV1\0".utf8)

  static func encode(_ value: AuthorizationRequestV1) throws -> Data {
    try value.validate()
    var encoder = PairRequestEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(value.formatVersion)
    try encoder.string(value.deviceDisplayName)
    try encoder.u8(UInt8(value.capabilities.count))
    for capability in value.capabilities {
      try encoder.u8(capability.rawValue)
    }
    try encoder.u8(UInt8(value.permissions.count))
    for permission in value.permissions {
      try encoder.u8(permission.rawValue)
    }
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> AuthorizationRequestV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairRequestCryptoError.sizeLimit("authorization request")
    }
    var decoder = PairRequestDecoder(bytes)
    try decoder.domain(domain)
    let formatVersion = try decoder.u16()
    let displayName = try decoder.string(maximum: PairRequestValidation.maximumDisplayNameBytes)
    let capabilityCount = Int(try decoder.u8())
    guard capabilityCount <= AuthorizationCapabilityV1.allCases.count else {
      throw PairRequestCryptoError.sizeLimit("capabilities")
    }
    var capabilities: [AuthorizationCapabilityV1] = []
    capabilities.reserveCapacity(capabilityCount)
    for _ in 0..<capabilityCount {
      guard let capability = AuthorizationCapabilityV1(rawValue: try decoder.u8()) else {
        throw PairRequestCryptoError.invalidEncoding
      }
      capabilities.append(capability)
    }
    let permissionCount = Int(try decoder.u8())
    guard permissionCount <= AuthorizationPermissionV1.allCases.count else {
      throw PairRequestCryptoError.sizeLimit("permissions")
    }
    var permissions: [AuthorizationPermissionV1] = []
    permissions.reserveCapacity(permissionCount)
    for _ in 0..<permissionCount {
      guard let permission = AuthorizationPermissionV1(rawValue: try decoder.u8()) else {
        throw PairRequestCryptoError.invalidEncoding
      }
      permissions.append(permission)
    }
    try decoder.finish()
    let value = try AuthorizationRequestV1(
      formatVersion: formatVersion,
      deviceDisplayName: displayName,
      capabilities: capabilities,
      permissions: permissions
    )
    guard try encode(value) == bytes else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return value
  }
}

struct PairInviteV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let relayProtocolVersion: UInt16
  let pairRoute: Data
  let inviteSecret: Data
  let inviteHPKEPublicKey: Data
  let wssURL: String
  let relayServerID: Data
  let currentSPKIPin: Data
  let nextSPKIPin: Data
  let expiresAtMilliseconds: UInt64
  let machineRootPublicKey: Data
  let machineRootFingerprint: Data
  let dataSignCertificate: RelayV2SignedCertificate
  let machineDisplayName: String

  init(
    formatVersion: UInt16 = 1,
    relayProtocolVersion: UInt16 = relayProtocolVersionV2,
    pairRoute: Data,
    inviteSecret: Data,
    inviteHPKEPublicKey: Data,
    wssURL: String,
    relayServerID: Data,
    currentSPKIPin: Data,
    nextSPKIPin: Data,
    expiresAtMilliseconds: UInt64,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    dataSignCertificate: RelayV2SignedCertificate,
    machineDisplayName: String
  ) throws {
    self.formatVersion = formatVersion
    self.relayProtocolVersion = relayProtocolVersion
    self.pairRoute = pairRoute
    self.inviteSecret = inviteSecret
    self.inviteHPKEPublicKey = inviteHPKEPublicKey
    self.wssURL = wssURL
    self.relayServerID = relayServerID
    self.currentSPKIPin = currentSPKIPin
    self.nextSPKIPin = nextSPKIPin
    self.expiresAtMilliseconds = expiresAtMilliseconds
    self.machineRootPublicKey = machineRootPublicKey
    self.machineRootFingerprint = machineRootFingerprint
    self.dataSignCertificate = dataSignCertificate
    self.machineDisplayName = machineDisplayName
    try validateStatic()
  }

  var debugDescription: String {
    "PairInviteV1(material: <redacted>)"
  }

  func validateStatic() throws {
    guard formatVersion == 1, relayProtocolVersion == relayProtocolVersionV2 else {
      throw PairRequestCryptoError.unsupportedVersion
    }
    try PairRequestValidation.validateCanonicalWSSURL(wssURL)
    try PairRequestValidation.validateDisplayName(machineDisplayName)
    guard PairRequestValidation.isNonzero(pairRoute, count: 16),
      PairRequestValidation.isNonzero(inviteSecret, count: 32),
      PairRequestValidation.isNonzero(inviteHPKEPublicKey, count: 32),
      PairRequestValidation.isNonzero(relayServerID, count: 16),
      PairRequestValidation.isNonzero(currentSPKIPin, count: 32),
      PairRequestValidation.isNonzero(nextSPKIPin, count: 32),
      PairRequestValidation.isNonzero(machineRootPublicKey, count: 32),
      PairRequestValidation.isNonzero(machineRootFingerprint, count: 32),
      expiresAtMilliseconds > 0
    else {
      throw PairRequestCryptoError.invalidField("zero identity/key material")
    }
    guard CanonicalCodec.sha256(machineRootPublicKey) == machineRootFingerprint else {
      throw PairRequestCryptoError.invalidField("MachineRoot fingerprint")
    }
    let certificate = dataSignCertificate
    guard certificate.certRole == .data,
      certificate.generation > 0,
      certificate.trustEpoch > 0,
      certificate.notAfterMs != 0,
      PairRequestValidation.isNonzero(certificate.subjectPubkey, count: 32),
      PairRequestValidation.isNonzero(certificate.rootKeyId, count: 16),
      PairRequestValidation.isNonzero(certificate.signature, count: 64)
    else {
      throw PairRequestCryptoError.invalidField("MachineDataSign certificate")
    }
    do {
      _ = try SignedCertificateCanonicalCodec.encode(certificate)
    } catch {
      throw PairRequestCryptoError.invalidField("MachineDataSign certificate")
    }
  }

  func validate(nowMilliseconds: UInt64) throws {
    try validateStatic()
    guard expiresAtMilliseconds > nowMilliseconds else {
      throw PairRequestCryptoError.expired
    }
    guard expiresAtMilliseconds - nowMilliseconds <= PairInviteCanonicalCodec.maximumTTLMilliseconds
    else {
      throw PairRequestCryptoError.expiryOutOfBounds
    }
    if let certificateExpiry = dataSignCertificate.notAfterMs,
      nowMilliseconds >= certificateExpiry
    {
      throw PairRequestCryptoError.invalidField("expired MachineDataSign certificate")
    }
  }

  func canonicalSHA256() throws -> Data {
    CanonicalCodec.sha256(try PairInviteCanonicalCodec.encode(self))
  }

  func encodeURI(nowMilliseconds: UInt64) throws -> String {
    try validate(nowMilliseconds: nowMilliseconds)
    let payload = PairInviteCanonicalCodec.base64URLNoPadding(
      try PairInviteCanonicalCodec.encode(self)
    )
    let encoded = PairInviteCanonicalCodec.uriPrefix + payload
    guard encoded.utf8.count <= PairInviteCanonicalCodec.maximumURIBytes else {
      throw PairRequestCryptoError.sizeLimit("pair invite URI")
    }
    return encoded
  }

  static func decodeURI(
    _ encoded: String,
    nowMilliseconds: UInt64
  ) throws -> PairInviteV1 {
    guard encoded.utf8.count <= PairInviteCanonicalCodec.maximumURIBytes,
      !encoded.contains("=")
    else {
      throw PairRequestCryptoError.sizeLimit("pair invite URI")
    }
    guard encoded.hasPrefix(PairInviteCanonicalCodec.uriPrefix) else {
      throw PairRequestCryptoError.invalidEncoding
    }
    let payload = String(encoded.dropFirst(PairInviteCanonicalCodec.uriPrefix.count))
    let bytes = try PairInviteCanonicalCodec.decodeBase64URLNoPadding(payload)
    guard PairInviteCanonicalCodec.base64URLNoPadding(bytes) == payload else {
      throw PairRequestCryptoError.invalidEncoding
    }
    let invite = try PairInviteCanonicalCodec.decode(bytes)
    try invite.validate(nowMilliseconds: nowMilliseconds)
    return invite
  }
}

enum PairInviteCanonicalCodec {
  static let uriPrefix = "agentdeck-pair:v1:"
  static let maximumTTLMilliseconds: UInt64 = 5 * 60 * 1_000
  static let maximumURIBytes = 8 * 1_024
  static let maximumCanonicalBytes = 8 * 1_024

  private static let domain = Data("AgentDeck/PairInviteV1\0".utf8)

  static func encode(_ value: PairInviteV1) throws -> Data {
    try value.validateStatic()
    let certificate: Data
    do {
      certificate = try SignedCertificateCanonicalCodec.encode(value.dataSignCertificate)
    } catch {
      throw PairRequestCryptoError.invalidEncoding
    }
    var encoder = PairRequestEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(value.formatVersion)
    try encoder.u16(value.relayProtocolVersion)
    try encoder.bytes(value.pairRoute, exact: 16)
    try encoder.bytes(value.inviteSecret, exact: 32)
    try encoder.bytes(value.inviteHPKEPublicKey, exact: 32)
    try encoder.string(value.wssURL)
    try encoder.bytes(value.relayServerID, exact: 16)
    try encoder.bytes(value.currentSPKIPin, exact: 32)
    try encoder.bytes(value.nextSPKIPin, exact: 32)
    try encoder.u64(value.expiresAtMilliseconds)
    try encoder.bytes(value.machineRootPublicKey, exact: 32)
    try encoder.bytes(value.machineRootFingerprint, exact: 32)
    try encoder.bytes(certificate)
    try encoder.string(value.machineDisplayName)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> PairInviteV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairRequestCryptoError.sizeLimit("pair invite canonical bytes")
    }
    var decoder = PairRequestDecoder(bytes)
    try decoder.domain(domain)
    let formatVersion = try decoder.u16()
    let relayProtocolVersion = try decoder.u16()
    let pairRoute = try decoder.bytes(exact: 16)
    let inviteSecret = try decoder.bytes(exact: 32)
    let inviteHPKEPublicKey = try decoder.bytes(exact: 32)
    let wssURL = try decoder.string(maximum: PairRequestValidation.maximumURLBytes)
    let relayServerID = try decoder.bytes(exact: 16)
    let currentSPKIPin = try decoder.bytes(exact: 32)
    let nextSPKIPin = try decoder.bytes(exact: 32)
    let expiresAtMilliseconds = try decoder.u64()
    let machineRootPublicKey = try decoder.bytes(exact: 32)
    let machineRootFingerprint = try decoder.bytes(exact: 32)
    let certificateBytes = try decoder.bytes(
      maximum: SignedCertificateCanonicalCodec.maximumCanonicalBytes
    )
    let certificate: RelayV2SignedCertificate
    do {
      certificate = try SignedCertificateCanonicalCodec.decode(certificateBytes)
    } catch {
      throw PairRequestCryptoError.invalidEncoding
    }
    let machineDisplayName = try decoder.string(
      maximum: PairRequestValidation.maximumDisplayNameBytes
    )
    try decoder.finish()
    let value = try PairInviteV1(
      formatVersion: formatVersion,
      relayProtocolVersion: relayProtocolVersion,
      pairRoute: pairRoute,
      inviteSecret: inviteSecret,
      inviteHPKEPublicKey: inviteHPKEPublicKey,
      wssURL: wssURL,
      relayServerID: relayServerID,
      currentSPKIPin: currentSPKIPin,
      nextSPKIPin: nextSPKIPin,
      expiresAtMilliseconds: expiresAtMilliseconds,
      machineRootPublicKey: machineRootPublicKey,
      machineRootFingerprint: machineRootFingerprint,
      dataSignCertificate: certificate,
      machineDisplayName: machineDisplayName
    )
    guard try encode(value) == bytes else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return value
  }

  fileprivate static func base64URLNoPadding(_ value: Data) -> String {
    value.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  fileprivate static func decodeBase64URLNoPadding(_ value: String) throws -> Data {
    guard
      value.utf8.allSatisfy({
        ($0 >= 0x41 && $0 <= 0x5A)
          || ($0 >= 0x61 && $0 <= 0x7A)
          || ($0 >= 0x30 && $0 <= 0x39)
          || $0 == 0x2D
          || $0 == 0x5F
      })
    else {
      throw PairRequestCryptoError.invalidEncoding
    }
    let remainder = value.utf8.count % 4
    guard remainder != 1 else {
      throw PairRequestCryptoError.invalidEncoding
    }
    var standard =
      value
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    if remainder != 0 {
      standard.append(String(repeating: "=", count: 4 - remainder))
    }
    guard let decoded = Data(base64Encoded: standard) else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return decoded
  }
}

struct PairRequestPlaintextV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let inviteSecret: Data
  let deviceSignPublicKey: Data
  let deviceHPKEPublicKey: Data
  let authorizationRequest: AuthorizationRequestV1

  init(
    formatVersion: UInt16 = 1,
    inviteSecret: Data,
    deviceSignPublicKey: Data,
    deviceHPKEPublicKey: Data,
    authorizationRequest: AuthorizationRequestV1
  ) throws {
    self.formatVersion = formatVersion
    self.inviteSecret = inviteSecret
    self.deviceSignPublicKey = deviceSignPublicKey
    self.deviceHPKEPublicKey = deviceHPKEPublicKey
    self.authorizationRequest = authorizationRequest
    try validate()
  }

  var debugDescription: String {
    "PairRequestPlaintextV1(formatVersion: \(formatVersion), plaintext: <redacted>)"
  }

  func validate() throws {
    guard formatVersion == 1 else {
      throw PairRequestCryptoError.unsupportedVersion
    }
    guard PairRequestValidation.isNonzero(inviteSecret, count: 32),
      PairRequestValidation.isNonzero(deviceSignPublicKey, count: 32),
      PairRequestValidation.isNonzero(deviceHPKEPublicKey, count: 32)
    else {
      throw PairRequestCryptoError.invalidField("pair request key material")
    }
    try authorizationRequest.validate()
  }
}

enum PairRequestPlaintextCanonicalCodec {
  static let maximumCanonicalBytes = 8 * 1_024

  private static let domain = Data("AgentDeck/PairRequestPlaintextV1\0".utf8)

  static func encode(_ value: PairRequestPlaintextV1) throws -> Data {
    try value.validate()
    var encoder = PairRequestEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.inviteSecret, exact: 32)
    try encoder.bytes(value.deviceSignPublicKey, exact: 32)
    try encoder.bytes(value.deviceHPKEPublicKey, exact: 32)
    try encoder.bytes(AuthorizationRequestCanonicalCodec.encode(value.authorizationRequest))
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> PairRequestPlaintextV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairRequestCryptoError.sizeLimit("pair request plaintext")
    }
    var decoder = PairRequestDecoder(bytes)
    try decoder.domain(domain)
    let value = try PairRequestPlaintextV1(
      formatVersion: decoder.u16(),
      inviteSecret: decoder.bytes(exact: 32),
      deviceSignPublicKey: decoder.bytes(exact: 32),
      deviceHPKEPublicKey: decoder.bytes(exact: 32),
      authorizationRequest: AuthorizationRequestCanonicalCodec.decode(
        decoder.bytes(maximum: AuthorizationRequestCanonicalCodec.maximumCanonicalBytes)
      )
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return value
  }
}

struct PairRequestV1: Equatable, Sendable, CustomDebugStringConvertible {
  let formatVersion: UInt16
  let encapsulatedKey: Data
  let ciphertext: Data
  let deviceProofSignature: Data

  init(
    formatVersion: UInt16 = 1,
    encapsulatedKey: Data,
    ciphertext: Data,
    deviceProofSignature: Data
  ) throws {
    self.formatVersion = formatVersion
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
    self.deviceProofSignature = deviceProofSignature
    try validate()
  }

  var debugDescription: String {
    "PairRequestV1(envelope: <redacted>)"
  }

  func validate() throws {
    guard formatVersion == 1 else {
      throw PairRequestCryptoError.unsupportedVersion
    }
    guard PairRequestValidation.isNonzero(encapsulatedKey, count: 32) else {
      throw PairRequestCryptoError.invalidField("HPKE enc")
    }
    guard !ciphertext.isEmpty,
      ciphertext.count <= PairRequestCanonicalCodec.maximumCiphertextBytes
    else {
      throw PairRequestCryptoError.sizeLimit("pairing ciphertext")
    }
    guard PairRequestValidation.isNonzero(deviceProofSignature, count: 64) else {
      throw PairRequestCryptoError.invalidField("detached signature")
    }
  }
}

enum PairRequestCanonicalCodec {
  static let maximumCiphertextBytes = 256 * 1_024
  static let maximumCanonicalBytes = maximumCiphertextBytes + 2 * 4 * 1_024

  private static let maximumUnsignedBytes = maximumCiphertextBytes + 4 * 1_024 + 128
  private static let unsignedDomain = Data("AgentDeck/PairRequestUnsignedV1\0".utf8)
  private static let domain = Data("AgentDeck/PairRequestV1\0".utf8)

  static func unsignedCanonicalBytes(_ value: PairRequestV1) throws -> Data {
    try value.validate()
    var encoder = PairRequestEncoder(maximumBytes: maximumUnsignedBytes)
    try encoder.raw(unsignedDomain)
    try encoder.u16(value.formatVersion)
    try encoder.bytes(value.encapsulatedKey, exact: 32)
    try encoder.bytes(value.ciphertext)
    return try encoder.finish()
  }

  static func encode(_ value: PairRequestV1) throws -> Data {
    let unsigned = try unsignedCanonicalBytes(value)
    var encoder = PairRequestEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.bytes(unsigned)
    try encoder.bytes(value.deviceProofSignature, exact: 64)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> PairRequestV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PairRequestCryptoError.sizeLimit("pair request envelope")
    }
    var outer = PairRequestDecoder(bytes)
    try outer.domain(domain)
    let unsigned = try outer.bytes(maximum: maximumUnsignedBytes)
    let signature = try outer.bytes(exact: 64)
    try outer.finish()

    var decoder = PairRequestDecoder(unsigned)
    try decoder.domain(unsignedDomain)
    let value = try PairRequestV1(
      formatVersion: decoder.u16(),
      encapsulatedKey: decoder.bytes(exact: 32),
      ciphertext: decoder.bytes(maximum: maximumCiphertextBytes),
      deviceProofSignature: signature
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return value
  }
}

struct OpaquePairRequestCarrier: Equatable, Sendable, CustomDebugStringConvertible {
  let pairRoute: Data
  let canonicalBytes: Data
  let requestHash: Data

  init(pairRoute: Data, canonicalBytes: Data, requestHash: Data) throws {
    guard PairRequestValidation.isNonzero(pairRoute, count: 16),
      canonicalBytes.count <= PairRequestCanonicalCodec.maximumCanonicalBytes,
      PairRequestValidation.isNonzero(requestHash, count: 32),
      CanonicalCodec.sha256(canonicalBytes) == requestHash
    else {
      throw PairRequestCryptoError.invalidEncoding
    }
    self.pairRoute = pairRoute
    self.canonicalBytes = canonicalBytes
    self.requestHash = requestHash
  }

  var debugDescription: String {
    "OpaquePairRequestCarrier(material: <redacted>)"
  }
}

enum PairRequestCrypto {
  static func sealPairRequest(
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1,
    deviceSigningKey: Curve25519.Signing.PrivateKey,
    deviceHPKEPublicKey: Curve25519.KeyAgreement.PublicKey,
    nowMilliseconds: UInt64
  ) throws -> OpaquePairRequestCarrier {
    try invite.validate(nowMilliseconds: nowMilliseconds)
    try authorizationRequest.validate()
    let info: PairRequestInfoV1
    do {
      info = try PairRequestInfoV1(
        relayServerID: invite.relayServerID,
        pairRoute: invite.pairRoute,
        inviteHash: invite.canonicalSHA256(),
        expiryMilliseconds: invite.expiresAtMilliseconds
      )
    } catch {
      throw PairRequestCryptoError.invalidContext
    }
    let context = OuterContextV1(
      frameKind: .pairRequest,
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

    let plaintext = try PairRequestPlaintextV1(
      inviteSecret: invite.inviteSecret,
      deviceSignPublicKey: deviceSigningKey.publicKey.rawRepresentation,
      deviceHPKEPublicKey: deviceHPKEPublicKey.rawRepresentation,
      authorizationRequest: authorizationRequest
    )
    let recipient: Curve25519.KeyAgreement.PublicKey
    do {
      recipient = try Curve25519.KeyAgreement.PublicKey(
        rawRepresentation: invite.inviteHPKEPublicKey
      )
    } catch {
      throw PairRequestCryptoError.invalidField("InviteHPKE public key")
    }
    let sealed: HPKEEnvelopeV1
    do {
      sealed = try RelayCrypto.sealHPKE(
        PairRequestPlaintextCanonicalCodec.encode(plaintext),
        recipient: recipient,
        info: info.canonicalBytes(),
        aad: CanonicalCodec.encodeAAD(context)
      )
    } catch {
      throw PairRequestCryptoError.hpkeSealFailed
    }
    let fingerprint = CanonicalCodec.sha256(deviceSigningKey.publicKey.rawRepresentation)
    let tbs = try signatureTBS(
      formatVersion: 1,
      encapsulatedKey: sealed.enc,
      ciphertext: sealed.ciphertext,
      info: info,
      context: context,
      deviceSignFingerprint: fingerprint
    )
    let signature: Data
    do {
      signature = try deviceSigningKey.signature(for: tbs)
    } catch {
      throw PairRequestCryptoError.signingFailed
    }
    let request = try PairRequestV1(
      encapsulatedKey: sealed.enc,
      ciphertext: sealed.ciphertext,
      deviceProofSignature: signature
    )
    let canonical = try PairRequestCanonicalCodec.encode(request)
    return try OpaquePairRequestCarrier(
      pairRoute: invite.pairRoute,
      canonicalBytes: canonical,
      requestHash: CanonicalCodec.sha256(canonical)
    )
  }

  static func signatureTBS(
    _ request: PairRequestV1,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    deviceSignFingerprint: Data
  ) throws -> Data {
    try request.validate()
    return try signatureTBS(
      formatVersion: request.formatVersion,
      encapsulatedKey: request.encapsulatedKey,
      ciphertext: request.ciphertext,
      info: info,
      context: context,
      deviceSignFingerprint: deviceSignFingerprint
    )
  }

  private static func signatureTBS(
    formatVersion: UInt16,
    encapsulatedKey: Data,
    ciphertext: Data,
    info: PairRequestInfoV1,
    context: OuterContextV1,
    deviceSignFingerprint: Data
  ) throws -> Data {
    try validateContext(info: info, context: context)
    guard formatVersion == 1,
      PairRequestValidation.isNonzero(deviceSignFingerprint, count: 32),
      PairRequestValidation.isNonzero(encapsulatedKey, count: 32),
      !ciphertext.isEmpty,
      ciphertext.count <= PairRequestCanonicalCodec.maximumCiphertextBytes
    else {
      throw PairRequestCryptoError.invalidField("pairing envelope TBS")
    }
    let infoBytes = try info.canonicalBytes()
    let aad: Data
    do {
      aad = try CanonicalCodec.encodeAAD(context)
    } catch {
      throw PairRequestCryptoError.invalidContext
    }
    var encoder = PairRequestEncoder(maximumBytes: 4 * 1_024)
    try encoder.raw(Data("AgentDeck/PairingEnvelopeTbsV1\0".utf8))
    try encoder.u8(0)
    try encoder.u16(formatVersion)
    try encoder.u16(info.runtimeProtocolVersion)
    try encoder.u16(context.relayProtocolVersion)
    try encoder.bytes(info.relayServerID, exact: 16)
    try encoder.bytes(info.pairRoute, exact: 16)
    try encoder.bytes(info.inviteHash, exact: 32)
    try encoder.u64(info.expiryMilliseconds)
    try encoder.u8(0)  // request hash
    try encoder.u8(0)  // machine route
    try encoder.u8(0)  // device route
    try encoder.u8(0)  // grant serial
    try encoder.u8(0)  // root trust epoch
    try encoder.bytes(deviceSignFingerprint, exact: 32)
    try encoder.u8(0)  // signing key generation
    try encoder.u8(0)  // signing credential hash
    try encoder.bytes(CanonicalCodec.sha256(infoBytes), exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(aad), exact: 32)
    try encoder.bytes(encapsulatedKey, exact: 32)
    try encoder.bytes(CanonicalCodec.sha256(ciphertext), exact: 32)
    return try encoder.finish()
  }

  private static func validateContext(
    info: PairRequestInfoV1,
    context: OuterContextV1
  ) throws {
    do {
      try context.validateShape()
    } catch {
      throw PairRequestCryptoError.invalidContext
    }
    guard context.frameKind == .pairRequest,
      context.pairRoute == info.pairRoute,
      context.e2eeFormatVersion == info.e2eeFormatVersion,
      info.e2eeFormatVersion == 1,
      info.runtimeProtocolVersion == runtimeProtocolVersionCurrent,
      context.relayProtocolVersion == relayProtocolVersionV2,
      PairRequestValidation.isNonzero(info.relayServerID, count: 16),
      PairRequestValidation.isNonzero(info.pairRoute, count: 16),
      PairRequestValidation.isNonzero(info.inviteHash, count: 32),
      info.expiryMilliseconds > 0
    else {
      throw PairRequestCryptoError.invalidContext
    }
  }
}

private enum PairRequestValidation {
  static let maximumURLBytes = 2 * 1_024
  static let maximumDisplayNameBytes = 128

  static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }

  static func isStrictlyIncreasing(_ values: [UInt8]) -> Bool {
    zip(values, values.dropFirst()).allSatisfy(<)
  }

  static func validateDisplayName(_ value: String) throws {
    guard !value.isEmpty,
      value.utf8.count <= maximumDisplayNameBytes,
      value.first?.isWhitespace != true,
      value.last?.isWhitespace != true,
      !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    else {
      throw PairRequestCryptoError.invalidField("display name")
    }
  }

  static func validateCanonicalWSSURL(_ value: String) throws {
    guard value.utf8.count <= maximumURLBytes else {
      throw PairRequestCryptoError.sizeLimit("wss URL")
    }
    guard value.hasPrefix("wss://"),
      value.unicodeScalars.allSatisfy({ $0.isASCII && !$0.properties.isWhitespace }),
      let components = URLComponents(string: value),
      components.scheme == "wss",
      let host = components.host,
      !host.isEmpty,
      components.user == nil,
      components.password == nil,
      components.percentEncodedPath == "/",
      components.percentEncodedQuery == nil,
      components.fragment == nil,
      components.port != 0,
      components.port != 443
    else {
      throw PairRequestCryptoError.invalidField("wss URL")
    }
    var canonical = URLComponents()
    canonical.scheme = "wss"
    canonical.host = host.lowercased()
    canonical.port = components.port
    canonical.percentEncodedPath = "/"
    guard canonical.string == value,
      URL(string: value)?.absoluteString == value
    else {
      throw PairRequestCryptoError.invalidField("wss URL")
    }
  }
}

private struct PairRequestEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func raw(_ value: Data) throws { try append(value) }
  mutating func u8(_ value: UInt8) throws { try append(Data([value])) }
  mutating func u16(_ value: UInt16) throws { try integer(value) }
  mutating func u64(_ value: UInt64) throws { try integer(value) }

  mutating func string(_ value: String) throws {
    try bytes(Data(value.utf8))
  }

  mutating func bytes(_ value: Data, exact: Int? = nil) throws {
    if let exact, value.count != exact {
      throw PairRequestCryptoError.invalidEncoding
    }
    guard let count = UInt32(exactly: value.count) else {
      throw PairRequestCryptoError.sizeLimit("canonical byte field")
    }
    try integer(count)
    try append(value)
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else {
      throw PairRequestCryptoError.sizeLimit("canonical bytes")
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
      throw PairRequestCryptoError.sizeLimit("canonical bytes")
    }
    output.append(value)
  }
}

private struct PairRequestDecoder {
  private let input: Data
  private var offset = 0

  init(_ input: Data) {
    self.input = input
  }

  mutating func domain(_ expected: Data) throws {
    guard try take(expected.count) == expected else {
      throw PairRequestCryptoError.invalidEncoding
    }
  }

  mutating func u8() throws -> UInt8 { try take(1)[0] }
  mutating func u16() throws -> UInt16 { try integer() }
  mutating func u32() throws -> UInt32 { try integer() }
  mutating func u64() throws -> UInt64 { try integer() }

  mutating func string(maximum: Int) throws -> String {
    let value = try bytes(maximum: maximum)
    guard let decoded = String(data: value, encoding: .utf8) else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return decoded
  }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else {
      throw PairRequestCryptoError.sizeLimit("canonical byte field")
    }
    return try take(count)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else {
      throw PairRequestCryptoError.invalidEncoding
    }
    return value
  }

  mutating func finish() throws {
    guard offset == input.count else {
      throw PairRequestCryptoError.invalidEncoding
    }
  }

  private mutating func integer<T: FixedWidthInteger>() throws -> T {
    try take(MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
  }

  private mutating func take(_ count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= input.count else {
      throw PairRequestCryptoError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return Data(input[offset..<end.partialValue])
  }
}
