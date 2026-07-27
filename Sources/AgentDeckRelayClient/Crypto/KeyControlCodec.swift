import AgentDeckCore
import Foundation

enum KeyControlCodecError: Error, Equatable, Sendable {
  case invalidAuthority
  case invalidEncoding
  case invalidKeyShape
  case invalidRevision
  case invalidAttempt
  case invalidAcknowledgement
  case sizeLimit
}

struct DeviceKeyControlAuthorityV1: Equatable, Sendable {
  let formatVersion: UInt16
  let runtimeProtocolVersion: UInt16
  let relayProtocolVersion: UInt16
  let machineRoute: Data
  let deviceRoute: Data
  let grantSerial: UInt64
  let rootTrustEpoch: UInt64

  init(
    formatVersion: UInt16 = 1,
    runtimeProtocolVersion: UInt16 = runtimeProtocolVersionCurrent,
    relayProtocolVersion: UInt16 = relayProtocolVersionV2,
    machineRoute: Data,
    deviceRoute: Data,
    grantSerial: UInt64,
    rootTrustEpoch: UInt64
  ) throws {
    guard formatVersion == 1,
      runtimeProtocolVersion == runtimeProtocolVersionCurrent,
      relayProtocolVersion == relayProtocolVersionV2,
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      grantSerial > 0,
      rootTrustEpoch > 0
    else {
      throw KeyControlCodecError.invalidAuthority
    }
    self.formatVersion = formatVersion
    self.runtimeProtocolVersion = runtimeProtocolVersion
    self.relayProtocolVersion = relayProtocolVersion
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.grantSerial = grantSerial
    self.rootTrustEpoch = rootTrustEpoch
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct DeviceKeySyncRequestV1: Equatable, Sendable {
  let authority: DeviceKeyControlAuthorityV1
  let knownKeyDirectoryRevision: UInt64
  let requestedKeyDirectoryRevision: UInt64
  let keyID: KeyIDV1
  let streamRoute: Data?
  let attempt: UInt8

  init(
    authority: DeviceKeyControlAuthorityV1,
    knownKeyDirectoryRevision: UInt64,
    requestedKeyDirectoryRevision: UInt64,
    keyID: KeyIDV1,
    streamRoute: Data?,
    attempt: UInt8
  ) throws {
    guard knownKeyDirectoryRevision > 0,
      requestedKeyDirectoryRevision > knownKeyDirectoryRevision,
      keyID.epoch > 0
    else {
      throw KeyControlCodecError.invalidRevision
    }
    try Self.validateKeyShape(keyID: keyID, streamRoute: streamRoute)
    guard (1...3).contains(attempt) else {
      throw KeyControlCodecError.invalidAttempt
    }
    self.authority = authority
    self.knownKeyDirectoryRevision = knownKeyDirectoryRevision
    self.requestedKeyDirectoryRevision = requestedKeyDirectoryRevision
    self.keyID = keyID
    self.streamRoute = streamRoute
    self.attempt = attempt
  }

  fileprivate static func validateKeyShape(
    keyID: KeyIDV1,
    streamRoute: Data?
  ) throws {
    let valid: Bool
    switch keyID.purpose {
    case .conversationDEK:
      valid = streamRoute.map({ $0.count == 16 && $0.contains(where: { $0 != 0 }) }) ?? false
    case .catalog, .deviceCommandTx, .deviceReplyTx:
      valid = streamRoute == nil
    }
    guard valid else { throw KeyControlCodecError.invalidKeyShape }
  }
}

struct DeviceKeyUpdateAckV1: Equatable, Sendable {
  let authority: DeviceKeyControlAuthorityV1
  let keyDirectoryRevision: UInt64
  let updateSetSHA256: Data

  init(
    authority: DeviceKeyControlAuthorityV1,
    keyDirectoryRevision: UInt64,
    updateSetSHA256: Data
  ) throws {
    guard keyDirectoryRevision > 0,
      updateSetSHA256.count == 32,
      updateSetSHA256.contains(where: { $0 != 0 })
    else {
      throw KeyControlCodecError.invalidAcknowledgement
    }
    self.authority = authority
    self.keyDirectoryRevision = keyDirectoryRevision
    self.updateSetSHA256 = updateSetSHA256
  }
}

struct DeviceStreamAppliedAckV1: Equatable, Sendable {
  let authority: DeviceKeyControlAuthorityV1
  let streamRoute: Data
  let streamGeneration: Data
  let appliedStreamSequence: UInt64
  let innerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
  let keyEpoch: UInt64
  let epochBarrierSHA256: Data

  init(
    authority: DeviceKeyControlAuthorityV1,
    streamRoute: Data,
    streamGeneration: Data,
    appliedStreamSequence: UInt64,
    innerCursor: RuntimeInnerCursorV1,
    keyDirectoryRevision: UInt64,
    keyEpoch: UInt64,
    epochBarrierSHA256: Data
  ) throws {
    guard Self.isNonzero(streamRoute, count: 16),
      Self.isNonzero(streamGeneration, count: 16),
      appliedStreamSequence < UInt64.max,
      keyDirectoryRevision > 0,
      keyEpoch > 0,
      Self.isNonzero(epochBarrierSHA256, count: 32)
    else {
      throw KeyControlCodecError.invalidAcknowledgement
    }
    if case .conversation(let conversationID, _) = innerCursor {
      let count = conversationID.rawValue.utf8.count
      guard count > 0, count <= KeyControlCanonicalCodec.maximumIdentityBytes else {
        throw KeyControlCodecError.sizeLimit
      }
    }
    self.authority = authority
    self.streamRoute = streamRoute
    self.streamGeneration = streamGeneration
    self.appliedStreamSequence = appliedStreamSequence
    self.innerCursor = innerCursor
    self.keyDirectoryRevision = keyDirectoryRevision
    self.keyEpoch = keyEpoch
    self.epochBarrierSHA256 = epochBarrierSHA256
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum DeviceKeyControlRequestV1: Equatable, Sendable {
  case keySync(DeviceKeySyncRequestV1)
  case keyUpdateAck(DeviceKeyUpdateAckV1)
  case streamAppliedAck(DeviceStreamAppliedAckV1)

  var authority: DeviceKeyControlAuthorityV1 {
    switch self {
    case .keySync(let request): request.authority
    case .keyUpdateAck(let acknowledgement): acknowledgement.authority
    case .streamAppliedAck(let acknowledgement): acknowledgement.authority
    }
  }

  var declaredKeyDirectoryRevision: UInt64 {
    switch self {
    case .keySync(let request): request.requestedKeyDirectoryRevision
    case .keyUpdateAck(let acknowledgement): acknowledgement.keyDirectoryRevision
    case .streamAppliedAck(let acknowledgement): acknowledgement.keyDirectoryRevision
    }
  }
}

/// daemon→device 的 authenticated current-directory 状态。它只允许表达
/// `current=r, requested=r+1`，并且继续绑定完整 pairing authority。
struct DaemonDirectoryCurrentV1: Equatable, Sendable {
  let authority: DeviceKeyControlAuthorityV1
  let currentKeyDirectoryRevision: UInt64
  let requestedKeyDirectoryRevision: UInt64

  init(
    authority: DeviceKeyControlAuthorityV1,
    currentKeyDirectoryRevision: UInt64,
    requestedKeyDirectoryRevision: UInt64
  ) throws {
    let next = currentKeyDirectoryRevision.addingReportingOverflow(1)
    guard currentKeyDirectoryRevision > 0,
      !next.overflow,
      requestedKeyDirectoryRevision == next.partialValue
    else {
      throw KeyControlCodecError.invalidRevision
    }
    self.authority = authority
    self.currentKeyDirectoryRevision = currentKeyDirectoryRevision
    self.requestedKeyDirectoryRevision = requestedKeyDirectoryRevision
  }
}

/// `DirectoryRevisionAdvanceV1` 的纯 canonical inner carrier。outer stream axes
/// 只能在 MachineDataSign/AEAD admission 后经 `binding(to:)` 注入，避免 decoder
/// 猜测 route/generation/sequence。
struct DaemonDirectoryRevisionAdvanceV1: Equatable, Sendable {
  let fromRevision: UInt64
  let toRevision: UInt64
  let canonicalBytes: Data

  init(fromRevision: UInt64, toRevision: UInt64) throws {
    let next = fromRevision.addingReportingOverflow(1)
    guard fromRevision > 0,
      !next.overflow,
      toRevision == next.partialValue
    else {
      throw KeyControlCodecError.invalidRevision
    }
    self.fromRevision = fromRevision
    self.toRevision = toRevision
    var encoder = KeyControlEncoder(
      maximumBytes: DaemonKeyControlCanonicalCodec.maximumSmallCanonicalBytes
    )
    try encoder.domain(Data("AgentDeck/DirectoryRevisionAdvanceV1\0".utf8))
    try encoder.u64(fromRevision)
    try encoder.u64(toRevision)
    canonicalBytes = try encoder.finish()
  }

  func binding(to context: OuterContextV1) throws -> DeviceDirectoryRevisionAdvanceV1 {
    guard context.frameKind == .catalogPublish,
      let streamRoute = context.streamRoute,
      let streamGeneration = context.streamGeneration,
      let streamSequence = context.streamSeq,
      context.requestRoute == nil,
      context.pairRoute == nil
    else {
      throw KeyControlCodecError.invalidEncoding
    }
    return try DeviceDirectoryRevisionAdvanceV1(
      streamRoute: streamRoute,
      streamGeneration: streamGeneration,
      streamSequence: streamSequence,
      fromRevision: fromRevision,
      toRevision: toRevision
    )
  }
}

/// daemon 返回的 authenticated publication binding。该类型镜像 Rust
/// `StreamBindingV1`，但仍不注册 correlation owner；注册必须发生在 outer request
/// route 已确认且 durable readback 完成之后。
struct DaemonStreamBindingV1: Equatable, Sendable {
  let authority: DeviceKeyControlAuthorityV1
  let streamRoute: Data
  let streamGeneration: Data
  let streamCursor: StreamCursor
  let innerCursor: RuntimeInnerCursorV1
  let keyDirectoryRevision: UInt64
  let keyID: KeyIDV1

  init(
    authority: DeviceKeyControlAuthorityV1,
    streamRoute: Data,
    streamGeneration: Data,
    streamCursor: StreamCursor,
    innerCursor: RuntimeInnerCursorV1,
    keyDirectoryRevision: UInt64,
    keyID: KeyIDV1
  ) throws {
    guard Self.isNonzero(streamRoute, count: 16),
      Self.isNonzero(streamGeneration, count: 16),
      keyDirectoryRevision > 0,
      keyID.epoch > 0,
      Self.hasSuccessor(streamCursor),
      Self.innerCursor(innerCursor, matches: keyID.purpose)
    else {
      throw KeyControlCodecError.invalidKeyShape
    }
    self.authority = authority
    self.streamRoute = streamRoute
    self.streamGeneration = streamGeneration
    self.streamCursor = streamCursor
    self.innerCursor = innerCursor
    self.keyDirectoryRevision = keyDirectoryRevision
    self.keyID = keyID
  }

  private static func innerCursor(
    _ cursor: RuntimeInnerCursorV1,
    matches purpose: KeyPurpose
  ) -> Bool {
    switch (cursor, purpose) {
    case (.catalog(let inner), .catalog):
      return hasSuccessor(inner)
    case (.conversation(let conversationID, let inner), .conversationDEK):
      let count = conversationID.rawValue.utf8.count
      return count > 0
        && count <= KeyControlCanonicalCodec.maximumIdentityBytes
        && hasSuccessor(inner)
    default:
      return false
    }
  }

  private static func hasSuccessor(_ cursor: StreamCursor) -> Bool {
    switch cursor {
    case .beforeFirst: true
    case .at(let value): value < UInt64.max
    }
  }

  private static func hasSuccessor(_ cursor: RuntimeStreamCursorV1) -> Bool {
    switch cursor {
    case .beforeFirst: true
    case .at(let value): value < UInt64.max
    }
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

/// daemon→device `KeyControlV1` 的封闭 Swift mirror。所有 case 都必须来自
/// `DaemonKeyControlCanonicalCodec.decode` 的 strict canonical carrier。
enum DaemonKeyControlV1: Equatable, Sendable {
  case updateSet(CanonicalKeyUpdateSetV1)
  case epochBarrier(DeviceEpochBarrierV1)
  case directoryCurrent(DaemonDirectoryCurrentV1)
  case streamBinding(DaemonStreamBindingV1)
  case directoryRevisionAdvance(DaemonDirectoryRevisionAdvanceV1)
}

enum DaemonKeyControlCanonicalCodec {
  static let maximumCanonicalBytes = 2 * 1_024 * 1_024
  static let maximumSmallCanonicalBytes = 8 * 1_024

  private static let domain = Data("AgentDeck/KeyControlV1\0".utf8)
  private static let directoryCurrentDomain = Data("AgentDeck/DirectoryCurrentV1\0".utf8)
  private static let epochBarrierDomain = Data("AgentDeck/EpochBarrierV1\0".utf8)
  private static let streamBindingDomain = Data("AgentDeck/StreamBindingV1\0".utf8)
  private static let directoryAdvanceDomain = Data(
    "AgentDeck/DirectoryRevisionAdvanceV1\0".utf8
  )

  static func encode(_ value: DaemonKeyControlV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(domain)
    switch value {
    case .updateSet(let set):
      try encoder.u8(0)
      try encoder.u16(1)
      try encoder.bytes(try KeyUpdateSetCanonicalCodec.encode(set))
    case .epochBarrier(let barrier):
      try encoder.u8(1)
      try encoder.u16(1)
      try encoder.bytes(barrier.streamRoute, exact: 16)
      try encoder.bytes(barrier.canonicalBytes)
    case .directoryCurrent(let status):
      try encoder.u8(2)
      try encoder.u16(1)
      try encoder.bytes(try encode(status))
    case .streamBinding(let binding):
      try encoder.u8(3)
      try encoder.u16(1)
      try encoder.bytes(try encode(binding))
    case .directoryRevisionAdvance(let advance):
      try encoder.u8(4)
      try encoder.u16(1)
      try encoder.bytes(advance.canonicalBytes)
    }
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> DaemonKeyControlV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw KeyControlCodecError.sizeLimit
    }
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(domain)
    let tag = try decoder.u8()
    guard try decoder.u16() == 1 else {
      throw KeyControlCodecError.invalidEncoding
    }
    let value: DaemonKeyControlV1
    switch tag {
    case 0:
      value = .updateSet(
        try KeyUpdateSetCanonicalCodec.decode(
          try decoder.bytes(maximum: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes)
        ))
    case 1:
      let streamRoute = try decoder.bytes(exact: 16)
      value = .epochBarrier(
        try decodeEpochBarrier(
          try decoder.bytes(maximum: maximumSmallCanonicalBytes),
          streamRoute: streamRoute
        ))
    case 2:
      value = .directoryCurrent(
        try decodeDirectoryCurrent(
          try decoder.bytes(maximum: maximumSmallCanonicalBytes)
        ))
    case 3:
      value = .streamBinding(
        try decodeStreamBinding(
          try decoder.bytes(maximum: maximumSmallCanonicalBytes)
        ))
    case 4:
      value = .directoryRevisionAdvance(
        try decodeDirectoryRevisionAdvance(
          try decoder.bytes(maximum: maximumSmallCanonicalBytes)
        ))
    default:
      throw KeyControlCodecError.invalidEncoding
    }
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func encode(_ value: DaemonDirectoryCurrentV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumSmallCanonicalBytes)
    try encoder.domain(directoryCurrentDomain)
    try encode(value.authority, into: &encoder)
    try encoder.u64(value.currentKeyDirectoryRevision)
    try encoder.u64(value.requestedKeyDirectoryRevision)
    return try encoder.finish()
  }

  private static func decodeDirectoryCurrent(_ bytes: Data) throws -> DaemonDirectoryCurrentV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(directoryCurrentDomain)
    let value = try DaemonDirectoryCurrentV1(
      authority: decoder.authority(),
      currentKeyDirectoryRevision: decoder.u64(),
      requestedKeyDirectoryRevision: decoder.u64()
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func encode(_ value: DaemonStreamBindingV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumSmallCanonicalBytes)
    try encoder.domain(streamBindingDomain)
    try encode(value.authority, into: &encoder)
    try encoder.bytes(value.streamRoute, exact: 16)
    try encoder.bytes(value.streamGeneration, exact: 16)
    try encoder.cursor(value.streamCursor)
    try encoder.innerCursor(value.innerCursor)
    try encoder.u64(value.keyDirectoryRevision)
    try encoder.u8(value.keyID.purpose.canonicalTag)
    try encoder.u64(value.keyID.epoch)
    return try encoder.finish()
  }

  private static func decodeStreamBinding(_ bytes: Data) throws -> DaemonStreamBindingV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(streamBindingDomain)
    let value = try DaemonStreamBindingV1(
      authority: decoder.authority(),
      streamRoute: decoder.bytes(exact: 16),
      streamGeneration: decoder.bytes(exact: 16),
      streamCursor: decoder.streamCursor(),
      innerCursor: decoder.innerCursor(
        maximumIdentityBytes: KeyControlCanonicalCodec.maximumIdentityBytes
      ),
      keyDirectoryRevision: decoder.u64(),
      keyID: KeyIDV1(purpose: decoder.keyPurpose(), epoch: decoder.u64())
    )
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func decodeEpochBarrier(
    _ bytes: Data,
    streamRoute: Data
  ) throws -> DeviceEpochBarrierV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(epochBarrierDomain)
    let value = try DeviceEpochBarrierV1(
      streamRoute: streamRoute,
      streamGeneration: decoder.bytes(exact: 16),
      streamCursor: decoder.streamCursor(),
      innerCursor: decoder.deviceInnerCursor(
        maximumIdentityBytes: KeyControlCanonicalCodec.maximumIdentityBytes
      ),
      oldEpoch: decoder.u64(),
      newEpoch: decoder.u64(),
      keyDirectoryRevision: decoder.u64()
    )
    try decoder.finish()
    guard value.canonicalBytes == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func decodeDirectoryRevisionAdvance(
    _ bytes: Data
  ) throws -> DaemonDirectoryRevisionAdvanceV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(directoryAdvanceDomain)
    let value = try DaemonDirectoryRevisionAdvanceV1(
      fromRevision: decoder.u64(),
      toRevision: decoder.u64()
    )
    try decoder.finish()
    guard value.canonicalBytes == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func encode(
    _ value: DeviceKeyControlAuthorityV1,
    into encoder: inout KeyControlEncoder
  ) throws {
    try encoder.u16(value.formatVersion)
    try encoder.u16(value.runtimeProtocolVersion)
    try encoder.u16(value.relayProtocolVersion)
    try encoder.bytes(value.machineRoute, exact: 16)
    try encoder.bytes(value.deviceRoute, exact: 16)
    try encoder.u64(value.grantSerial)
    try encoder.u64(value.rootTrustEpoch)
  }
}

enum KeyControlCanonicalCodec {
  static let maximumCanonicalBytes = 8 * 1_024
  static let maximumIdentityBytes = 1_024

  private static let requestDomain = Data("AgentDeck/KeyControlRequestV1\0".utf8)
  private static let keySyncDomain = Data("AgentDeck/KeySyncRequestV1\0".utf8)
  private static let keyUpdateAckDomain = Data("AgentDeck/KeyUpdateAckV1\0".utf8)
  private static let streamAppliedAckDomain = Data("AgentDeck/StreamAppliedAckV1\0".utf8)

  static func encode(_ value: DeviceKeyControlRequestV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(requestDomain)
    switch value {
    case .keySync(let request):
      try encoder.u8(0)
      try encoder.bytes(encode(request))
    case .keyUpdateAck(let acknowledgement):
      try encoder.u8(1)
      try encoder.bytes(encode(acknowledgement))
    case .streamAppliedAck(let acknowledgement):
      try encoder.u8(2)
      try encoder.bytes(encode(acknowledgement))
    }
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> DeviceKeyControlRequestV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw KeyControlCodecError.sizeLimit
    }
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(requestDomain)
    let value: DeviceKeyControlRequestV1
    switch try decoder.u8() {
    case 0: value = .keySync(try decodeKeySync(try decoder.bytes(maximum: maximumCanonicalBytes)))
    case 1:
      value = .keyUpdateAck(
        try decodeKeyUpdateAck(try decoder.bytes(maximum: maximumCanonicalBytes))
      )
    case 2:
      value = .streamAppliedAck(
        try decodeStreamAppliedAck(try decoder.bytes(maximum: maximumCanonicalBytes))
      )
    default: throw KeyControlCodecError.invalidEncoding
    }
    try decoder.finish()
    guard try encode(value) == bytes else {
      throw KeyControlCodecError.invalidEncoding
    }
    return value
  }

  private static func encode(_ value: DeviceKeySyncRequestV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(keySyncDomain)
    try encode(value.authority, into: &encoder)
    try encoder.u64(value.knownKeyDirectoryRevision)
    try encoder.u64(value.requestedKeyDirectoryRevision)
    try encoder.u8(value.keyID.purpose.canonicalTag)
    try encoder.u64(value.keyID.epoch)
    try encoder.optionalID16(value.streamRoute)
    try encoder.u8(value.attempt)
    return try encoder.finish()
  }

  private static func encode(_ value: DeviceKeyUpdateAckV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(keyUpdateAckDomain)
    try encode(value.authority, into: &encoder)
    try encoder.u64(value.keyDirectoryRevision)
    try encoder.bytes(value.updateSetSHA256, exact: 32)
    return try encoder.finish()
  }

  private static func encode(_ value: DeviceStreamAppliedAckV1) throws -> Data {
    var encoder = KeyControlEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.domain(streamAppliedAckDomain)
    try encode(value.authority, into: &encoder)
    try encoder.bytes(value.streamRoute, exact: 16)
    try encoder.bytes(value.streamGeneration, exact: 16)
    try encoder.u64(value.appliedStreamSequence)
    try encoder.innerCursor(value.innerCursor)
    try encoder.u64(value.keyDirectoryRevision)
    try encoder.u64(value.keyEpoch)
    try encoder.bytes(value.epochBarrierSHA256, exact: 32)
    return try encoder.finish()
  }

  private static func encode(
    _ value: DeviceKeyControlAuthorityV1,
    into encoder: inout KeyControlEncoder
  ) throws {
    try encoder.u16(value.formatVersion)
    try encoder.u16(value.runtimeProtocolVersion)
    try encoder.u16(value.relayProtocolVersion)
    try encoder.bytes(value.machineRoute, exact: 16)
    try encoder.bytes(value.deviceRoute, exact: 16)
    try encoder.u64(value.grantSerial)
    try encoder.u64(value.rootTrustEpoch)
  }

  private static func decodeKeySync(_ bytes: Data) throws -> DeviceKeySyncRequestV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(keySyncDomain)
    let authority = try decoder.authority()
    let known = try decoder.u64()
    let requested = try decoder.u64()
    let purpose = try decoder.keyPurpose()
    let epoch = try decoder.u64()
    let streamRoute = try decoder.optionalID16()
    let attempt = try decoder.u8()
    try decoder.finish()
    let value = try DeviceKeySyncRequestV1(
      authority: authority,
      knownKeyDirectoryRevision: known,
      requestedKeyDirectoryRevision: requested,
      keyID: KeyIDV1(purpose: purpose, epoch: epoch),
      streamRoute: streamRoute,
      attempt: attempt
    )
    guard try encode(value) == bytes else { throw KeyControlCodecError.invalidEncoding }
    return value
  }

  private static func decodeKeyUpdateAck(_ bytes: Data) throws -> DeviceKeyUpdateAckV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(keyUpdateAckDomain)
    let value = try DeviceKeyUpdateAckV1(
      authority: decoder.authority(),
      keyDirectoryRevision: decoder.u64(),
      updateSetSHA256: decoder.bytes(exact: 32)
    )
    try decoder.finish()
    guard try encode(value) == bytes else { throw KeyControlCodecError.invalidEncoding }
    return value
  }

  private static func decodeStreamAppliedAck(_ bytes: Data) throws -> DeviceStreamAppliedAckV1 {
    var decoder = KeyControlDecoder(bytes)
    try decoder.domain(streamAppliedAckDomain)
    let value = try DeviceStreamAppliedAckV1(
      authority: decoder.authority(),
      streamRoute: decoder.bytes(exact: 16),
      streamGeneration: decoder.bytes(exact: 16),
      appliedStreamSequence: decoder.u64(),
      innerCursor: decoder.innerCursor(maximumIdentityBytes: maximumIdentityBytes),
      keyDirectoryRevision: decoder.u64(),
      keyEpoch: decoder.u64(),
      epochBarrierSHA256: decoder.bytes(exact: 32)
    )
    try decoder.finish()
    guard try encode(value) == bytes else { throw KeyControlCodecError.invalidEncoding }
    return value
  }
}

private struct KeyControlEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func domain(_ value: Data) throws { try append(value) }
  mutating func u8(_ value: UInt8) throws { try append(Data([value])) }
  mutating func u16(_ value: UInt16) throws { try integer(value) }
  mutating func u64(_ value: UInt64) throws { try integer(value) }

  mutating func bytes(_ value: Data, exact: Int? = nil) throws {
    if let exact, value.count != exact { throw KeyControlCodecError.invalidEncoding }
    guard let count = UInt32(exactly: value.count) else {
      throw KeyControlCodecError.sizeLimit
    }
    try integer(count)
    try append(value)
  }

  mutating func optionalID16(_ value: Data?) throws {
    guard let value else {
      try u8(0)
      return
    }
    guard value.count == 16 else { throw KeyControlCodecError.invalidEncoding }
    try u8(1)
    try append(value)
  }

  mutating func innerCursor(_ value: RuntimeInnerCursorV1) throws {
    switch value {
    case .catalog(let cursor):
      try u8(0)
      try self.cursor(cursor)
    case .conversation(let conversationID, let cursor):
      try u8(1)
      try bytes(Data(conversationID.rawValue.utf8))
      try self.cursor(cursor)
    }
  }

  mutating func cursor(_ value: RuntimeStreamCursorV1) throws {
    switch value {
    case .beforeFirst: try u8(0)
    case .at(let cursor):
      try u8(1)
      try u64(cursor)
    }
  }

  mutating func cursor(_ value: StreamCursor) throws {
    switch value {
    case .beforeFirst: try u8(0)
    case .at(let cursor):
      try u8(1)
      try u64(cursor)
    }
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else { throw KeyControlCodecError.sizeLimit }
    return output
  }

  private mutating func integer<T: FixedWidthInteger>(_ value: T) throws {
    var value = value.bigEndian
    try Swift.withUnsafeBytes(of: &value) { try append(Data($0)) }
  }

  private mutating func append(_ value: Data) throws {
    let (count, overflow) = output.count.addingReportingOverflow(value.count)
    guard !overflow, count <= maximumBytes else { throw KeyControlCodecError.sizeLimit }
    output.append(value)
  }
}

private struct KeyControlDecoder {
  private let input: Data
  private var offset = 0

  init(_ input: Data) {
    self.input = input
  }

  mutating func domain(_ expected: Data) throws {
    guard try take(expected.count) == expected else {
      throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func u8() throws -> UInt8 { try take(1)[0] }
  mutating func u16() throws -> UInt16 { try integer() }
  mutating func u32() throws -> UInt32 { try integer() }
  mutating func u64() throws -> UInt64 { try integer() }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else { throw KeyControlCodecError.sizeLimit }
    return try take(count)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else { throw KeyControlCodecError.invalidEncoding }
    return value
  }

  mutating func optionalID16() throws -> Data? {
    switch try u8() {
    case 0: return nil
    case 1: return try take(16)
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func keyPurpose() throws -> KeyPurpose {
    switch try u8() {
    case 0: .catalog
    case 1: .conversationDEK
    case 2: .deviceCommandTx
    case 3: .deviceReplyTx
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func authority() throws -> DeviceKeyControlAuthorityV1 {
    try DeviceKeyControlAuthorityV1(
      formatVersion: u16(),
      runtimeProtocolVersion: u16(),
      relayProtocolVersion: u16(),
      machineRoute: bytes(exact: 16),
      deviceRoute: bytes(exact: 16),
      grantSerial: u64(),
      rootTrustEpoch: u64()
    )
  }

  mutating func innerCursor(maximumIdentityBytes: Int) throws -> RuntimeInnerCursorV1 {
    switch try u8() {
    case 0: return .catalog(cursor: try cursor())
    case 1:
      let bytes = try bytes(maximum: maximumIdentityBytes)
      guard let identity = String(data: bytes, encoding: .utf8), !identity.isEmpty else {
        throw KeyControlCodecError.invalidEncoding
      }
      return .conversation(
        conversationID: RuntimeConversationID(rawValue: identity),
        cursor: try cursor()
      )
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func cursor() throws -> RuntimeStreamCursorV1 {
    switch try u8() {
    case 0: .beforeFirst
    case 1: .at(try u64())
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func streamCursor() throws -> StreamCursor {
    switch try u8() {
    case 0: .beforeFirst
    case 1: .at(try u64())
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func deviceInnerCursor(maximumIdentityBytes: Int) throws -> DeviceInnerCursorV1 {
    switch try u8() {
    case 0: return .catalog(try streamCursor())
    case 1:
      let bytes = try bytes(maximum: maximumIdentityBytes)
      guard let identity = String(data: bytes, encoding: .utf8), !identity.isEmpty else {
        throw KeyControlCodecError.invalidEncoding
      }
      return .conversation(id: identity, cursor: try streamCursor())
    default: throw KeyControlCodecError.invalidEncoding
    }
  }

  mutating func finish() throws {
    guard offset == input.count else { throw KeyControlCodecError.invalidEncoding }
  }

  private mutating func integer<T: FixedWidthInteger>() throws -> T {
    let bytes = try take(MemoryLayout<T>.size)
    return bytes.reduce(T.zero) { ($0 << 8) | T($1) }
  }

  private mutating func take(_ count: Int) throws -> Data {
    let (end, overflow) = offset.addingReportingOverflow(count)
    guard count >= 0, !overflow, end <= input.count else {
      throw KeyControlCodecError.invalidEncoding
    }
    let value = Data(input[offset..<end])
    offset = end
    return value
  }
}
