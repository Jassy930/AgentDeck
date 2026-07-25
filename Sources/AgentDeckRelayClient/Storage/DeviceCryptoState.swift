import Foundation

/// 设备侧 sealed state 的信任轴。所有随机标识都必须来自已验证的配对响应。
public struct DeviceCryptoTrustScopeV1: Equatable, Sendable {
  public let relayServerID: Data
  public let machineRootFingerprint: Data
  public let machineRoute: Data
  public let deviceRoute: Data
  public let grantSerial: UInt64
  public let trustEpoch: UInt64

  public init(
    relayServerID: Data,
    machineRootFingerprint: Data,
    machineRoute: Data,
    deviceRoute: Data,
    grantSerial: UInt64,
    trustEpoch: UInt64
  ) throws {
    guard relayServerID.count == 16,
      machineRootFingerprint.count == 32,
      machineRoute.count == 16,
      deviceRoute.count == 16,
      !relayServerID.isAllZero,
      !machineRootFingerprint.isAllZero,
      !machineRoute.isAllZero,
      !deviceRoute.isAllZero,
      grantSerial > 0,
      trustEpoch > 0
    else {
      throw DeviceCryptoStateError.invalidTrustScope
    }
    self.relayServerID = relayServerID
    self.machineRootFingerprint = machineRootFingerprint
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.grantSerial = grantSerial
    self.trustEpoch = trustEpoch
  }
}

/// 已签名 KeyDirectory 中面向本设备的一条 wrapped key carrier。
///
/// `enc` 与 `wrappedKey` 都是 HPKE carrier，不是解密后的 transcript。
public struct DeviceWrappedKeyV1: Equatable, Sendable {
  public static let encapsulatedKeyBytes = 32
  public static let wrappedKeyBytes = 48

  public let keyID: KeyIDV1
  public let deviceRoute: Data
  public let streamRoute: Data?
  public let enc: Data
  public let wrappedKey: Data

  public init(
    keyID: KeyIDV1,
    deviceRoute: Data,
    streamRoute: Data?,
    enc: Data,
    wrappedKey: Data
  ) throws {
    guard keyID.epoch > 0,
      deviceRoute.count == 16,
      !deviceRoute.isAllZero,
      Self.streamShapeIsValid(purpose: keyID.purpose, streamRoute: streamRoute),
      enc.count == Self.encapsulatedKeyBytes,
      !enc.isAllZero,
      wrappedKey.count == Self.wrappedKeyBytes,
      !wrappedKey.isAllZero
    else {
      throw DeviceCryptoStateError.invalidKeyDirectory
    }
    self.keyID = keyID
    self.deviceRoute = deviceRoute
    self.streamRoute = streamRoute
    self.enc = enc
    self.wrappedKey = wrappedKey
  }

  fileprivate static func streamShapeIsValid(
    purpose: KeyPurpose,
    streamRoute: Data?
  ) -> Bool {
    switch purpose {
    case .conversationDEK:
      return streamRoute?.count == 16 && streamRoute?.isAllZero == false
    case .catalog, .deviceCommandTx, .deviceReplyTx:
      return streamRoute == nil
    }
  }
}

/// 设备已验证的 signed KeyDirectory 投影。
public struct DeviceKeyDirectoryV1: Equatable, Sendable {
  public static let maximumEntries = 1_027

  public let revision: UInt64
  public let entries: [DeviceWrappedKeyV1]
  public let signature: Data

  public init(
    revision: UInt64,
    entries: [DeviceWrappedKeyV1],
    signature: Data
  ) throws {
    guard revision > 0,
      entries.count >= 3,
      entries.count <= Self.maximumEntries,
      signature.count == 64,
      !signature.isAllZero
    else {
      throw DeviceCryptoStateError.invalidKeyDirectory
    }
    var previousIdentity: DeviceKeyDirectoryEntryIdentity?
    var catalogCount = 0
    var conversationCount = 0
    var commandCount = 0
    var replyCount = 0
    let deviceRoute = entries[0].deviceRoute
    for entry in entries {
      let identity = DeviceKeyDirectoryEntryIdentity(entry)
      guard entry.deviceRoute == deviceRoute,
        previousIdentity.map({ $0.isStrictlyBefore(identity) }) ?? true
      else {
        throw DeviceCryptoStateError.invalidKeyDirectory
      }
      previousIdentity = identity
      switch entry.keyID.purpose {
      case .catalog: catalogCount += 1
      case .conversationDEK: conversationCount += 1
      case .deviceCommandTx: commandCount += 1
      case .deviceReplyTx: replyCount += 1
      }
    }
    guard catalogCount == 1,
      conversationCount <= 1_024,
      commandCount == 1,
      replyCount == 1
    else {
      throw DeviceCryptoStateError.invalidKeyDirectory
    }
    self.revision = revision
    self.entries = entries
    self.signature = signature
  }
}

private struct DeviceKeyDirectoryEntryIdentity {
  let purpose: UInt8
  let streamRoute: Data
  let epoch: UInt64

  init(_ entry: DeviceWrappedKeyV1) {
    purpose = entry.keyID.purpose.deviceStateTag
    streamRoute = entry.streamRoute ?? Data(repeating: 0, count: 16)
    epoch = entry.keyID.epoch
  }

  func isStrictlyBefore(_ other: Self) -> Bool {
    if purpose != other.purpose { return purpose < other.purpose }
    if streamRoute != other.streamRoute {
      return streamRoute.lexicographicallyPrecedes(other.streamRoute)
    }
    return epoch < other.epoch
  }
}

/// 当前 device-command sender key 的 crash-safe reservation 投影。
public struct DeviceSenderCounterV1: Equatable, Sendable {
  public let keyID: KeyIDV1
  public let keyDirectoryRevision: UInt64
  public let noncePrefix: Data
  public let reservedHighWater: UInt64
  public let reservationID: Data

  public init(
    keyID: KeyIDV1,
    keyDirectoryRevision: UInt64,
    noncePrefix: Data,
    reservedHighWater: UInt64,
    reservationID: Data
  ) throws {
    guard keyID.purpose == .deviceCommandTx,
      keyID.epoch > 0,
      keyDirectoryRevision > 0,
      noncePrefix.count == 4,
      reservationID.count == 16,
      (reservedHighWater == 0) == reservationID.isAllZero
    else {
      throw DeviceCryptoStateError.invalidSenderCounter
    }
    self.keyID = keyID
    self.keyDirectoryRevision = keyDirectoryRevision
    self.noncePrefix = noncePrefix
    self.reservedHighWater = reservedHighWater
    self.reservationID = reservationID
  }
}

/// replay window 的持久化 key scope。
public struct DeviceCryptoKeyScopeV1: Hashable, Sendable {
  public let keyID: KeyIDV1
  public let streamRoute: Data?

  public init(keyID: KeyIDV1, streamRoute: Data?) {
    self.keyID = keyID
    self.streamRoute = streamRoute
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.keyID == rhs.keyID && lhs.streamRoute == rhs.streamRoute
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(keyID.purpose.rawValue)
    hasher.combine(keyID.epoch)
    hasher.combine(streamRoute)
  }
}

public enum DeviceReplayStatusV1: Equatable, Sendable {
  case active
  case quarantined(reason: DeviceCryptoSecurityReason, observedAtMS: UInt64)
  case retired(retiredAtMS: UInt64, deleteAfterMS: UInt64)
}

public enum DeviceCryptoSecurityReason: UInt8, Equatable, Sendable {
  case nonceReuse = 1
  case keyRevisionRollback = 2
  case authenticatedStateRollback = 3
}

public enum DeviceMachineSecurityStateV1: Equatable, Sendable {
  case active
  case quarantined(
    reason: DeviceCryptoSecurityReason,
    observedAtMS: UInt64,
    scope: DeviceCryptoKeyScopeV1?
  )
}

public struct DeviceReplayStateV1: Equatable, Sendable {
  public let scope: DeviceCryptoKeyScopeV1
  public let window: ReplayWindowSnapshot
  public let status: DeviceReplayStatusV1

  public init(
    scope: DeviceCryptoKeyScopeV1,
    window: ReplayWindowSnapshot,
    status: DeviceReplayStatusV1
  ) throws {
    guard scope.keyID.epoch > 0,
      scope.keyID.purpose != .deviceCommandTx,
      DeviceWrappedKeyV1.streamShapeIsValid(
        purpose: scope.keyID.purpose,
        streamRoute: scope.streamRoute
      )
    else {
      throw DeviceCryptoStateError.invalidReplayState
    }
    _ = try ReplayWindow(snapshot: window)
    switch status {
    case .active:
      break
    case .quarantined(_, let observedAtMS):
      guard observedAtMS > 0 else { throw DeviceCryptoStateError.invalidReplayState }
    case .retired(let retiredAtMS, let deleteAfterMS):
      let minimum = retiredAtMS.addingReportingOverflow(
        ReplayWindow.retiredWindowRetentionMilliseconds
      )
      guard retiredAtMS > 0,
        !minimum.overflow,
        deleteAfterMS >= minimum.partialValue
      else {
        throw DeviceCryptoStateError.invalidReplayState
      }
    }
    self.scope = scope
    self.window = window
    self.status = status
  }
}

public enum DeviceInnerCursorV1: Equatable, Sendable {
  case catalog(StreamCursor)
  case conversation(id: String, cursor: StreamCursor)
}

public struct DeviceStreamCursorStateV1: Equatable, Sendable {
  public let streamRoute: Data
  public let generation: Data
  public let outerCursor: StreamCursor
  public let innerCursor: DeviceInnerCursorV1

  public init(
    streamRoute: Data,
    generation: Data,
    outerCursor: StreamCursor,
    innerCursor: DeviceInnerCursorV1
  ) throws {
    guard streamRoute.count == 16,
      generation.count == 16,
      !streamRoute.isAllZero,
      !generation.isAllZero
    else {
      throw DeviceCryptoStateError.invalidCursor
    }
    if case .conversation(let id, _) = innerCursor {
      guard !id.isEmpty, id.utf8.count <= 8 * 1_024 else {
        throw DeviceCryptoStateError.invalidCursor
      }
    }
    self.streamRoute = streamRoute
    self.generation = generation
    self.outerCursor = outerCursor
    self.innerCursor = innerCursor
  }
}

/// `CryptoStateFileV1` plaintext 的唯一 production schema。
///
/// 类型只承载 trust/key/counter/replay/cursor；没有 prompt、output 或 transcript 字段。
public struct DeviceCryptoStateV1: Equatable, Sendable, CustomDebugStringConvertible {
  public static let maximumReplayStates = DeviceKeyDirectoryV1.maximumEntries - 1
  public static let maximumStreamStates = 4_096

  public let stateRevision: UInt64
  public let trustScope: DeviceCryptoTrustScopeV1
  public let keyDirectory: DeviceKeyDirectoryV1
  public let senderCounter: DeviceSenderCounterV1
  public let securityState: DeviceMachineSecurityStateV1
  public let replayStates: [DeviceReplayStateV1]
  public let streamStates: [DeviceStreamCursorStateV1]

  public init(
    stateRevision: UInt64,
    trustScope: DeviceCryptoTrustScopeV1,
    keyDirectory: DeviceKeyDirectoryV1,
    senderCounter: DeviceSenderCounterV1,
    securityState: DeviceMachineSecurityStateV1,
    replayStates: [DeviceReplayStateV1],
    streamStates: [DeviceStreamCursorStateV1]
  ) throws {
    guard stateRevision > 0,
      keyDirectory.revision == senderCounter.keyDirectoryRevision,
      keyDirectory.entries.contains(where: {
        $0.keyID == senderCounter.keyID && $0.deviceRoute == trustScope.deviceRoute
      }),
      keyDirectory.entries.allSatisfy({ $0.deviceRoute == trustScope.deviceRoute }),
      replayStates.count <= Self.maximumReplayStates,
      streamStates.count <= Self.maximumStreamStates
    else {
      throw DeviceCryptoStateError.invalidState
    }
    if case .quarantined(_, let observedAtMS, let scope) = securityState {
      guard observedAtMS > 0,
        scope == nil || replayStates.contains(where: { $0.scope == scope })
      else {
        throw DeviceCryptoStateError.invalidState
      }
    }
    var replayScopes = Set<DeviceCryptoKeyScopeV1>()
    for replay in replayStates {
      guard replayScopes.insert(replay.scope).inserted,
        keyDirectory.entries.contains(where: {
          $0.keyID == replay.scope.keyID && $0.streamRoute == replay.scope.streamRoute
        })
      else {
        throw DeviceCryptoStateError.invalidState
      }
    }
    var streamRoutes = Set<Data>()
    for stream in streamStates {
      guard streamRoutes.insert(stream.streamRoute).inserted else {
        throw DeviceCryptoStateError.invalidState
      }
    }
    self.stateRevision = stateRevision
    self.trustScope = trustScope
    self.keyDirectory = keyDirectory
    self.senderCounter = senderCounter
    self.securityState = securityState
    self.replayStates = replayStates
    self.streamStates = streamStates
  }

  public var debugDescription: String {
    "DeviceCryptoStateV1(revision: \(stateRevision), <redacted>)"
  }

  func reservingCounterBlock(endExclusive: UInt64, reservationID: Data) throws -> Self {
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow,
      endExclusive > senderCounter.reservedHighWater
    else {
      throw DeviceCryptoStateError.invalidSenderCounter
    }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: DeviceSenderCounterV1(
        keyID: senderCounter.keyID,
        keyDirectoryRevision: senderCounter.keyDirectoryRevision,
        noncePrefix: senderCounter.noncePrefix,
        reservedHighWater: endExclusive,
        reservationID: reservationID
      ),
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streamStates
    )
  }

  func replacingReplayState(_ replacement: DeviceReplayStateV1) throws -> Self {
    guard let index = replayStates.firstIndex(where: { $0.scope == replacement.scope }) else {
      throw DeviceCryptoStateError.missingReplayState
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    var nextReplayStates = replayStates
    nextReplayStates[index] = replacement
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: nextReplayStates,
      streamStates: streamStates
    )
  }

  func quarantining(
    reason: DeviceCryptoSecurityReason,
    scope: DeviceCryptoKeyScopeV1?,
    observedAtMS: UInt64
  ) throws -> Self {
    guard observedAtMS > 0 else { throw DeviceCryptoStateError.invalidState }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    var nextReplayStates = replayStates
    if let scope {
      guard let index = nextReplayStates.firstIndex(where: { $0.scope == scope }) else {
        throw DeviceCryptoStateError.missingReplayState
      }
      nextReplayStates[index] = try DeviceReplayStateV1(
        scope: nextReplayStates[index].scope,
        window: nextReplayStates[index].window,
        status: .quarantined(reason: reason, observedAtMS: observedAtMS)
      )
    }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: .quarantined(
        reason: reason,
        observedAtMS: observedAtMS,
        scope: scope
      ),
      replayStates: nextReplayStates,
      streamStates: streamStates
    )
  }
}

public enum DeviceCryptoStateError: Error, Equatable, Sendable {
  case invalidTrustScope
  case invalidKeyDirectory
  case invalidSenderCounter
  case invalidReplayState
  case invalidCursor
  case invalidState
  case invalidEncoding
  case inputTooLarge
  case missingReplayState
}

enum DeviceCryptoStateCodec {
  private static let magic = Data("ADDS".utf8)
  private static let version: UInt16 = 1
  private static let headerBytes = 12

  static func encode(
    _ state: DeviceCryptoStateV1,
    maximumDataBytes: Int = CryptoStateSnapshot.maximumDataBytes
  ) throws -> Data {
    guard maximumDataBytes >= headerBytes else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    var body = DeviceStateEncoder(maximumBytes: maximumDataBytes - headerBytes)
    body.u64(state.stateRevision)
    body.fixed(state.trustScope.relayServerID)
    body.fixed(state.trustScope.machineRootFingerprint)
    body.fixed(state.trustScope.machineRoute)
    body.fixed(state.trustScope.deviceRoute)
    body.u64(state.trustScope.grantSerial)
    body.u64(state.trustScope.trustEpoch)

    body.u64(state.keyDirectory.revision)
    try body.count(state.keyDirectory.entries.count)
    for entry in state.keyDirectory.entries {
      body.u8(entry.keyID.purpose.deviceStateTag)
      body.zeros(7)
      body.u64(entry.keyID.epoch)
      body.fixed(entry.deviceRoute)
      body.optionalFixed(entry.streamRoute, count: 16)
      try body.bytes(entry.enc, maximum: DeviceWrappedKeyV1.encapsulatedKeyBytes)
      try body.bytes(entry.wrappedKey, maximum: DeviceWrappedKeyV1.wrappedKeyBytes)
    }
    body.fixed(state.keyDirectory.signature)

    body.u8(state.senderCounter.keyID.purpose.deviceStateTag)
    body.zeros(7)
    body.u64(state.senderCounter.keyID.epoch)
    body.u64(state.senderCounter.keyDirectoryRevision)
    body.fixed(state.senderCounter.noncePrefix)
    body.zeros(4)
    body.u64(state.senderCounter.reservedHighWater)
    body.fixed(state.senderCounter.reservationID)

    switch state.securityState {
    case .active:
      body.u8(0)
      body.u8(0)
      body.zeros(6)
      body.u64(0)
      body.u8(0)
      body.u8(0)
      body.zeros(6)
      body.u64(0)
      body.optionalFixed(nil, count: 16)
    case .quarantined(let reason, let observedAtMS, let scope):
      body.u8(1)
      body.u8(reason.rawValue)
      body.zeros(6)
      body.u64(observedAtMS)
      if let scope {
        body.u8(1)
        body.u8(scope.keyID.purpose.deviceStateTag)
        body.zeros(6)
        body.u64(scope.keyID.epoch)
        body.optionalFixed(scope.streamRoute, count: 16)
      } else {
        body.u8(0)
        body.u8(0)
        body.zeros(6)
        body.u64(0)
        body.optionalFixed(nil, count: 16)
      }
    }

    try body.count(state.replayStates.count)
    for replay in state.replayStates {
      body.u8(replay.scope.keyID.purpose.deviceStateTag)
      body.zeros(7)
      body.u64(replay.scope.keyID.epoch)
      body.optionalFixed(replay.scope.streamRoute, count: 16)
      switch replay.status {
      case .active:
        body.u8(0)
        body.u8(0)
        body.zeros(6)
        body.u64(0)
        body.u64(0)
      case .quarantined(let reason, let observedAtMS):
        body.u8(1)
        body.u8(reason.rawValue)
        body.zeros(6)
        body.u64(observedAtMS)
        body.u64(0)
      case .retired(let retiredAtMS, let deleteAfterMS):
        body.u8(2)
        body.u8(0)
        body.zeros(6)
        body.u64(retiredAtMS)
        body.u64(deleteAfterMS)
      }
      if let highWater = replay.window.highWater {
        body.u8(1)
        body.zeros(7)
        body.u64(highWater)
      } else {
        body.zeros(16)
      }
      body.u64(replay.window.floor)
      try body.count(replay.window.entries.count)
      for entry in replay.window.entries {
        body.u64(entry.counter)
        body.fixed(entry.ciphertextHash)
      }
    }

    try body.count(state.streamStates.count)
    for stream in state.streamStates {
      body.fixed(stream.streamRoute)
      body.fixed(stream.generation)
      body.cursor(stream.outerCursor)
      switch stream.innerCursor {
      case .catalog(let cursor):
        body.u8(0)
        body.zeros(7)
        body.cursor(cursor)
      case .conversation(let id, let cursor):
        body.u8(1)
        body.zeros(7)
        try body.bytes(Data(id.utf8), maximum: 8 * 1_024)
        body.cursor(cursor)
      }
    }

    guard !body.exceededMaximum,
      body.data.count <= maximumDataBytes - headerBytes,
      let bodyLength = UInt32(exactly: body.data.count)
    else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    var encoded = magic
    encoded.appendInteger(version)
    encoded.appendInteger(UInt16(0))
    encoded.appendInteger(bodyLength)
    encoded.append(body.data)
    return encoded
  }

  static func decode(_ data: Data) throws -> DeviceCryptoStateV1 {
    guard data.count <= CryptoStateSnapshot.maximumDataBytes else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    guard data.count >= headerBytes,
      data.prefix(4) == magic
    else {
      throw DeviceCryptoStateError.invalidEncoding
    }
    var header = DeviceStateDecoder(data: data)
    _ = try header.fixed(count: 4)
    guard try header.u16() == version,
      try header.u16() == 0,
      Int(try header.u32()) == data.count - headerBytes
    else {
      throw DeviceCryptoStateError.invalidEncoding
    }
    var decoder = DeviceStateDecoder(data: data.subdata(in: headerBytes..<data.count))
    let stateRevision = try decoder.u64()
    let trust = try DeviceCryptoTrustScopeV1(
      relayServerID: decoder.fixed(count: 16),
      machineRootFingerprint: decoder.fixed(count: 32),
      machineRoute: decoder.fixed(count: 16),
      deviceRoute: decoder.fixed(count: 16),
      grantSerial: decoder.u64(),
      trustEpoch: decoder.u64()
    )

    let directoryRevision = try decoder.u64()
    let keyCount = try decoder.count(maximum: DeviceKeyDirectoryV1.maximumEntries)
    var keys: [DeviceWrappedKeyV1] = []
    keys.reserveCapacity(keyCount)
    for _ in 0..<keyCount {
      let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
      try decoder.requireZeros(count: 7)
      keys.append(
        try DeviceWrappedKeyV1(
          keyID: KeyIDV1(purpose: purpose, epoch: decoder.u64()),
          deviceRoute: decoder.fixed(count: 16),
          streamRoute: decoder.optionalFixed(count: 16),
          enc: decoder.bytes(maximum: DeviceWrappedKeyV1.encapsulatedKeyBytes),
          wrappedKey: decoder.bytes(maximum: DeviceWrappedKeyV1.wrappedKeyBytes)
        ))
    }
    let directory = try DeviceKeyDirectoryV1(
      revision: directoryRevision,
      entries: keys,
      signature: decoder.fixed(count: 64)
    )

    let senderPurpose = try KeyPurpose(deviceStateTag: decoder.u8())
    try decoder.requireZeros(count: 7)
    let senderEpoch = try decoder.u64()
    let senderDirectoryRevision = try decoder.u64()
    let senderNoncePrefix = try decoder.fixed(count: 4)
    try decoder.requireZeros(count: 4)
    let senderHighWater = try decoder.u64()
    let senderReservationID = try decoder.fixed(count: 16)
    let sender = try DeviceSenderCounterV1(
      keyID: KeyIDV1(purpose: senderPurpose, epoch: senderEpoch),
      keyDirectoryRevision: senderDirectoryRevision,
      noncePrefix: senderNoncePrefix,
      reservedHighWater: senderHighWater,
      reservationID: senderReservationID
    )

    let securityTag = try decoder.u8()
    let securityReasonTag = try decoder.u8()
    try decoder.requireZeros(count: 6)
    let securityObservedAtMS = try decoder.u64()
    let securityScopeTag = try decoder.u8()
    let securityPurposeTag = try decoder.u8()
    try decoder.requireZeros(count: 6)
    let securityEpoch = try decoder.u64()
    let securityStreamRoute = try decoder.optionalFixed(count: 16)
    let securityState: DeviceMachineSecurityStateV1
    switch (securityTag, securityScopeTag) {
    case (0, 0)
    where securityReasonTag == 0 && securityObservedAtMS == 0 && securityPurposeTag == 0
      && securityEpoch == 0 && securityStreamRoute == nil:
      securityState = .active
    case (1, 0)
    where securityPurposeTag == 0 && securityEpoch == 0 && securityStreamRoute == nil:
      guard let reason = DeviceCryptoSecurityReason(rawValue: securityReasonTag) else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      securityState = .quarantined(
        reason: reason,
        observedAtMS: securityObservedAtMS,
        scope: nil
      )
    case (1, 1):
      guard let reason = DeviceCryptoSecurityReason(rawValue: securityReasonTag) else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      securityState = .quarantined(
        reason: reason,
        observedAtMS: securityObservedAtMS,
        scope: DeviceCryptoKeyScopeV1(
          keyID: KeyIDV1(
            purpose: try KeyPurpose(deviceStateTag: securityPurposeTag),
            epoch: securityEpoch
          ),
          streamRoute: securityStreamRoute
        )
      )
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }

    let replayCount = try decoder.count(maximum: DeviceCryptoStateV1.maximumReplayStates)
    var replayStates: [DeviceReplayStateV1] = []
    replayStates.reserveCapacity(replayCount)
    for _ in 0..<replayCount {
      let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
      try decoder.requireZeros(count: 7)
      let scope = DeviceCryptoKeyScopeV1(
        keyID: KeyIDV1(purpose: purpose, epoch: try decoder.u64()),
        streamRoute: try decoder.optionalFixed(count: 16)
      )
      let statusTag = try decoder.u8()
      let reasonTag = try decoder.u8()
      try decoder.requireZeros(count: 6)
      let firstTime = try decoder.u64()
      let secondTime = try decoder.u64()
      let status: DeviceReplayStatusV1
      switch statusTag {
      case 0 where reasonTag == 0 && firstTime == 0 && secondTime == 0:
        status = .active
      case 1 where secondTime == 0:
        guard let reason = DeviceCryptoSecurityReason(rawValue: reasonTag) else {
          throw DeviceCryptoStateError.invalidEncoding
        }
        status = .quarantined(reason: reason, observedAtMS: firstTime)
      case 2 where reasonTag == 0:
        status = .retired(retiredAtMS: firstTime, deleteAfterMS: secondTime)
      default:
        throw DeviceCryptoStateError.invalidEncoding
      }
      let highWaterTag = try decoder.u8()
      try decoder.requireZeros(count: 7)
      let encodedHighWater = try decoder.u64()
      let highWater: UInt64?
      switch highWaterTag {
      case 0 where encodedHighWater == 0: highWater = nil
      case 1: highWater = encodedHighWater
      default: throw DeviceCryptoStateError.invalidEncoding
      }
      let floor = try decoder.u64()
      let entryCount = try decoder.count(maximum: Int(ReplayWindow.windowSize))
      var entries: [ReplayWindowEntry] = []
      entries.reserveCapacity(entryCount)
      for _ in 0..<entryCount {
        entries.append(
          ReplayWindowEntry(
            counter: try decoder.u64(),
            ciphertextHash: try decoder.fixed(count: 32)
          ))
      }
      replayStates.append(
        try DeviceReplayStateV1(
          scope: scope,
          window: ReplayWindowSnapshot(highWater: highWater, floor: floor, entries: entries),
          status: status
        ))
    }

    let streamCount = try decoder.count(maximum: DeviceCryptoStateV1.maximumStreamStates)
    var streams: [DeviceStreamCursorStateV1] = []
    streams.reserveCapacity(streamCount)
    for _ in 0..<streamCount {
      let route = try decoder.fixed(count: 16)
      let generation = try decoder.fixed(count: 16)
      let outer = try decoder.cursor()
      let innerTag = try decoder.u8()
      try decoder.requireZeros(count: 7)
      let inner: DeviceInnerCursorV1
      switch innerTag {
      case 0:
        inner = .catalog(try decoder.cursor())
      case 1:
        guard
          let id = String(
            data: try decoder.bytes(maximum: 8 * 1_024),
            encoding: .utf8
          )
        else {
          throw DeviceCryptoStateError.invalidEncoding
        }
        inner = .conversation(id: id, cursor: try decoder.cursor())
      default:
        throw DeviceCryptoStateError.invalidEncoding
      }
      streams.append(
        try DeviceStreamCursorStateV1(
          streamRoute: route,
          generation: generation,
          outerCursor: outer,
          innerCursor: inner
        ))
    }
    guard decoder.isAtEnd else { throw DeviceCryptoStateError.invalidEncoding }
    return try DeviceCryptoStateV1(
      stateRevision: stateRevision,
      trustScope: trust,
      keyDirectory: directory,
      senderCounter: sender,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streams
    )
  }
}

private struct DeviceStateEncoder {
  private let maximumBytes: Int
  private(set) var data = Data()
  private(set) var exceededMaximum = false

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func u8(_ value: UInt8) { appendBounded(Data([value])) }
  mutating func u64(_ value: UInt64) { integer(value) }
  mutating func zeros(_ count: Int) {
    appendBounded(Data(repeating: 0, count: count))
  }
  mutating func fixed(_ value: Data) { appendBounded(value) }

  mutating func count(_ value: Int) throws {
    guard let encoded = UInt32(exactly: value) else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    integer(encoded)
  }

  mutating func bytes(_ value: Data, maximum: Int) throws {
    guard value.count <= maximum, let count = UInt32(exactly: value.count) else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    integer(count)
    appendBounded(value)
  }

  mutating func optionalFixed(_ value: Data?, count: Int) {
    if let value {
      u8(1)
      fixed(value)
    } else {
      u8(0)
      zeros(count)
    }
  }

  mutating func cursor(_ value: StreamCursor) {
    switch value {
    case .beforeFirst:
      u8(0)
      zeros(7)
      u64(0)
    case .at(let cursor):
      u8(1)
      zeros(7)
      u64(cursor)
    }
  }

  private mutating func integer<T: FixedWidthInteger>(_ value: T) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { appendBounded(Data($0)) }
  }

  private mutating func appendBounded(_ value: Data) {
    let end = data.count.addingReportingOverflow(value.count)
    guard !exceededMaximum,
      !end.overflow,
      end.partialValue <= maximumBytes
    else {
      exceededMaximum = true
      return
    }
    data.append(value)
  }
}

private struct DeviceStateDecoder {
  let data: Data
  private(set) var offset = 0
  var isAtEnd: Bool { offset == data.count }

  mutating func u8() throws -> UInt8 { try fixed(count: 1)[0] }
  mutating func u16() throws -> UInt16 { try integer(count: 2) }
  mutating func u32() throws -> UInt32 { try integer(count: 4) }
  mutating func u64() throws -> UInt64 { try integer(count: 8) }

  mutating func fixed(count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= data.count else {
      throw DeviceCryptoStateError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return data.subdata(in: offset..<end.partialValue)
  }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else { throw DeviceCryptoStateError.inputTooLarge }
    return try fixed(count: count)
  }

  mutating func count(maximum: Int) throws -> Int {
    let value = Int(try u32())
    guard value <= maximum else { throw DeviceCryptoStateError.invalidEncoding }
    return value
  }

  mutating func optionalFixed(count: Int) throws -> Data? {
    let tag = try u8()
    let value = try fixed(count: count)
    switch tag {
    case 0 where value.isAllZero: return nil
    case 1: return value
    default: throw DeviceCryptoStateError.invalidEncoding
    }
  }

  mutating func cursor() throws -> StreamCursor {
    let tag = try u8()
    try requireZeros(count: 7)
    let value = try u64()
    switch tag {
    case 0 where value == 0: return .beforeFirst
    case 1: return .at(value)
    default: throw DeviceCryptoStateError.invalidEncoding
    }
  }

  mutating func requireZeros(count: Int) throws {
    guard try fixed(count: count).isAllZero else {
      throw DeviceCryptoStateError.invalidEncoding
    }
  }

  private mutating func integer<T: FixedWidthInteger>(count: Int) throws -> T {
    try fixed(count: count).reduce(0) { ($0 << 8) | T($1) }
  }
}

extension KeyPurpose {
  fileprivate var deviceStateTag: UInt8 {
    switch self {
    case .catalog: 0
    case .conversationDEK: 1
    case .deviceCommandTx: 2
    case .deviceReplyTx: 3
    }
  }

  fileprivate init(deviceStateTag: UInt8) throws {
    switch deviceStateTag {
    case 0: self = .catalog
    case 1: self = .conversationDEK
    case 2: self = .deviceCommandTx
    case 3: self = .deviceReplyTx
    default: throw DeviceCryptoStateError.invalidEncoding
    }
  }
}

extension Data {
  fileprivate var isAllZero: Bool { allSatisfy { $0 == 0 } }

  fileprivate mutating func appendInteger<T: FixedWidthInteger>(_ value: T) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
  }
}
