import AgentDeckCore
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

  static func streamShapeIsValid(
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

enum DeviceStreamBindingTargetV1: Hashable, Sendable {
  case catalog
  case conversation(String)
}

/// MachineDataSign + DeviceReplyTx 保护的 StreamBinding 在 Relay Subscribe 前落盘的
/// pending capability。它与已提交的 `streamStates` 分离，避免仅收到 bootstrap binding
/// 就把 reducer/cursor 伪装成已经完成 SyncComplete。
struct DeviceDurableStreamBindingV1: Equatable, Sendable {
  let streamRoute: Data
  let streamGeneration: Data
  let streamCursor: StreamCursor
  let innerCursor: DeviceInnerCursorV1
  let keyDirectoryRevision: UInt64
  let keyID: KeyIDV1

  init(
    streamRoute: Data,
    streamGeneration: Data,
    streamCursor: StreamCursor,
    innerCursor: DeviceInnerCursorV1,
    keyDirectoryRevision: UInt64,
    keyID: KeyIDV1
  ) throws {
    let target = Self.target(innerCursor)
    let shapeMatches: Bool
    switch (target, keyID.purpose) {
    case (.catalog, .catalog):
      shapeMatches = true
    case (.conversation, .conversationDEK):
      shapeMatches = true
    default:
      shapeMatches = false
    }
    guard streamRoute.count == 16,
      streamGeneration.count == 16,
      !streamRoute.isAllZero,
      !streamGeneration.isAllZero,
      keyDirectoryRevision > 0,
      keyID.epoch > 0,
      shapeMatches,
      streamCursor.checkedNextForKeyLifecycle != nil,
      Self.innerStreamCursor(innerCursor).checkedNextForKeyLifecycle != nil
    else {
      throw DeviceCryptoStateError.invalidStreamBinding
    }
    self.streamRoute = streamRoute
    self.streamGeneration = streamGeneration
    self.streamCursor = streamCursor
    self.innerCursor = innerCursor
    self.keyDirectoryRevision = keyDirectoryRevision
    self.keyID = keyID
  }

  init(_ binding: DaemonStreamBindingV1) throws {
    try self.init(
      streamRoute: binding.streamRoute,
      streamGeneration: binding.streamGeneration,
      streamCursor: binding.streamCursor,
      innerCursor: DeviceInnerCursorV1(binding.innerCursor),
      keyDirectoryRevision: binding.keyDirectoryRevision,
      keyID: binding.keyID
    )
  }

  var target: DeviceStreamBindingTargetV1 { Self.target(innerCursor) }

  static func target(
    _ cursor: DeviceInnerCursorV1
  ) -> DeviceStreamBindingTargetV1 {
    switch cursor {
    case .catalog:
      return .catalog
    case .conversation(let id, _):
      return .conversation(id)
    }
  }

  private static func innerStreamCursor(
    _ cursor: DeviceInnerCursorV1
  ) -> StreamCursor {
    switch cursor {
    case .catalog(let value), .conversation(_, let value):
      return value
    }
  }

}

/// 首个 authenticated exact-next probe 到最终 barrier activation 之间的 durable
/// KeySync episode。transport generation、进程重启和 staged ACK retry 都只能恢复这一个
/// absolute deadline / attempt，不能重新获得 30 秒或从 attempt 1 开始。
struct DeviceKeySyncEpisodeV1: Equatable, Sendable {
  static let maximumAttempts: UInt8 = 3
  static let deadlineMilliseconds: UInt64 = 30_000

  let targetRevision: UInt64
  let observedKeyID: KeyIDV1
  let streamRoute: Data?
  let attempt: UInt8
  let startedAtMS: UInt64
  let expiresAtMS: UInt64
  let exhausted: Bool

  init(
    targetRevision: UInt64,
    observedKeyID: KeyIDV1,
    streamRoute: Data?,
    attempt: UInt8,
    startedAtMS: UInt64,
    expiresAtMS: UInt64,
    exhausted: Bool = false
  ) throws {
    let expectedExpiry = startedAtMS.addingReportingOverflow(Self.deadlineMilliseconds)
    guard targetRevision > 0,
      observedKeyID.epoch > 0,
      Self.observedStreamShapeIsValid(
        purpose: observedKeyID.purpose,
        streamRoute: streamRoute
      ),
      (1...Self.maximumAttempts).contains(attempt),
      startedAtMS > 0,
      !expectedExpiry.overflow,
      expiresAtMS == expectedExpiry.partialValue
    else {
      throw DeviceCryptoStateError.invalidKeySyncEpisode
    }
    self.targetRevision = targetRevision
    self.observedKeyID = observedKeyID
    self.streamRoute = streamRoute
    self.attempt = attempt
    self.startedAtMS = startedAtMS
    self.expiresAtMS = expiresAtMS
    self.exhausted = exhausted
  }

  private static func observedStreamShapeIsValid(
    purpose: KeyPurpose,
    streamRoute: Data?
  ) -> Bool {
    switch purpose {
    case .conversationDEK:
      return streamRoute?.count == 16 && streamRoute?.isAllZero == false
    case .catalog:
      return streamRoute == nil
        || (streamRoute?.count == 16 && streamRoute?.isAllZero == false)
    case .deviceCommandTx, .deviceReplyTx:
      return streamRoute == nil
    }
  }

  func validateActive(at observedAtMS: UInt64) throws {
    guard observedAtMS >= startedAtMS else {
      throw DeviceCryptoStateError.invalidClock
    }
    guard !exhausted, observedAtMS < expiresAtMS else {
      throw DeviceCryptoStateError.keySyncEpisodeEnded
    }
  }
}

extension DeviceInnerCursorV1 {
  init(_ cursor: RuntimeInnerCursorV1) {
    switch cursor {
    case .catalog(let value):
      self = .catalog(value.deviceStreamCursor)
    case .conversation(let conversationID, let value):
      self = .conversation(
        id: conversationID.rawValue,
        cursor: value.deviceStreamCursor
      )
    }
  }
}

extension DeviceStreamCursorStateV1 {
  fileprivate var bindingTarget: DeviceStreamBindingTargetV1 {
    DeviceDurableStreamBindingV1.target(innerCursor)
  }
}

enum DeviceStreamBindingInstallDisposition: Equatable, Sendable {
  case installed
  case exactRetry
}

struct DeviceStreamBindingInstallTransition: Sendable {
  let state: DeviceCryptoStateV1
  let installed: DeviceDurableStreamBindingV1
  let retired: DeviceDurableStreamBindingV1?
  let disposition: DeviceStreamBindingInstallDisposition
}

enum DeviceKeyLifecycleError: Error, Equatable, Sendable {
  case invalidState
  case invalidRoster
  case invalidRevision
  case invalidEpoch
  case invalidCarrier
  case secretReuse
  case forkedUpdateSet
  case invalidBarrier
  case invalidDirectoryAdvance
  case capacity
  case coldOpenAuditFailed
  case receivingKeyNotFound
  case retiredKeyExpired
}

struct DeviceKeySlotIDV1: Hashable, Sendable {
  let purpose: KeyPurpose
  let streamRoute: Data?

  init(purpose: KeyPurpose, streamRoute: Data?) throws {
    guard
      DeviceWrappedKeyV1.streamShapeIsValid(
        purpose: purpose,
        streamRoute: streamRoute
      )
    else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    self.purpose = purpose
    self.streamRoute = streamRoute
  }

  fileprivate var sortKey: (UInt8, Data) {
    (purpose.deviceStateTag, streamRoute ?? Data(repeating: 0, count: 16))
  }
}

enum DeviceStoredKeyCarrierSourceV1: Equatable, Sendable {
  case bootstrapDirectory
  case signedUpdate(Data)
}

struct DeviceStoredKeyCarrierV1: Equatable, Sendable, CustomDebugStringConvertible {
  let keyID: KeyIDV1
  let streamRoute: Data?
  let keyDirectoryRevision: UInt64
  let secretFingerprint: Data
  let source: DeviceStoredKeyCarrierSourceV1
  let activationProof: DeviceEpochBarrierV1?

  init(
    keyID: KeyIDV1,
    streamRoute: Data?,
    keyDirectoryRevision: UInt64,
    secretFingerprint: Data,
    source: DeviceStoredKeyCarrierSourceV1,
    activationProof: DeviceEpochBarrierV1? = nil
  ) throws {
    guard keyID.epoch > 0,
      keyDirectoryRevision > 0,
      secretFingerprint.count == 32,
      secretFingerprint.contains(where: { $0 != 0 }),
      DeviceWrappedKeyV1.streamShapeIsValid(
        purpose: keyID.purpose,
        streamRoute: streamRoute
      )
    else {
      throw DeviceKeyLifecycleError.invalidCarrier
    }
    switch source {
    case .bootstrapDirectory:
      guard
        activationProof.map({
          $0.oldEpoch == 0 && $0.newEpoch == 1 && keyID.epoch == 1
        }) ?? true
      else {
        throw DeviceKeyLifecycleError.invalidCarrier
      }
    case .signedUpdate(let canonical):
      let decoded: CanonicalKeyUpdateV1
      do {
        decoded = try KeyUpdateCanonicalCodec.decode(canonical)
      } catch {
        throw DeviceKeyLifecycleError.invalidCarrier
      }
      guard decoded.keyID == keyID,
        decoded.streamRoute == streamRoute,
        decoded.keyDirectoryRevision == keyDirectoryRevision
      else {
        throw DeviceKeyLifecycleError.invalidCarrier
      }
    }
    if let activationProof {
      guard activationProof.keyDirectoryRevision == keyDirectoryRevision,
        activationProof.newEpoch == keyID.epoch,
        Self.activationProofMatchesCarrier(
          activationProof,
          keyID: keyID,
          streamRoute: streamRoute,
          source: source
        )
      else {
        throw DeviceKeyLifecycleError.invalidCarrier
      }
    }
    self.keyID = keyID
    self.streamRoute = streamRoute
    self.keyDirectoryRevision = keyDirectoryRevision
    self.secretFingerprint = secretFingerprint
    self.source = source
    self.activationProof = activationProof
  }

  private static func activationProofMatchesCarrier(
    _ proof: DeviceEpochBarrierV1,
    keyID: KeyIDV1,
    streamRoute: Data?,
    source: DeviceStoredKeyCarrierSourceV1
  ) -> Bool {
    switch (keyID.purpose, proof.innerCursor) {
    case (.catalog, .catalog):
      guard streamRoute == nil else { return false }
    case (.conversationDEK, .conversation):
      guard streamRoute == proof.streamRoute else { return false }
    case (.catalog, .conversation), (.conversationDEK, .catalog),
      (.deviceCommandTx, _), (.deviceReplyTx, _):
      return false
    }
    switch source {
    case .bootstrapDirectory:
      return proof.oldEpoch == 0 && proof.newEpoch == 1 && keyID.epoch == 1
    case .signedUpdate:
      return proof.oldEpoch > 0
    }
  }

  var slotID: DeviceKeySlotIDV1 {
    // Construction already validated this shape.
    try! DeviceKeySlotIDV1(purpose: keyID.purpose, streamRoute: streamRoute)
  }

  var debugDescription: String {
    "DeviceStoredKeyCarrierV1(identity: <redacted>, material: <redacted>)"
  }

  func withActivationProof(_ proof: DeviceEpochBarrierV1) throws -> Self {
    try Self(
      keyID: keyID,
      streamRoute: streamRoute,
      keyDirectoryRevision: keyDirectoryRevision,
      secretFingerprint: secretFingerprint,
      source: source,
      activationProof: proof
    )
  }
}

struct DeviceRetiredKeyCarrierV1: Equatable, Sendable {
  let carrier: DeviceStoredKeyCarrierV1
  let retiredAtMS: UInt64
  let deleteAfterMS: UInt64

  init(
    carrier: DeviceStoredKeyCarrierV1,
    retiredAtMS: UInt64,
    deleteAfterMS: UInt64
  ) throws {
    let minimum = retiredAtMS.addingReportingOverflow(
      ReplayWindow.retiredWindowRetentionMilliseconds
    )
    guard retiredAtMS > 0,
      !minimum.overflow,
      deleteAfterMS >= minimum.partialValue
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    self.carrier = carrier
    self.retiredAtMS = retiredAtMS
    self.deleteAfterMS = deleteAfterMS
  }
}

struct DeviceKeySlotStateV1: Equatable, Sendable {
  static let maximumRetiredCarriers = 4_096

  let id: DeviceKeySlotIDV1
  let current: DeviceStoredKeyCarrierV1?
  let staged: DeviceStoredKeyCarrierV1?
  let retired: [DeviceRetiredKeyCarrierV1]

  init(
    id: DeviceKeySlotIDV1,
    current: DeviceStoredKeyCarrierV1?,
    staged: DeviceStoredKeyCarrierV1?,
    retired: [DeviceRetiredKeyCarrierV1]
  ) throws {
    guard current != nil || staged != nil,
      retired.count <= Self.maximumRetiredCarriers,
      current.map({ $0.slotID == id }) ?? true,
      staged.map({ $0.slotID == id }) ?? true,
      retired.allSatisfy({ $0.carrier.slotID == id })
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    if current == nil {
      guard id.purpose == .conversationDEK,
        staged?.keyID.epoch == 1,
        retired.isEmpty
      else {
        throw DeviceKeyLifecycleError.invalidEpoch
      }
    } else if let current, let staged {
      let successor = current.keyID.epoch.addingReportingOverflow(1)
      let isExactAlias =
        staged.keyID == current.keyID
        && staged.secretFingerprint == current.secretFingerprint
      let isRotation =
        !successor.overflow
        && staged.keyID.epoch == successor.partialValue
      guard isExactAlias || isRotation else {
        throw DeviceKeyLifecycleError.invalidEpoch
      }
    }
    var previousEpoch: UInt64?
    for entry in retired {
      guard previousEpoch.map({ $0 < entry.carrier.keyID.epoch }) ?? true,
        current.map({ entry.carrier.keyID.epoch < $0.keyID.epoch }) ?? true
      else {
        throw DeviceKeyLifecycleError.invalidState
      }
      previousEpoch = entry.carrier.keyID.epoch
    }
    self.id = id
    self.current = current
    self.staged = staged
    self.retired = retired
  }
}

struct DeviceStagedKeyTransitionV1: Equatable, Sendable {
  let fromRevision: UInt64
  let toRevision: UInt64
  let canonicalUpdateSet: Data
  let updateSetSHA256: Data

  init(
    fromRevision: UInt64,
    toRevision: UInt64,
    canonicalUpdateSet: Data,
    updateSetSHA256: Data
  ) throws {
    let next = fromRevision.addingReportingOverflow(1)
    let decoded: CanonicalKeyUpdateSetV1
    do {
      decoded = try KeyUpdateSetCanonicalCodec.decode(canonicalUpdateSet)
    } catch {
      throw DeviceKeyLifecycleError.invalidCarrier
    }
    guard fromRevision > 0,
      !next.overflow,
      toRevision == next.partialValue,
      decoded.keyDirectoryRevision == toRevision,
      updateSetSHA256.count == 32,
      updateSetSHA256.contains(where: { $0 != 0 }),
      CanonicalCodec.sha256(canonicalUpdateSet) == updateSetSHA256
    else {
      throw DeviceKeyLifecycleError.invalidRevision
    }
    self.fromRevision = fromRevision
    self.toRevision = toRevision
    self.canonicalUpdateSet = canonicalUpdateSet
    self.updateSetSHA256 = updateSetSHA256
  }
}

struct DeviceKeyLifecycleStateV1: Equatable, Sendable, CustomDebugStringConvertible {
  static let maximumRetiredCarriers = 4_096
  static let maximumRetiredSecretFingerprints = 4_096

  let activeRevision: UInt64
  let activeUpdateSet: Data?
  let stagedTransition: DeviceStagedKeyTransitionV1?
  let lastDirectoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1?
  let slots: [DeviceKeySlotStateV1]
  let retiredSecretFingerprints: [Data]

  init(
    activeRevision: UInt64,
    activeUpdateSet: Data?,
    stagedTransition: DeviceStagedKeyTransitionV1?,
    lastDirectoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1? = nil,
    slots: [DeviceKeySlotStateV1],
    retiredSecretFingerprints: [Data]
  ) throws {
    guard activeRevision > 0,
      !slots.isEmpty,
      slots.count <= DeviceKeyDirectoryV1.maximumEntries,
      retiredSecretFingerprints.count <= Self.maximumRetiredSecretFingerprints,
      stagedTransition.map({ $0.fromRevision == activeRevision }) ?? true
    else {
      throw DeviceKeyLifecycleError.invalidState
    }
    if let lastDirectoryAdvanceProof {
      guard stagedTransition == nil,
        lastDirectoryAdvanceProof.toRevision == activeRevision
      else {
        throw DeviceKeyLifecycleError.invalidDirectoryAdvance
      }
    }
    if let activeUpdateSet {
      let decoded: CanonicalKeyUpdateSetV1
      do {
        decoded = try KeyUpdateSetCanonicalCodec.decode(activeUpdateSet)
      } catch {
        throw DeviceKeyLifecycleError.invalidCarrier
      }
      guard decoded.keyDirectoryRevision == activeRevision else {
        throw DeviceKeyLifecycleError.invalidRevision
      }
    }

    var previous: DeviceKeySlotIDV1?
    var catalogCount = 0
    var commandCount = 0
    var replyCount = 0
    var retiredCount = 0
    var fingerprints: [Data: (DeviceKeySlotIDV1, UInt64)] = [:]
    for slot in slots {
      if let previous {
        let lhs = previous.sortKey
        let rhs = slot.id.sortKey
        guard lhs.0 < rhs.0 || (lhs.0 == rhs.0 && lhs.1.lexicographicallyPrecedes(rhs.1))
        else {
          throw DeviceKeyLifecycleError.invalidRoster
        }
      }
      previous = slot.id
      switch slot.id.purpose {
      case .catalog: catalogCount += 1
      case .deviceCommandTx: commandCount += 1
      case .deviceReplyTx: replyCount += 1
      case .conversationDEK: break
      }
      retiredCount += slot.retired.count
      for carrier in [slot.current, slot.staged].compactMap({ $0 })
        + slot.retired.map(\.carrier)
      {
        let identity = (slot.id, carrier.keyID.epoch)
        if let previousIdentity = fingerprints[carrier.secretFingerprint],
          previousIdentity.0 != identity.0 || previousIdentity.1 != identity.1
        {
          throw DeviceKeyLifecycleError.secretReuse
        }
        fingerprints[carrier.secretFingerprint] = identity
      }
    }
    guard catalogCount == 1,
      commandCount == 1,
      replyCount == 1,
      retiredCount <= Self.maximumRetiredCarriers
    else {
      throw DeviceKeyLifecycleError.capacity
    }
    var previousTombstone: Data?
    for fingerprint in retiredSecretFingerprints {
      guard fingerprint.count == 32,
        fingerprint.contains(where: { $0 != 0 }),
        fingerprints[fingerprint] == nil,
        previousTombstone.map({ $0.lexicographicallyPrecedes(fingerprint) }) ?? true
      else {
        throw DeviceKeyLifecycleError.secretReuse
      }
      previousTombstone = fingerprint
    }
    self.activeRevision = activeRevision
    self.activeUpdateSet = activeUpdateSet
    self.stagedTransition = stagedTransition
    self.lastDirectoryAdvanceProof = lastDirectoryAdvanceProof
    self.slots = slots
    self.retiredSecretFingerprints = retiredSecretFingerprints
  }

  var debugDescription: String {
    "DeviceKeyLifecycleStateV1(revision: \(activeRevision), material: <redacted>)"
  }

  func slot(purpose: KeyPurpose, streamRoute: Data?) -> DeviceKeySlotStateV1? {
    slots.first(where: { $0.id.purpose == purpose && $0.id.streamRoute == streamRoute })
  }
}

struct DeviceKeyLifecycleAcknowledgementBasisV1: Sendable {
  let epochBarriers: [DeviceEpochBarrierV1]
  let directoryAdvance: DeviceDirectoryRevisionAdvanceV1?
}

/// `CryptoStateFileV1` plaintext 的唯一 production schema。
///
/// 类型只承载 trust/key/counter/replay/cursor；没有 prompt、output 或 transcript 字段。
public struct DeviceCryptoStateV1: Equatable, Sendable, CustomDebugStringConvertible {
  /// active receive keys 与 25 小时 retention 内的 retired replay windows 共用的硬上界。
  ///
  /// 单个 KeyDirectory 最多承载 1,026 个 receive key；rotation 必须同时保留旧 window，
  /// 因而不能把上界错误地收窄成“当前 directory entry 数”。
  public static let maximumReplayStates = 4_096
  public static let maximumStreamStates = 4_096

  public let stateRevision: UInt64
  public let trustScope: DeviceCryptoTrustScopeV1
  public let keyDirectory: DeviceKeyDirectoryV1
  public let senderCounter: DeviceSenderCounterV1
  public let securityState: DeviceMachineSecurityStateV1
  public let replayStates: [DeviceReplayStateV1]
  public let streamStates: [DeviceStreamCursorStateV1]
  let keyLifecycle: DeviceKeyLifecycleStateV1?
  let pendingStreamBindings: [DeviceDurableStreamBindingV1]
  let keySyncEpisode: DeviceKeySyncEpisodeV1?

  public init(
    stateRevision: UInt64,
    trustScope: DeviceCryptoTrustScopeV1,
    keyDirectory: DeviceKeyDirectoryV1,
    senderCounter: DeviceSenderCounterV1,
    securityState: DeviceMachineSecurityStateV1,
    replayStates: [DeviceReplayStateV1],
    streamStates: [DeviceStreamCursorStateV1]
  ) throws {
    try self.init(
      stateRevision: stateRevision,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streamStates,
      keyLifecycle: nil,
      pendingStreamBindings: [],
      keySyncEpisode: nil
    )
  }

  init(
    stateRevision: UInt64,
    trustScope: DeviceCryptoTrustScopeV1,
    keyDirectory: DeviceKeyDirectoryV1,
    senderCounter: DeviceSenderCounterV1,
    securityState: DeviceMachineSecurityStateV1,
    replayStates: [DeviceReplayStateV1],
    streamStates: [DeviceStreamCursorStateV1],
    keyLifecycle: DeviceKeyLifecycleStateV1?,
    pendingStreamBindings: [DeviceDurableStreamBindingV1] = [],
    keySyncEpisode: DeviceKeySyncEpisodeV1? = nil
  ) throws {
    let activeRevision = keyLifecycle?.activeRevision ?? keyDirectory.revision
    guard stateRevision > 0,
      activeRevision == senderCounter.keyDirectoryRevision,
      keyDirectory.entries.contains(where: {
        $0.keyID == senderCounter.keyID && $0.deviceRoute == trustScope.deviceRoute
      }),
      keyDirectory.entries.allSatisfy({ $0.deviceRoute == trustScope.deviceRoute }),
      replayStates.count <= Self.maximumReplayStates,
      streamStates.count <= Self.maximumStreamStates,
      pendingStreamBindings.count <= Self.maximumStreamStates
    else {
      throw DeviceCryptoStateError.invalidState
    }
    if let keyLifecycle {
      let maximumInstalledRevision =
        keyLifecycle.stagedTransition?.toRevision ?? keyLifecycle.activeRevision
      guard
        keyLifecycle.slot(purpose: .deviceCommandTx, streamRoute: nil)?.current?.keyID
          == senderCounter.keyID,
        keyLifecycle.slots.allSatisfy({ slot in
          slot.current.map({ $0.keyDirectoryRevision <= maximumInstalledRevision }) ?? true
        })
      else {
        throw DeviceCryptoStateError.invalidState
      }
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
      guard replayScopes.insert(replay.scope).inserted else {
        throw DeviceCryptoStateError.invalidState
      }
      let isInCurrentDirectory = keyDirectory.entries.contains(where: {
        $0.keyID == replay.scope.keyID && $0.streamRoute == replay.scope.streamRoute
      })
      let isCurrentLifecycleKey =
        keyLifecycle?.slots.contains(where: {
          $0.current?.keyID == replay.scope.keyID
            && $0.current?.streamRoute == replay.scope.streamRoute
        }) ?? false
      let isStagedLifecycleKey =
        keyLifecycle?.slots.contains(where: {
          $0.staged?.keyID == replay.scope.keyID
            && $0.staged?.streamRoute == replay.scope.streamRoute
        }) ?? false
      let isRetiredLifecycleKey =
        keyLifecycle?.slots.contains(where: { slot in
          slot.retired.contains(where: {
            $0.carrier.keyID == replay.scope.keyID
              && $0.carrier.streamRoute == replay.scope.streamRoute
          })
        }) ?? false
      switch replay.status {
      case .active, .quarantined:
        guard
          isCurrentLifecycleKey || isStagedLifecycleKey
            || (keyLifecycle == nil && isInCurrentDirectory)
        else {
          throw DeviceCryptoStateError.invalidState
        }
      case .retired:
        guard keyLifecycle == nil || isRetiredLifecycleKey else {
          throw DeviceCryptoStateError.invalidState
        }
      }
    }
    var streamRoutes = Set<Data>()
    var streamGenerations = Set<Data>()
    var streamTargets = Set<DeviceStreamBindingTargetV1>()
    for stream in streamStates {
      guard streamRoutes.insert(stream.streamRoute).inserted,
        streamGenerations.insert(stream.generation).inserted,
        streamTargets.insert(stream.bindingTarget).inserted
      else {
        throw DeviceCryptoStateError.invalidState
      }
    }
    var pendingTargets = Set<DeviceStreamBindingTargetV1>()
    var pendingRoutes = Set<Data>()
    var pendingGenerations = Set<Data>()
    for binding in pendingStreamBindings {
      guard pendingTargets.insert(binding.target).inserted,
        pendingRoutes.insert(binding.streamRoute).inserted,
        pendingGenerations.insert(binding.streamGeneration).inserted,
        binding.keyDirectoryRevision == activeRevision,
        Self.bindingKeyIsCurrent(
          binding,
          directory: keyDirectory,
          lifecycle: keyLifecycle
        ),
        !streamStates.contains(where: {
          if $0.bindingTarget != binding.target {
            return $0.streamRoute == binding.streamRoute
              || $0.generation == binding.streamGeneration
          }
          return $0.generation == binding.streamGeneration
            && $0.streamRoute != binding.streamRoute
        })
      else {
        throw DeviceCryptoStateError.invalidStreamBinding
      }
    }
    if let keySyncEpisode {
      let target = activeRevision.addingReportingOverflow(1)
      guard securityState == .active,
        !target.overflow,
        keySyncEpisode.targetRevision == target.partialValue,
        keyLifecycle?.stagedTransition.map({ transition in
          transition.fromRevision == activeRevision
            && transition.toRevision == keySyncEpisode.targetRevision
        }) ?? true
      else {
        throw DeviceCryptoStateError.invalidKeySyncEpisode
      }
    }
    self.stateRevision = stateRevision
    self.trustScope = trustScope
    self.keyDirectory = keyDirectory
    self.senderCounter = senderCounter
    self.securityState = securityState
    self.replayStates = replayStates
    self.streamStates = streamStates
    self.keyLifecycle = keyLifecycle
    self.pendingStreamBindings = pendingStreamBindings
    self.keySyncEpisode = keySyncEpisode
  }

  public var debugDescription: String {
    "DeviceCryptoStateV1(revision: \(stateRevision), <redacted>)"
  }

  func startingOrResumingKeySyncEpisode(
    targetRevision: UInt64,
    observedKeyID: KeyIDV1,
    streamRoute: Data?,
    observedAtMS: UInt64
  ) throws -> Self {
    let activeRevision = keyLifecycle?.activeRevision ?? keyDirectory.revision
    let next = activeRevision.addingReportingOverflow(1)
    guard securityState == .active,
      !next.overflow,
      targetRevision == next.partialValue
    else {
      throw DeviceCryptoStateError.invalidKeySyncEpisode
    }
    if let keySyncEpisode {
      guard keySyncEpisode.targetRevision == targetRevision else {
        throw DeviceCryptoStateError.invalidKeySyncEpisode
      }
      try keySyncEpisode.validateActive(at: observedAtMS)
      return self
    }
    guard keyLifecycle?.stagedTransition == nil else {
      throw DeviceCryptoStateError.invalidKeySyncEpisode
    }
    let expires = observedAtMS.addingReportingOverflow(
      DeviceKeySyncEpisodeV1.deadlineMilliseconds
    )
    guard !expires.overflow else { throw DeviceCryptoStateError.invalidClock }
    return try replacingKeySyncEpisode(
      DeviceKeySyncEpisodeV1(
        targetRevision: targetRevision,
        observedKeyID: observedKeyID,
        streamRoute: streamRoute,
        attempt: 1,
        startedAtMS: observedAtMS,
        expiresAtMS: expires.partialValue
      ))
  }

  func recordingKeySyncAttemptFailure(
    targetRevision: UInt64,
    attempt: UInt8,
    observedAtMS: UInt64
  ) throws -> Self {
    guard let episode = keySyncEpisode,
      episode.targetRevision == targetRevision,
      episode.attempt == attempt
    else {
      throw DeviceCryptoStateError.invalidKeySyncEpisode
    }
    try episode.validateActive(at: observedAtMS)
    let nextAttempt: UInt8
    let exhausted: Bool
    if attempt < DeviceKeySyncEpisodeV1.maximumAttempts {
      nextAttempt = attempt + 1
      exhausted = false
    } else {
      nextAttempt = attempt
      exhausted = true
    }
    return try replacingKeySyncEpisode(
      DeviceKeySyncEpisodeV1(
        targetRevision: episode.targetRevision,
        observedKeyID: episode.observedKeyID,
        streamRoute: episode.streamRoute,
        attempt: nextAttempt,
        startedAtMS: episode.startedAtMS,
        expiresAtMS: episode.expiresAtMS,
        exhausted: exhausted
      ))
  }

  func expiringKeySyncEpisode(observedAtMS: UInt64) throws -> Self {
    guard let episode = keySyncEpisode,
      !episode.exhausted,
      observedAtMS >= episode.expiresAtMS,
      observedAtMS >= episode.startedAtMS
    else {
      throw DeviceCryptoStateError.invalidKeySyncEpisode
    }
    return try replacingKeySyncEpisode(
      DeviceKeySyncEpisodeV1(
        targetRevision: episode.targetRevision,
        observedKeyID: episode.observedKeyID,
        streamRoute: episode.streamRoute,
        attempt: episode.attempt,
        startedAtMS: episode.startedAtMS,
        expiresAtMS: episode.expiresAtMS,
        exhausted: true
      ))
  }

  private func replacingKeySyncEpisode(
    _ replacement: DeviceKeySyncEpisodeV1?
  ) throws -> Self {
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streamStates,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: replacement
    )
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
      streamStates: streamStates,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
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
      streamStates: streamStates,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
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
      streamStates: streamStates,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: nil
    )
  }

  /// 已验签、AEAD-open、strict decode 的 daemon StreamBinding 唯一 durable admission。
  /// pending binding 与 committed cursor 分离；只有后续 SyncComplete permit commit 才
  /// 会把它提升为 live `streamStates` generation。
  func installingStreamBinding(
    _ binding: DaemonStreamBindingV1
  ) throws -> DeviceStreamBindingInstallTransition {
    let candidate = try validatedStreamBinding(binding)
    let activeRevision = keyLifecycle?.activeRevision ?? keyDirectory.revision

    if let exact = pendingStreamBindings.first(where: {
      $0.target == candidate.target
    }), exact == candidate {
      return DeviceStreamBindingInstallTransition(
        state: self,
        installed: exact,
        retired: nil,
        disposition: .exactRetry
      )
    }

    let previousPending = pendingStreamBindings.first(where: {
      $0.target == candidate.target
    })
    let previousCommitted = streamStates.first(where: {
      $0.bindingTarget == candidate.target
    })
    if let previousPending {
      guard
        Self.innerCursor(
          candidate.innerCursor,
          isAtLeast: previousPending.innerCursor
        )
      else {
        throw DeviceCryptoStateError.invalidStreamBinding
      }
      if previousPending.streamGeneration == candidate.streamGeneration {
        guard previousPending.streamRoute == candidate.streamRoute,
          candidate.streamCursor.isAtLeastForKeyLifecycle(
            previousPending.streamCursor
          )
        else {
          throw DeviceCryptoStateError.invalidStreamBinding
        }
      }
    }
    if let previousCommitted {
      guard
        Self.innerCursor(
          candidate.innerCursor,
          isAtLeast: previousCommitted.innerCursor
        )
      else {
        throw DeviceCryptoStateError.invalidStreamBinding
      }
      if previousCommitted.generation == candidate.streamGeneration {
        guard previousCommitted.streamRoute == candidate.streamRoute,
          candidate.streamCursor.isAtLeastForKeyLifecycle(
            previousCommitted.outerCursor
          )
        else {
          throw DeviceCryptoStateError.invalidStreamBinding
        }
      }
    }
    guard
      !pendingStreamBindings.contains(where: {
        $0.target != candidate.target
          && ($0.streamRoute == candidate.streamRoute
            || $0.streamGeneration == candidate.streamGeneration)
      }),
      !streamStates.contains(where: {
        $0.bindingTarget != candidate.target
          && ($0.streamRoute == candidate.streamRoute
            || $0.generation == candidate.streamGeneration)
      })
    else {
      throw DeviceCryptoStateError.invalidStreamBinding
    }

    let retired: DeviceDurableStreamBindingV1?
    if let previousPending {
      retired = previousPending
    } else if let previousCommitted {
      retired = try DeviceDurableStreamBindingV1(
        streamRoute: previousCommitted.streamRoute,
        streamGeneration: previousCommitted.generation,
        streamCursor: previousCommitted.outerCursor,
        innerCursor: previousCommitted.innerCursor,
        keyDirectoryRevision: activeRevision,
        keyID: candidate.keyID
      )
    } else {
      retired = nil
    }

    var nextBindings = pendingStreamBindings.filter {
      $0.target != candidate.target
    }
    nextBindings.append(candidate)
    nextBindings.sort {
      $0.streamRoute.lexicographicallyPrecedes($1.streamRoute)
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else {
      throw DeviceCryptoStateError.invalidState
    }
    let next = try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streamStates,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: nextBindings,
      keySyncEpisode: keySyncEpisode
    )
    return DeviceStreamBindingInstallTransition(
      state: next,
      installed: candidate,
      retired: retired,
      disposition: .installed
    )
  }

  private func validatedStreamBinding(
    _ binding: DaemonStreamBindingV1
  ) throws -> DeviceDurableStreamBindingV1 {
    let authority = binding.authority
    guard securityState == .active,
      authority.formatVersion == 1,
      authority.runtimeProtocolVersion == runtimeProtocolVersionCurrent,
      authority.relayProtocolVersion == relayProtocolVersionV2,
      authority.machineRoute == trustScope.machineRoute,
      authority.deviceRoute == trustScope.deviceRoute,
      authority.grantSerial == trustScope.grantSerial,
      authority.rootTrustEpoch == trustScope.trustEpoch
    else {
      throw DeviceCryptoStateError.invalidStreamBinding
    }
    let candidate = try DeviceDurableStreamBindingV1(binding)
    let activeRevision = keyLifecycle?.activeRevision ?? keyDirectory.revision
    guard candidate.keyDirectoryRevision == activeRevision,
      Self.bindingKeyIsCurrent(
        candidate,
        directory: keyDirectory,
        lifecycle: keyLifecycle
      )
    else {
      throw DeviceCryptoStateError.invalidStreamBinding
    }
    return candidate
  }

  /// Runtime Subscribed/Snapshot/Backfill/SyncComplete 已由 correlation + Source permit
  /// 提交后，消费最后到达的 authenticated StreamBinding。binding outer 必须等于
  /// SyncComplete outer；SyncComplete inner 可高于 daemon capture H，但不能低于它。
  /// 最终 state 只推进一次 revision，并且不暴露中间 pending binding。
  func committingSubscriptionBootstrap(
    _ binding: DaemonStreamBindingV1,
    synchronizedInnerCursor: DeviceInnerCursorV1
  ) throws -> DeviceStreamBindingInstallTransition {
    let durable = try validatedStreamBinding(binding)
    guard
      durable.target
        == DeviceDurableStreamBindingV1.target(synchronizedInnerCursor),
      Self.innerCursor(
        synchronizedInnerCursor,
        isAtLeast: durable.innerCursor
      )
    else {
      throw DeviceCryptoStateError.invalidStreamBinding
    }
    if let current = streamStates.first(where: {
      $0.bindingTarget == durable.target
    }), current.streamRoute == durable.streamRoute,
      current.generation == durable.streamGeneration,
      pendingStreamBindings.allSatisfy({ $0.target != durable.target })
    {
      let resumed = try advancingSynchronizedStreamProgress(
        streamRoute: durable.streamRoute,
        streamGeneration: durable.streamGeneration,
        outerCursor: durable.streamCursor,
        innerCursor: synchronizedInnerCursor
      )
      return DeviceStreamBindingInstallTransition(
        state: resumed,
        installed: durable,
        retired: nil,
        disposition: resumed == self ? .exactRetry : .installed
      )
    }

    let installed = try installingStreamBinding(binding)
    let promoted = try installed.state.advancingSynchronizedStreamProgress(
      streamRoute: durable.streamRoute,
      streamGeneration: durable.streamGeneration,
      outerCursor: durable.streamCursor,
      innerCursor: synchronizedInnerCursor
    )
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else {
      throw DeviceCryptoStateError.invalidState
    }
    let normalized = try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: promoted.trustScope,
      keyDirectory: promoted.keyDirectory,
      senderCounter: promoted.senderCounter,
      securityState: promoted.securityState,
      replayStates: promoted.replayStates,
      streamStates: promoted.streamStates,
      keyLifecycle: promoted.keyLifecycle,
      pendingStreamBindings: promoted.pendingStreamBindings,
      keySyncEpisode: promoted.keySyncEpisode
    )
    return DeviceStreamBindingInstallTransition(
      state: normalized,
      installed: installed.installed,
      retired: installed.retired,
      disposition: .installed
    )
  }

  /// source 已在 scratch reducer 验证完成后，由 ingress delivery permit 提交的唯一
  /// live Publish cursor successor。outer 与 inner 必须同时 exact-next，避免合法 replay
  /// tuple 被借来跳过 reducer/cursor cut。
  func advancingPublishedStreamProgress(
    streamRoute: Data,
    streamGeneration: Data,
    streamSequence: UInt64,
    innerCursor: DeviceInnerCursorV1
  ) throws -> Self {
    guard securityState == .active,
      let index = streamStates.firstIndex(where: { $0.streamRoute == streamRoute }),
      streamStates[index].generation == streamGeneration,
      streamStates[index].outerCursor.checkedNextForKeyLifecycle == streamSequence,
      Self.innerCursor(innerCursor, exactlyFollows: streamStates[index].innerCursor)
    else {
      throw DeviceCryptoStateError.invalidCursor
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    var nextStreams = streamStates
    nextStreams[index] = try DeviceStreamCursorStateV1(
      streamRoute: streamRoute,
      generation: streamGeneration,
      outerCursor: .at(streamSequence),
      innerCursor: innerCursor
    )
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: nextStreams,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  /// Subscription SyncComplete 可以经定向 backfill 先把 source inner 推进到 publication
  /// binding 之后。随后重放的 Relay overlap 只允许 outer exact-next；incoming inner
  /// 必须已经被 durable synchronized inner 覆盖，最终状态保留较新的 inner floor。
  func advancingPublishedOverlapProgress(
    streamRoute: Data,
    streamGeneration: Data,
    firstStreamSequence: UInt64,
    lastStreamSequence: UInt64,
    coveredInnerCursor: DeviceInnerCursorV1
  ) throws -> Self {
    guard securityState == .active,
      firstStreamSequence <= lastStreamSequence,
      let index = streamStates.firstIndex(where: { $0.streamRoute == streamRoute }),
      streamStates[index].generation == streamGeneration,
      streamStates[index].outerCursor.checkedNextForKeyLifecycle == firstStreamSequence,
      Self.innerCursor(
        streamStates[index].innerCursor,
        isAtLeast: coveredInnerCursor
      )
    else {
      throw DeviceCryptoStateError.invalidCursor
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    var nextStreams = streamStates
    nextStreams[index] = try DeviceStreamCursorStateV1(
      streamRoute: streamRoute,
      generation: streamGeneration,
      outerCursor: .at(lastStreamSequence),
      innerCursor: streamStates[index].innerCursor
    )
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: nextStreams,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  /// compact stream transfer 的 parts 逐帧通过 replay admission，但只有完整 hash 与
  /// Runtime decode/reducer 都成功后才一次提交 cursor。outer range 必须从当前 cut
  /// exact-next 开始且非空连续；inner logical item 仍只能 exact-next。
  func advancingPublishedTransferProgress(
    streamRoute: Data,
    streamGeneration: Data,
    firstStreamSequence: UInt64,
    lastStreamSequence: UInt64,
    innerCursor: DeviceInnerCursorV1
  ) throws -> Self {
    guard securityState == .active,
      firstStreamSequence <= lastStreamSequence,
      let index = streamStates.firstIndex(where: { $0.streamRoute == streamRoute }),
      streamStates[index].generation == streamGeneration,
      streamStates[index].outerCursor.checkedNextForKeyLifecycle == firstStreamSequence,
      Self.innerCursor(innerCursor, exactlyFollows: streamStates[index].innerCursor)
    else {
      throw DeviceCryptoStateError.invalidCursor
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    var nextStreams = streamStates
    nextStreams[index] = try DeviceStreamCursorStateV1(
      streamRoute: streamRoute,
      generation: streamGeneration,
      outerCursor: .at(lastStreamSequence),
      innerCursor: innerCursor
    )
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: nextStreams,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  /// Snapshot/Backfill 已在 Source scratch reducer 完整验证后，由最终 SyncComplete
  /// delivery permit 提交的 durable cut。bootstrap 可以跨过已验证区间，但不能切换
  /// route/generation、回退 outer/inner cursor，或借零进展 receipt 制造 state revision。
  func advancingSynchronizedStreamProgress(
    streamRoute: Data,
    streamGeneration: Data,
    outerCursor: StreamCursor,
    innerCursor: DeviceInnerCursorV1
  ) throws -> Self {
    guard securityState == .active else {
      throw DeviceCryptoStateError.invalidCursor
    }

    var nextStreams = streamStates
    var nextPending = pendingStreamBindings
    if let pendingIndex = pendingStreamBindings.firstIndex(where: {
      $0.streamRoute == streamRoute && $0.streamGeneration == streamGeneration
    }) {
      let pending = pendingStreamBindings[pendingIndex]
      guard pending.target == DeviceDurableStreamBindingV1.target(innerCursor),
        outerCursor == pending.streamCursor,
        Self.innerCursor(innerCursor, isAtLeast: pending.innerCursor)
      else {
        throw DeviceCryptoStateError.invalidCursor
      }
      if let oldIndex = streamStates.firstIndex(where: {
        $0.bindingTarget == pending.target
      }) {
        guard
          Self.innerCursor(
            innerCursor,
            isAtLeast: streamStates[oldIndex].innerCursor
          )
        else {
          throw DeviceCryptoStateError.invalidCursor
        }
        if streamStates[oldIndex].generation == streamGeneration {
          guard
            outerCursor.isAtLeastForKeyLifecycle(
              streamStates[oldIndex].outerCursor
            )
          else {
            throw DeviceCryptoStateError.invalidCursor
          }
        }
        nextStreams.remove(at: oldIndex)
      }
      nextStreams.append(
        try DeviceStreamCursorStateV1(
          streamRoute: streamRoute,
          generation: streamGeneration,
          outerCursor: outerCursor,
          innerCursor: innerCursor
        ))
      nextStreams.sort { $0.streamRoute.lexicographicallyPrecedes($1.streamRoute) }
      nextPending.remove(at: pendingIndex)
    } else {
      guard let index = streamStates.firstIndex(where: { $0.streamRoute == streamRoute }),
        streamStates[index].generation == streamGeneration,
        outerCursor.isAtLeastForKeyLifecycle(streamStates[index].outerCursor),
        Self.innerCursor(innerCursor, isAtLeast: streamStates[index].innerCursor)
      else {
        throw DeviceCryptoStateError.invalidCursor
      }
      guard
        outerCursor != streamStates[index].outerCursor
          || innerCursor != streamStates[index].innerCursor
      else {
        return self
      }
      nextStreams[index] = try DeviceStreamCursorStateV1(
        streamRoute: streamRoute,
        generation: streamGeneration,
        outerCursor: outerCursor,
        innerCursor: innerCursor
      )
    }
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: nextStreams,
      keyLifecycle: keyLifecycle,
      pendingStreamBindings: nextPending,
      keySyncEpisode: keySyncEpisode
    )
  }

  private static func innerCursor(
    _ candidate: DeviceInnerCursorV1,
    exactlyFollows previous: DeviceInnerCursorV1
  ) -> Bool {
    switch (previous, candidate) {
    case (.catalog(let old), .catalog(let next)):
      return old.checkedNextForKeyLifecycle == next.exactValueForKeyLifecycle
    case (
      .conversation(let oldID, let old),
      .conversation(let nextID, let next)
    ):
      return oldID == nextID
        && old.checkedNextForKeyLifecycle == next.exactValueForKeyLifecycle
    case (.catalog, .conversation), (.conversation, .catalog):
      return false
    }
  }

  private static func innerCursor(
    _ candidate: DeviceInnerCursorV1,
    isAtLeast previous: DeviceInnerCursorV1
  ) -> Bool {
    switch (previous, candidate) {
    case (.catalog(let old), .catalog(let next)):
      return next.isAtLeastForKeyLifecycle(old)
    case (
      .conversation(let oldID, let old),
      .conversation(let nextID, let next)
    ):
      return oldID == nextID && next.isAtLeastForKeyLifecycle(old)
    case (.catalog, .conversation), (.conversation, .catalog):
      return false
    }
  }

  private static func bindingKeyIsCurrent(
    _ binding: DeviceDurableStreamBindingV1,
    directory: DeviceKeyDirectoryV1,
    lifecycle: DeviceKeyLifecycleStateV1?
  ) -> Bool {
    let slotRoute: Data? =
      binding.keyID.purpose == .conversationDEK ? binding.streamRoute : nil
    if let lifecycle {
      guard
        let current = lifecycle.slot(
          purpose: binding.keyID.purpose,
          streamRoute: slotRoute
        )?.current
      else {
        return false
      }
      return current.keyID == binding.keyID
        && current.keyDirectoryRevision == binding.keyDirectoryRevision
    }
    let candidates = directory.entries.filter {
      $0.keyID.purpose == binding.keyID.purpose
        && $0.streamRoute == slotRoute
    }
    guard let maximum = candidates.map(\.keyID.epoch).max() else {
      return false
    }
    return binding.keyDirectoryRevision == directory.revision
      && binding.keyID.epoch == maximum
      && candidates.contains(where: { $0.keyID == binding.keyID })
  }

  /// 将 exact committed stream cut 上的 barrier 只应用到它声明的 shared slot。
  ///
  /// 其他 slot 的 staged carrier 保持不变；只有最后一个 required barrier 完成后，
  /// same-identity aliases 与 sender directory revision 才一起切换。
  func applyingEpochBarrier(
    _ barrier: DeviceEpochBarrierV1,
    activatedAtMS: UInt64
  ) throws -> Self {
    guard securityState == .active,
      activatedAtMS > 0,
      let lifecycle = keyLifecycle
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    let slotID: DeviceKeySlotIDV1
    switch barrier.innerCursor {
    case .catalog:
      slotID = try DeviceKeySlotIDV1(purpose: .catalog, streamRoute: nil)
    case .conversation:
      slotID = try DeviceKeySlotIDV1(
        purpose: .conversationDEK,
        streamRoute: barrier.streamRoute
      )
    }
    guard
      let streamIndex = streamStates.firstIndex(where: {
        $0.streamRoute == barrier.streamRoute
      }),
      streamStates[streamIndex].generation == barrier.streamGeneration,
      let slotIndex = lifecycle.slots.firstIndex(where: { $0.id == slotID })
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }

    let oldSlot = lifecycle.slots[slotIndex]
    if oldSlot.current?.keyID.epoch == barrier.newEpoch,
      oldSlot.current?.activationProof == barrier,
      streamStates[streamIndex].outerCursor == .at(barrier.appliedStreamSequence)
    {
      return self
    }
    guard streamStates[streamIndex].outerCursor == barrier.streamCursor,
      streamStates[streamIndex].innerCursor == barrier.innerCursor
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    guard let transition = lifecycle.stagedTransition,
      transition.toRevision == barrier.keyDirectoryRevision,
      let oldCurrent = oldSlot.current,
      let staged = oldSlot.staged,
      oldCurrent.keyID.epoch == barrier.oldEpoch,
      staged.keyID.epoch == barrier.newEpoch,
      staged.keyDirectoryRevision == transition.toRevision
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }

    let retentionEnd = activatedAtMS.addingReportingOverflow(
      ReplayWindow.retiredWindowRetentionMilliseconds
    )
    guard !retentionEnd.overflow else { throw DeviceCryptoStateError.invalidClock }
    let oldScope = DeviceCryptoKeyScopeV1(
      keyID: oldCurrent.keyID,
      streamRoute: oldCurrent.streamRoute
    )
    let newScope = DeviceCryptoKeyScopeV1(
      keyID: staged.keyID,
      streamRoute: staged.streamRoute
    )
    guard let oldReplayIndex = replayStates.firstIndex(where: { $0.scope == oldScope }),
      let newReplayIndex = replayStates.firstIndex(where: { $0.scope == newScope }),
      oldReplayIndex != newReplayIndex,
      replayStates[oldReplayIndex].status == .active,
      replayStates[newReplayIndex].status == .active
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }

    var nextReplayStates = replayStates
    let oldReplay = nextReplayStates[oldReplayIndex]
    nextReplayStates[oldReplayIndex] = try DeviceReplayStateV1(
      scope: oldReplay.scope,
      window: oldReplay.window,
      status: .retired(
        retiredAtMS: activatedAtMS,
        deleteAfterMS: retentionEnd.partialValue
      )
    )
    guard nextReplayStates.count <= Self.maximumReplayStates else {
      throw DeviceKeyLifecycleError.capacity
    }

    var nextSlots = lifecycle.slots
    let retired = try DeviceRetiredKeyCarrierV1(
      carrier: oldCurrent,
      retiredAtMS: activatedAtMS,
      deleteAfterMS: retentionEnd.partialValue
    )
    nextSlots[slotIndex] = try DeviceKeySlotStateV1(
      id: oldSlot.id,
      current: staged.withActivationProof(barrier),
      staged: nil,
      retired: oldSlot.retired + [retired]
    )

    var nextStreams = streamStates
    nextStreams[streamIndex] = try DeviceStreamCursorStateV1(
      streamRoute: barrier.streamRoute,
      generation: barrier.streamGeneration,
      outerCursor: .at(barrier.appliedStreamSequence),
      innerCursor: barrier.innerCursor
    )

    let hasUnresolvedSemanticStage = nextSlots.contains(where: { slot in
      guard let staged = slot.staged else { return false }
      guard let current = slot.current else { return true }
      return staged.keyID != current.keyID
        || staged.secretFingerprint != current.secretFingerprint
    })
    let nextLifecycle: DeviceKeyLifecycleStateV1
    let nextSender: DeviceSenderCounterV1
    if hasUnresolvedSemanticStage {
      nextLifecycle = try DeviceKeyLifecycleStateV1(
        activeRevision: lifecycle.activeRevision,
        activeUpdateSet: lifecycle.activeUpdateSet,
        stagedTransition: transition,
        slots: nextSlots,
        retiredSecretFingerprints: lifecycle.retiredSecretFingerprints
      )
      nextSender = senderCounter
    } else {
      for index in nextSlots.indices {
        guard let staged = nextSlots[index].staged else { continue }
        guard let current = nextSlots[index].current,
          staged.keyID == current.keyID,
          staged.secretFingerprint == current.secretFingerprint
        else {
          throw DeviceKeyLifecycleError.invalidState
        }
        nextSlots[index] = try DeviceKeySlotStateV1(
          id: nextSlots[index].id,
          current: staged,
          staged: nil,
          retired: nextSlots[index].retired
        )
      }
      nextLifecycle = try DeviceKeyLifecycleStateV1(
        activeRevision: transition.toRevision,
        activeUpdateSet: transition.canonicalUpdateSet,
        stagedTransition: nil,
        slots: nextSlots,
        retiredSecretFingerprints: lifecycle.retiredSecretFingerprints
      )
      nextSender = try DeviceSenderCounterV1(
        keyID: senderCounter.keyID,
        keyDirectoryRevision: transition.toRevision,
        noncePrefix: senderCounter.noncePrefix,
        reservedHighWater: senderCounter.reservedHighWater,
        reservationID: senderCounter.reservationID
      )
    }

    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: nextSender,
      securityState: securityState,
      replayStates: nextReplayStates,
      streamStates: nextStreams,
      keyLifecycle: nextLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: nextSender.keyDirectoryRevision == senderCounter.keyDirectoryRevision
        ? keySyncEpisode : nil
    )
  }

  /// 首个 remote member 收到的 `0 -> 1` barrier 不旋转本地已由 PairResponse
  /// bootstrap 的 epoch-1 material；它只把 exact committed stream cut 与 durable
  /// `StreamAppliedAck` basis 绑定到该 carrier。`oldEpoch == 0` 是“此前没有 shared
  /// sender”的 sentinel，不能伪造 retired predecessor 或 replay scope。该迁移严格
  /// 单向；已提交 proof 的 exact duplicate 必须走 ACK recovery，fresh 重封不得再进入。
  func applyingBootstrapEpochBarrier(
    _ barrier: DeviceEpochBarrierV1
  ) throws -> Self {
    guard securityState == .active,
      barrier.oldEpoch == 0,
      barrier.newEpoch == 1,
      let lifecycle = keyLifecycle,
      lifecycle.stagedTransition == nil,
      lifecycle.activeRevision == barrier.keyDirectoryRevision,
      senderCounter.keyDirectoryRevision == barrier.keyDirectoryRevision
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    let slotID: DeviceKeySlotIDV1
    switch barrier.innerCursor {
    case .catalog:
      slotID = try DeviceKeySlotIDV1(purpose: .catalog, streamRoute: nil)
    case .conversation:
      slotID = try DeviceKeySlotIDV1(
        purpose: .conversationDEK,
        streamRoute: barrier.streamRoute
      )
    }
    guard
      let streamIndex = streamStates.firstIndex(where: {
        $0.streamRoute == barrier.streamRoute
      }),
      streamStates[streamIndex].generation == barrier.streamGeneration,
      let slotIndex = lifecycle.slots.firstIndex(where: { $0.id == slotID })
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }

    let slot = lifecycle.slots[slotIndex]
    guard streamStates[streamIndex].outerCursor == barrier.streamCursor,
      streamStates[streamIndex].innerCursor == barrier.innerCursor,
      let current = slot.current,
      current.source == .bootstrapDirectory,
      current.activationProof == nil,
      current.keyID.epoch == 1,
      current.keyDirectoryRevision == barrier.keyDirectoryRevision,
      slot.staged == nil,
      slot.retired.isEmpty
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    let currentScope = DeviceCryptoKeyScopeV1(
      keyID: current.keyID,
      streamRoute: current.streamRoute
    )
    guard
      replayStates.contains(where: {
        $0.scope == currentScope && $0.status == .active
      })
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }

    var nextSlots = lifecycle.slots
    nextSlots[slotIndex] = try DeviceKeySlotStateV1(
      id: slot.id,
      current: current.withActivationProof(barrier),
      staged: nil,
      retired: []
    )
    var nextStreams = streamStates
    nextStreams[streamIndex] = try DeviceStreamCursorStateV1(
      streamRoute: barrier.streamRoute,
      generation: barrier.streamGeneration,
      outerCursor: .at(barrier.appliedStreamSequence),
      innerCursor: barrier.innerCursor
    )
    let nextLifecycle = try DeviceKeyLifecycleStateV1(
      activeRevision: lifecycle.activeRevision,
      activeUpdateSet: lifecycle.activeUpdateSet,
      stagedTransition: nil,
      lastDirectoryAdvanceProof: lifecycle.lastDirectoryAdvanceProof,
      slots: nextSlots,
      retiredSecretFingerprints: lifecycle.retiredSecretFingerprints
    )
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: nextStreams,
      keyLifecycle: nextLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  /// ActivateConversation 没有 EpochBarrier cuts；它在 current Catalog key 下发布 exact
  /// DirectoryRevisionAdvance。只有该 proof 与 durable catalog cut 对齐时才激活 epoch-1 新 slot。
  func applyingDirectoryRevisionAdvance(
    _ advance: DeviceDirectoryRevisionAdvanceV1
  ) throws -> Self {
    guard securityState == .active,
      let lifecycle = keyLifecycle,
      let transition = lifecycle.stagedTransition,
      transition.fromRevision == advance.fromRevision,
      transition.toRevision == advance.toRevision,
      let streamIndex = streamStates.firstIndex(where: {
        $0.streamRoute == advance.streamRoute
      }),
      streamStates[streamIndex].generation == advance.streamGeneration,
      advance.streamSequence == streamStates[streamIndex].outerCursor.checkedNextForKeyLifecycle,
      lifecycle.slot(purpose: .catalog, streamRoute: nil)?.current?.keyID.purpose == .catalog
    else {
      throw DeviceKeyLifecycleError.invalidDirectoryAdvance
    }

    var nextSlots = lifecycle.slots
    let nextReplayStates = replayStates
    var activatedNewConversation = false
    for index in nextSlots.indices {
      guard let staged = nextSlots[index].staged else { continue }
      if let current = nextSlots[index].current {
        guard staged.keyID == current.keyID,
          staged.secretFingerprint == current.secretFingerprint
        else {
          throw DeviceKeyLifecycleError.invalidDirectoryAdvance
        }
      } else {
        guard nextSlots[index].id.purpose == .conversationDEK,
          staged.keyID.epoch == 1
        else {
          throw DeviceKeyLifecycleError.invalidDirectoryAdvance
        }
        let scope = DeviceCryptoKeyScopeV1(
          keyID: staged.keyID,
          streamRoute: staged.streamRoute
        )
        guard let stagedReplay = nextReplayStates.first(where: { $0.scope == scope }),
          stagedReplay.status == .active,
          stagedReplay.window.highWater == nil,
          stagedReplay.window.floor == 0,
          stagedReplay.window.entries.isEmpty
        else {
          throw DeviceKeyLifecycleError.invalidDirectoryAdvance
        }
        activatedNewConversation = true
      }
      nextSlots[index] = try DeviceKeySlotStateV1(
        id: nextSlots[index].id,
        current: staged,
        staged: nil,
        retired: nextSlots[index].retired
      )
    }
    guard activatedNewConversation,
      nextReplayStates.count <= Self.maximumReplayStates
    else {
      throw DeviceKeyLifecycleError.invalidDirectoryAdvance
    }

    var nextStreams = streamStates
    nextStreams[streamIndex] = try DeviceStreamCursorStateV1(
      streamRoute: nextStreams[streamIndex].streamRoute,
      generation: nextStreams[streamIndex].generation,
      outerCursor: .at(advance.streamSequence),
      innerCursor: nextStreams[streamIndex].innerCursor
    )
    let nextLifecycle = try DeviceKeyLifecycleStateV1(
      activeRevision: transition.toRevision,
      activeUpdateSet: transition.canonicalUpdateSet,
      stagedTransition: nil,
      lastDirectoryAdvanceProof: advance,
      slots: nextSlots,
      retiredSecretFingerprints: lifecycle.retiredSecretFingerprints
    )
    let nextSender = try DeviceSenderCounterV1(
      keyID: senderCounter.keyID,
      keyDirectoryRevision: transition.toRevision,
      noncePrefix: senderCounter.noncePrefix,
      reservedHighWater: senderCounter.reservedHighWater,
      reservationID: senderCounter.reservationID
    )
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: nextSender,
      securityState: securityState,
      replayStates: nextReplayStates,
      streamStates: nextStreams,
      keyLifecycle: nextLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: nil
    )
  }

  /// 从 durable lifecycle 交叉审计可安全重发的 ACK basis。proof 是 activation CAS 的
  /// 一部分，因此正常 StreamBinding replacement 后不要求旧 physical binding 继续 live；
  /// 但 owning slot、revision phase、epoch predecessor、replay retirement 与 logical inner
  /// target 必须仍能逐项对账。
  func auditingKeyLifecycleAcknowledgementBasis() throws
    -> DeviceKeyLifecycleAcknowledgementBasisV1
  {
    guard let lifecycle = keyLifecycle else {
      return DeviceKeyLifecycleAcknowledgementBasisV1(
        epochBarriers: [],
        directoryAdvance: nil
      )
    }

    var seenProofs = Set<Data>()
    var barriers: [DeviceEpochBarrierV1] = []
    for slot in lifecycle.slots {
      guard let current = slot.current, let proof = current.activationProof else { continue }
      let proofSlot: DeviceKeySlotIDV1
      switch proof.innerCursor {
      case .catalog:
        proofSlot = try DeviceKeySlotIDV1(purpose: .catalog, streamRoute: nil)
      case .conversation:
        proofSlot = try DeviceKeySlotIDV1(
          purpose: .conversationDEK,
          streamRoute: proof.streamRoute
        )
      }
      let revisionPhaseMatches: Bool
      if let transition = lifecycle.stagedTransition {
        revisionPhaseMatches =
          transition.fromRevision == lifecycle.activeRevision
          && transition.toRevision == proof.keyDirectoryRevision
      } else {
        revisionPhaseMatches = lifecycle.activeRevision == proof.keyDirectoryRevision
      }
      let predecessors = slot.retired.filter {
        $0.carrier.keyID.purpose == current.keyID.purpose
          && $0.carrier.keyID.epoch == proof.oldEpoch
          && $0.carrier.streamRoute == current.streamRoute
      }
      let currentScope = DeviceCryptoKeyScopeV1(
        keyID: current.keyID,
        streamRoute: current.streamRoute
      )
      let predecessorMatches: Bool
      if proof.oldEpoch == 0 {
        predecessorMatches =
          current.source == .bootstrapDirectory
          && current.keyID.epoch == 1
          && predecessors.isEmpty
          && slot.retired.isEmpty
      } else {
        predecessorMatches = predecessors.count == 1
      }
      guard seenProofs.insert(proof.canonicalSHA256).inserted,
        slot.id == proofSlot,
        slot.staged == nil,
        current.keyDirectoryRevision == proof.keyDirectoryRevision,
        current.keyID.epoch == proof.newEpoch,
        revisionPhaseMatches,
        predecessorMatches,
        replayStates.contains(where: {
          $0.scope == currentScope && $0.status == .active
        })
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
      if let predecessor = predecessors.first {
        let predecessorScope = DeviceCryptoKeyScopeV1(
          keyID: predecessor.carrier.keyID,
          streamRoute: predecessor.carrier.streamRoute
        )
        guard
          replayStates.contains(where: { replay in
            guard replay.scope == predecessorScope else { return false }
            guard case .retired(_, let deleteAfterMS) = replay.status else { return false }
            return deleteAfterMS == predecessor.deleteAfterMS
          })
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
      }
      guard try streamStateCoversActivationProof(proof) else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
      barriers.append(proof)
    }

    if let advance = lifecycle.lastDirectoryAdvanceProof {
      guard lifecycle.stagedTransition == nil,
        lifecycle.activeRevision == advance.toRevision,
        let catalog = lifecycle.slot(purpose: .catalog, streamRoute: nil)?.current,
        catalog.keyID.purpose == .catalog,
        catalog.keyDirectoryRevision == advance.toRevision,
        replayStates.contains(where: {
          $0.scope
            == DeviceCryptoKeyScopeV1(keyID: catalog.keyID, streamRoute: catalog.streamRoute)
            && $0.status == .active
        }),
        try streamStateCoversDirectoryAdvance(advance)
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    }

    barriers.sort {
      if $0.streamRoute != $1.streamRoute {
        return $0.streamRoute.lexicographicallyPrecedes($1.streamRoute)
      }
      return $0.streamGeneration.lexicographicallyPrecedes($1.streamGeneration)
    }
    return DeviceKeyLifecycleAcknowledgementBasisV1(
      epochBarriers: barriers,
      directoryAdvance: lifecycle.lastDirectoryAdvanceProof
    )
  }

  private func streamStateCoversActivationProof(
    _ proof: DeviceEpochBarrierV1
  ) throws -> Bool {
    let matchingTarget = streamStates.filter {
      Self.innerCursor($0.innerCursor, covers: proof.innerCursor)
    }
    guard matchingTarget.count == 1, let stream = matchingTarget.first else { return false }
    if stream.streamRoute == proof.streamRoute,
      stream.generation == proof.streamGeneration
    {
      return stream.outerCursor.isAtLeastForKeyLifecycle(
        .at(proof.appliedStreamSequence)
      )
    }
    return true
  }

  private func streamStateCoversDirectoryAdvance(
    _ advance: DeviceDirectoryRevisionAdvanceV1
  ) throws -> Bool {
    let catalogs = streamStates.filter {
      if case .catalog = $0.innerCursor { return true }
      return false
    }
    guard catalogs.count == 1, let stream = catalogs.first else { return false }
    if stream.streamRoute == advance.streamRoute,
      stream.generation == advance.streamGeneration
    {
      return stream.outerCursor.isAtLeastForKeyLifecycle(.at(advance.streamSequence))
    }
    return true
  }

  private static func innerCursor(
    _ candidate: DeviceInnerCursorV1,
    covers proof: DeviceInnerCursorV1
  ) -> Bool {
    switch (candidate, proof) {
    case (.catalog(let candidate), .catalog(let proof)):
      return candidate.isAtLeastForKeyLifecycle(proof)
    case (
      .conversation(let candidateID, let candidate),
      .conversation(let proofID, let proof)
    ):
      return candidateID == proofID && candidate.isAtLeastForKeyLifecycle(proof)
    case (.catalog, .conversation), (.conversation, .catalog):
      return false
    }
  }

  /// 到期 GC 原子删除 retired carrier 与对应 replay window，并永久保留 secret fingerprint
  /// tombstone。到达 tombstone cap 时 fail-retain，不驱逐未过期或历史 anti-reuse 证据。
  func garbageCollectingRetiredKeys(nowMS: UInt64) throws -> Self {
    guard nowMS > 0, let lifecycle = keyLifecycle else {
      throw DeviceCryptoStateError.invalidClock
    }
    var nextSlots = lifecycle.slots
    var nextReplayStates = replayStates
    var tombstones = lifecycle.retiredSecretFingerprints
    var changed = false
    for slotIndex in nextSlots.indices {
      let slot = nextSlots[slotIndex]
      let expired = slot.retired.filter { nowMS >= $0.deleteAfterMS }
      guard !expired.isEmpty else { continue }
      changed = true
      for retired in expired {
        let scope = DeviceCryptoKeyScopeV1(
          keyID: retired.carrier.keyID,
          streamRoute: retired.carrier.streamRoute
        )
        guard let replayIndex = nextReplayStates.firstIndex(where: { $0.scope == scope }),
          case .retired(_, let deleteAfterMS) = nextReplayStates[replayIndex].status,
          deleteAfterMS == retired.deleteAfterMS
        else {
          throw DeviceKeyLifecycleError.invalidState
        }
        nextReplayStates.remove(at: replayIndex)
        tombstones.append(retired.carrier.secretFingerprint)
      }
      nextSlots[slotIndex] = try DeviceKeySlotStateV1(
        id: slot.id,
        current: slot.current,
        staged: slot.staged,
        retired: slot.retired.filter { nowMS < $0.deleteAfterMS }
      )
    }
    guard changed else { return self }
    tombstones.sort { $0.lexicographicallyPrecedes($1) }
    guard tombstones.count <= DeviceKeyLifecycleStateV1.maximumRetiredSecretFingerprints else {
      throw DeviceKeyLifecycleError.capacity
    }
    let nextLifecycle = try DeviceKeyLifecycleStateV1(
      activeRevision: lifecycle.activeRevision,
      activeUpdateSet: lifecycle.activeUpdateSet,
      stagedTransition: lifecycle.stagedTransition,
      lastDirectoryAdvanceProof: lifecycle.lastDirectoryAdvanceProof,
      slots: nextSlots,
      retiredSecretFingerprints: tombstones
    )
    let nextRevision = stateRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try Self(
      stateRevision: nextRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: keyDirectory,
      senderCounter: senderCounter,
      securityState: securityState,
      replayStates: nextReplayStates,
      streamStates: streamStates,
      keyLifecycle: nextLifecycle,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  /// 构造 legacy full-directory repository seam 的唯一 canonical successor。
  ///
  /// Production live key sync 不调用本方法；它必须逐项 stage signed `KeyUpdateSetV1`，并在
  /// exact `EpochBarrierV1` 后激活 shared next epoch。
  /// - 同一 sender key 必须完整保留 key ID / nonce prefix / high-water / reservation ID；
  /// - directed command/reply epoch 必须原样保留；legacy seam 拒绝轮换；
  /// - 保留的 receive scope 必须逐字保留 replay tuple/window；
  /// - 被移除的 receive scope 转成 25 小时 retired tombstone；新 scope 从空 window 开始。
  func advancingKeyDirectory(
    to nextDirectory: DeviceKeyDirectoryV1,
    senderCounter nextSender: DeviceSenderCounterV1,
    retiredAtMS: UInt64
  ) throws -> Self {
    guard securityState == .active, keyLifecycle == nil, keySyncEpisode == nil else {
      throw DeviceCryptoStateError.invalidKeyTransition
    }
    guard retiredAtMS > 0 else { throw DeviceCryptoStateError.invalidClock }
    let nextStateRevision = stateRevision.addingReportingOverflow(1)
    let nextDirectoryRevision = keyDirectory.revision.addingReportingOverflow(1)
    guard !nextStateRevision.overflow, !nextDirectoryRevision.overflow else {
      throw DeviceCryptoStateError.invalidState
    }
    guard nextDirectory.revision == nextDirectoryRevision.partialValue,
      nextSender.keyDirectoryRevision == nextDirectory.revision,
      keyEpochsAdvance(previous: keyDirectory, next: nextDirectory),
      senderAdvancesSafely(previous: senderCounter, next: nextSender)
    else {
      throw DeviceCryptoStateError.invalidKeyTransition
    }

    let retentionEnd = retiredAtMS.addingReportingOverflow(
      ReplayWindow.retiredWindowRetentionMilliseconds
    )
    guard !retentionEnd.overflow else { throw DeviceCryptoStateError.invalidClock }

    let nextActiveReceiveScopes = activeReceiveScopes(in: nextDirectory)
    guard replayLineageAdvances(to: nextActiveReceiveScopes) else {
      throw DeviceCryptoStateError.invalidKeyTransition
    }
    let nextActiveReceiveScopeSet = Set(nextActiveReceiveScopes)
    var nextReplayStates: [DeviceReplayStateV1] = []
    nextReplayStates.reserveCapacity(replayStates.count + nextActiveReceiveScopes.count)

    for replay in replayStates {
      if nextActiveReceiveScopeSet.contains(replay.scope) {
        switch replay.status {
        case .active, .quarantined:
          nextReplayStates.append(replay)
          continue
        case .retired:
          throw DeviceCryptoStateError.invalidKeyTransition
        }
      }
      switch replay.status {
      case .retired:
        nextReplayStates.append(replay)
      case .active, .quarantined:
        nextReplayStates.append(
          try DeviceReplayStateV1(
            scope: replay.scope,
            window: replay.window,
            status: .retired(
              retiredAtMS: retiredAtMS,
              deleteAfterMS: retentionEnd.partialValue
            )
          ))
      }
    }

    let previousScopes = Set(replayStates.map(\.scope))
    for scope in nextActiveReceiveScopes where !previousScopes.contains(scope) {
      nextReplayStates.append(
        try DeviceReplayStateV1(
          scope: scope,
          window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
          status: .active
        ))
    }

    guard nextReplayStates.count <= Self.maximumReplayStates else {
      throw DeviceCryptoStateError.inputTooLarge
    }
    return try Self(
      stateRevision: nextStateRevision.partialValue,
      trustScope: trustScope,
      keyDirectory: nextDirectory,
      senderCounter: nextSender,
      securityState: securityState,
      replayStates: nextReplayStates,
      streamStates: streamStates,
      keyLifecycle: nil,
      pendingStreamBindings: pendingStreamBindings,
      keySyncEpisode: nil
    )
  }

  private func senderAdvancesSafely(
    previous: DeviceSenderCounterV1,
    next: DeviceSenderCounterV1
  ) -> Bool {
    next.keyID == previous.keyID
      && next.noncePrefix == previous.noncePrefix
      && next.reservedHighWater == previous.reservedHighWater
      && next.reservationID == previous.reservationID
  }

  private func keyEpochsAdvance(
    previous: DeviceKeyDirectoryV1,
    next: DeviceKeyDirectoryV1
  ) -> Bool {
    var previousSlots: [DeviceKeyDirectorySlot] = []
    for entry in previous.entries {
      let slot = DeviceKeyDirectorySlot(entry)
      if !previousSlots.contains(slot) { previousSlots.append(slot) }
    }
    var nextSlots: [DeviceKeyDirectorySlot] = []
    for entry in next.entries {
      let slot = DeviceKeyDirectorySlot(entry)
      if !nextSlots.contains(slot) { nextSlots.append(slot) }
    }
    guard previousSlots.allSatisfy(nextSlots.contains) else { return false }
    let addedSlots = nextSlots.filter { !previousSlots.contains($0) }
    guard addedSlots.count <= 1 else { return false }
    if let added = addedSlots.first {
      let addedEpochs = next.entries
        .filter { DeviceKeyDirectorySlot($0) == added }
        .map(\.keyID.epoch)
      guard added.purpose == .conversationDEK, addedEpochs == [1] else { return false }
    }

    for slot in previousSlots {
      let oldEpochs = previous.entries
        .filter { DeviceKeyDirectorySlot($0) == slot }
        .map(\.keyID.epoch)
      let nextEpochs = next.entries
        .filter { DeviceKeyDirectorySlot($0) == slot }
        .map(\.keyID.epoch)
      switch slot.purpose {
      case .deviceCommandTx, .deviceReplyTx:
        guard nextEpochs == oldEpochs else { return false }
      case .catalog:
        guard oldEpochs.count == 1, nextEpochs.count == 1 else { return false }
        if nextEpochs == oldEpochs { continue }
        let successor = oldEpochs[0].addingReportingOverflow(1)
        guard !successor.overflow, nextEpochs == [successor.partialValue] else { return false }
      case .conversationDEK:
        if nextEpochs == oldEpochs { continue }
        guard let oldMaximum = oldEpochs.last else { return false }
        let successor = oldMaximum.addingReportingOverflow(1)
        guard !successor.overflow,
          nextEpochs == oldEpochs + [successor.partialValue]
        else {
          return false
        }
      }
    }
    return true
  }

  private func activeReceiveScopes(
    in directory: DeviceKeyDirectoryV1
  ) -> [DeviceCryptoKeyScopeV1] {
    directory.entries.compactMap { entry in
      guard entry.keyID.purpose != .deviceCommandTx else { return nil }
      let slot = DeviceKeyDirectorySlot(entry)
      let hasNewerEpoch = directory.entries.contains(where: {
        DeviceKeyDirectorySlot($0) == slot && $0.keyID.epoch > entry.keyID.epoch
      })
      guard !hasNewerEpoch else { return nil }
      return DeviceCryptoKeyScopeV1(keyID: entry.keyID, streamRoute: entry.streamRoute)
    }
  }

  private func replayLineageAdvances(
    to nextActiveScopes: [DeviceCryptoKeyScopeV1]
  ) -> Bool {
    for nextScope in nextActiveScopes {
      let slot = DeviceKeyDirectorySlot(
        purpose: nextScope.keyID.purpose,
        streamRoute: nextScope.streamRoute
      )
      let previousForSlot = replayStates.filter {
        DeviceKeyDirectorySlot(
          purpose: $0.scope.keyID.purpose,
          streamRoute: $0.scope.streamRoute
        ) == slot
      }
      guard let previousMaximum = previousForSlot.map(\.scope.keyID.epoch).max() else {
        continue
      }
      if let exact = previousForSlot.first(where: { $0.scope == nextScope }) {
        guard nextScope.keyID.epoch == previousMaximum else { return false }
        if case .retired = exact.status { return false }
        continue
      }
      let successor = previousMaximum.addingReportingOverflow(1)
      guard !successor.overflow,
        nextScope.keyID.epoch == successor.partialValue
      else {
        return false
      }
    }
    return true
  }
}

private struct DeviceKeyDirectorySlot: Equatable {
  let purpose: KeyPurpose
  let streamRoute: Data?

  init(_ entry: DeviceWrappedKeyV1) {
    purpose = entry.keyID.purpose
    streamRoute = entry.streamRoute
  }

  init(purpose: KeyPurpose, streamRoute: Data?) {
    self.purpose = purpose
    self.streamRoute = streamRoute
  }
}

extension StreamCursor {
  fileprivate var checkedNextForKeyLifecycle: UInt64? {
    switch self {
    case .beforeFirst:
      return 0
    case .at(let value):
      let next = value.addingReportingOverflow(1)
      guard !next.overflow else { return nil }
      return next.partialValue
    }
  }

  fileprivate var exactValueForKeyLifecycle: UInt64? {
    guard case .at(let value) = self else { return nil }
    return value
  }

  fileprivate func isAtLeastForKeyLifecycle(_ previous: Self) -> Bool {
    switch (previous, self) {
    case (.beforeFirst, _):
      return true
    case (.at, .beforeFirst):
      return false
    case (.at(let old), .at(let candidate)):
      return candidate >= old
    }
  }
}

extension RuntimeStreamCursorV1 {
  var deviceStreamCursor: StreamCursor {
    switch self {
    case .beforeFirst: .beforeFirst
    case .at(let value): .at(value)
    }
  }
}

public enum DeviceCryptoStateError: Error, Equatable, Sendable {
  case invalidTrustScope
  case invalidKeyDirectory
  case invalidSenderCounter
  case invalidReplayState
  case invalidCursor
  case invalidStreamBinding
  case invalidState
  case invalidEncoding
  case inputTooLarge
  case invalidClock
  case missingReplayState
  case invalidKeyTransition
  case invalidKeySyncEpisode
  case keySyncEpisodeEnded
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

    if state.keyLifecycle != nil || !state.pendingStreamBindings.isEmpty
      || state.keySyncEpisode != nil
    {
      if let lifecycle = state.keyLifecycle {
        body.u8(1)
        body.zeros(7)
        try encode(lifecycle, into: &body)
      } else {
        body.u8(0)
        body.zeros(7)
      }
    }
    if !state.pendingStreamBindings.isEmpty || state.keySyncEpisode != nil {
      body.u8(state.pendingStreamBindings.isEmpty ? 0 : 1)
      body.zeros(7)
      if !state.pendingStreamBindings.isEmpty {
        try body.count(state.pendingStreamBindings.count)
        for binding in state.pendingStreamBindings {
          body.fixed(binding.streamRoute)
          body.fixed(binding.streamGeneration)
          body.cursor(binding.streamCursor)
          switch binding.innerCursor {
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
          body.u64(binding.keyDirectoryRevision)
          body.u8(binding.keyID.purpose.deviceStateTag)
          body.zeros(7)
          body.u64(binding.keyID.epoch)
        }
      }
    }
    if let episode = state.keySyncEpisode {
      body.u8(1)
      body.zeros(7)
      body.u64(episode.targetRevision)
      body.u8(episode.observedKeyID.purpose.deviceStateTag)
      body.u8(episode.attempt)
      body.u8(episode.exhausted ? 1 : 0)
      body.zeros(5)
      body.u64(episode.observedKeyID.epoch)
      body.optionalFixed(episode.streamRoute, count: 16)
      body.u64(episode.startedAtMS)
      body.u64(episode.expiresAtMS)
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
    var lifecycle: DeviceKeyLifecycleStateV1?
    if decoder.isAtEnd {
      lifecycle = nil
    } else {
      let tag = try decoder.u8()
      guard tag == 0 || tag == 1 else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      try decoder.requireZeros(count: 7)
      lifecycle = tag == 1 ? try decodeLifecycle(from: &decoder) : nil
    }
    var pendingBindings: [DeviceDurableStreamBindingV1] = []
    if !decoder.isAtEnd {
      let tag = try decoder.u8()
      guard tag == 0 || tag == 1 else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      try decoder.requireZeros(count: 7)
      if tag == 1 {
        let count = try decoder.count(maximum: DeviceCryptoStateV1.maximumStreamStates)
        pendingBindings.reserveCapacity(count)
        for _ in 0..<count {
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
          let revision = try decoder.u64()
          let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
          try decoder.requireZeros(count: 7)
          pendingBindings.append(
            try DeviceDurableStreamBindingV1(
              streamRoute: route,
              streamGeneration: generation,
              streamCursor: outer,
              innerCursor: inner,
              keyDirectoryRevision: revision,
              keyID: KeyIDV1(purpose: purpose, epoch: try decoder.u64())
            ))
        }
      }
    }
    var keySyncEpisode: DeviceKeySyncEpisodeV1?
    if decoder.isAtEnd {
      keySyncEpisode = nil
    } else {
      guard try decoder.u8() == 1 else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      try decoder.requireZeros(count: 7)
      let targetRevision = try decoder.u64()
      let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
      let attempt = try decoder.u8()
      let exhaustedTag = try decoder.u8()
      guard exhaustedTag == 0 || exhaustedTag == 1 else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      try decoder.requireZeros(count: 5)
      keySyncEpisode = try DeviceKeySyncEpisodeV1(
        targetRevision: targetRevision,
        observedKeyID: KeyIDV1(purpose: purpose, epoch: try decoder.u64()),
        streamRoute: decoder.optionalFixed(count: 16),
        attempt: attempt,
        startedAtMS: decoder.u64(),
        expiresAtMS: decoder.u64(),
        exhausted: exhaustedTag == 1
      )
    }
    guard decoder.isAtEnd else { throw DeviceCryptoStateError.invalidEncoding }
    return try DeviceCryptoStateV1(
      stateRevision: stateRevision,
      trustScope: trust,
      keyDirectory: directory,
      senderCounter: sender,
      securityState: securityState,
      replayStates: replayStates,
      streamStates: streams,
      keyLifecycle: lifecycle,
      pendingStreamBindings: pendingBindings,
      keySyncEpisode: keySyncEpisode
    )
  }

  private static func encode(
    _ lifecycle: DeviceKeyLifecycleStateV1,
    into encoder: inout DeviceStateEncoder
  ) throws {
    encoder.u64(lifecycle.activeRevision)
    try encodeOptionalBytes(
      lifecycle.activeUpdateSet,
      maximum: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes,
      into: &encoder
    )
    if let transition = lifecycle.stagedTransition {
      encoder.u8(1)
      encoder.zeros(7)
      encoder.u64(transition.fromRevision)
      encoder.u64(transition.toRevision)
      try encoder.bytes(
        transition.canonicalUpdateSet,
        maximum: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes
      )
      encoder.fixed(transition.updateSetSHA256)
    } else {
      encoder.u8(0)
      encoder.zeros(7)
    }
    if let advance = lifecycle.lastDirectoryAdvanceProof {
      encoder.u8(1)
      encoder.zeros(7)
      encode(advance, into: &encoder)
    } else {
      encoder.u8(0)
      encoder.zeros(7)
    }
    try encoder.count(lifecycle.slots.count)
    for slot in lifecycle.slots {
      encoder.u8(slot.id.purpose.deviceStateTag)
      encoder.zeros(7)
      encoder.optionalFixed(slot.id.streamRoute, count: 16)
      try encodeOptionalCarrier(slot.current, into: &encoder)
      try encodeOptionalCarrier(slot.staged, into: &encoder)
      try encoder.count(slot.retired.count)
      for retired in slot.retired {
        try encode(retired.carrier, into: &encoder)
        encoder.u64(retired.retiredAtMS)
        encoder.u64(retired.deleteAfterMS)
      }
    }
    try encoder.count(lifecycle.retiredSecretFingerprints.count)
    for fingerprint in lifecycle.retiredSecretFingerprints {
      encoder.fixed(fingerprint)
    }
  }

  private static func encodeOptionalBytes(
    _ value: Data?,
    maximum: Int,
    into encoder: inout DeviceStateEncoder
  ) throws {
    if let value {
      encoder.u8(1)
      encoder.zeros(7)
      try encoder.bytes(value, maximum: maximum)
    } else {
      encoder.u8(0)
      encoder.zeros(7)
    }
  }

  private static func encodeOptionalCarrier(
    _ carrier: DeviceStoredKeyCarrierV1?,
    into encoder: inout DeviceStateEncoder
  ) throws {
    if let carrier {
      encoder.u8(1)
      encoder.zeros(7)
      try encode(carrier, into: &encoder)
    } else {
      encoder.u8(0)
      encoder.zeros(7)
    }
  }

  private static func encode(
    _ carrier: DeviceStoredKeyCarrierV1,
    into encoder: inout DeviceStateEncoder
  ) throws {
    encoder.u8(carrier.keyID.purpose.deviceStateTag)
    encoder.zeros(7)
    encoder.u64(carrier.keyID.epoch)
    encoder.optionalFixed(carrier.streamRoute, count: 16)
    encoder.u64(carrier.keyDirectoryRevision)
    encoder.fixed(carrier.secretFingerprint)
    switch carrier.source {
    case .bootstrapDirectory:
      encoder.u8(0)
      encoder.zeros(7)
    case .signedUpdate(let canonical):
      encoder.u8(1)
      encoder.zeros(7)
      try encoder.bytes(canonical, maximum: KeyUpdateCanonicalCodec.maximumCanonicalBytes)
    }
    if let proof = carrier.activationProof {
      encoder.u8(1)
      encoder.zeros(7)
      try encode(proof, into: &encoder)
    } else {
      encoder.u8(0)
      encoder.zeros(7)
    }
  }

  private static func encode(
    _ barrier: DeviceEpochBarrierV1,
    into encoder: inout DeviceStateEncoder
  ) throws {
    encoder.fixed(barrier.streamRoute)
    encoder.fixed(barrier.streamGeneration)
    encoder.cursor(barrier.streamCursor)
    switch barrier.innerCursor {
    case .catalog(let cursor):
      encoder.u8(0)
      encoder.zeros(7)
      encoder.cursor(cursor)
    case .conversation(let id, let cursor):
      encoder.u8(1)
      encoder.zeros(7)
      try encoder.bytes(Data(id.utf8), maximum: 1_024)
      encoder.cursor(cursor)
    }
    encoder.u64(barrier.oldEpoch)
    encoder.u64(barrier.newEpoch)
    encoder.u64(barrier.keyDirectoryRevision)
  }

  private static func encode(
    _ advance: DeviceDirectoryRevisionAdvanceV1,
    into encoder: inout DeviceStateEncoder
  ) {
    encoder.fixed(advance.streamRoute)
    encoder.fixed(advance.streamGeneration)
    encoder.u64(advance.streamSequence)
    encoder.u64(advance.fromRevision)
    encoder.u64(advance.toRevision)
  }

  private static func decodeLifecycle(
    from decoder: inout DeviceStateDecoder
  ) throws -> DeviceKeyLifecycleStateV1 {
    let activeRevision = try decoder.u64()
    let activeSet = try decodeOptionalBytes(
      maximum: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes,
      from: &decoder
    )
    let staged: DeviceStagedKeyTransitionV1?
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      staged = nil
    case 1:
      try decoder.requireZeros(count: 7)
      staged = try DeviceStagedKeyTransitionV1(
        fromRevision: decoder.u64(),
        toRevision: decoder.u64(),
        canonicalUpdateSet: decoder.bytes(
          maximum: KeyUpdateSetCanonicalCodec.maximumCanonicalBytes
        ),
        updateSetSHA256: decoder.fixed(count: 32)
      )
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
    let advance: DeviceDirectoryRevisionAdvanceV1?
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      advance = nil
    case 1:
      try decoder.requireZeros(count: 7)
      advance = try decodeDirectoryAdvance(from: &decoder)
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
    let slotCount = try decoder.count(maximum: DeviceKeyDirectoryV1.maximumEntries)
    var slots: [DeviceKeySlotStateV1] = []
    slots.reserveCapacity(slotCount)
    for _ in 0..<slotCount {
      let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
      try decoder.requireZeros(count: 7)
      let id = try DeviceKeySlotIDV1(
        purpose: purpose,
        streamRoute: decoder.optionalFixed(count: 16)
      )
      let current = try decodeOptionalCarrier(from: &decoder)
      let stagedCarrier = try decodeOptionalCarrier(from: &decoder)
      let retiredCount = try decoder.count(
        maximum: DeviceKeySlotStateV1.maximumRetiredCarriers
      )
      var retired: [DeviceRetiredKeyCarrierV1] = []
      retired.reserveCapacity(retiredCount)
      for _ in 0..<retiredCount {
        retired.append(
          try DeviceRetiredKeyCarrierV1(
            carrier: decodeCarrier(from: &decoder),
            retiredAtMS: decoder.u64(),
            deleteAfterMS: decoder.u64()
          ))
      }
      slots.append(
        try DeviceKeySlotStateV1(
          id: id,
          current: current,
          staged: stagedCarrier,
          retired: retired
        ))
    }
    let tombstoneCount = try decoder.count(
      maximum: DeviceKeyLifecycleStateV1.maximumRetiredSecretFingerprints
    )
    var tombstones: [Data] = []
    tombstones.reserveCapacity(tombstoneCount)
    for _ in 0..<tombstoneCount {
      tombstones.append(try decoder.fixed(count: 32))
    }
    return try DeviceKeyLifecycleStateV1(
      activeRevision: activeRevision,
      activeUpdateSet: activeSet,
      stagedTransition: staged,
      lastDirectoryAdvanceProof: advance,
      slots: slots,
      retiredSecretFingerprints: tombstones
    )
  }

  private static func decodeOptionalBytes(
    maximum: Int,
    from decoder: inout DeviceStateDecoder
  ) throws -> Data? {
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      return nil
    case 1:
      try decoder.requireZeros(count: 7)
      return try decoder.bytes(maximum: maximum)
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
  }

  private static func decodeOptionalCarrier(
    from decoder: inout DeviceStateDecoder
  ) throws -> DeviceStoredKeyCarrierV1? {
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      return nil
    case 1:
      try decoder.requireZeros(count: 7)
      return try decodeCarrier(from: &decoder)
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
  }

  private static func decodeCarrier(
    from decoder: inout DeviceStateDecoder
  ) throws -> DeviceStoredKeyCarrierV1 {
    let purpose = try KeyPurpose(deviceStateTag: decoder.u8())
    try decoder.requireZeros(count: 7)
    let keyID = KeyIDV1(purpose: purpose, epoch: try decoder.u64())
    let streamRoute = try decoder.optionalFixed(count: 16)
    let revision = try decoder.u64()
    let fingerprint = try decoder.fixed(count: 32)
    let source: DeviceStoredKeyCarrierSourceV1
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      source = .bootstrapDirectory
    case 1:
      try decoder.requireZeros(count: 7)
      source = .signedUpdate(
        try decoder.bytes(maximum: KeyUpdateCanonicalCodec.maximumCanonicalBytes)
      )
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
    let proof: DeviceEpochBarrierV1?
    switch try decoder.u8() {
    case 0:
      try decoder.requireZeros(count: 7)
      proof = nil
    case 1:
      try decoder.requireZeros(count: 7)
      proof = try decodeBarrier(from: &decoder)
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
    return try DeviceStoredKeyCarrierV1(
      keyID: keyID,
      streamRoute: streamRoute,
      keyDirectoryRevision: revision,
      secretFingerprint: fingerprint,
      source: source,
      activationProof: proof
    )
  }

  private static func decodeBarrier(
    from decoder: inout DeviceStateDecoder
  ) throws -> DeviceEpochBarrierV1 {
    let streamRoute = try decoder.fixed(count: 16)
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
          data: try decoder.bytes(maximum: 1_024),
          encoding: .utf8
        )
      else {
        throw DeviceCryptoStateError.invalidEncoding
      }
      inner = .conversation(id: id, cursor: try decoder.cursor())
    default:
      throw DeviceCryptoStateError.invalidEncoding
    }
    return try DeviceEpochBarrierV1(
      streamRoute: streamRoute,
      streamGeneration: generation,
      streamCursor: outer,
      innerCursor: inner,
      oldEpoch: decoder.u64(),
      newEpoch: decoder.u64(),
      keyDirectoryRevision: decoder.u64()
    )
  }

  private static func decodeDirectoryAdvance(
    from decoder: inout DeviceStateDecoder
  ) throws -> DeviceDirectoryRevisionAdvanceV1 {
    try DeviceDirectoryRevisionAdvanceV1(
      streamRoute: decoder.fixed(count: 16),
      streamGeneration: decoder.fixed(count: 16),
      streamSequence: decoder.u64(),
      fromRevision: decoder.u64(),
      toRevision: decoder.u64()
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
