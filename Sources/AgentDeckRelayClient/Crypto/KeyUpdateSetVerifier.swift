import Foundation

enum KeyUpdateSetVerifierError: Error, Equatable, Sendable {
  case invalidEncoding
  case sizeLimit
  case revisionMismatch
  case openedMetadataMismatch
  case invalidIndex
}

/// Rust `KeyUpdateSetV1` 的严格、canonical Swift mirror。
///
/// 该类型只证明同一 revision/device 下的 bounded carrier 集合、顺序与唯一性；它不知道
/// daemon Store 的 authenticated active-stream roster，因此不能单独证明 update set 完整。
struct CanonicalKeyUpdateSetV1: Equatable, Sendable, CustomDebugStringConvertible {
  static let maximumUpdates = 1_027

  let keyDirectoryRevision: UInt64
  let deviceRoute: Data
  let updates: [CanonicalKeyUpdateV1]

  init(
    keyDirectoryRevision: UInt64,
    deviceRoute: Data,
    updates: [CanonicalKeyUpdateV1]
  ) throws {
    self.keyDirectoryRevision = keyDirectoryRevision
    self.deviceRoute = deviceRoute
    self.updates = updates
    try validate()
  }

  var debugDescription: String {
    "CanonicalKeyUpdateSetV1(revision: \(keyDirectoryRevision), carriers: <redacted>)"
  }

  fileprivate func validate() throws {
    guard keyDirectoryRevision > 0,
      deviceRoute.count == 16,
      deviceRoute.contains(where: { $0 != 0 }),
      !updates.isEmpty,
      updates.count <= Self.maximumUpdates
    else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }

    var previousIdentity: KeyUpdateSetIdentity?
    for update in updates {
      guard update.keyDirectoryRevision == keyDirectoryRevision,
        update.deviceRoute == deviceRoute
      else {
        throw KeyUpdateSetVerifierError.invalidEncoding
      }
      do {
        let canonical = try KeyUpdateCanonicalCodec.encode(update)
        guard canonical.count <= KeyUpdateCanonicalCodec.maximumCanonicalBytes else {
          throw KeyUpdateSetVerifierError.sizeLimit
        }
      } catch KeyDirectoryVerifierError.sizeLimit {
        throw KeyUpdateSetVerifierError.sizeLimit
      } catch {
        throw KeyUpdateSetVerifierError.invalidEncoding
      }

      let identity = KeyUpdateSetIdentity(update)
      guard previousIdentity.map({ $0.isStrictlyBefore(identity) }) ?? true else {
        throw KeyUpdateSetVerifierError.invalidEncoding
      }
      previousIdentity = identity
    }
  }
}

enum KeyUpdateSetCanonicalCodec {
  static let maximumCanonicalBytes = 384 * 1_024

  private static let domain = Data("AgentDeck/KeyUpdateSetV1\0".utf8)

  static func encode(_ value: CanonicalKeyUpdateSetV1) throws -> Data {
    try value.validate()
    var encoder = KeyUpdateSetEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u64(value.keyDirectoryRevision)
    try encoder.bytes(value.deviceRoute, maximum: 16, exact: 16)
    try encoder.u16Count(value.updates.count)
    for update in value.updates {
      let canonical: Data
      do {
        canonical = try KeyUpdateCanonicalCodec.encode(update)
      } catch KeyDirectoryVerifierError.sizeLimit {
        throw KeyUpdateSetVerifierError.sizeLimit
      } catch {
        throw KeyUpdateSetVerifierError.invalidEncoding
      }
      try encoder.bytes(
        canonical,
        maximum: KeyUpdateCanonicalCodec.maximumCanonicalBytes
      )
    }
    return try encoder.finish()
  }

  static func decode(
    _ bytes: Data,
    maximumEncodedBytes: Int = maximumCanonicalBytes
  ) throws -> CanonicalKeyUpdateSetV1 {
    guard maximumEncodedBytes >= 0 else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    guard bytes.count <= maximumCanonicalBytes,
      bytes.count <= maximumEncodedBytes
    else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }

    var decoder = KeyUpdateSetDecoder(bytes)
    try decoder.domain(domain)
    let revision = try decoder.u64()
    let deviceRoute = try decoder.bytes(exact: 16)
    let count = try decoder.u16Count()
    guard count > 0, count <= CanonicalKeyUpdateSetV1.maximumUpdates else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }

    var updates: [CanonicalKeyUpdateV1] = []
    updates.reserveCapacity(count)
    for _ in 0..<count {
      let canonical = try decoder.bytes(
        maximum: KeyUpdateCanonicalCodec.maximumCanonicalBytes
      )
      do {
        updates.append(try KeyUpdateCanonicalCodec.decode(canonical))
      } catch KeyDirectoryVerifierError.sizeLimit {
        throw KeyUpdateSetVerifierError.sizeLimit
      } catch {
        throw KeyUpdateSetVerifierError.invalidEncoding
      }
    }
    try decoder.finish()

    let value = try CanonicalKeyUpdateSetV1(
      keyDirectoryRevision: revision,
      deviceRoute: deviceRoute,
      updates: updates
    )
    guard try encode(value) == bytes else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    return value
  }
}

/// 单个 update 的已验签、已 HPKE-open 封闭能力。
///
/// exact canonical carrier 可持久化和审计；opened material 保持 private，既没有 raw-key
/// getter，也没有单项 install API。后续 staged-state validator 只能通过 typed relation
/// 方法比较两个已经验证的 capability。
struct VerifiedOpenedKeyUpdate: Sendable, CustomDebugStringConvertible {
  let keyID: KeyIDV1
  let streamRoute: Data?
  let canonicalBytes: Data
  fileprivate let material: OpenedKeyMaterialCapabilityV1

  fileprivate init(
    keyID: KeyIDV1,
    streamRoute: Data?,
    canonicalBytes: Data,
    material: OpenedKeyMaterialCapabilityV1
  ) throws {
    guard canonicalBytes.count <= KeyUpdateCanonicalCodec.maximumCanonicalBytes,
      material.keyID == keyID,
      material.streamRoute == streamRoute
    else {
      throw KeyUpdateSetVerifierError.openedMetadataMismatch
    }
    self.keyID = keyID
    self.streamRoute = streamRoute
    self.canonicalBytes = canonicalBytes
    self.material = material
  }

  var debugDescription: String {
    "VerifiedOpenedKeyUpdate(identity: <redacted>, material: <redacted>)"
  }

  fileprivate func matchesSecret(_ other: Self) -> Bool {
    material.matchesSecret(other.material)
  }

  fileprivate var secretFingerprint: Data {
    material.secretFingerprint()
  }
}

/// 完整 set 验证与解封成功后的唯一输出。
///
/// 此能力仍只证明 protocol-level set 同质性，不证明 Store roster 完整，也不推进任何 durable
/// state。所有 update 必须作为一个集合交给后续 staged-state validator，不能拆出任意 install。
struct VerifiedOpenedKeyUpdateSet: Sendable, CustomDebugStringConvertible {
  let keyDirectoryRevision: UInt64
  let deviceRoute: Data
  let canonicalBytes: Data
  let updates: [VerifiedOpenedKeyUpdate]

  fileprivate init(
    keyDirectoryRevision: UInt64,
    deviceRoute: Data,
    canonicalBytes: Data,
    updates: [VerifiedOpenedKeyUpdate]
  ) throws {
    guard keyDirectoryRevision > 0,
      deviceRoute.count == 16,
      deviceRoute.contains(where: { $0 != 0 }),
      canonicalBytes.count <= KeyUpdateSetCanonicalCodec.maximumCanonicalBytes,
      !updates.isEmpty,
      updates.count <= CanonicalKeyUpdateSetV1.maximumUpdates
    else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    self.keyDirectoryRevision = keyDirectoryRevision
    self.deviceRoute = deviceRoute
    self.canonicalBytes = canonicalBytes
    self.updates = updates
  }

  var debugDescription: String {
    "VerifiedOpenedKeyUpdateSet(revision: \(keyDirectoryRevision), material: <redacted>)"
  }

  /// 后续 full-inventory lineage validator 使用的 constant-time relation；不暴露任一 raw key。
  func updatesShareSecret(at left: Int, _ right: Int) throws -> Bool {
    guard updates.indices.contains(left), updates.indices.contains(right) else {
      throw KeyUpdateSetVerifierError.invalidIndex
    }
    return updates[left].matchesSecret(updates[right])
  }
}

private struct AuditedDeviceKeyCarrierMaterial: Sendable {
  let carrier: DeviceStoredKeyCarrierV1
  let material: OpenedKeyMaterialCapabilityV1
}

enum AuditedReceivingKeyLifecycleV1: Equatable, Sendable {
  case current
  case staged
  /// slot 已由 exact EpochBarrier 激活，但 directory revision 尚未整体切换。
  case activatedPending
  /// activation proof 的旧 physical route 已被同 target rebind 替换；仅供 exact duplicate。
  case epochBarrierProofAlias
  /// revision-only activation 后，以 current Catalog material 恢复 predecessor proof duplicate。
  case directoryAdvancePredecessor
  case retired(retiredAtMS: UInt64, deleteAfterMS: UInt64)
}

/// cold-open 后可供 ingress 精确解析 signed header 的 opaque receiving capability。
/// raw key 不可读取；lifecycle 只决定后续 replay/activation policy，不能由 caller 改写。
struct AuditedReceivingKeyCapabilityV1: Sendable, CustomDebugStringConvertible {
  let replayScope: DeviceCryptoKeyScopeV1
  let outerStreamRoute: Data?
  let keyDirectoryRevision: UInt64
  let lifecycle: AuditedReceivingKeyLifecycleV1
  fileprivate let installed: InstalledReceivingKeyV1
  fileprivate let activationProof: DeviceEpochBarrierV1?
  fileprivate let directoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1?

  fileprivate init(
    installed: InstalledReceivingKeyV1,
    outerStreamRoute: Data?,
    keyDirectoryRevision: UInt64? = nil,
    lifecycle: AuditedReceivingKeyLifecycleV1,
    activationProof: DeviceEpochBarrierV1? = nil,
    directoryAdvanceProof: DeviceDirectoryRevisionAdvanceV1? = nil
  ) throws {
    let routeIsValid: Bool
    switch installed.key.keyID.purpose {
    case .catalog, .conversationDEK:
      routeIsValid =
        outerStreamRoute.map({
          $0.count == 16 && $0.contains(where: { $0 != 0 })
        }) == true
    case .deviceReplyTx:
      routeIsValid = outerStreamRoute == nil
    case .deviceCommandTx:
      routeIsValid = false
    }
    guard routeIsValid else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    let resolvedRevision = keyDirectoryRevision ?? installed.keyDirectoryRevision
    guard resolvedRevision > 0 else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    switch lifecycle {
    case .activatedPending:
      guard let activationProof,
        directoryAdvanceProof == nil,
        resolvedRevision == installed.keyDirectoryRevision,
        Self.activationProof(
          activationProof,
          matches: installed,
          requireExactOuterRoute: false,
          outerStreamRoute: outerStreamRoute
        )
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    case .epochBarrierProofAlias:
      guard let activationProof,
        directoryAdvanceProof == nil,
        resolvedRevision == installed.keyDirectoryRevision,
        Self.activationProof(
          activationProof,
          matches: installed,
          requireExactOuterRoute: true,
          outerStreamRoute: outerStreamRoute
        )
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    case .directoryAdvancePredecessor:
      guard activationProof == nil,
        let directoryAdvanceProof,
        installed.key.keyID.purpose == .catalog,
        installed.streamRoute == nil,
        outerStreamRoute == directoryAdvanceProof.streamRoute,
        resolvedRevision == directoryAdvanceProof.fromRevision,
        installed.keyDirectoryRevision == directoryAdvanceProof.toRevision
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    case .current, .staged, .retired:
      guard activationProof == nil,
        directoryAdvanceProof == nil,
        resolvedRevision == installed.keyDirectoryRevision
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    }
    self.installed = installed
    replayScope = DeviceCryptoKeyScopeV1(
      keyID: installed.key.keyID,
      streamRoute: installed.streamRoute
    )
    self.outerStreamRoute = outerStreamRoute
    self.keyDirectoryRevision = resolvedRevision
    self.lifecycle = lifecycle
    self.activationProof = activationProof
    self.directoryAdvanceProof = directoryAdvanceProof
  }

  func machineDataBinding() throws -> MachineDataReceivingKeyBinding {
    try MachineDataReceivingKeyBinding(
      key: installed.key,
      streamRoute: outerStreamRoute,
      noncePrefix: installed.noncePrefix,
      keyDirectoryRevision: keyDirectoryRevision
    )
  }

  func activatedPendingProof() throws -> DeviceEpochBarrierV1 {
    guard lifecycle == .activatedPending, let activationProof else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    return activationProof
  }

  func epochBarrierAliasProof() throws -> DeviceEpochBarrierV1 {
    guard lifecycle == .epochBarrierProofAlias, let activationProof else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    return activationProof
  }

  func directoryAdvancePredecessorProof() throws -> DeviceDirectoryRevisionAdvanceV1 {
    guard lifecycle == .directoryAdvancePredecessor, let directoryAdvanceProof else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    return directoryAdvanceProof
  }

  var debugDescription: String {
    "AuditedReceivingKeyCapabilityV1(material: <redacted>)"
  }

  private static func activationProof(
    _ proof: DeviceEpochBarrierV1,
    matches installed: InstalledReceivingKeyV1,
    requireExactOuterRoute: Bool,
    outerStreamRoute: Data?
  ) -> Bool {
    let purposeMatches: Bool
    switch (installed.key.keyID.purpose, proof.innerCursor) {
    case (.catalog, .catalog):
      purposeMatches = true
    case (.conversationDEK, .conversation):
      purposeMatches = installed.streamRoute == proof.streamRoute
    case (.catalog, .conversation), (.conversationDEK, .catalog),
      (.deviceCommandTx, _), (.deviceReplyTx, _):
      purposeMatches = false
    }
    return purposeMatches
      && proof.keyDirectoryRevision == installed.keyDirectoryRevision
      && proof.newEpoch == installed.key.keyID.epoch
      && (!requireExactOuterRoute || outerStreamRoute == proof.streamRoute)
  }
}

/// cold-open 对每个 current/staged/unexpired-retired carrier 重验签、HPKE-open 后的
/// 封闭运行时能力。raw bytes 不离开 Crypto module。
struct AuditedDeviceKeyInventoryV1: Sendable, CustomDebugStringConvertible {
  let activeRevision: UInt64
  let commandKey: AeadSendingKey
  let currentReceivingKeys: [InstalledReceivingKeyV1]
  let stagedReceivingKeys: [InstalledReceivingKeyV1]
  fileprivate let retainedReceivingKeys: [AuditedReceivingKeyCapabilityV1]
  fileprivate let carrierMaterials: [AuditedDeviceKeyCarrierMaterial]

  var debugDescription: String {
    "AuditedDeviceKeyInventoryV1(revision: \(activeRevision), material: <redacted>)"
  }

  fileprivate func material(
    for carrier: DeviceStoredKeyCarrierV1
  ) -> OpenedKeyMaterialCapabilityV1? {
    carrierMaterials.first(where: { $0.carrier == carrier })?.material
  }

  /// signed header 的 `(keyID, revision, route)` 必须唯一命中 cold-open 已审计 carrier。
  /// retired capability 只在 `nowMS < deleteAfterMS` 返回；到期但尚未 GC 也 fail-close。
  func resolveReceivingKey(
    keyID: KeyIDV1,
    keyDirectoryRevision: UInt64,
    streamRoute: Data?,
    nowMS: UInt64
  ) throws -> AuditedReceivingKeyCapabilityV1 {
    guard nowMS > 0,
      keyDirectoryRevision > 0,
      keyID.epoch > 0,
      keyID.purpose != .deviceCommandTx,
      Self.outerRouteShapeIsValid(purpose: keyID.purpose, streamRoute: streamRoute)
    else {
      throw DeviceKeyLifecycleError.receivingKeyNotFound
    }
    let matches = retainedReceivingKeys.filter {
      $0.replayScope.keyID == keyID
        && $0.outerStreamRoute == streamRoute
        && $0.keyDirectoryRevision == keyDirectoryRevision
    }
    guard matches.count == 1, let match = matches.first else {
      throw DeviceKeyLifecycleError.receivingKeyNotFound
    }
    if case .retired(_, let deleteAfterMS) = match.lifecycle,
      nowMS >= deleteAfterMS
    {
      throw DeviceKeyLifecycleError.retiredKeyExpired
    }
    return match
  }

  private static func outerRouteShapeIsValid(
    purpose: KeyPurpose,
    streamRoute: Data?
  ) -> Bool {
    switch purpose {
    case .catalog, .conversationDEK:
      return streamRoute.map({
        $0.count == 16 && $0.contains(where: { $0 != 0 })
      }) == true
    case .deviceReplyTx:
      return streamRoute == nil
    case .deviceCommandTx:
      return false
    }
  }
}

/// strict set decode → 每项 MachineDataSign/TBS verify → 每项 DeviceHPKE open。
struct KeyUpdateSetVerifier: Sendable {
  private let keyVerifier: KeyDirectoryVerifier

  init(material: PairedMachineConnectionMaterial) throws {
    keyVerifier = try KeyDirectoryVerifier(material: material)
  }

  init(keyVerifier: KeyDirectoryVerifier) {
    self.keyVerifier = keyVerifier
  }

  func verifyAndOpen(
    canonicalBytes: Data,
    expectedRevision: UInt64
  ) throws -> VerifiedOpenedKeyUpdateSet {
    let set = try KeyUpdateSetCanonicalCodec.decode(canonicalBytes)
    guard expectedRevision > 0,
      set.keyDirectoryRevision == expectedRevision
    else {
      throw KeyUpdateSetVerifierError.revisionMismatch
    }

    var opened: [VerifiedOpenedKeyUpdate] = []
    opened.reserveCapacity(set.updates.count)
    for update in set.updates {
      let carrier = try KeyUpdateCanonicalCodec.encode(update)
      let verified = try keyVerifier.openKeyUpdate(
        canonicalBytes: carrier,
        expectedRevision: expectedRevision
      )
      guard verified.keyID == update.keyID,
        verified.streamRoute == update.streamRoute,
        verified.keyDirectoryRevision == update.keyDirectoryRevision
      else {
        throw KeyUpdateSetVerifierError.openedMetadataMismatch
      }
      opened.append(
        try VerifiedOpenedKeyUpdate(
          keyID: verified.keyID,
          streamRoute: verified.streamRoute,
          canonicalBytes: carrier,
          material: verified.material
        ))
    }

    return try VerifiedOpenedKeyUpdateSet(
      keyDirectoryRevision: set.keyDirectoryRevision,
      deviceRoute: set.deviceRoute,
      canonicalBytes: canonicalBytes,
      updates: opened
    )
  }

  /// 完整 set 一次性验证后构造 durable staged candidate；任何单项都不能提前 install。
  func prepareDurableStage(
    state: DeviceCryptoStateV1,
    canonicalBytes: Data,
    expectedConversationRoutes: [Data]
  ) throws -> DeviceCryptoStateV1 {
    guard state.securityState == .active,
      keyVerifier.trustMatches(state.trustScope)
    else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    let expectedRoutes = try normalizedConversationRoutes(expectedConversationRoutes)
    let activeRevision = state.keyLifecycle?.activeRevision ?? state.keyDirectory.revision
    let nextRevision = activeRevision.addingReportingOverflow(1)
    guard !nextRevision.overflow else { throw DeviceKeyLifecycleError.invalidRevision }

    if let pending = state.keyLifecycle?.stagedTransition {
      guard pending.toRevision == nextRevision.partialValue else {
        throw DeviceKeyLifecycleError.invalidRevision
      }
      guard pending.canonicalUpdateSet == canonicalBytes else {
        throw DeviceKeyLifecycleError.forkedUpdateSet
      }
      _ = try auditColdOpen(
        state: state,
        expectedConversationRoutes: expectedRoutes
      )
      return state
    }

    let verified = try verifyAndOpen(
      canonicalBytes: canonicalBytes,
      expectedRevision: nextRevision.partialValue
    )
    guard verified.deviceRoute == state.trustScope.deviceRoute else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    let expectedSlots = try expectedSlotIDs(expectedRoutes)
    let updateSlots = try verified.updates.map {
      try DeviceKeySlotIDV1(purpose: $0.keyID.purpose, streamRoute: $0.streamRoute)
    }
    guard updateSlots == expectedSlots else {
      throw DeviceKeyLifecycleError.invalidRoster
    }

    let baseline: DeviceKeyLifecycleStateV1
    if let lifecycle = state.keyLifecycle {
      baseline = lifecycle
    } else {
      let bootstrapRoutes = state.keyDirectory.entries.compactMap {
        $0.keyID.purpose == .conversationDEK ? $0.streamRoute : nil
      }
      baseline = try bootstrapLifecycle(
        state: state,
        expectedConversationRoutes: bootstrapRoutes
      )
    }
    let baselineSlots = Set(baseline.slots.map(\.id))
    let expectedSlotSet = Set(expectedSlots)
    guard baselineSlots.isSubset(of: expectedSlotSet) else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    let added = expectedSlots.filter { !baselineSlots.contains($0) }
    guard added.count <= 1,
      added.allSatisfy({ $0.purpose == .conversationDEK })
    else {
      throw DeviceKeyLifecycleError.invalidRoster
    }

    let audited = try auditColdOpen(
      state: state,
      expectedConversationRoutes: state.keyLifecycle == nil
        ? baseline.slots.compactMap {
          $0.id.purpose == .conversationDEK ? $0.id.streamRoute : nil
        }
        : expectedRoutes
    )
    var existingFingerprints: [Data: (DeviceKeySlotIDV1, UInt64)] = [:]
    for entry in audited.carrierMaterials {
      existingFingerprints[entry.carrier.secretFingerprint] = (
        entry.carrier.slotID,
        entry.carrier.keyID.epoch
      )
    }
    let tombstones = Set(baseline.retiredSecretFingerprints)
    var stagedFingerprints: [Data: (DeviceKeySlotIDV1, UInt64)] = [:]
    var nextSlots: [DeviceKeySlotStateV1] = []
    nextSlots.reserveCapacity(expectedSlots.count)
    for (index, slotID) in expectedSlots.enumerated() {
      let update = verified.updates[index]
      let fingerprint = update.secretFingerprint
      let identity = (slotID, update.keyID.epoch)
      let existingSlot = baseline.slots.first(where: { $0.id == slotID })
      if let existingSlot {
        guard let current = existingSlot.current else {
          throw DeviceKeyLifecycleError.invalidState
        }
        if update.keyID.epoch == current.keyID.epoch {
          guard let currentMaterial = audited.material(for: current),
            update.material.matchesSecret(currentMaterial)
          else {
            throw DeviceKeyLifecycleError.secretReuse
          }
        } else {
          let successor = current.keyID.epoch.addingReportingOverflow(1)
          guard !successor.overflow,
            update.keyID.epoch == successor.partialValue
          else {
            throw DeviceKeyLifecycleError.invalidEpoch
          }
        }
      } else {
        guard slotID.purpose == .conversationDEK,
          update.keyID.epoch == 1
        else {
          throw DeviceKeyLifecycleError.invalidEpoch
        }
      }
      if let previous = existingFingerprints[fingerprint],
        previous.0 != identity.0 || previous.1 != identity.1
      {
        throw DeviceKeyLifecycleError.secretReuse
      }
      if let previous = stagedFingerprints[fingerprint],
        previous.0 != identity.0 || previous.1 != identity.1
      {
        throw DeviceKeyLifecycleError.secretReuse
      }
      guard !tombstones.contains(fingerprint) else {
        throw DeviceKeyLifecycleError.secretReuse
      }
      stagedFingerprints[fingerprint] = identity
      let carrier = try DeviceStoredKeyCarrierV1(
        keyID: update.keyID,
        streamRoute: update.streamRoute,
        keyDirectoryRevision: verified.keyDirectoryRevision,
        secretFingerprint: fingerprint,
        source: .signedUpdate(update.canonicalBytes)
      )
      nextSlots.append(
        try DeviceKeySlotStateV1(
          id: slotID,
          current: existingSlot?.current,
          staged: carrier,
          retired: existingSlot?.retired ?? []
        ))
    }
    let transition = try DeviceStagedKeyTransitionV1(
      fromRevision: activeRevision,
      toRevision: verified.keyDirectoryRevision,
      canonicalUpdateSet: canonicalBytes,
      updateSetSHA256: CanonicalCodec.sha256(canonicalBytes)
    )
    let lifecycle = try DeviceKeyLifecycleStateV1(
      activeRevision: activeRevision,
      activeUpdateSet: baseline.activeUpdateSet,
      stagedTransition: transition,
      slots: nextSlots,
      retiredSecretFingerprints: baseline.retiredSecretFingerprints
    )
    // staged receive key 在任何 AEAD open 前也必须有 durable replay scope。这里预建
    // 空 window；普通业务 verifier 仍拒绝 staged revision，只有 staged key-control
    // candidate 能在 replay admission 后解密。相同 keyID 的 revision-only stage 复用
    // 既有 current scope，不能制造第二份 replay window。
    var nextReplayStates = state.replayStates
    for slot in nextSlots {
      guard let staged = slot.staged,
        staged.keyID.purpose != .deviceCommandTx
      else { continue }
      let scope = DeviceCryptoKeyScopeV1(
        keyID: staged.keyID,
        streamRoute: staged.streamRoute
      )
      if let existing = nextReplayStates.first(where: { $0.scope == scope }) {
        guard existing.status == .active,
          slot.current?.keyID == staged.keyID,
          slot.current?.streamRoute == staged.streamRoute
        else {
          throw DeviceKeyLifecycleError.invalidState
        }
        continue
      }
      nextReplayStates.append(
        try DeviceReplayStateV1(
          scope: scope,
          window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
          status: .active
        ))
    }
    guard nextReplayStates.count <= DeviceCryptoStateV1.maximumReplayStates else {
      throw DeviceKeyLifecycleError.capacity
    }
    let stateRevision = state.stateRevision.addingReportingOverflow(1)
    guard !stateRevision.overflow else { throw DeviceCryptoStateError.invalidState }
    return try DeviceCryptoStateV1(
      stateRevision: stateRevision.partialValue,
      trustScope: state.trustScope,
      keyDirectory: state.keyDirectory,
      senderCounter: state.senderCounter,
      securityState: state.securityState,
      replayStates: nextReplayStates,
      streamStates: state.streamStates,
      keyLifecycle: lifecycle,
      pendingStreamBindings: state.pendingStreamBindings,
      keySyncEpisode: state.keySyncEpisode
    )
  }

  /// PairResponse 的初始 state 为兼容既有 durable schema 可暂不物化 lifecycle。
  /// 首个 `0 -> 1` barrier 到达时，在同一个 candidate 中从已签名 bootstrap directory
  /// 重建完整 carrier roster，并绑定 exact activation proof；中间 lifecycle 不单独落盘。
  func prepareBootstrapEpochBarrier(
    state: DeviceCryptoStateV1,
    barrier: DeviceEpochBarrierV1,
    expectedConversationRoutes: [Data]
  ) throws -> DeviceCryptoStateV1 {
    guard state.securityState == .active,
      keyVerifier.trustMatches(state.trustScope),
      barrier.oldEpoch == 0,
      barrier.newEpoch == 1,
      barrier.keyDirectoryRevision == state.senderCounter.keyDirectoryRevision
    else {
      throw DeviceKeyLifecycleError.invalidBarrier
    }
    let expectedRoutes = try normalizedConversationRoutes(expectedConversationRoutes)
    let baseline: DeviceCryptoStateV1
    if state.keyLifecycle == nil {
      let lifecycle: DeviceKeyLifecycleStateV1
      do {
        lifecycle = try bootstrapLifecycle(
          state: state,
          expectedConversationRoutes: expectedRoutes
        )
      } catch KeyDirectoryVerifierError.invalidBootstrapRoster {
        // 该入口对调用方暴露的是 durable lifecycle transition；bootstrap
        // directory 的 roster mismatch 也必须归一为同一 fail-close contract。
        throw DeviceKeyLifecycleError.invalidRoster
      }
      baseline = try DeviceCryptoStateV1(
        stateRevision: state.stateRevision,
        trustScope: state.trustScope,
        keyDirectory: state.keyDirectory,
        senderCounter: state.senderCounter,
        securityState: state.securityState,
        replayStates: state.replayStates,
        streamStates: state.streamStates,
        keyLifecycle: lifecycle,
        pendingStreamBindings: state.pendingStreamBindings,
        keySyncEpisode: state.keySyncEpisode
      )
    } else {
      _ = try auditColdOpen(
        state: state,
        expectedConversationRoutes: expectedRoutes
      )
      baseline = state
    }
    return try baseline.applyingBootstrapEpochBarrier(barrier)
  }

  /// cold-open 在返回任何运行时 key 前重验 bootstrap directory、完整 active/staged set 与
  /// 每个 retained carrier，并重新执行 exact roster / fingerprint lineage 对账。
  func auditColdOpen(
    state: DeviceCryptoStateV1,
    expectedConversationRoutes: [Data]
  ) throws -> AuditedDeviceKeyInventoryV1 {
    guard keyVerifier.trustMatches(state.trustScope) else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    let expectedRoutes = try normalizedConversationRoutes(expectedConversationRoutes)
    let bootstrapRoutes = state.keyDirectory.entries.compactMap {
      $0.keyID.purpose == .conversationDEK ? $0.streamRoute : nil
    }
    let bootstrap = try keyVerifier.auditBootstrapDirectory(
      canonicalBytes: KeyDirectoryCanonicalCodec.encode(state.keyDirectory),
      expectedRevision: state.keyDirectory.revision,
      expectedConversationRoutes: bootstrapRoutes
    )
    guard let lifecycle = state.keyLifecycle else {
      guard bootstrapRoutes == expectedRoutes else {
        throw DeviceKeyLifecycleError.invalidRoster
      }
      let carriers = try state.keyDirectory.entries.map { entry in
        guard
          let material = bootstrap.material(
            keyID: entry.keyID,
            streamRoute: entry.streamRoute
          )
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        return AuditedDeviceKeyCarrierMaterial(
          carrier: try DeviceStoredKeyCarrierV1(
            keyID: entry.keyID,
            streamRoute: entry.streamRoute,
            keyDirectoryRevision: state.keyDirectory.revision,
            secretFingerprint: material.secretFingerprint(),
            source: .bootstrapDirectory
          ),
          material: material
        )
      }
      let inventory = try makeAuditedInventory(
        lifecycle: try bootstrapLifecycle(
          state: state,
          expectedConversationRoutes: expectedRoutes
        ),
        carrierMaterials: carriers,
        streamStates: state.streamStates
      )
      return try validateSenderCapability(inventory, state: state)
    }

    guard lifecycle.slots.map(\.id) == (try expectedSlotIDs(expectedRoutes)),
      lifecycle.activeRevision == state.senderCounter.keyDirectoryRevision
    else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    if let activeSet = lifecycle.activeUpdateSet {
      _ = try verifyAndOpen(canonicalBytes: activeSet, expectedRevision: lifecycle.activeRevision)
    }
    if let staged = lifecycle.stagedTransition {
      let opened = try verifyAndOpen(
        canonicalBytes: staged.canonicalUpdateSet,
        expectedRevision: staged.toRevision
      )
      guard CanonicalCodec.sha256(staged.canonicalUpdateSet) == staged.updateSetSHA256,
        try opened.updates.map({
          try DeviceKeySlotIDV1(
            purpose: $0.keyID.purpose,
            streamRoute: $0.streamRoute
          )
        }) == lifecycle.slots.map(\.id)
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
    }

    var carrierMaterials: [AuditedDeviceKeyCarrierMaterial] = []
    for carrier in lifecycle.slots.flatMap({ slot in
      [slot.current, slot.staged].compactMap({ $0 }) + slot.retired.map(\.carrier)
    }) {
      let material: OpenedKeyMaterialCapabilityV1
      switch carrier.source {
      case .bootstrapDirectory:
        guard carrier.keyDirectoryRevision == state.keyDirectory.revision,
          let bootstrapMaterial = bootstrap.material(
            keyID: carrier.keyID,
            streamRoute: carrier.streamRoute
          )
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        material = bootstrapMaterial
      case .signedUpdate(let canonical):
        let opened = try keyVerifier.openKeyUpdate(
          canonicalBytes: canonical,
          expectedRevision: carrier.keyDirectoryRevision
        )
        guard opened.keyID == carrier.keyID,
          opened.streamRoute == carrier.streamRoute
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        material = opened.material
      }
      guard material.secretFingerprint() == carrier.secretFingerprint else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
      carrierMaterials.append(
        AuditedDeviceKeyCarrierMaterial(carrier: carrier, material: material)
      )
    }
    let inventory = try makeAuditedInventory(
      lifecycle: lifecycle,
      carrierMaterials: carrierMaterials,
      streamStates: state.streamStates
    )
    return try validateSenderCapability(inventory, state: state)
  }

  private func bootstrapLifecycle(
    state: DeviceCryptoStateV1,
    expectedConversationRoutes: [Data]
  ) throws -> DeviceKeyLifecycleStateV1 {
    let bootstrap = try keyVerifier.auditBootstrapDirectory(
      canonicalBytes: KeyDirectoryCanonicalCodec.encode(state.keyDirectory),
      expectedRevision: state.keyDirectory.revision,
      expectedConversationRoutes: expectedConversationRoutes
    )
    let slots = try state.keyDirectory.entries.map { entry in
      guard
        let material = bootstrap.material(
          keyID: entry.keyID,
          streamRoute: entry.streamRoute
        )
      else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
      let carrier = try DeviceStoredKeyCarrierV1(
        keyID: entry.keyID,
        streamRoute: entry.streamRoute,
        keyDirectoryRevision: state.keyDirectory.revision,
        secretFingerprint: material.secretFingerprint(),
        source: .bootstrapDirectory
      )
      return try DeviceKeySlotStateV1(
        id: carrier.slotID,
        current: carrier,
        staged: nil,
        retired: []
      )
    }
    return try DeviceKeyLifecycleStateV1(
      activeRevision: state.keyDirectory.revision,
      activeUpdateSet: nil,
      stagedTransition: nil,
      slots: slots,
      retiredSecretFingerprints: []
    )
  }

  private func makeAuditedInventory(
    lifecycle: DeviceKeyLifecycleStateV1,
    carrierMaterials: [AuditedDeviceKeyCarrierMaterial],
    streamStates: [DeviceStreamCursorStateV1]
  ) throws -> AuditedDeviceKeyInventoryV1 {
    var commandKey: AeadSendingKey?
    var currentReceiving: [InstalledReceivingKeyV1] = []
    var stagedReceiving: [InstalledReceivingKeyV1] = []
    var retainedReceiving: [AuditedReceivingKeyCapabilityV1] = []
    for slot in lifecycle.slots {
      if let current = slot.current {
        guard let material = carrierMaterials.first(where: { $0.carrier == current })?.material
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        if current.keyID.purpose == .deviceCommandTx {
          commandKey = try material.makeSendingKey(
            keyDirectoryRevision: current.keyDirectoryRevision,
            payloadKind: .commandRequest
          )
        } else {
          let installed = try material.makeReceivingKey(
            keyDirectoryRevision: current.keyDirectoryRevision
          )
          currentReceiving.append(installed)
          let currentLifecycle: AuditedReceivingKeyLifecycleV1
          let pendingProof: DeviceEpochBarrierV1?
          if current.keyDirectoryRevision == lifecycle.activeRevision {
            currentLifecycle = .current
            pendingProof = nil
          } else {
            guard let transition = lifecycle.stagedTransition,
              current.keyDirectoryRevision == transition.toRevision,
              let proof = current.activationProof
            else {
              throw DeviceKeyLifecycleError.coldOpenAuditFailed
            }
            currentLifecycle = .activatedPending
            pendingProof = proof
          }
          let primaryCapabilities = try retainedCapabilities(
            installed: installed,
            lifecycle: currentLifecycle,
            streamStates: streamStates,
            activationProof: pendingProof
          )
          retainedReceiving.append(contentsOf: primaryCapabilities)

          // A same-target rebind may replace the physical route in streamStates after the
          // barrier was durably committed. Preserve only an exact proof-bound alias; never
          // reopen that retired route as an ordinary publication capability.
          if let proof = current.activationProof,
            !primaryCapabilities.contains(where: {
              $0.outerStreamRoute == proof.streamRoute
            })
          {
            retainedReceiving.append(
              try AuditedReceivingKeyCapabilityV1(
                installed: installed,
                outerStreamRoute: proof.streamRoute,
                lifecycle: .epochBarrierProofAlias,
                activationProof: proof
              ))
          }

          // DirectoryRevisionAdvance deliberately keeps the Catalog secret/key identity
          // while advancing only its revision. The predecessor alias is therefore minted
          // from the audited current material, but is bound to every exact proof axis.
          if current.keyID.purpose == .catalog,
            let proof = lifecycle.lastDirectoryAdvanceProof
          {
            retainedReceiving.append(
              try AuditedReceivingKeyCapabilityV1(
                installed: installed,
                outerStreamRoute: proof.streamRoute,
                keyDirectoryRevision: proof.fromRevision,
                lifecycle: .directoryAdvancePredecessor,
                directoryAdvanceProof: proof
              ))
          }
        }
      }
      if let staged = slot.staged,
        staged.keyID.purpose != .deviceCommandTx
      {
        guard let material = carrierMaterials.first(where: { $0.carrier == staged })?.material
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        let installed = try material.makeReceivingKey(
          keyDirectoryRevision: staged.keyDirectoryRevision
        )
        stagedReceiving.append(installed)
        retainedReceiving.append(
          contentsOf: try retainedCapabilities(
            installed: installed,
            lifecycle: .staged,
            streamStates: streamStates
          ))
      }
      for retired in slot.retired where retired.carrier.keyID.purpose != .deviceCommandTx {
        guard
          let material = carrierMaterials.first(where: {
            $0.carrier == retired.carrier
          })?.material
        else {
          throw DeviceKeyLifecycleError.coldOpenAuditFailed
        }
        let installed = try material.makeReceivingKey(
          keyDirectoryRevision: retired.carrier.keyDirectoryRevision
        )
        retainedReceiving.append(
          contentsOf: try retainedCapabilities(
            installed: installed,
            lifecycle: .retired(
              retiredAtMS: retired.retiredAtMS,
              deleteAfterMS: retired.deleteAfterMS
            ),
            streamStates: streamStates
          ))
      }
    }
    guard let commandKey else { throw DeviceKeyLifecycleError.coldOpenAuditFailed }
    return AuditedDeviceKeyInventoryV1(
      activeRevision: lifecycle.activeRevision,
      commandKey: commandKey,
      currentReceivingKeys: currentReceiving,
      stagedReceivingKeys: stagedReceiving,
      retainedReceivingKeys: retainedReceiving,
      carrierMaterials: carrierMaterials
    )
  }

  private func retainedCapabilities(
    installed: InstalledReceivingKeyV1,
    lifecycle: AuditedReceivingKeyLifecycleV1,
    streamStates: [DeviceStreamCursorStateV1],
    activationProof: DeviceEpochBarrierV1? = nil
  ) throws -> [AuditedReceivingKeyCapabilityV1] {
    let outerRoutes: [Data?]
    switch installed.key.keyID.purpose {
    case .catalog:
      outerRoutes = streamStates.compactMap { state -> Data? in
        guard case .catalog = state.innerCursor else { return nil }
        return state.streamRoute
      }.map(Optional.some)
    case .conversationDEK:
      guard let streamRoute = installed.streamRoute else {
        throw DeviceKeyLifecycleError.coldOpenAuditFailed
      }
      outerRoutes = [streamRoute]
    case .deviceReplyTx:
      outerRoutes = [nil]
    case .deviceCommandTx:
      outerRoutes = []
    }
    return try outerRoutes.map {
      try AuditedReceivingKeyCapabilityV1(
        installed: installed,
        outerStreamRoute: $0,
        lifecycle: lifecycle,
        activationProof: activationProof
      )
    }
  }

  private func validateSenderCapability(
    _ inventory: AuditedDeviceKeyInventoryV1,
    state: DeviceCryptoStateV1
  ) throws -> AuditedDeviceKeyInventoryV1 {
    guard inventory.activeRevision == state.senderCounter.keyDirectoryRevision,
      inventory.commandKey.keyID == state.senderCounter.keyID,
      inventory.commandKey.keyDirectoryRevision == state.senderCounter.keyDirectoryRevision,
      inventory.commandKey.noncePrefix == state.senderCounter.noncePrefix
    else {
      throw DeviceKeyLifecycleError.coldOpenAuditFailed
    }
    return inventory
  }

  private func normalizedConversationRoutes(_ routes: [Data]) throws -> [Data] {
    guard
      routes.allSatisfy({
        $0.count == 16 && $0.contains(where: { $0 != 0 })
      })
    else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    let sorted = routes.sorted { $0.lexicographicallyPrecedes($1) }
    guard Set(sorted).count == sorted.count else {
      throw DeviceKeyLifecycleError.invalidRoster
    }
    return sorted
  }

  private func expectedSlotIDs(_ routes: [Data]) throws -> [DeviceKeySlotIDV1] {
    try [DeviceKeySlotIDV1(purpose: .catalog, streamRoute: nil)]
      + routes.map {
        try DeviceKeySlotIDV1(purpose: .conversationDEK, streamRoute: $0)
      }
      + [
        DeviceKeySlotIDV1(purpose: .deviceCommandTx, streamRoute: nil),
        DeviceKeySlotIDV1(purpose: .deviceReplyTx, streamRoute: nil),
      ]
  }
}

private struct KeyUpdateSetIdentity {
  let purpose: UInt8
  let streamRoute: Data

  init(_ update: CanonicalKeyUpdateV1) {
    purpose = update.keyID.purpose.canonicalTag
    streamRoute = update.streamRoute ?? Data(repeating: 0, count: 16)
  }

  func isStrictlyBefore(_ other: Self) -> Bool {
    if purpose != other.purpose { return purpose < other.purpose }
    return streamRoute.lexicographicallyPrecedes(other.streamRoute)
  }
}

private struct KeyUpdateSetEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) {
    self.maximumBytes = maximumBytes
  }

  mutating func raw(_ value: Data) throws {
    try append(value)
  }

  mutating func u64(_ value: UInt64) throws {
    try appendInteger(value)
  }

  mutating func u16Count(_ count: Int) throws {
    guard let value = UInt16(exactly: count) else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    try appendInteger(value)
  }

  mutating func bytes(
    _ value: Data,
    maximum: Int,
    exact: Int? = nil
  ) throws {
    guard value.count <= maximum else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    if let exact, value.count != exact {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    guard let count = UInt32(exactly: value.count) else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    try appendInteger(count)
    try append(value)
  }

  func finish() throws -> Data {
    guard output.count <= maximumBytes else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    return output
  }

  private mutating func append(_ value: Data) throws {
    let end = output.count.addingReportingOverflow(value.count)
    guard !end.overflow, end.partialValue <= maximumBytes else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    output.append(value)
  }

  private mutating func appendInteger<T: FixedWidthInteger>(_ value: T) throws {
    var encoded = value.bigEndian
    try Swift.withUnsafeBytes(of: &encoded) { try append(Data($0)) }
  }
}

private struct KeyUpdateSetDecoder {
  private let bytes: Data
  private var offset = 0

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  mutating func domain(_ expected: Data) throws {
    guard try fixed(count: expected.count) == expected else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
  }

  mutating func u64() throws -> UInt64 {
    try integer(count: 8)
  }

  mutating func u16Count() throws -> Int {
    Int(try integer(count: 2) as UInt16)
  }

  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try integer(count: 4) as UInt32)
    guard count <= maximum else {
      throw KeyUpdateSetVerifierError.sizeLimit
    }
    return try fixed(count: count)
  }

  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    return value
  }

  func finish() throws {
    guard offset == bytes.count else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
  }

  private mutating func fixed(count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0,
      !end.overflow,
      end.partialValue <= bytes.count
    else {
      throw KeyUpdateSetVerifierError.invalidEncoding
    }
    defer { offset = end.partialValue }
    return bytes.subdata(in: offset..<end.partialValue)
  }

  private mutating func integer<T: FixedWidthInteger>(count: Int) throws -> T {
    try fixed(count: count).reduce(0) { ($0 << 8) | T($1) }
  }
}
