import AgentDeckSessionSource
import CryptoKit
import Foundation

/// Keychain commit marker 中的无 secret、versioned paired machine record。
public struct StoredPairedMachineRecordV1: Equatable, Sendable, CustomDebugStringConvertible {
  public let clientKind: RelayClientKind
  public let installationID: UUID
  public let machineID: String
  public let machineName: String
  public let relayURL: URL
  public let relayServerID: Data
  public let machineRootPublicKey: Data
  public let machineRootFingerprint: Data
  public let machineDataCertificate: RelayV2SignedCertificate
  public let machineRoute: Data
  public let deviceRoute: Data
  public let currentSPKIPin: Data
  public let nextSPKIPin: Data?
  public let grantSerial: UInt64
  public let trustEpoch: UInt64
  public let createdAtMS: UInt64

  public init(
    clientKind: RelayClientKind,
    installationID: UUID,
    machineID: String,
    machineName: String,
    relayURL: URL,
    relayServerID: Data,
    machineRootPublicKey: Data,
    machineRootFingerprint: Data,
    machineDataCertificate: RelayV2SignedCertificate,
    machineRoute: Data,
    deviceRoute: Data,
    currentSPKIPin: Data,
    nextSPKIPin: Data?,
    grantSerial: UInt64,
    trustEpoch: UInt64,
    createdAtMS: UInt64
  ) throws {
    guard isNonzeroRelayInstallationID(installationID),
      !machineID.isEmpty,
      machineID.utf8.count <= 8 * 1_024,
      !machineName.isEmpty,
      machineName.utf8.count <= 128,
      machineName.trimmingCharacters(in: .whitespacesAndNewlines) == machineName,
      !machineName.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
      Self.isCanonicalRelayURL(relayURL),
      Self.isNonzero(relayServerID, count: 16),
      Self.isNonzero(machineRootPublicKey, count: 32),
      Self.isNonzero(machineRootFingerprint, count: 32),
      CanonicalCodec.sha256(machineRootPublicKey) == machineRootFingerprint,
      Self.isValidDataCertificate(machineDataCertificate, trustEpoch: trustEpoch),
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      Self.isNonzero(currentSPKIPin, count: 32),
      nextSPKIPin.map({ Self.isNonzero($0, count: 32) }) ?? true,
      grantSerial > 0,
      trustEpoch > 0,
      createdAtMS > 0
    else {
      throw PairedMachineStoreError.invalidRecord
    }
    self.clientKind = clientKind
    self.installationID = installationID
    self.machineID = machineID
    self.machineName = machineName
    self.relayURL = relayURL
    self.relayServerID = relayServerID
    self.machineRootPublicKey = machineRootPublicKey
    self.machineRootFingerprint = machineRootFingerprint
    self.machineDataCertificate = machineDataCertificate
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.currentSPKIPin = currentSPKIPin
    self.nextSPKIPin = nextSPKIPin
    self.grantSerial = grantSerial
    self.trustEpoch = trustEpoch
    self.createdAtMS = createdAtMS
  }

  public var pairedMachine: PairedMachine {
    PairedMachine(
      id: machineID,
      name: machineName,
      relayHost: relayURL.host ?? "",
      rootFingerprint: machineRootFingerprint
    )
  }

  public var debugDescription: String {
    "StoredPairedMachineRecordV1(machineID: <redacted>, routes: <redacted>)"
  }

  private static func isCanonicalRelayURL(_ url: URL) -> Bool {
    let value = url.absoluteString
    guard value.utf8.count <= 2 * 1_024,
      let components = URLComponents(string: value),
      components.scheme == "wss",
      components.host != nil,
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.port != 0,
      components.percentEncodedPath == "/",
      components.string == value
    else {
      return false
    }
    return true
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }

  private static func isValidDataCertificate(
    _ certificate: RelayV2SignedCertificate,
    trustEpoch: UInt64
  ) -> Bool {
    certificate.certRole == .data
      && isNonzero(certificate.subjectPubkey, count: 32)
      && certificate.generation > 0
      && isNonzero(certificate.rootKeyId, count: 16)
      && certificate.trustEpoch == trustEpoch
      && (certificate.notAfterMs.map { $0 > 0 } ?? true)
      && isNonzero(certificate.signature, count: 64)
  }
}

/// pairing response 验证完成后交给 marker-last promotion 的封闭 carrier。
///
/// private material 只进入各自 Keychain account；debug 输出永不展开 secret。
struct PreparedPairedMachinePromotionV1: Sendable, CustomDebugStringConvertible {
  static let privateKeyBytes = 32
  static let maximumGrantBytes = 2 * 1_024

  let record: StoredPairedMachineRecordV1
  let promotionID32: Data
  let deviceSignPrivateKey: Data
  let deviceHPKEPrivateKey: Data
  let deviceGrant: Data
  let deviceStorageKEK: DeviceStorageKEK
  let initialCryptoState: CryptoStateSnapshot

  init(
    record: StoredPairedMachineRecordV1,
    promotionID32: Data,
    deviceSignPrivateKey: Data,
    deviceHPKEPrivateKey: Data,
    deviceGrant: Data,
    deviceStorageKEK: DeviceStorageKEK,
    initialCryptoState: CryptoStateSnapshot
  ) throws {
    let state = initialCryptoState.state
    let trust = state.trustScope
    guard Self.isNonzero(promotionID32, count: 32),
      Self.isNonzero(deviceSignPrivateKey, count: Self.privateKeyBytes),
      Self.isNonzero(deviceHPKEPrivateKey, count: Self.privateKeyBytes),
      !deviceGrant.isEmpty,
      deviceGrant.count <= Self.maximumGrantBytes,
      state.stateRevision == 1,
      state.senderCounter.reservedHighWater == 0,
      state.senderCounter.reservationID.allSatisfy({ $0 == 0 }),
      state.securityState == .active,
      trust.relayServerID == record.relayServerID,
      trust.machineRootFingerprint == record.machineRootFingerprint,
      trust.machineRoute == record.machineRoute,
      trust.deviceRoute == record.deviceRoute,
      trust.grantSerial == record.grantSerial,
      trust.trustEpoch == record.trustEpoch
    else {
      throw PairedMachineStoreError.invalidPromotion
    }
    do {
      _ = try PairedCredentialAuditor.audit(
        record: record,
        deviceSignPrivateKey: deviceSignPrivateKey,
        deviceHPKEPrivateKey: deviceHPKEPrivateKey,
        deviceGrant: deviceGrant
      )
    } catch {
      throw PairedMachineStoreError.invalidPromotion
    }
    self.record = record
    self.promotionID32 = promotionID32
    self.deviceSignPrivateKey = deviceSignPrivateKey
    self.deviceHPKEPrivateKey = deviceHPKEPrivateKey
    self.deviceGrant = deviceGrant
    self.deviceStorageKEK = deviceStorageKEK
    self.initialCryptoState = initialCryptoState
  }

  var debugDescription: String {
    "PreparedPairedMachinePromotionV1(record: <redacted>, material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

/// cold-open 审计完成后交给单台 `MachineConnection` 的封闭能力。
///
/// secret、state store 与 coordinator 都保持 module-internal；public API 只暴露
/// 无 secret 的 paired record，避免把 Keychain 退化成通用 raw-secret store。
struct PairedMachineConnectionMaterial: Sendable, CustomDebugStringConvertible {
  let record: StoredPairedMachineRecordV1
  let deviceSigningKey: Curve25519.Signing.PrivateKey
  let deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey
  let relayGrant: VerifiedRelayGrantCredential
  let machineDataCertificate: VerifiedMachineDataCertificate
  let auditedCryptoState: CryptoStateSnapshot
  let cryptoStateStore: FileCryptoStateStore
  let cryptoStateCoordinator: DurableCryptoStateCoordinator

  var debugDescription: String {
    "PairedMachineConnectionMaterial(record: <redacted>, material: <redacted>)"
  }
}

private struct AuditedPairedCredentials: Sendable {
  let deviceSigningKey: Curve25519.Signing.PrivateKey
  let deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey
  let relayGrant: VerifiedRelayGrantCredential
  let machineDataCertificate: VerifiedMachineDataCertificate
}

private enum PairedCredentialAuditor {
  static func audit(
    record: StoredPairedMachineRecordV1,
    deviceSignPrivateKey: Data,
    deviceHPKEPrivateKey: Data,
    deviceGrant: Data
  ) throws -> AuditedPairedCredentials {
    let signingKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: deviceSignPrivateKey
    )
    let hpkeKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: deviceHPKEPrivateKey
    )
    let verifiedGrant = try RelayGrantCredentialVerifier.verify(
      canonicalBytes: deviceGrant,
      relayServerID: record.relayServerID,
      machineRootPublicKey: record.machineRootPublicKey,
      machineRootFingerprint: record.machineRootFingerprint,
      expectedMachineRoute: record.machineRoute,
      expectedDeviceRoute: record.deviceRoute,
      expectedDeviceSignPublicKey: signingKey.publicKey.rawRepresentation,
      expectedGrantSerial: record.grantSerial,
      expectedRootKeyID: record.machineDataCertificate.rootKeyId,
      expectedTrustEpoch: record.trustEpoch
    )
    let verifiedDataCertificate = try MachineDataCertificateVerifier.verify(
      record.machineDataCertificate,
      relayServerID: record.relayServerID,
      machineRoute: record.machineRoute,
      machineRootPublicKey: record.machineRootPublicKey,
      machineRootFingerprint: record.machineRootFingerprint,
      expectedRootKeyID: verifiedGrant.grant.rootKeyId,
      expectedTrustEpoch: record.trustEpoch,
      minimumDataCertificateGeneration: record.machineDataCertificate.generation
    )
    return AuditedPairedCredentials(
      deviceSigningKey: signingKey,
      deviceHPKEPrivateKey: hpkeKey,
      relayGrant: verifiedGrant,
      machineDataCertificate: verifiedDataCertificate
    )
  }
}

public enum PairedMachineStoreError: Error, Equatable, Sendable {
  case invalidRecord
  case invalidPromotion
  case invalidBinding
  case persistenceMismatch

  public var code: String {
    switch self {
    case .invalidRecord: "remote.paired_machine.invalid_record"
    case .invalidPromotion: "remote.paired_machine.invalid_promotion"
    case .invalidBinding: "remote.paired_machine.invalid_binding"
    case .persistenceMismatch: "remote.paired_machine.persistence_mismatch"
    }
  }
}

/// PairResponse material 已完整持久化后、PairRoute terminal 尚未确认时的 durable 状态。
///
/// `.staged` 只允许 pairing recovery 使用；它不会进入 `list/load/openConnectionMaterial`。
/// `.committed` 表示 matching `PairRouteClosed` 已确认，可以正式连接。
enum DurablePairingPromotionState: Equatable, Sendable {
  case staged(StoredPairedMachineRecordV1)
  case committed(StoredPairedMachineRecordV1)

  var record: StoredPairedMachineRecordV1 {
    switch self {
    case .staged(let record), .committed(let record): record
    }
  }
}

/// committed marker 是 paired 可见性的唯一边界。
///
/// pairing promotion 先写 durable staged marker；只有 matching PairRoute terminal
/// readback 才 exact-CAS 为 committed。partial/staged promotion 与 cleanup journal
/// 都不会出现在 list/load/openConnectionMaterial。
public actor PairedMachineStore {
  private let keyStore: any PairedMarkerListingKeyStore
  private let stateRootURL: URL
  private let clientKind: RelayClientKind
  private let installationID: UUID
  private let stateFileProtectionPolicy: URLFileProtection

  public init(
    keyStore: any PairedMarkerListingKeyStore,
    stateRootURL: URL,
    clientKind: RelayClientKind,
    installationID: UUID
  ) {
    self.keyStore = keyStore
    self.stateRootURL = stateRootURL.standardizedFileURL
    self.clientKind = clientKind
    self.installationID = installationID
    stateFileProtectionPolicy = FileCryptoStateStore.fileProtectionPolicy
  }

  init(
    keyStore: any PairedMarkerListingKeyStore,
    stateRootURL: URL,
    clientKind: RelayClientKind,
    installationID: UUID,
    testingFileProtectionPolicy: URLFileProtection
  ) {
    precondition(
      testingFileProtectionPolicy == .complete
        || testingFileProtectionPolicy == .completeUntilFirstUserAuthentication,
      "unsupported test file-protection policy"
    )
    self.keyStore = keyStore
    self.stateRootURL = stateRootURL.standardizedFileURL
    self.clientKind = clientKind
    self.installationID = installationID
    stateFileProtectionPolicy = testingFileProtectionPolicy
  }

  /// 与 paired marker 共用同一 app/installation Keychain namespace 的 pending owner。
  /// raw backend 与 identity 不向 composition root 暴露，避免外层自行拼 account。
  func makePendingPairingStore() throws -> PendingPairingStore {
    try PendingPairingStore(
      keyStore: keyStore,
      clientKind: clientKind,
      installationID: installationID
    )
  }

  func makePendingPairingResponseState(
    verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    nowMilliseconds: UInt64
  ) throws -> PendingPairingResponseStateV1 {
    try PairingPromotionBuilder.makeResponseState(
      clientKind: clientKind,
      installationID: installationID,
      verified: verified,
      prepared: prepared,
      nowMilliseconds: nowMilliseconds
    )
  }

  func makePairingPromotion(
    verified: VerifiedPendingPairResponseV1,
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) throws -> PreparedPairedMachinePromotionV1 {
    try PairingPromotionBuilder.makePromotion(
      clientKind: clientKind,
      installationID: installationID,
      verified: verified,
      prepared: prepared,
      response: response
    )
  }

  /// signed terminal 在 paired marker 前后都必须能收敛。marker 已存在时走正常 cleanup
  /// journal；marker 尚未写入时，pending response marker 充当恢复索引，按 promotion 的
  /// 反向顺序 exact-delete partial material，最后才允许 pending terminal cleanup。
  func abortPairingPromotion(
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) async throws {
    let binding = try pairingPromotionBinding(
      prepared: prepared,
      response: response
    )

    let context = try makePartialPairingContext(
      rootFingerprint: binding.record.machineRootFingerprint,
      machineRoute: response.machineRoute
    )
    let lease = try await context.leaseManager.acquire()
    do {
      try await abortPairingPromotion(
        binding: binding,
        context: context,
        under: lease
      )
      await lease.release()
    } catch {
      await lease.release()
      throw error
    }
  }

  private func abortExpiredPairingPromotion(
    pendingRecord: PendingPairingRecordV1,
    response: PendingPairingResponseStateV1
  ) async throws {
    let binding = try pairingPromotionBinding(
      pendingRecord: pendingRecord,
      response: response
    )
    let context = try makeContext(record: binding.record)
    let lease = try await context.leaseManager.acquire()
    do {
      try await abortPairingPromotion(
        binding: binding,
        context: context,
        under: lease
      )
      await lease.release()
    } catch {
      await lease.release()
      throw error
    }
  }

  /// 顺序固定为 KEK → sealed state → private material/grant → CounterGuard → marker。
  @discardableResult
  func promote(
    _ prepared: PreparedPairedMachinePromotionV1
  ) async throws -> KeyStorePersistence {
    try validateBinding(prepared.record)
    let context = try makeContext(record: prepared.record)
    let lease = try await context.leaseManager.acquire()
    do {
      let result = try await persistPromotion(
        prepared,
        phase: .committed,
        context: context,
        under: lease
      )
      await lease.release()
      return result
    } catch {
      await lease.release()
      throw error
    }
  }

  /// PairResponse 后先完整落盘但保持不可见；只有 terminal readback 才能 finalize。
  @discardableResult
  func stagePairingPromotion(
    _ prepared: PreparedPairedMachinePromotionV1
  ) async throws -> KeyStorePersistence {
    try validateBinding(prepared.record)
    let context = try makeContext(record: prepared.record)
    let lease = try await context.leaseManager.acquire()
    do {
      let result = try await persistPromotion(
        prepared,
        phase: .staged,
        context: context,
        under: lease
      )
      await lease.release()
      return result
    } catch {
      await lease.release()
      throw error
    }
  }

  /// 只为 exact pending response 恢复 staged/committed marker；不打开正式连接能力。
  func pairingPromotionState(
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) async throws -> DurablePairingPromotionState? {
    let binding = try pairingPromotionBinding(
      prepared: prepared,
      response: response
    )
    return try await pairingPromotionState(binding: binding)
  }

  /// matching PairRouteClosed 后，把 durable staged marker 原子变为可见。
  func finalizePairingPromotion(
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) async throws -> StoredPairedMachineRecordV1 {
    let binding = try pairingPromotionBinding(
      prepared: prepared,
      response: response
    )
    let context = try makeContext(record: binding.record)
    let lease = try await context.leaseManager.acquire()
    do {
      guard let markerData = try await keyStore.load(context.keys.marker) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      let marker = try PairedMachineMarkerCodec.decode(markerData)
      try validateMarker(marker, at: context.keys.marker)
      try await auditPairingPromotionMarker(
        marker,
        binding: binding,
        context: context,
        under: lease
      )
      if marker.phase == .committed {
        await lease.release()
        return marker.record
      }
      guard marker.phase == .staged else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      let committed = marker.withPhase(.committed)
      let committedData = try PairedMachineMarkerCodec.encode(committed)
      try await keyStore.compareAndReplaceExact(
        expected: markerData,
        replacement: committedData,
        for: context.keys.marker
      )
      guard try await keyStore.load(context.keys.marker) == committedData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
      await lease.release()
      return committed.record
    } catch {
      await lease.release()
      throw error
    }
  }

  /// 只返回通过 marker binding、材料、CounterGuard 与 sealed state 完整审计的机器。
  public func list() async throws -> [StoredPairedMachineRecordV1] {
    let markerKeys = try await keyStore.pairedCommitMarkerKeys(
      clientKind: clientKind,
      installationID: installationID
    )
    var records: [StoredPairedMachineRecordV1] = []
    records.reserveCapacity(markerKeys.count)
    for key in markerKeys {
      if let record = try await auditVisibleMarker(at: key) {
        records.append(record)
      }
    }
    return records
  }

  /// 扫描 marker-native namespace 并续做已经进入 cleanup journal 的事务。
  /// cleanup marker 已关闭 paired 可见性，但仍必须把 state/key material 与 marker
  /// 全部 exact-delete；调用方无需另存一份可漂移的 recovery index。
  func resumeIncompleteCleanups() async throws {
    let markerKeys = try await keyStore.pairedCommitMarkerKeys(
      clientKind: clientKind,
      installationID: installationID
    )
    for key in markerKeys {
      guard let markerData = try await keyStore.load(key) else { continue }
      let marker = try PairedMachineMarkerCodec.decode(markerData)
      try validateMarker(marker, at: key)
      guard marker.phase == .cleanup else { continue }
      try await deleteExact(marker.record)
    }
  }

  /// cold-open / inspect / pair 前收敛 pending terminal/completed 与本地 TTL。
  /// responsePrepared 的本地过期只回滚没有完整 marker 的 partial promotion。
  /// staged/committed marker 表示 response 已 durable 安装，必须保留到 signed terminal
  /// 或 exact route terminal 收敛，不能仅凭 invite TTL 删除长期 grant credential。
  func recoverPendingPairings(nowMilliseconds: UInt64) async throws {
    let pendingStore = try makePendingPairingStore()
    let candidates = try await pendingStore.cleanupCandidates(
      nowMilliseconds: nowMilliseconds
    )
    for candidate in candidates {
      if let record = candidate.record,
        record.expiresAtMilliseconds <= nowMilliseconds,
        case .responsePrepared(let response) = record.phase
      {
        let binding = try pairingPromotionBinding(
          pendingRecord: record,
          response: response
        )
        if try await pairingPromotionState(binding: binding) != nil {
          continue
        }
        try await abortExpiredPairingPromotion(
          pendingRecord: record,
          response: response
        )
      }
      try await pendingStore.finishLocalCleanup(candidate)
    }
  }

  public func load(
    rootFingerprint: Data,
    machineRoute: Data
  ) async throws -> StoredPairedMachineRecordV1? {
    let key = try markerKey(
      rootFingerprint: rootFingerprint,
      machineRoute: machineRoute
    )
    return try await auditVisibleMarker(at: key)
  }

  /// 为连接 cold-open 重新审计 marker、全部 secret、sealed state 与 CounterGuard。
  ///
  /// 本能力保持 module-internal，调用方不能绕过审计直接读取任意 Keychain material。
  func openConnectionMaterial(
    rootFingerprint: Data,
    machineRoute: Data
  ) async throws -> PairedMachineConnectionMaterial? {
    let key = try markerKey(
      rootFingerprint: rootFingerprint,
      machineRoute: machineRoute
    )
    guard let preliminaryData = try await keyStore.load(key) else {
      return nil
    }
    let preliminary = try PairedMachineMarkerCodec.decode(preliminaryData)
    try validateMarker(preliminary, at: key)
    guard preliminary.phase == .committed else { return nil }

    let context = try makeContext(record: preliminary.record)
    let lease = try await context.leaseManager.acquire()
    do {
      guard let currentData = try await keyStore.load(key) else {
        await lease.release()
        return nil
      }
      let current = try PairedMachineMarkerCodec.decode(currentData)
      try validateMarker(current, at: key)
      guard current.phase == .committed else {
        await lease.release()
        return nil
      }
      guard current == preliminary else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      let audited = try await auditDependencies(
        current,
        context: context,
        under: lease
      )
      let material = PairedMachineConnectionMaterial(
        record: current.record,
        deviceSigningKey: audited.credentials.deviceSigningKey,
        deviceHPKEPrivateKey: audited.credentials.deviceHPKEPrivateKey,
        relayGrant: audited.credentials.relayGrant,
        machineDataCertificate: audited.credentials.machineDataCertificate,
        auditedCryptoState: audited.cryptoState,
        cryptoStateStore: audited.cryptoStateStore,
        cryptoStateCoordinator: audited.cryptoStateCoordinator
      )
      await lease.release()
      return material
    } catch {
      await lease.release()
      throw error
    }
  }

  /// marker 先 exact-CAS 为 cleanup journal，再按固定顺序做 expected delete。
  public func deleteExact(_ record: StoredPairedMachineRecordV1) async throws {
    try validateBinding(record)
    let context = try makeContext(record: record)
    let lease = try await context.leaseManager.acquire()
    do {
      try await deleteExact(record, context: context, under: lease)
      await lease.release()
    } catch {
      await lease.release()
      throw error
    }
  }

  private func persistPromotion(
    _ prepared: PreparedPairedMachinePromotionV1,
    phase: PairedMachineMarkerPhase,
    context: MachineContext,
    under lease: MachineCryptoLease
  ) async throws -> KeyStorePersistence {
    guard phase == .staged || phase == .committed else {
      throw PairedMachineStoreError.invalidPromotion
    }
    if let existingData = try await keyStore.load(context.keys.marker) {
      let existing = try PairedMachineMarkerCodec.decode(existingData)
      try validateMarker(existing, at: context.keys.marker)
      guard existing.matches(prepared),
        existing.phase == phase || (phase == .staged && existing.phase == .committed)
      else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      _ = try await auditDependencies(existing, context: context, under: lease)
      return .alreadyPresent
    }

    try await persistAndReadBack(
      prepared.deviceStorageKEK.rawRepresentation,
      for: context.keys.storageKEK
    )
    let stateStore = try FileCryptoStateStore(
      rootURL: stateRootURL,
      identity: context.identity,
      storageKey: prepared.deviceStorageKEK,
      testHooks: .none,
      testingFileProtectionPolicy: stateFileProtectionPolicy
    )
    _ = try await stateStore.commitInitial(prepared.initialCryptoState)
    guard try await stateStore.load() == prepared.initialCryptoState else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }

    try await persistAndReadBack(
      prepared.deviceSignPrivateKey,
      for: context.keys.deviceSign
    )
    try await persistAndReadBack(
      prepared.deviceHPKEPrivateKey,
      for: context.keys.deviceHPKE
    )
    try await persistAndReadBack(prepared.deviceGrant, for: context.keys.grant)

    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: stateRootURL,
      identity: context.identity,
      stateStore: stateStore,
      keyStore: keyStore,
      guardKey: context.keys.counterGuard
    )
    let permit = try CounterBootstrapPermit(
      snapshot: prepared.initialCryptoState,
      promotionID: prepared.promotionID32
    )
    let evidence = try await coordinator.bootstrap(permit, under: lease)
    let marker = PairedMachineMarker(
      phase: phase,
      record: prepared.record,
      promotionID: prepared.promotionID32,
      initialStateCommitment: evidence.initialStateCommitment,
      initialGuardCommitment: evidence.initialGuardCommitment,
      deviceSignHash: CanonicalCodec.sha256(prepared.deviceSignPrivateKey),
      deviceHPKEHash: CanonicalCodec.sha256(prepared.deviceHPKEPrivateKey),
      grantHash: CanonicalCodec.sha256(prepared.deviceGrant),
      storageKEKHash: CanonicalCodec.sha256(
        prepared.deviceStorageKEK.rawRepresentation
      ),
      cleanupStateCommitment: nil,
      cleanupGuardHash: nil
    )
    let encoded = try PairedMachineMarkerCodec.encode(marker)
    let outcome = try await keyStore.persistImmutable(encoded, for: context.keys.marker)
    guard try await keyStore.load(context.keys.marker) == encoded else {
      throw KeyStoreError.persistenceReadbackFailed
    }
    return outcome
  }

  private func auditVisibleMarker(
    at markerKey: KeyStoreKey
  ) async throws -> StoredPairedMachineRecordV1? {
    guard let preliminaryData = try await keyStore.load(markerKey) else {
      return nil
    }
    let preliminary = try PairedMachineMarkerCodec.decode(preliminaryData)
    try validateMarker(preliminary, at: markerKey)
    guard preliminary.phase == .committed else { return nil }

    let context = try makeContext(record: preliminary.record)
    let lease = try await context.leaseManager.acquire()
    do {
      guard let currentData = try await keyStore.load(markerKey) else {
        await lease.release()
        return nil
      }
      let current = try PairedMachineMarkerCodec.decode(currentData)
      try validateMarker(current, at: markerKey)
      guard current.phase == .committed else {
        await lease.release()
        return nil
      }
      guard current == preliminary else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      _ = try await auditDependencies(current, context: context, under: lease)
      await lease.release()
      return current.record
    } catch {
      await lease.release()
      throw error
    }
  }

  private func pairingPromotionState(
    binding: PairingPromotionRollbackBinding
  ) async throws -> DurablePairingPromotionState? {
    let context = try makeContext(record: binding.record)
    let lease = try await context.leaseManager.acquire()
    do {
      guard let markerData = try await keyStore.load(context.keys.marker) else {
        await lease.release()
        return nil
      }
      let marker = try PairedMachineMarkerCodec.decode(markerData)
      try validateMarker(marker, at: context.keys.marker)
      try await auditPairingPromotionMarker(
        marker,
        binding: binding,
        context: context,
        under: lease
      )
      let state: DurablePairingPromotionState
      switch marker.phase {
      case .staged: state = .staged(marker.record)
      case .committed: state = .committed(marker.record)
      case .cleanup: throw PairedMachineStoreError.persistenceMismatch
      }
      await lease.release()
      return state
    } catch {
      await lease.release()
      throw error
    }
  }

  private func auditPairingPromotionMarker(
    _ marker: PairedMachineMarker,
    binding: PairingPromotionRollbackBinding,
    context: MachineContext,
    under lease: MachineCryptoLease
  ) async throws {
    guard marker.phase == .staged || marker.phase == .committed,
      marker.record == binding.record,
      marker.promotionID == binding.promotionID,
      marker.storageKEKHash == CanonicalCodec.sha256(binding.storageKEK)
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    let audited = try await auditDependencies(marker, context: context, under: lease)
    guard
      audited.credentials.deviceSigningKey.publicKey.rawRepresentation
        == binding.deviceSignPublicKey,
      audited.credentials.deviceHPKEPrivateKey.publicKey.rawRepresentation
        == binding.deviceHPKEPublicKey
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
  }

  private func auditDependencies(
    _ marker: PairedMachineMarker,
    context: MachineContext,
    under lease: MachineCryptoLease
  ) async throws -> AuditedPairedMachineDependencies {
    let storageKeyData = try await loadMaterial(
      context.keys.storageKEK,
      expectedHash: marker.storageKEKHash
    )
    let storageKey = try DeviceStorageKEK(rawRepresentation: storageKeyData)
    let sign = try await loadMaterial(
      context.keys.deviceSign,
      expectedHash: marker.deviceSignHash
    )
    let hpke = try await loadMaterial(
      context.keys.deviceHPKE,
      expectedHash: marker.deviceHPKEHash
    )
    let grant = try await loadMaterial(
      context.keys.grant,
      expectedHash: marker.grantHash
    )
    guard Self.isPrivateKey(sign),
      Self.isPrivateKey(hpke),
      !grant.isEmpty,
      grant.count <= PreparedPairedMachinePromotionV1.maximumGrantBytes
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    let credentials: AuditedPairedCredentials
    do {
      credentials = try PairedCredentialAuditor.audit(
        record: marker.record,
        deviceSignPrivateKey: sign,
        deviceHPKEPrivateKey: hpke,
        deviceGrant: grant
      )
    } catch {
      throw PairedMachineStoreError.persistenceMismatch
    }

    let stateStore = try FileCryptoStateStore(
      rootURL: stateRootURL,
      identity: context.identity,
      storageKey: storageKey,
      testHooks: .none,
      testingFileProtectionPolicy: stateFileProtectionPolicy
    )
    guard let snapshot = try await stateStore.load() else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    try validateStateBinding(snapshot.state, record: marker.record)
    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: stateRootURL,
      identity: context.identity,
      stateStore: stateStore,
      keyStore: keyStore,
      guardKey: context.keys.counterGuard
    )
    try await coordinator.auditBootstrap(
      CounterBootstrapEvidence(
        initialStateCommitment: marker.initialStateCommitment,
        initialGuardCommitment: marker.initialGuardCommitment
      ),
      promotionID: marker.promotionID,
      under: lease
    )
    guard let finalSnapshot = try await stateStore.load(),
      let finalGuard = try await keyStore.load(context.keys.counterGuard)
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    try validateStateBinding(finalSnapshot.state, record: marker.record)
    return AuditedPairedMachineDependencies(
      credentials: credentials,
      cryptoState: finalSnapshot,
      cryptoStateStore: stateStore,
      cryptoStateCoordinator: coordinator,
      cleanupBindings: AuditedCleanupBindings(
        stateCommitment: finalSnapshot.commitment,
        guardHash: CanonicalCodec.sha256(finalGuard)
      )
    )
  }

  private func deleteExact(
    _ record: StoredPairedMachineRecordV1,
    context: MachineContext,
    under lease: MachineCryptoLease
  ) async throws {
    guard await lease.isActive(for: context.leaseManager.identifier) else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    guard let markerData = try await keyStore.load(context.keys.marker) else {
      return
    }
    var marker = try PairedMachineMarkerCodec.decode(markerData)
    try validateMarker(marker, at: context.keys.marker)
    guard marker.record == record else {
      throw PairedMachineStoreError.persistenceMismatch
    }

    var cleanupData = markerData
    if marker.phase == .committed || marker.phase == .staged {
      let audited = try await auditDependencies(marker, context: context, under: lease)
      marker = marker.withCleanup(audited.cleanupBindings)
      cleanupData = try PairedMachineMarkerCodec.encode(marker)
      try await keyStore.compareAndReplaceExact(
        expected: markerData,
        replacement: cleanupData,
        for: context.keys.marker
      )
      guard try await keyStore.load(context.keys.marker) == cleanupData else {
        throw KeyStoreError.persistenceReadbackFailed
      }
    }

    try await validateCleanupDependencies(marker: marker, context: context)
    try await deleteStateIfPresent(marker: marker, context: context)
    guard let currentGuardHash = marker.cleanupGuardHash else {
      throw PairedMachineStoreError.invalidRecord
    }
    try await deleteHashedMaterialIfPresent(
      context.keys.counterGuard,
      expectedHash: currentGuardHash
    )
    try await deleteHashedMaterialIfPresent(
      context.keys.grant,
      expectedHash: marker.grantHash
    )
    try await deleteHashedMaterialIfPresent(
      context.keys.deviceHPKE,
      expectedHash: marker.deviceHPKEHash
    )
    try await deleteHashedMaterialIfPresent(
      context.keys.deviceSign,
      expectedHash: marker.deviceSignHash
    )
    try await deleteHashedMaterialIfPresent(
      context.keys.storageKEK,
      expectedHash: marker.storageKEKHash
    )
    try await keyStore.deleteExact(expected: cleanupData, for: context.keys.marker)
    guard try await keyStore.load(context.keys.marker) == nil else {
      throw KeyStoreError.deleteReadbackFailed
    }
  }

  private func abortPairingPromotion(
    binding: PairingPromotionRollbackBinding,
    context: MachineContext,
    under lease: MachineCryptoLease
  ) async throws {
    guard await lease.isActive(for: context.leaseManager.identifier) else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    if let markerData = try await keyStore.load(context.keys.marker) {
      let marker = try PairedMachineMarkerCodec.decode(markerData)
      try validateMarker(marker, at: context.keys.marker)
      guard marker.promotionID == binding.promotionID,
        marker.record == binding.record
      else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      try await deleteExact(marker.record, context: context, under: lease)
      return
    }

    let storageKEK = try await keyStore.load(context.keys.storageKEK)
    let sign = try await keyStore.load(context.keys.deviceSign)
    let hpke = try await keyStore.load(context.keys.deviceHPKE)
    let grantBytes = try await keyStore.load(context.keys.grant)
    let guardBytes = try await keyStore.load(context.keys.counterGuard)
    guard storageKEK == nil || storageKEK == binding.storageKEK,
      sign == nil || binding.exactDeviceSignPrivateKey == nil
        || sign == binding.exactDeviceSignPrivateKey,
      hpke == nil || binding.exactDeviceHPKEPrivateKey == nil
        || hpke == binding.exactDeviceHPKEPrivateKey,
      guardBytes == nil || !(guardBytes?.isEmpty ?? true)
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }

    let stateStore: FileCryptoStateStore?
    let snapshot: CryptoStateSnapshot?
    if let storageKEK {
      let store = try FileCryptoStateStore(
        rootURL: stateRootURL,
        identity: context.identity,
        storageKey: DeviceStorageKEK(rawRepresentation: storageKEK),
        testHooks: .none,
        testingFileProtectionPolicy: stateFileProtectionPolicy
      )
      stateStore = store
      snapshot = try await store.load()
    } else {
      let stateURL = FileCryptoStateStore.stateURL(
        rootURL: stateRootURL,
        identity: context.identity
      )
      guard try !FileCryptoStateStore.entryExistsNoFollow(at: stateURL) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      stateStore = nil
      snapshot = nil
    }

    do {
      if let sign {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sign)
        guard privateKey.publicKey.rawRepresentation == binding.deviceSignPublicKey else {
          throw PairedMachineStoreError.persistenceMismatch
        }
      }
      if let hpke {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hpke)
        guard privateKey.publicKey.rawRepresentation == binding.deviceHPKEPublicKey else {
          throw PairedMachineStoreError.persistenceMismatch
        }
      }
    } catch is PairedMachineStoreError {
      throw PairedMachineStoreError.persistenceMismatch
    } catch {
      throw PairedMachineStoreError.persistenceMismatch
    }

    let verifiedGrant: VerifiedRelayGrantCredential?
    if let grantBytes {
      let grant = try RelayGrantCanonicalCodec.decode(grantBytes)
      do {
        verifiedGrant = try RelayGrantCredentialVerifier.verify(
          grant,
          relayServerID: binding.record.relayServerID,
          machineRootPublicKey: binding.record.machineRootPublicKey,
          machineRootFingerprint: binding.record.machineRootFingerprint,
          expectedMachineRoute: binding.record.machineRoute,
          expectedDeviceRoute: binding.record.deviceRoute,
          expectedDeviceSignPublicKey: binding.deviceSignPublicKey,
          expectedGrantSerial: binding.record.grantSerial,
          expectedRootKeyID: binding.record.machineDataCertificate.rootKeyId,
          expectedTrustEpoch: binding.record.trustEpoch
        )
      } catch {
        throw PairedMachineStoreError.persistenceMismatch
      }
    } else {
      verifiedGrant = nil
    }

    if let snapshot {
      let trust = snapshot.state.trustScope
      guard snapshot.state.stateRevision == 1,
        trust.relayServerID == binding.record.relayServerID,
        trust.machineRootFingerprint == binding.record.machineRootFingerprint,
        trust.machineRoute == binding.record.machineRoute,
        trust.deviceRoute == binding.record.deviceRoute,
        trust.grantSerial == binding.record.grantSerial,
        trust.trustEpoch == binding.record.trustEpoch,
        verifiedGrant.map({
          trust.grantSerial == $0.grant.grantSerial
            && trust.trustEpoch == $0.grant.trustEpoch
        }) ?? true
      else {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }

    if let guardBytes {
      guard let snapshot else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      do {
        try DurableCryptoStateCoordinator.auditInitialBootstrapGuard(
          guardBytes,
          snapshot: snapshot,
          promotionID: binding.promotionID
        )
      } catch {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }

    // promotion 合法 partial 只能是创建顺序的 present-prefix；反向删除后，任意
    // cleanup crash 仍保持同一形状，可由 retained pending response marker 冷恢复。
    let presence = [
      storageKEK != nil,
      snapshot != nil,
      sign != nil,
      hpke != nil,
      grantBytes != nil,
      guardBytes != nil,
    ]
    var reachedMissingSuffix = false
    for itemIsPresent in presence {
      if itemIsPresent {
        guard !reachedMissingSuffix else {
          throw PairedMachineStoreError.persistenceMismatch
        }
      } else {
        reachedMissingSuffix = true
      }
    }

    guard try await keyStore.load(context.keys.marker) == nil else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    if let guardBytes {
      try await keyStore.deleteExact(expected: guardBytes, for: context.keys.counterGuard)
    }
    if let grantBytes {
      try await keyStore.deleteExact(expected: grantBytes, for: context.keys.grant)
    }
    if let hpke {
      try await keyStore.deleteExact(expected: hpke, for: context.keys.deviceHPKE)
    }
    if let sign {
      try await keyStore.deleteExact(expected: sign, for: context.keys.deviceSign)
    }
    if let snapshot, let stateStore {
      try await stateStore.deleteExact(expected: snapshot)
    }
    if let storageKEK {
      try await keyStore.deleteExact(expected: storageKEK, for: context.keys.storageKEK)
    }
    let stateURL = FileCryptoStateStore.stateURL(
      rootURL: stateRootURL,
      identity: context.identity
    )
    guard try await keyStore.load(context.keys.counterGuard) == nil,
      try await keyStore.load(context.keys.grant) == nil,
      try await keyStore.load(context.keys.deviceHPKE) == nil,
      try await keyStore.load(context.keys.deviceSign) == nil,
      try await keyStore.load(context.keys.storageKEK) == nil,
      try !FileCryptoStateStore.entryExistsNoFollow(at: stateURL),
      try await keyStore.load(context.keys.marker) == nil
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
  }

  private func validateCleanupDependencies(
    marker: PairedMachineMarker,
    context: MachineContext
  ) async throws {
    guard marker.phase == .cleanup,
      let stateCommitment = marker.cleanupStateCommitment,
      let guardHash = marker.cleanupGuardHash
    else {
      throw PairedMachineStoreError.invalidRecord
    }

    let rawKEK = try await keyStore.load(context.keys.storageKEK)
    let stateIsPresent: Bool
    if let rawKEK {
      guard CanonicalCodec.sha256(rawKEK) == marker.storageKEKHash else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      let stateStore = try FileCryptoStateStore(
        rootURL: stateRootURL,
        identity: context.identity,
        storageKey: DeviceStorageKEK(rawRepresentation: rawKEK),
        testHooks: .none,
        testingFileProtectionPolicy: stateFileProtectionPolicy
      )
      if let snapshot = try await stateStore.load() {
        guard snapshot.commitment == stateCommitment else {
          throw PairedMachineStoreError.persistenceMismatch
        }
        try validateStateBinding(snapshot.state, record: marker.record)
        stateIsPresent = true
      } else {
        stateIsPresent = false
      }
    } else {
      let stateURL = FileCryptoStateStore.stateURL(
        rootURL: stateRootURL,
        identity: context.identity
      )
      guard try !FileCryptoStateStore.entryExistsNoFollow(at: stateURL) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      stateIsPresent = false
    }

    let guardValue = try await loadCleanupMaterialIfPresent(
      context.keys.counterGuard,
      expectedHash: guardHash
    )
    let grant = try await loadCleanupMaterialIfPresent(
      context.keys.grant,
      expectedHash: marker.grantHash
    )
    let hpke = try await loadCleanupMaterialIfPresent(
      context.keys.deviceHPKE,
      expectedHash: marker.deviceHPKEHash
    )
    let sign = try await loadCleanupMaterialIfPresent(
      context.keys.deviceSign,
      expectedHash: marker.deviceSignHash
    )
    if let grant {
      guard !grant.isEmpty,
        grant.count <= PreparedPairedMachinePromotionV1.maximumGrantBytes
      else {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }
    if let hpke {
      guard Self.isPrivateKey(hpke) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }
    if let sign {
      guard Self.isPrivateKey(sign) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }

    // cleanup 的合法 crash cut 只能形成 missing-prefix + present-suffix。
    let presence = [
      stateIsPresent,
      guardValue != nil,
      grant != nil,
      hpke != nil,
      sign != nil,
      rawKEK != nil,
    ]
    var reachedPresentSuffix = false
    for itemIsPresent in presence {
      if itemIsPresent {
        reachedPresentSuffix = true
      } else if reachedPresentSuffix {
        throw PairedMachineStoreError.persistenceMismatch
      }
    }
  }

  private func deleteStateIfPresent(
    marker: PairedMachineMarker,
    context: MachineContext
  ) async throws {
    guard let rawKey = try await keyStore.load(context.keys.storageKEK) else {
      let stateURL = FileCryptoStateStore.stateURL(
        rootURL: stateRootURL,
        identity: context.identity
      )
      guard try !FileCryptoStateStore.entryExistsNoFollow(at: stateURL) else {
        throw PairedMachineStoreError.persistenceMismatch
      }
      return
    }
    guard CanonicalCodec.sha256(rawKey) == marker.storageKEKHash else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    let stateStore = try FileCryptoStateStore(
      rootURL: stateRootURL,
      identity: context.identity,
      storageKey: DeviceStorageKEK(rawRepresentation: rawKey),
      testHooks: .none,
      testingFileProtectionPolicy: stateFileProtectionPolicy
    )
    guard let snapshot = try await stateStore.load() else { return }
    guard let currentStateCommitment = marker.cleanupStateCommitment,
      snapshot.commitment == currentStateCommitment
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    try validateStateBinding(snapshot.state, record: marker.record)
    try await stateStore.deleteExact(expected: snapshot)
    guard try await stateStore.load() == nil else {
      throw CryptoStateStoreError.persistenceReadbackFailed
    }
  }

  private func makeContext(record: StoredPairedMachineRecordV1) throws -> MachineContext {
    let identity = try CryptoStateIdentity(
      clientKind: record.clientKind,
      installationID: record.installationID,
      machineID: record.machineID,
      machineRootFingerprint: record.machineRootFingerprint,
      machineRoute: record.machineRoute
    )
    return MachineContext(
      identity: identity,
      leaseManager: try MachineCryptoLeaseManager(
        rootURL: stateRootURL,
        identity: identity
      ),
      keys: try MachineKeys(record: record)
    )
  }

  private func makePartialPairingContext(
    rootFingerprint: Data,
    machineRoute: Data
  ) throws -> MachineContext {
    let identity = try CryptoStateIdentity(
      clientKind: clientKind,
      installationID: installationID,
      machineID: PairingPromotionBuilder.machineID(rootFingerprint: rootFingerprint),
      machineRootFingerprint: rootFingerprint,
      machineRoute: machineRoute
    )
    return MachineContext(
      identity: identity,
      leaseManager: try MachineCryptoLeaseManager(
        rootURL: stateRootURL,
        identity: identity
      ),
      keys: try MachineKeys(
        clientKind: clientKind,
        installationID: installationID,
        rootFingerprint: rootFingerprint,
        machineRoute: machineRoute
      )
    )
  }

  private func pairingPromotionBinding(
    prepared: PreparedPendingPairingV1,
    response: PendingPairingResponseStateV1
  ) throws -> PairingPromotionRollbackBinding {
    guard prepared.record.clientKind == clientKind,
      prepared.record.installationID == installationID,
      response.machineRoute.count == 16,
      response.deviceRoute.count == 16
    else {
      throw PairedMachineStoreError.invalidBinding
    }
    do {
      try PairingPromotionBuilder.auditResponseState(
        response,
        clientKind: clientKind,
        installationID: installationID,
        inviteHash: prepared.record.inviteHash,
        requestHash: prepared.record.requestHash,
        deviceSigningPublicKey: prepared.deviceSigningKey.publicKey
      )
    } catch {
      throw PairedMachineStoreError.invalidBinding
    }
    let pairedRecord: StoredPairedMachineRecordV1
    do {
      pairedRecord = try PairedMachineRecordCodec.decode(
        response.pairedRecordCanonicalBytes
      )
    } catch {
      throw PairedMachineStoreError.invalidBinding
    }
    guard pairedRecord.clientKind == clientKind,
      pairedRecord.installationID == installationID,
      pairedRecord.machineRootPublicKey == prepared.invite.machineRootPublicKey,
      pairedRecord.machineRootFingerprint == prepared.invite.machineRootFingerprint,
      pairedRecord.relayServerID == prepared.invite.relayServerID,
      pairedRecord.machineRoute == response.machineRoute,
      pairedRecord.deviceRoute == response.deviceRoute,
      pairedRecord.createdAtMS == response.createdAtMilliseconds
    else {
      throw PairedMachineStoreError.invalidBinding
    }
    return PairingPromotionRollbackBinding(
      record: pairedRecord,
      promotionID: response.promotionID,
      storageKEK: response.storageKEK,
      deviceSignPublicKey: prepared.record.deviceSignPublicKey,
      deviceHPKEPublicKey: prepared.record.deviceHPKEPublicKey,
      exactDeviceSignPrivateKey: prepared.deviceSigningKey.rawRepresentation,
      exactDeviceHPKEPrivateKey: prepared.deviceHPKEPrivateKey.rawRepresentation
    )
  }

  private func pairingPromotionBinding(
    pendingRecord: PendingPairingRecordV1,
    response: PendingPairingResponseStateV1
  ) throws -> PairingPromotionRollbackBinding {
    guard pendingRecord.clientKind == clientKind,
      pendingRecord.installationID == installationID
    else {
      throw PairedMachineStoreError.invalidBinding
    }
    let signingPublicKey: Curve25519.Signing.PublicKey
    do {
      signingPublicKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: pendingRecord.deviceSignPublicKey
      )
      try PairingPromotionBuilder.auditResponseState(
        response,
        clientKind: clientKind,
        installationID: installationID,
        inviteHash: pendingRecord.inviteHash,
        requestHash: pendingRecord.requestHash,
        deviceSigningPublicKey: signingPublicKey
      )
    } catch {
      throw PairedMachineStoreError.invalidBinding
    }
    let pairedRecord: StoredPairedMachineRecordV1
    do {
      pairedRecord = try PairedMachineRecordCodec.decode(
        response.pairedRecordCanonicalBytes
      )
    } catch {
      throw PairedMachineStoreError.invalidBinding
    }
    guard pairedRecord.clientKind == clientKind,
      pairedRecord.installationID == installationID,
      pairedRecord.machineRoute == response.machineRoute,
      pairedRecord.deviceRoute == response.deviceRoute,
      pairedRecord.createdAtMS == response.createdAtMilliseconds
    else {
      throw PairedMachineStoreError.invalidBinding
    }
    return PairingPromotionRollbackBinding(
      record: pairedRecord,
      promotionID: response.promotionID,
      storageKEK: response.storageKEK,
      deviceSignPublicKey: pendingRecord.deviceSignPublicKey,
      deviceHPKEPublicKey: pendingRecord.deviceHPKEPublicKey,
      exactDeviceSignPrivateKey: nil,
      exactDeviceHPKEPrivateKey: nil
    )
  }

  private func markerKey(
    rootFingerprint: Data,
    machineRoute: Data
  ) throws -> KeyStoreKey {
    do {
      return try KeyStoreKey.paired(
        clientKind: clientKind,
        installationID: installationID,
        rootFingerprint: rootFingerprint,
        machineRoute: machineRoute,
        purpose: .commitMarker
      )
    } catch {
      throw PairedMachineStoreError.invalidRecord
    }
  }

  private func validateMarker(
    _ marker: PairedMachineMarker,
    at actualKey: KeyStoreKey
  ) throws {
    try validateBinding(marker.record)
    let expected = try markerKey(
      rootFingerprint: marker.record.machineRootFingerprint,
      machineRoute: marker.record.machineRoute
    )
    guard actualKey == expected else {
      throw PairedMachineStoreError.invalidBinding
    }
  }

  private func validateBinding(_ record: StoredPairedMachineRecordV1) throws {
    guard record.clientKind == clientKind,
      record.installationID == installationID
    else {
      throw PairedMachineStoreError.invalidBinding
    }
  }

  private func validateStateBinding(
    _ state: DeviceCryptoStateV1,
    record: StoredPairedMachineRecordV1
  ) throws {
    let trust = state.trustScope
    guard trust.relayServerID == record.relayServerID,
      trust.machineRootFingerprint == record.machineRootFingerprint,
      trust.machineRoute == record.machineRoute,
      trust.deviceRoute == record.deviceRoute,
      trust.grantSerial == record.grantSerial,
      trust.trustEpoch == record.trustEpoch
    else {
      throw PairedMachineStoreError.invalidBinding
    }
  }

  private func persistAndReadBack(_ data: Data, for key: KeyStoreKey) async throws {
    _ = try await keyStore.persistImmutable(data, for: key)
    guard try await keyStore.load(key) == data else {
      throw KeyStoreError.persistenceReadbackFailed
    }
  }

  private func loadMaterial(
    _ key: KeyStoreKey,
    expectedHash: Data
  ) async throws -> Data {
    guard let value = try await keyStore.load(key),
      CanonicalCodec.sha256(value) == expectedHash
    else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    return value
  }

  private func loadCleanupMaterialIfPresent(
    _ key: KeyStoreKey,
    expectedHash: Data
  ) async throws -> Data? {
    guard let value = try await keyStore.load(key) else { return nil }
    guard CanonicalCodec.sha256(value) == expectedHash else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    return value
  }

  private func deleteHashedMaterialIfPresent(
    _ key: KeyStoreKey,
    expectedHash: Data
  ) async throws {
    guard let value = try await keyStore.load(key) else { return }
    guard CanonicalCodec.sha256(value) == expectedHash else {
      throw PairedMachineStoreError.persistenceMismatch
    }
    try await keyStore.deleteExact(expected: value, for: key)
    guard try await keyStore.load(key) == nil else {
      throw KeyStoreError.deleteReadbackFailed
    }
  }

  private static func isPrivateKey(_ data: Data) -> Bool {
    data.count == PreparedPairedMachinePromotionV1.privateKeyBytes
      && data.contains(where: { $0 != 0 })
  }
}

private struct MachineContext {
  let identity: CryptoStateIdentity
  let leaseManager: MachineCryptoLeaseManager
  let keys: MachineKeys
}

private struct PairingPromotionRollbackBinding {
  let record: StoredPairedMachineRecordV1
  let promotionID: Data
  let storageKEK: Data
  let deviceSignPublicKey: Data
  let deviceHPKEPublicKey: Data
  let exactDeviceSignPrivateKey: Data?
  let exactDeviceHPKEPrivateKey: Data?
}

private struct AuditedCleanupBindings {
  let stateCommitment: Data
  let guardHash: Data
}

private struct AuditedPairedMachineDependencies {
  let credentials: AuditedPairedCredentials
  let cryptoState: CryptoStateSnapshot
  let cryptoStateStore: FileCryptoStateStore
  let cryptoStateCoordinator: DurableCryptoStateCoordinator
  let cleanupBindings: AuditedCleanupBindings
}

private struct MachineKeys {
  let deviceSign: KeyStoreKey
  let deviceHPKE: KeyStoreKey
  let grant: KeyStoreKey
  let storageKEK: KeyStoreKey
  let counterGuard: KeyStoreKey
  let marker: KeyStoreKey

  init(record: StoredPairedMachineRecordV1) throws {
    try self.init(
      clientKind: record.clientKind,
      installationID: record.installationID,
      rootFingerprint: record.machineRootFingerprint,
      machineRoute: record.machineRoute
    )
  }

  init(
    clientKind: RelayClientKind,
    installationID: UUID,
    rootFingerprint: Data,
    machineRoute: Data
  ) throws {
    func key(_ purpose: PairedKeyStorePurpose) throws -> KeyStoreKey {
      try KeyStoreKey.paired(
        clientKind: clientKind,
        installationID: installationID,
        rootFingerprint: rootFingerprint,
        machineRoute: machineRoute,
        purpose: purpose
      )
    }
    deviceSign = try key(.deviceSignPrivateKey)
    deviceHPKE = try key(.deviceHPKEPrivateKey)
    grant = try key(.deviceGrant)
    storageKEK = try key(.deviceStorageKEK)
    counterGuard = try key(.counterGuard)
    marker = try key(.commitMarker)
  }
}

private enum PairedMachineMarkerPhase: UInt8, Equatable {
  case committed = 0
  case cleanup = 1
  case staged = 2
}

private struct PairedMachineMarker: Equatable {
  let phase: PairedMachineMarkerPhase
  let record: StoredPairedMachineRecordV1
  let promotionID: Data
  let initialStateCommitment: Data
  let initialGuardCommitment: Data
  let deviceSignHash: Data
  let deviceHPKEHash: Data
  let grantHash: Data
  let storageKEKHash: Data
  let cleanupStateCommitment: Data?
  let cleanupGuardHash: Data?

  func withCleanup(_ bindings: AuditedCleanupBindings) -> Self {
    Self(
      phase: .cleanup,
      record: record,
      promotionID: promotionID,
      initialStateCommitment: initialStateCommitment,
      initialGuardCommitment: initialGuardCommitment,
      deviceSignHash: deviceSignHash,
      deviceHPKEHash: deviceHPKEHash,
      grantHash: grantHash,
      storageKEKHash: storageKEKHash,
      cleanupStateCommitment: bindings.stateCommitment,
      cleanupGuardHash: bindings.guardHash
    )
  }

  func withPhase(_ phase: PairedMachineMarkerPhase) -> Self {
    precondition(phase == .staged || phase == .committed)
    return Self(
      phase: phase,
      record: record,
      promotionID: promotionID,
      initialStateCommitment: initialStateCommitment,
      initialGuardCommitment: initialGuardCommitment,
      deviceSignHash: deviceSignHash,
      deviceHPKEHash: deviceHPKEHash,
      grantHash: grantHash,
      storageKEKHash: storageKEKHash,
      cleanupStateCommitment: nil,
      cleanupGuardHash: nil
    )
  }

  func matches(_ prepared: PreparedPairedMachinePromotionV1) -> Bool {
    record == prepared.record
      && promotionID == prepared.promotionID32
      && initialStateCommitment == prepared.initialCryptoState.commitment
      && deviceSignHash == CanonicalCodec.sha256(prepared.deviceSignPrivateKey)
      && deviceHPKEHash == CanonicalCodec.sha256(prepared.deviceHPKEPrivateKey)
      && grantHash == CanonicalCodec.sha256(prepared.deviceGrant)
      && storageKEKHash
        == CanonicalCodec.sha256(prepared.deviceStorageKEK.rawRepresentation)
      && cleanupStateCommitment == nil
      && cleanupGuardHash == nil
  }
}

private enum PairedMachineMarkerCodec {
  private static let maximumMarkerBytes = 64 * 1_024

  static func encode(_ marker: PairedMachineMarker) throws -> Data {
    var encoder = RecordEncoder()
    encoder.fixed(Data("ADPM".utf8))
    encoder.u16(2)
    encoder.u8(marker.phase.rawValue)
    encoder.u8(0)
    try encoder.bytes(PairedMachineRecordCodec.encode(marker.record))
    encoder.fixed(marker.promotionID)
    encoder.fixed(marker.initialStateCommitment)
    encoder.fixed(marker.initialGuardCommitment)
    encoder.fixed(marker.deviceSignHash)
    encoder.fixed(marker.deviceHPKEHash)
    encoder.fixed(marker.grantHash)
    encoder.fixed(marker.storageKEKHash)
    switch marker.phase {
    case .committed, .staged:
      guard marker.cleanupStateCommitment == nil,
        marker.cleanupGuardHash == nil
      else {
        throw PairedMachineStoreError.invalidRecord
      }
      encoder.fixed(Data(repeating: 0, count: 64))
    case .cleanup:
      guard let stateCommitment = marker.cleanupStateCommitment,
        let guardHash = marker.cleanupGuardHash,
        stateCommitment.count == 32,
        stateCommitment.contains(where: { $0 != 0 }),
        guardHash.count == 32,
        guardHash.contains(where: { $0 != 0 })
      else {
        throw PairedMachineStoreError.invalidRecord
      }
      encoder.fixed(stateCommitment)
      encoder.fixed(guardHash)
    }
    guard encoder.data.count <= maximumMarkerBytes else {
      throw PairedMachineStoreError.invalidRecord
    }
    return encoder.data
  }

  static func decode(_ data: Data) throws -> PairedMachineMarker {
    guard data.count <= maximumMarkerBytes else {
      throw PairedMachineStoreError.invalidRecord
    }
    var decoder = RecordDecoder(data: data)
    guard try decoder.fixed(count: 4) == Data("ADPM".utf8),
      try decoder.u16() == 2,
      let phase = PairedMachineMarkerPhase(rawValue: try decoder.u8()),
      try decoder.u8() == 0
    else {
      throw PairedMachineStoreError.invalidRecord
    }
    let record = try PairedMachineRecordCodec.decode(try decoder.bytes())
    let promotionID = try decoder.nonzeroFixed(count: 32)
    let initialStateCommitment = try decoder.nonzeroFixed(count: 32)
    let initialGuardCommitment = try decoder.nonzeroFixed(count: 32)
    let deviceSignHash = try decoder.nonzeroFixed(count: 32)
    let deviceHPKEHash = try decoder.nonzeroFixed(count: 32)
    let grantHash = try decoder.nonzeroFixed(count: 32)
    let storageKEKHash = try decoder.nonzeroFixed(count: 32)
    let cleanupStateCommitment: Data?
    let cleanupGuardHash: Data?
    switch phase {
    case .committed, .staged:
      guard try decoder.fixed(count: 64).allSatisfy({ $0 == 0 }) else {
        throw PairedMachineStoreError.invalidRecord
      }
      cleanupStateCommitment = nil
      cleanupGuardHash = nil
    case .cleanup:
      cleanupStateCommitment = try decoder.nonzeroFixed(count: 32)
      cleanupGuardHash = try decoder.nonzeroFixed(count: 32)
    }
    guard decoder.isAtEnd else {
      throw PairedMachineStoreError.invalidRecord
    }
    return PairedMachineMarker(
      phase: phase,
      record: record,
      promotionID: promotionID,
      initialStateCommitment: initialStateCommitment,
      initialGuardCommitment: initialGuardCommitment,
      deviceSignHash: deviceSignHash,
      deviceHPKEHash: deviceHPKEHash,
      grantHash: grantHash,
      storageKEKHash: storageKEKHash,
      cleanupStateCommitment: cleanupStateCommitment,
      cleanupGuardHash: cleanupGuardHash
    )
  }
}

enum PairedMachineRecordCodec {
  static let maximumRecordBytes = 48 * 1_024

  static func encode(_ record: StoredPairedMachineRecordV1) throws -> Data {
    var encoder = RecordEncoder()
    encoder.fixed(Data("ADPR".utf8))
    encoder.u16(2)
    encoder.u16(0)
    switch record.clientKind {
    case .macOSApp: encoder.u8(0)
    case .iOSApp: encoder.u8(1)
    case .cli: encoder.u8(2)
    }
    encoder.fixed(uuidBytes(record.installationID))
    try encoder.bytes(Data(record.machineID.utf8))
    try encoder.bytes(Data(record.machineName.utf8))
    try encoder.bytes(Data(record.relayURL.absoluteString.utf8))
    encoder.fixed(record.relayServerID)
    encoder.fixed(record.machineRootPublicKey)
    encoder.fixed(record.machineRootFingerprint)
    encodeDataCertificate(record.machineDataCertificate, to: &encoder)
    encoder.fixed(record.machineRoute)
    encoder.fixed(record.deviceRoute)
    encoder.fixed(record.currentSPKIPin)
    if let next = record.nextSPKIPin {
      encoder.u8(1)
      encoder.fixed(next)
    } else {
      encoder.u8(0)
    }
    encoder.u64(record.grantSerial)
    encoder.u64(record.trustEpoch)
    encoder.u64(record.createdAtMS)
    guard encoder.data.count <= maximumRecordBytes else {
      throw PairedMachineStoreError.invalidRecord
    }
    return encoder.data
  }

  static func decode(_ data: Data) throws -> StoredPairedMachineRecordV1 {
    guard data.count <= maximumRecordBytes else {
      throw PairedMachineStoreError.invalidRecord
    }
    var decoder = RecordDecoder(data: data)
    guard try decoder.fixed(count: 4) == Data("ADPR".utf8),
      try decoder.u16() == 2,
      try decoder.u16() == 0
    else {
      throw PairedMachineStoreError.invalidRecord
    }
    let clientKind: RelayClientKind
    switch try decoder.u8() {
    case 0: clientKind = .macOSApp
    case 1: clientKind = .iOSApp
    case 2: clientKind = .cli
    default: throw PairedMachineStoreError.invalidRecord
    }
    let installationID = try uuid(try decoder.fixed(count: 16))
    let machineID = try string(try decoder.bytes())
    let machineName = try string(try decoder.bytes())
    guard let relayURL = URL(string: try string(try decoder.bytes())) else {
      throw PairedMachineStoreError.invalidRecord
    }
    let relayServerID = try decoder.fixed(count: 16)
    let rootPublicKey = try decoder.fixed(count: 32)
    let root = try decoder.fixed(count: 32)
    let dataCertificate = try decodeDataCertificate(from: &decoder)
    let machineRoute = try decoder.fixed(count: 16)
    let deviceRoute = try decoder.fixed(count: 16)
    let currentPin = try decoder.fixed(count: 32)
    let nextPin: Data?
    switch try decoder.u8() {
    case 0: nextPin = nil
    case 1: nextPin = try decoder.fixed(count: 32)
    default: throw PairedMachineStoreError.invalidRecord
    }
    let grantSerial = try decoder.u64()
    let trustEpoch = try decoder.u64()
    let createdAtMS = try decoder.u64()
    guard decoder.isAtEnd else {
      throw PairedMachineStoreError.invalidRecord
    }
    return try StoredPairedMachineRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      machineID: machineID,
      machineName: machineName,
      relayURL: relayURL,
      relayServerID: relayServerID,
      machineRootPublicKey: rootPublicKey,
      machineRootFingerprint: root,
      machineDataCertificate: dataCertificate,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      currentSPKIPin: currentPin,
      nextSPKIPin: nextPin,
      grantSerial: grantSerial,
      trustEpoch: trustEpoch,
      createdAtMS: createdAtMS
    )
  }

  private static func encodeDataCertificate(
    _ certificate: RelayV2SignedCertificate,
    to encoder: inout RecordEncoder
  ) {
    encoder.fixed(certificate.subjectPubkey)
    encoder.u8(certificate.certRole == .link ? 0 : 1)
    encoder.u64(certificate.generation)
    encoder.fixed(certificate.rootKeyId)
    encoder.u64(certificate.trustEpoch)
    if let notAfterMS = certificate.notAfterMs {
      encoder.u8(1)
      encoder.u64(notAfterMS)
    } else {
      encoder.u8(0)
    }
    encoder.fixed(certificate.signature)
  }

  private static func decodeDataCertificate(
    from decoder: inout RecordDecoder
  ) throws -> RelayV2SignedCertificate {
    let subjectPublicKey = try decoder.fixed(count: 32)
    let role: RelayV2CertRole
    switch try decoder.u8() {
    case 0: role = .link
    case 1: role = .data
    default: throw PairedMachineStoreError.invalidRecord
    }
    let generation = try decoder.u64()
    let rootKeyID = try decoder.fixed(count: 16)
    let trustEpoch = try decoder.u64()
    let notAfterMS: UInt64?
    switch try decoder.u8() {
    case 0: notAfterMS = nil
    case 1: notAfterMS = try decoder.u64()
    default: throw PairedMachineStoreError.invalidRecord
    }
    return RelayV2SignedCertificate(
      subjectPubkey: subjectPublicKey,
      certRole: role,
      generation: generation,
      rootKeyId: rootKeyID,
      trustEpoch: trustEpoch,
      notAfterMs: notAfterMS,
      signature: try decoder.fixed(count: 64)
    )
  }

  private static func uuidBytes(_ value: UUID) -> Data {
    var bytes = value.uuid
    return Swift.withUnsafeBytes(of: &bytes) { Data($0) }
  }

  private static func uuid(_ bytes: Data) throws -> UUID {
    guard bytes.count == 16 else { throw PairedMachineStoreError.invalidRecord }
    let values = [UInt8](bytes)
    return UUID(
      uuid: (
        values[0], values[1], values[2], values[3],
        values[4], values[5], values[6], values[7],
        values[8], values[9], values[10], values[11],
        values[12], values[13], values[14], values[15]
      ))
  }

  private static func string(_ data: Data) throws -> String {
    guard let value = String(data: data, encoding: .utf8) else {
      throw PairedMachineStoreError.invalidRecord
    }
    return value
  }
}

private struct RecordEncoder {
  var data = Data()

  mutating func u8(_ value: UInt8) { data.append(value) }
  mutating func u16(_ value: UInt16) { append(value) }
  mutating func u64(_ value: UInt64) { append(value) }
  mutating func fixed(_ value: Data) { data.append(value) }

  mutating func bytes(_ value: Data) throws {
    guard let count = UInt32(exactly: value.count) else {
      throw PairedMachineStoreError.invalidRecord
    }
    append(count)
    data.append(value)
  }

  private mutating func append<T: FixedWidthInteger>(_ value: T) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
  }
}

private struct RecordDecoder {
  let data: Data
  var offset = 0
  var isAtEnd: Bool { offset == data.count }

  mutating func u8() throws -> UInt8 {
    try fixed(count: 1)[0]
  }

  mutating func u16() throws -> UInt16 {
    try integer(count: 2, as: UInt16.self)
  }

  mutating func u64() throws -> UInt64 {
    try integer(count: 8, as: UInt64.self)
  }

  mutating func bytes() throws -> Data {
    let count = Int(try integer(count: 4, as: UInt32.self))
    return try fixed(count: count)
  }

  mutating func nonzeroFixed(count: Int) throws -> Data {
    let value = try fixed(count: count)
    guard value.contains(where: { $0 != 0 }) else {
      throw PairedMachineStoreError.invalidRecord
    }
    return value
  }

  mutating func fixed(count: Int) throws -> Data {
    let addition = offset.addingReportingOverflow(count)
    guard count >= 0, !addition.overflow, addition.partialValue <= data.count else {
      throw PairedMachineStoreError.invalidRecord
    }
    let end = addition.partialValue
    defer { offset = end }
    return data.subdata(in: offset..<end)
  }

  private mutating func integer<T: FixedWidthInteger>(
    count: Int,
    as _: T.Type
  ) throws -> T {
    try fixed(count: count).reduce(0) { ($0 << 8) | T($1) }
  }
}
