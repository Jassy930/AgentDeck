import CryptoKit
import Foundation

enum PendingPairingStoreError: Error, Equatable, Sendable {
  case invalidBinding
  case invalidRecord
  case incompleteState
  case immutableConflict
  case persistenceMismatch
}

struct PendingPairingRecoveryIntentV1: Equatable, Sendable {
  let clientKind: RelayClientKind
  let installationID: UUID
  let inviteHash: Data
  let expiresAtMilliseconds: UInt64

  init(
    clientKind: RelayClientKind,
    installationID: UUID,
    inviteHash: Data,
    expiresAtMilliseconds: UInt64
  ) throws {
    guard isNonzeroRelayInstallationID(installationID),
      inviteHash.count == 32,
      inviteHash.contains(where: { $0 != 0 }),
      expiresAtMilliseconds > 0
    else {
      throw PendingPairingStoreError.invalidRecord
    }
    self.clientKind = clientKind
    self.installationID = installationID
    self.inviteHash = inviteHash
    self.expiresAtMilliseconds = expiresAtMilliseconds
  }
}

struct PendingPairingCleanupCandidateV1: Sendable {
  let inviteHash: Data
  let intent: PendingPairingRecoveryIntentV1?
  let canonicalIntent: Data?
  let record: PendingPairingRecordV1?
  let canonicalRecord: Data?
}

struct PendingPairingResponseStateV1: Equatable, Sendable, CustomDebugStringConvertible {
  let responseHash: Data
  let machineRoute: Data
  let deviceRoute: Data
  let createdAtMilliseconds: UInt64
  let promotionID: Data
  let storageKEK: Data
  let pairedRecordCanonicalBytes: Data
  let receiptCarrier: Data
  let receiptAuditSignature: Data

  init(
    responseHash: Data,
    machineRoute: Data,
    deviceRoute: Data,
    createdAtMilliseconds: UInt64,
    promotionID: Data,
    storageKEK: Data,
    pairedRecordCanonicalBytes: Data,
    receiptCarrier: Data,
    receiptAuditSignature: Data,
    requireAuditSignature: Bool = true
  ) throws {
    guard Self.isNonzero(responseHash, count: 32),
      Self.isNonzero(machineRoute, count: 16),
      Self.isNonzero(deviceRoute, count: 16),
      createdAtMilliseconds > 0,
      Self.isNonzero(promotionID, count: 32),
      Self.isNonzero(storageKEK, count: 32),
      !pairedRecordCanonicalBytes.isEmpty,
      pairedRecordCanonicalBytes.count <= PairedMachineRecordCodec.maximumRecordBytes,
      receiptCarrier.count <= PairTerminalEnvelopeCodec.maximumCanonicalBytes,
      receiptAuditSignature.count == 64,
      !requireAuditSignature || receiptAuditSignature.contains(where: { $0 != 0 })
    else {
      throw PendingPairingStoreError.invalidRecord
    }
    let pairedRecord = try PairedMachineRecordCodec.decode(pairedRecordCanonicalBytes)
    guard pairedRecord.machineRoute == machineRoute,
      pairedRecord.deviceRoute == deviceRoute,
      pairedRecord.createdAtMS == createdAtMilliseconds
    else {
      throw PendingPairingStoreError.invalidRecord
    }
    _ = try PairTerminalEnvelopeCodec.decode(receiptCarrier)
    self.responseHash = responseHash
    self.machineRoute = machineRoute
    self.deviceRoute = deviceRoute
    self.createdAtMilliseconds = createdAtMilliseconds
    self.promotionID = promotionID
    self.storageKEK = storageKEK
    self.pairedRecordCanonicalBytes = pairedRecordCanonicalBytes
    self.receiptCarrier = receiptCarrier
    self.receiptAuditSignature = receiptAuditSignature
  }

  var debugDescription: String {
    "PendingPairingResponseStateV1(material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

enum PendingPairingPhaseV1: Equatable, Sendable {
  case requestPrepared
  case responsePrepared(PendingPairingResponseStateV1)
  case terminal(PairTerminalOutcomeV1)
  case completed(PendingPairingResponseStateV1)
}

struct PendingPairingRecordV1: Equatable, Sendable, CustomDebugStringConvertible {
  let clientKind: RelayClientKind
  let installationID: UUID
  let inviteHash: Data
  let expiresAtMilliseconds: UInt64
  let authorizationHash: Data
  let requestHash: Data
  let canonicalRequest: Data
  let deviceSignPublicKey: Data
  let deviceHPKEPublicKey: Data
  let phase: PendingPairingPhaseV1

  init(
    clientKind: RelayClientKind,
    installationID: UUID,
    inviteHash: Data,
    expiresAtMilliseconds: UInt64,
    authorizationHash: Data,
    requestHash: Data,
    canonicalRequest: Data,
    deviceSignPublicKey: Data,
    deviceHPKEPublicKey: Data,
    phase: PendingPairingPhaseV1
  ) throws {
    guard isNonzeroRelayInstallationID(installationID),
      Self.isNonzero(inviteHash, count: 32),
      expiresAtMilliseconds > 0,
      Self.isNonzero(authorizationHash, count: 32),
      Self.isNonzero(requestHash, count: 32),
      !canonicalRequest.isEmpty,
      canonicalRequest.count <= PairRequestCanonicalCodec.maximumCanonicalBytes,
      CanonicalCodec.sha256(canonicalRequest) == requestHash,
      Self.isNonzero(deviceSignPublicKey, count: 32),
      Self.isNonzero(deviceHPKEPublicKey, count: 32)
    else {
      throw PendingPairingStoreError.invalidRecord
    }
    _ = try PairRequestCanonicalCodec.decode(canonicalRequest)
    self.clientKind = clientKind
    self.installationID = installationID
    self.inviteHash = inviteHash
    self.expiresAtMilliseconds = expiresAtMilliseconds
    self.authorizationHash = authorizationHash
    self.requestHash = requestHash
    self.canonicalRequest = canonicalRequest
    self.deviceSignPublicKey = deviceSignPublicKey
    self.deviceHPKEPublicKey = deviceHPKEPublicKey
    self.phase = phase
  }

  var debugDescription: String {
    "PendingPairingRecordV1(phase: \(phase), material: <redacted>)"
  }

  private static func isNonzero(_ value: Data, count: Int) -> Bool {
    value.count == count && value.contains(where: { $0 != 0 })
  }
}

struct PreparedPendingPairingV1: Sendable, CustomDebugStringConvertible {
  let invite: PairInviteV1
  let authorizationRequest: AuthorizationRequestV1
  let record: PendingPairingRecordV1
  let canonicalRecord: Data
  let requestCarrier: OpaquePairRequestCarrier
  let deviceSigningKey: Curve25519.Signing.PrivateKey
  let deviceHPKEPrivateKey: Curve25519.KeyAgreement.PrivateKey

  var debugDescription: String {
    "PreparedPendingPairingV1(material: <redacted>)"
  }
}

enum PendingPairingPrepareResult: Sendable {
  case active(PreparedPendingPairingV1)
  case terminal(PairTerminalOutcomeV1)
  case completed(machineRoute: Data, responseHash: Data)
}

/// Pending PairRequest 的 marker-last Keychain transaction。
///
/// 无 secret recovery intent 先落盘，DeviceSign/DeviceHPKE 随后各自 immutable 落盘，
/// 完整 byte-identical PairRequest record 最后作为 active commit marker。response receipt
/// 与 promotion KEK 通过 exact CAS 冻结；cleanup 始终保留 intent/record 中至少一个到最后，
/// 崩溃后可由 Keychain-native enumeration 续做。
actor PendingPairingStore {
  private let keyStore: any PairedMarkerListingKeyStore
  private let clientKind: RelayClientKind
  private let installationID: UUID

  init(
    keyStore: any PairedMarkerListingKeyStore,
    clientKind: RelayClientKind,
    installationID: UUID
  ) throws {
    guard isNonzeroRelayInstallationID(installationID) else {
      throw PendingPairingStoreError.invalidBinding
    }
    self.keyStore = keyStore
    self.clientKind = clientKind
    self.installationID = installationID
  }

  func prepare(
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1,
    nowMilliseconds: UInt64
  ) async throws -> PendingPairingPrepareResult {
    try invite.validate(nowMilliseconds: nowMilliseconds)
    try authorizationRequest.validate()
    if let existing = try await resumeIfPresent(
      invite: invite,
      authorizationRequest: authorizationRequest,
      nowMilliseconds: nowMilliseconds
    ) {
      return existing
    }
    let inviteHash = try invite.canonicalSHA256()
    let keys = try pendingKeys(inviteHash: inviteHash)
    let intent = try PendingPairingRecoveryIntentV1(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: inviteHash,
      expiresAtMilliseconds: invite.expiresAtMilliseconds
    )
    try await persistRecoveryIntent(intent, key: keys.recoveryIntent)

    let signingKey = try await loadOrCreateSigningKey(keys.deviceSign)
    let hpkeKey = try await loadOrCreateHPKEKey(keys.deviceHPKE)
    let carrier = try PairRequestCrypto.sealPairRequest(
      invite: invite,
      authorizationRequest: authorizationRequest,
      deviceSigningKey: signingKey,
      deviceHPKEPublicKey: hpkeKey.publicKey,
      nowMilliseconds: nowMilliseconds
    )
    let record = try PendingPairingRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: inviteHash,
      expiresAtMilliseconds: invite.expiresAtMilliseconds,
      authorizationHash: CanonicalCodec.sha256(
        AuthorizationRequestCanonicalCodec.encode(authorizationRequest)
      ),
      requestHash: carrier.requestHash,
      canonicalRequest: carrier.canonicalBytes,
      deviceSignPublicKey: signingKey.publicKey.rawRepresentation,
      deviceHPKEPublicKey: hpkeKey.publicKey.rawRepresentation,
      phase: .requestPrepared
    )
    let encoded = try PendingPairingRecordCodec.encode(record)
    do {
      _ = try await keyStore.persistImmutable(encoded, for: keys.record)
    } catch KeyStoreError.immutableConflict {
      guard let winner = try await keyStore.load(keys.record) else {
        throw PendingPairingStoreError.persistenceMismatch
      }
      let winnerRecord = try PendingPairingRecordCodec.decode(winner)
      try validateBinding(
        winnerRecord,
        invite: invite,
        authorizationRequest: authorizationRequest
      )
      return .active(
        try await loadActive(
          record: winnerRecord,
          canonicalRecord: winner,
          invite: invite,
          authorizationRequest: authorizationRequest,
          keys: keys
        )
      )
    }
    guard try await keyStore.load(keys.record) == encoded else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    return .active(
      PreparedPendingPairingV1(
        invite: invite,
        authorizationRequest: authorizationRequest,
        record: record,
        canonicalRecord: encoded,
        requestCarrier: carrier,
        deviceSigningKey: signingKey,
        deviceHPKEPrivateKey: hpkeKey
      )
    )
  }

  /// 只恢复既有 pending transaction，不在缺失时生成任何 key/record。pairing
  /// composition 用它区分“promotion 后 receipt/Close 尚未收敛”和“已经完成且
  /// pending marker 已清理”，避免对同一 installation 重开第二份 grant。
  func resumeIfPresent(
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1,
    nowMilliseconds: UInt64
  ) async throws -> PendingPairingPrepareResult? {
    // requestPrepared 仍严格受 invite absolute expiry 约束；responsePrepared 已包含
    // verified response + durable promotion identity，过期后必须保留到 outcome reconciliation，
    // 不能把长期 grant material 当作临时 invite key 一并删除。
    try invite.validateStatic()
    try authorizationRequest.validate()
    let inviteHash = try invite.canonicalSHA256()
    let keys = try pendingKeys(inviteHash: inviteHash)
    guard let existing = try await keyStore.load(keys.record) else {
      try invite.validate(nowMilliseconds: nowMilliseconds)
      return nil
    }
    let record = try PendingPairingRecordCodec.decode(existing)
    try validateBinding(
      record,
      invite: invite,
      authorizationRequest: authorizationRequest
    )
    let intent = try PendingPairingRecoveryIntentV1(
      clientKind: record.clientKind,
      installationID: record.installationID,
      inviteHash: record.inviteHash,
      expiresAtMilliseconds: record.expiresAtMilliseconds
    )
    try await persistRecoveryIntent(intent, key: keys.recoveryIntent)
    switch record.phase {
    case .terminal(let outcome):
      try await finishCleanup(keys: keys, recordBytes: existing)
      return .terminal(outcome)
    case .completed(let response):
      try await finishCleanup(keys: keys, recordBytes: existing)
      return .completed(
        machineRoute: response.machineRoute,
        responseHash: response.responseHash
      )
    case .requestPrepared:
      try invite.validate(nowMilliseconds: nowMilliseconds)
      return .active(
        try await loadActive(
          record: record,
          canonicalRecord: existing,
          invite: invite,
          authorizationRequest: authorizationRequest,
          keys: keys
        )
      )
    case .responsePrepared:
      return .active(
        try await loadActive(
          record: record,
          canonicalRecord: existing,
          invite: invite,
          authorizationRequest: authorizationRequest,
          keys: keys
        )
      )
    }
  }

  func stageResponse(
    _ response: PendingPairingResponseStateV1,
    for prepared: PreparedPendingPairingV1
  ) async throws -> PreparedPendingPairingV1 {
    let keys = try pendingKeys(inviteHash: prepared.record.inviteHash)
    guard let currentBytes = try await keyStore.load(keys.record) else {
      throw PendingPairingStoreError.incompleteState
    }
    let current = try PendingPairingRecordCodec.decode(currentBytes)
    try validatePreparedIdentity(current, expected: prepared.record)
    let replacement: PendingPairingRecordV1
    switch current.phase {
    case .requestPrepared:
      replacement = try replacing(current, phase: .responsePrepared(response))
    case .responsePrepared(let existing) where existing == response:
      return try await loadActive(
        record: current,
        canonicalRecord: currentBytes,
        invite: prepared.invite,
        authorizationRequest: prepared.authorizationRequest,
        keys: keys
      )
    case .responsePrepared, .terminal, .completed:
      throw PendingPairingStoreError.immutableConflict
    }
    let replacementBytes = try PendingPairingRecordCodec.encode(replacement)
    do {
      try await keyStore.compareAndReplaceExact(
        expected: currentBytes,
        replacement: replacementBytes,
        for: keys.record
      )
    } catch KeyStoreError.compareAndReplaceMismatch {
      throw PendingPairingStoreError.immutableConflict
    } catch KeyStoreError.compareAndReplaceMissing {
      throw PendingPairingStoreError.incompleteState
    }
    guard try await keyStore.load(keys.record) == replacementBytes else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    return try await loadActive(
      record: replacement,
      canonicalRecord: replacementBytes,
      invite: prepared.invite,
      authorizationRequest: prepared.authorizationRequest,
      keys: keys
    )
  }

  func stageTerminal(
    _ outcome: PairTerminalOutcomeV1,
    for prepared: PreparedPendingPairingV1
  ) async throws {
    let keys = try pendingKeys(inviteHash: prepared.record.inviteHash)
    guard let currentBytes = try await keyStore.load(keys.record) else {
      throw PendingPairingStoreError.incompleteState
    }
    let current = try PendingPairingRecordCodec.decode(currentBytes)
    try validatePreparedIdentity(current, expected: prepared.record)
    switch current.phase {
    case .terminal(let existing) where existing == outcome:
      try await finishCleanup(keys: keys, recordBytes: currentBytes)
      return
    case .requestPrepared, .responsePrepared:
      break
    case .terminal, .completed:
      throw PendingPairingStoreError.immutableConflict
    }
    let terminal = try replacing(current, phase: .terminal(outcome))
    let terminalBytes = try PendingPairingRecordCodec.encode(terminal)
    try await keyStore.compareAndReplaceExact(
      expected: currentBytes,
      replacement: terminalBytes,
      for: keys.record
    )
    guard try await keyStore.load(keys.record) == terminalBytes else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    try await finishCleanup(keys: keys, recordBytes: terminalBytes)
  }

  func markCompleted(
    for prepared: PreparedPendingPairingV1
  ) async throws {
    let keys = try pendingKeys(inviteHash: prepared.record.inviteHash)
    guard let currentBytes = try await keyStore.load(keys.record) else {
      throw PendingPairingStoreError.incompleteState
    }
    let current = try PendingPairingRecordCodec.decode(currentBytes)
    try validatePreparedIdentity(current, expected: prepared.record)
    let response: PendingPairingResponseStateV1
    switch current.phase {
    case .responsePrepared(let value): response = value
    case .completed:
      try await finishCleanup(keys: keys, recordBytes: currentBytes)
      return
    case .requestPrepared, .terminal:
      throw PendingPairingStoreError.immutableConflict
    }
    let completed = try replacing(current, phase: .completed(response))
    let completedBytes = try PendingPairingRecordCodec.encode(completed)
    try await keyStore.compareAndReplaceExact(
      expected: currentBytes,
      replacement: completedBytes,
      for: keys.record
    )
    guard try await keyStore.load(keys.record) == completedBytes else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    try await finishCleanup(keys: keys, recordBytes: completedBytes)
  }

  /// 枚举 cold-start 可收敛的 terminal/completed，以及已越过本地 TTL 的 active
  /// transaction。expiry 只产生本地 cleanup candidate；不会伪造远端签名 terminal。
  func cleanupCandidates(
    nowMilliseconds: UInt64
  ) async throws -> [PendingPairingCleanupCandidateV1] {
    guard nowMilliseconds > 0 else {
      throw PendingPairingStoreError.invalidBinding
    }
    let markerKeys = try await keyStore.pendingPairingRecoveryKeys(
      clientKind: clientKind,
      installationID: installationID
    )
    var grouped: [Data: PendingPairingCleanupBuilder] = [:]
    for key in markerKeys {
      guard let bytes = try await keyStore.load(key) else { continue }
      if key.account.hasSuffix("/\(PendingKeyStorePurpose.recoveryIntent.rawValue)") {
        let intent = try PendingPairingRecoveryIntentCodec.decode(bytes)
        try validateRecoveryBinding(intent)
        let expected = try pendingKeys(inviteHash: intent.inviteHash).recoveryIntent
        guard expected == key else { throw PendingPairingStoreError.invalidBinding }
        var builder = grouped[intent.inviteHash] ?? PendingPairingCleanupBuilder()
        guard builder.intent == nil else {
          throw PendingPairingStoreError.persistenceMismatch
        }
        builder.intent = intent
        builder.canonicalIntent = bytes
        grouped[intent.inviteHash] = builder
      } else if key.account.hasSuffix(
        "/\(PendingKeyStorePurpose.pairingRecord.rawValue)"
      ) {
        let record = try PendingPairingRecordCodec.decode(bytes)
        try validateRecoveryBinding(record)
        let expected = try pendingKeys(inviteHash: record.inviteHash).record
        guard expected == key else { throw PendingPairingStoreError.invalidBinding }
        var builder = grouped[record.inviteHash] ?? PendingPairingCleanupBuilder()
        guard builder.record == nil else {
          throw PendingPairingStoreError.persistenceMismatch
        }
        builder.record = record
        builder.canonicalRecord = bytes
        grouped[record.inviteHash] = builder
      } else {
        throw PendingPairingStoreError.invalidBinding
      }
    }

    var candidates: [PendingPairingCleanupCandidateV1] = []
    for (inviteHash, builder) in grouped {
      guard
        let expiry =
          builder.record?.expiresAtMilliseconds
          ?? builder.intent?.expiresAtMilliseconds
      else {
        throw PendingPairingStoreError.incompleteState
      }
      if let intent = builder.intent, let record = builder.record {
        guard intent.expiresAtMilliseconds == record.expiresAtMilliseconds else {
          throw PendingPairingStoreError.persistenceMismatch
        }
      }
      let isFinished: Bool
      switch builder.record?.phase {
      case .terminal, .completed: isFinished = true
      case .requestPrepared, .responsePrepared, nil: isFinished = false
      }
      guard isFinished || nowMilliseconds >= expiry else { continue }
      candidates.append(
        PendingPairingCleanupCandidateV1(
          inviteHash: inviteHash,
          intent: builder.intent,
          canonicalIntent: builder.canonicalIntent,
          record: builder.record,
          canonicalRecord: builder.canonicalRecord
        )
      )
    }
    return candidates.sorted {
      $0.inviteHash.lexicographicallyPrecedes($1.inviteHash)
    }
  }

  /// paired rollback 成功后的 exact pending cleanup。candidate 获取后若 marker 被并发
  /// 替换则 fail-closed；已经按同一 candidate 删除的 prefix 允许幂等续做。
  func finishLocalCleanup(
    _ candidate: PendingPairingCleanupCandidateV1
  ) async throws {
    let keys = try pendingKeys(inviteHash: candidate.inviteHash)
    try await validateCurrent(
      key: keys.recoveryIntent,
      expected: candidate.canonicalIntent
    )
    try await validateCurrent(key: keys.record, expected: candidate.canonicalRecord)
    if candidate.canonicalRecord != nil,
      let intentBytes = candidate.canonicalIntent,
      try await keyStore.load(keys.recoveryIntent) != nil
    {
      try await keyStore.deleteExact(expected: intentBytes, for: keys.recoveryIntent)
    }
    try await keyStore.deleteExact(keys.deviceHPKE)
    try await keyStore.deleteExact(keys.deviceSign)
    if let recordBytes = candidate.canonicalRecord,
      try await keyStore.load(keys.record) != nil
    {
      try await keyStore.deleteExact(expected: recordBytes, for: keys.record)
    }
    if candidate.canonicalRecord == nil,
      let intentBytes = candidate.canonicalIntent,
      try await keyStore.load(keys.recoveryIntent) != nil
    {
      try await keyStore.deleteExact(expected: intentBytes, for: keys.recoveryIntent)
    }
    guard try await keyStore.load(keys.deviceHPKE) == nil,
      try await keyStore.load(keys.deviceSign) == nil,
      try await keyStore.load(keys.record) == nil,
      try await keyStore.load(keys.recoveryIntent) == nil
    else {
      throw PendingPairingStoreError.persistenceMismatch
    }
  }

  private func loadActive(
    record: PendingPairingRecordV1,
    canonicalRecord: Data,
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1,
    keys: PendingPairingKeys
  ) async throws -> PreparedPendingPairingV1 {
    let signBytes = try await loadRequired(keys.deviceSign)
    let hpkeBytes = try await loadRequired(keys.deviceHPKE)
    let sign: Curve25519.Signing.PrivateKey
    let hpke: Curve25519.KeyAgreement.PrivateKey
    do {
      sign = try Curve25519.Signing.PrivateKey(rawRepresentation: signBytes)
      hpke = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hpkeBytes)
    } catch {
      throw PendingPairingStoreError.incompleteState
    }
    guard sign.publicKey.rawRepresentation == record.deviceSignPublicKey,
      hpke.publicKey.rawRepresentation == record.deviceHPKEPublicKey
    else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    let request = try PairRequestCanonicalCodec.decode(record.canonicalRequest)
    let info = try PairRequestInfoV1(
      relayServerID: invite.relayServerID,
      pairRoute: invite.pairRoute,
      inviteHash: record.inviteHash,
      expiryMilliseconds: record.expiresAtMilliseconds
    )
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
    guard
      sign.publicKey.isValidSignature(
        request.deviceProofSignature,
        for: try PairRequestCrypto.signatureTBS(
          request,
          info: info,
          context: context,
          deviceSignFingerprint: CanonicalCodec.sha256(record.deviceSignPublicKey)
        )
      )
    else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    if case .responsePrepared(let response) = record.phase {
      do {
        try PairingPromotionBuilder.auditResponseState(
          response,
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: record.inviteHash,
          requestHash: record.requestHash,
          deviceSigningPublicKey: sign.publicKey
        )
      } catch {
        throw PendingPairingStoreError.persistenceMismatch
      }
    }
    let carrier = try OpaquePairRequestCarrier(
      pairRoute: invite.pairRoute,
      canonicalBytes: record.canonicalRequest,
      requestHash: record.requestHash
    )
    return PreparedPendingPairingV1(
      invite: invite,
      authorizationRequest: authorizationRequest,
      record: record,
      canonicalRecord: canonicalRecord,
      requestCarrier: carrier,
      deviceSigningKey: sign,
      deviceHPKEPrivateKey: hpke
    )
  }

  private func validateBinding(
    _ record: PendingPairingRecordV1,
    invite: PairInviteV1,
    authorizationRequest: AuthorizationRequestV1
  ) throws {
    guard record.clientKind == clientKind,
      record.installationID == installationID,
      record.inviteHash == (try invite.canonicalSHA256()),
      record.expiresAtMilliseconds == invite.expiresAtMilliseconds,
      record.authorizationHash
        == CanonicalCodec.sha256(
          try AuthorizationRequestCanonicalCodec.encode(authorizationRequest)
        )
    else {
      throw PendingPairingStoreError.invalidBinding
    }
  }

  private func validateRecoveryBinding(
    _ intent: PendingPairingRecoveryIntentV1
  ) throws {
    guard intent.clientKind == clientKind,
      intent.installationID == installationID
    else {
      throw PendingPairingStoreError.invalidBinding
    }
  }

  private func validateRecoveryBinding(
    _ record: PendingPairingRecordV1
  ) throws {
    guard record.clientKind == clientKind,
      record.installationID == installationID
    else {
      throw PendingPairingStoreError.invalidBinding
    }
  }

  private func validateCurrent(
    key: KeyStoreKey,
    expected: Data?
  ) async throws {
    let current = try await keyStore.load(key)
    if let expected {
      guard current == nil || current == expected else {
        throw PendingPairingStoreError.immutableConflict
      }
    } else {
      guard current == nil else {
        throw PendingPairingStoreError.immutableConflict
      }
    }
  }

  private func validatePreparedIdentity(
    _ current: PendingPairingRecordV1,
    expected: PendingPairingRecordV1
  ) throws {
    guard current.clientKind == clientKind,
      current.installationID == installationID,
      expected.clientKind == clientKind,
      expected.installationID == installationID,
      current.inviteHash == expected.inviteHash,
      current.expiresAtMilliseconds == expected.expiresAtMilliseconds,
      current.authorizationHash == expected.authorizationHash,
      current.requestHash == expected.requestHash,
      current.canonicalRequest == expected.canonicalRequest,
      current.deviceSignPublicKey == expected.deviceSignPublicKey,
      current.deviceHPKEPublicKey == expected.deviceHPKEPublicKey
    else {
      throw PendingPairingStoreError.immutableConflict
    }
  }

  private func replacing(
    _ record: PendingPairingRecordV1,
    phase: PendingPairingPhaseV1
  ) throws -> PendingPairingRecordV1 {
    try PendingPairingRecordV1(
      clientKind: record.clientKind,
      installationID: record.installationID,
      inviteHash: record.inviteHash,
      expiresAtMilliseconds: record.expiresAtMilliseconds,
      authorizationHash: record.authorizationHash,
      requestHash: record.requestHash,
      canonicalRequest: record.canonicalRequest,
      deviceSignPublicKey: record.deviceSignPublicKey,
      deviceHPKEPublicKey: record.deviceHPKEPublicKey,
      phase: phase
    )
  }

  private func loadOrCreateSigningKey(
    _ key: KeyStoreKey
  ) async throws -> Curve25519.Signing.PrivateKey {
    if let existing = try await keyStore.load(key) {
      do { return try Curve25519.Signing.PrivateKey(rawRepresentation: existing) } catch {
        throw PendingPairingStoreError.incompleteState
      }
    }
    let candidate = Curve25519.Signing.PrivateKey()
    return try await persistOrLoad(
      candidate,
      raw: candidate.rawRepresentation,
      key: key,
      decode: Curve25519.Signing.PrivateKey.init(rawRepresentation:)
    )
  }

  private func loadOrCreateHPKEKey(
    _ key: KeyStoreKey
  ) async throws -> Curve25519.KeyAgreement.PrivateKey {
    if let existing = try await keyStore.load(key) {
      do { return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existing) } catch {
        throw PendingPairingStoreError.incompleteState
      }
    }
    let candidate = Curve25519.KeyAgreement.PrivateKey()
    return try await persistOrLoad(
      candidate,
      raw: candidate.rawRepresentation,
      key: key,
      decode: Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation:)
    )
  }

  private func persistOrLoad<Key>(
    _ candidate: Key,
    raw: Data,
    key: KeyStoreKey,
    decode: (Data) throws -> Key
  ) async throws -> Key {
    do {
      _ = try await keyStore.persistImmutable(raw, for: key)
    } catch KeyStoreError.immutableConflict {
      guard let winner = try await keyStore.load(key) else {
        throw PendingPairingStoreError.persistenceMismatch
      }
      do { return try decode(winner) } catch {
        throw PendingPairingStoreError.incompleteState
      }
    }
    guard try await keyStore.load(key) == raw else {
      throw PendingPairingStoreError.persistenceMismatch
    }
    return candidate
  }

  private func loadRequired(_ key: KeyStoreKey) async throws -> Data {
    guard let value = try await keyStore.load(key) else {
      throw PendingPairingStoreError.incompleteState
    }
    return value
  }

  private func finishCleanup(
    keys: PendingPairingKeys,
    recordBytes: Data
  ) async throws {
    // record 已存在后由它接管 recovery marker；先删 intent、最后删 record，任一
    // crash cut 仍至少保留一个可枚举 marker。
    try await keyStore.deleteExact(keys.recoveryIntent)
    try await keyStore.deleteExact(keys.deviceHPKE)
    try await keyStore.deleteExact(keys.deviceSign)
    try await keyStore.deleteExact(expected: recordBytes, for: keys.record)
    guard try await keyStore.load(keys.deviceHPKE) == nil,
      try await keyStore.load(keys.deviceSign) == nil,
      try await keyStore.load(keys.record) == nil,
      try await keyStore.load(keys.recoveryIntent) == nil
    else {
      throw PendingPairingStoreError.persistenceMismatch
    }
  }

  private func persistRecoveryIntent(
    _ intent: PendingPairingRecoveryIntentV1,
    key: KeyStoreKey
  ) async throws {
    let encoded = try PendingPairingRecoveryIntentCodec.encode(intent)
    do {
      _ = try await keyStore.persistImmutable(encoded, for: key)
    } catch KeyStoreError.immutableConflict {
      throw PendingPairingStoreError.immutableConflict
    }
    guard try await keyStore.load(key) == encoded else {
      throw PendingPairingStoreError.persistenceMismatch
    }
  }

  private func pendingKeys(inviteHash: Data) throws -> PendingPairingKeys {
    do {
      return PendingPairingKeys(
        recoveryIntent: try KeyStoreKey.pending(
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          purpose: .recoveryIntent
        ),
        record: try KeyStoreKey.pending(
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          purpose: .pairingRecord
        ),
        deviceSign: try KeyStoreKey.pending(
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          purpose: .deviceSignPrivateKey
        ),
        deviceHPKE: try KeyStoreKey.pending(
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          purpose: .deviceHPKEPrivateKey
        )
      )
    } catch {
      throw PendingPairingStoreError.invalidBinding
    }
  }
}

private struct PendingPairingKeys: Sendable {
  let recoveryIntent: KeyStoreKey
  let record: KeyStoreKey
  let deviceSign: KeyStoreKey
  let deviceHPKE: KeyStoreKey
}

private struct PendingPairingCleanupBuilder {
  var intent: PendingPairingRecoveryIntentV1?
  var canonicalIntent: Data?
  var record: PendingPairingRecordV1?
  var canonicalRecord: Data?
}

enum PendingPairingRecoveryIntentCodec {
  static let maximumCanonicalBytes = 256
  private static let domain = Data("AgentDeck/PendingPairingRecoveryIntentV1\0".utf8)

  static func encode(_ value: PendingPairingRecoveryIntentV1) throws -> Data {
    var encoder = PendingPairingEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(1)
    switch value.clientKind {
    case .macOSApp: try encoder.u8(0)
    case .iOSApp: try encoder.u8(1)
    case .cli: try encoder.u8(2)
    }
    var installationID = value.installationID.uuid
    try encoder.bytes(
      Swift.withUnsafeBytes(of: &installationID) { Data($0) },
      exact: 16
    )
    try encoder.bytes(value.inviteHash, exact: 32)
    try encoder.u64(value.expiresAtMilliseconds)
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> PendingPairingRecoveryIntentV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PendingPairingStoreError.invalidRecord
    }
    var decoder = PendingPairingDecoder(bytes)
    try decoder.domain(domain)
    guard try decoder.u16() == 1 else {
      throw PendingPairingStoreError.invalidRecord
    }
    let clientKind: RelayClientKind
    switch try decoder.u8() {
    case 0: clientKind = .macOSApp
    case 1: clientKind = .iOSApp
    case 2: clientKind = .cli
    default: throw PendingPairingStoreError.invalidRecord
    }
    let installationBytes = try decoder.bytes(exact: 16)
    let values = [UInt8](installationBytes)
    let installationID = UUID(
      uuid: (
        values[0], values[1], values[2], values[3],
        values[4], values[5], values[6], values[7],
        values[8], values[9], values[10], values[11],
        values[12], values[13], values[14], values[15]
      ))
    let intent = try PendingPairingRecoveryIntentV1(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: decoder.bytes(exact: 32),
      expiresAtMilliseconds: decoder.u64()
    )
    try decoder.finish()
    guard try encode(intent) == bytes else {
      throw PendingPairingStoreError.invalidRecord
    }
    return intent
  }
}

enum PendingPairingRecordCodec {
  static let maximumCanonicalBytes = 640 * 1_024
  private static let domain = Data("AgentDeck/PendingPairingRecordV1\0".utf8)

  static func encode(_ value: PendingPairingRecordV1) throws -> Data {
    var encoder = PendingPairingEncoder(maximumBytes: maximumCanonicalBytes)
    try encoder.raw(domain)
    try encoder.u16(1)
    switch value.clientKind {
    case .macOSApp: try encoder.u8(0)
    case .iOSApp: try encoder.u8(1)
    case .cli: try encoder.u8(2)
    }
    try encoder.bytes(uuidBytes(value.installationID), exact: 16)
    try encoder.bytes(value.inviteHash, exact: 32)
    try encoder.u64(value.expiresAtMilliseconds)
    try encoder.bytes(value.authorizationHash, exact: 32)
    try encoder.bytes(value.requestHash, exact: 32)
    try encoder.bytes(
      value.canonicalRequest,
      maximum: PairRequestCanonicalCodec.maximumCanonicalBytes
    )
    try encoder.bytes(value.deviceSignPublicKey, exact: 32)
    try encoder.bytes(value.deviceHPKEPublicKey, exact: 32)
    switch value.phase {
    case .requestPrepared:
      try encoder.u8(0)
    case .responsePrepared(let response):
      try encoder.u8(1)
      try encode(response, to: &encoder)
    case .terminal(.canceled):
      try encoder.u8(2)
    case .terminal(.expired):
      try encoder.u8(3)
    case .completed(let response):
      try encoder.u8(4)
      try encode(response, to: &encoder)
    }
    return try encoder.finish()
  }

  static func decode(_ bytes: Data) throws -> PendingPairingRecordV1 {
    guard bytes.count <= maximumCanonicalBytes else {
      throw PendingPairingStoreError.invalidRecord
    }
    var decoder = PendingPairingDecoder(bytes)
    try decoder.domain(domain)
    guard try decoder.u16() == 1 else {
      throw PendingPairingStoreError.invalidRecord
    }
    let clientKind: RelayClientKind
    switch try decoder.u8() {
    case 0: clientKind = .macOSApp
    case 1: clientKind = .iOSApp
    case 2: clientKind = .cli
    default: throw PendingPairingStoreError.invalidRecord
    }
    let installationID = try uuid(decoder.bytes(exact: 16))
    let inviteHash = try decoder.bytes(exact: 32)
    let expiry = try decoder.u64()
    let authorizationHash = try decoder.bytes(exact: 32)
    let requestHash = try decoder.bytes(exact: 32)
    let request = try decoder.bytes(
      maximum: PairRequestCanonicalCodec.maximumCanonicalBytes
    )
    let signPublic = try decoder.bytes(exact: 32)
    let hpkePublic = try decoder.bytes(exact: 32)
    let phase: PendingPairingPhaseV1
    switch try decoder.u8() {
    case 0: phase = .requestPrepared
    case 1: phase = .responsePrepared(try decodeResponse(from: &decoder))
    case 2: phase = .terminal(.canceled)
    case 3: phase = .terminal(.expired)
    case 4: phase = .completed(try decodeResponse(from: &decoder))
    default: throw PendingPairingStoreError.invalidRecord
    }
    try decoder.finish()
    let record = try PendingPairingRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: inviteHash,
      expiresAtMilliseconds: expiry,
      authorizationHash: authorizationHash,
      requestHash: requestHash,
      canonicalRequest: request,
      deviceSignPublicKey: signPublic,
      deviceHPKEPublicKey: hpkePublic,
      phase: phase
    )
    guard try encode(record) == bytes else {
      throw PendingPairingStoreError.invalidRecord
    }
    return record
  }

  private static func encode(
    _ value: PendingPairingResponseStateV1,
    to encoder: inout PendingPairingEncoder
  ) throws {
    try encoder.bytes(value.responseHash, exact: 32)
    try encoder.bytes(value.machineRoute, exact: 16)
    try encoder.bytes(value.deviceRoute, exact: 16)
    try encoder.u64(value.createdAtMilliseconds)
    try encoder.bytes(value.promotionID, exact: 32)
    try encoder.bytes(value.storageKEK, exact: 32)
    try encoder.bytes(
      value.pairedRecordCanonicalBytes,
      maximum: PairedMachineRecordCodec.maximumRecordBytes
    )
    try encoder.bytes(
      value.receiptCarrier,
      maximum: PairTerminalEnvelopeCodec.maximumCanonicalBytes
    )
    try encoder.bytes(value.receiptAuditSignature, exact: 64)
  }

  private static func decodeResponse(
    from decoder: inout PendingPairingDecoder
  ) throws -> PendingPairingResponseStateV1 {
    try PendingPairingResponseStateV1(
      responseHash: decoder.bytes(exact: 32),
      machineRoute: decoder.bytes(exact: 16),
      deviceRoute: decoder.bytes(exact: 16),
      createdAtMilliseconds: decoder.u64(),
      promotionID: decoder.bytes(exact: 32),
      storageKEK: decoder.bytes(exact: 32),
      pairedRecordCanonicalBytes: decoder.bytes(
        maximum: PairedMachineRecordCodec.maximumRecordBytes
      ),
      receiptCarrier: decoder.bytes(
        maximum: PairTerminalEnvelopeCodec.maximumCanonicalBytes
      ),
      receiptAuditSignature: decoder.bytes(exact: 64)
    )
  }

  private static func uuidBytes(_ value: UUID) -> Data {
    var bytes = value.uuid
    return Swift.withUnsafeBytes(of: &bytes) { Data($0) }
  }

  private static func uuid(_ bytes: Data) throws -> UUID {
    guard bytes.count == 16 else { throw PendingPairingStoreError.invalidRecord }
    let values = [UInt8](bytes)
    return UUID(
      uuid: (
        values[0], values[1], values[2], values[3],
        values[4], values[5], values[6], values[7],
        values[8], values[9], values[10], values[11],
        values[12], values[13], values[14], values[15]
      ))
  }
}

private struct PendingPairingEncoder {
  private let maximumBytes: Int
  private var output = Data()

  init(maximumBytes: Int) { self.maximumBytes = maximumBytes }
  mutating func raw(_ value: Data) throws { try append(value) }
  mutating func u8(_ value: UInt8) throws { try append(Data([value])) }
  mutating func u16(_ value: UInt16) throws { try integer(value) }
  mutating func u64(_ value: UInt64) throws { try integer(value) }
  mutating func bytes(_ value: Data, exact: Int? = nil, maximum: Int? = nil) throws {
    if let exact, value.count != exact { throw PendingPairingStoreError.invalidRecord }
    if let maximum, value.count > maximum { throw PendingPairingStoreError.invalidRecord }
    guard let count = UInt32(exactly: value.count) else {
      throw PendingPairingStoreError.invalidRecord
    }
    try integer(count)
    try append(value)
  }
  func finish() throws -> Data {
    guard output.count <= maximumBytes else { throw PendingPairingStoreError.invalidRecord }
    return output
  }
  private mutating func integer<T: FixedWidthInteger>(_ value: T) throws {
    var value = value.bigEndian
    try Swift.withUnsafeBytes(of: &value) { try append(Data($0)) }
  }
  private mutating func append(_ value: Data) throws {
    let end = output.count.addingReportingOverflow(value.count)
    guard !end.overflow, end.partialValue <= maximumBytes else {
      throw PendingPairingStoreError.invalidRecord
    }
    output.append(value)
  }
}

private struct PendingPairingDecoder {
  private let input: Data
  private var offset = 0
  init(_ input: Data) { self.input = input }
  mutating func domain(_ expected: Data) throws {
    guard try take(expected.count) == expected else {
      throw PendingPairingStoreError.invalidRecord
    }
  }
  mutating func u8() throws -> UInt8 { try take(1)[0] }
  mutating func u16() throws -> UInt16 { try integer() }
  mutating func u32() throws -> UInt32 { try integer() }
  mutating func u64() throws -> UInt64 { try integer() }
  mutating func bytes(maximum: Int) throws -> Data {
    let count = Int(try u32())
    guard count <= maximum else { throw PendingPairingStoreError.invalidRecord }
    return try take(count)
  }
  mutating func bytes(exact: Int) throws -> Data {
    let value = try bytes(maximum: exact)
    guard value.count == exact else { throw PendingPairingStoreError.invalidRecord }
    return value
  }
  mutating func finish() throws {
    guard offset == input.count else { throw PendingPairingStoreError.invalidRecord }
  }
  private mutating func integer<T: FixedWidthInteger>() throws -> T {
    try take(MemoryLayout<T>.size).reduce(T.zero) { ($0 << 8) | T($1) }
  }
  private mutating func take(_ count: Int) throws -> Data {
    let end = offset.addingReportingOverflow(count)
    guard count >= 0, !end.overflow, end.partialValue <= input.count else {
      throw PendingPairingStoreError.invalidRecord
    }
    defer { offset = end.partialValue }
    return Data(input[offset..<end.partialValue])
  }
}
