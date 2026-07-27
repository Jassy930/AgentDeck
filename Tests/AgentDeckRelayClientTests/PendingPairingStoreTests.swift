import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PendingPairingStoreTests: XCTestCase {
  func testPrepareCommitsMarkerLastAndRestartReturnsByteIdenticalRequest() async throws {
    let fixture = try PendingPairingStoreFixture()
    let store = try fixture.makeStore()
    await fixture.keyStore.failAfterMutation(4)

    do {
      _ = try await store.prepare(
        invite: fixture.invite,
        authorizationRequest: fixture.authorization,
        nowMilliseconds: fixture.nowMilliseconds
      )
      XCTFail("record marker 落盘后的 outcome-unknown 必须由 crash fixture 截断")
    } catch is PendingPairingInjectedCrash {
      // expected
    }

    let persistedMarker = await fixture.keyStore.value(for: fixture.recordKey)
    let markerBytes = try XCTUnwrap(persistedMarker)
    let marker = try PendingPairingRecordCodec.decode(markerBytes)
    let markerValueCount = await fixture.keyStore.valueCount
    let persistedPurposeSuffixes = await fixture.keyStore.persistedPurposeSuffixes
    XCTAssertEqual(markerValueCount, 4)
    XCTAssertEqual(
      persistedPurposeSuffixes,
      [
        PendingKeyStorePurpose.recoveryIntent.rawValue,
        PendingKeyStorePurpose.deviceSignPrivateKey.rawValue,
        PendingKeyStorePurpose.deviceHPKEPrivateKey.rawValue,
        PendingKeyStorePurpose.pairingRecord.rawValue,
      ]
    )

    await fixture.keyStore.clearFailure()
    let reopened = try await fixture.prepareActive()
    XCTAssertEqual(reopened.canonicalRecord, markerBytes)
    XCTAssertEqual(reopened.requestCarrier.canonicalBytes, marker.canonicalRequest)
    XCTAssertEqual(reopened.requestCarrier.requestHash, marker.requestHash)

    let reopenedAgain = try await fixture.prepareActive()
    XCTAssertEqual(
      reopenedAgain.requestCarrier.canonicalBytes,
      reopened.requestCarrier.canonicalBytes
    )
    XCTAssertEqual(reopenedAgain.canonicalRecord, reopened.canonicalRecord)
    XCTAssertEqual(
      reopenedAgain.deviceSigningKey.rawRepresentation,
      reopened.deviceSigningKey.rawRepresentation
    )
    XCTAssertEqual(
      reopenedAgain.deviceHPKEPrivateKey.rawRepresentation,
      reopened.deviceHPKEPrivateKey.rawRepresentation
    )
    let reopenedValueCount = await fixture.keyStore.valueCount
    XCTAssertEqual(reopenedValueCount, 4)
  }

  func testPrepareRecoversEveryPartialPrivateKeyCrashWithExactReadback() async throws {
    for crashAfterMutation in 1...3 {
      let fixture = try PendingPairingStoreFixture(index: UInt8(crashAfterMutation))
      let store = try fixture.makeStore()
      await fixture.keyStore.failAfterMutation(crashAfterMutation)

      do {
        _ = try await store.prepare(
          invite: fixture.invite,
          authorizationRequest: fixture.authorization,
          nowMilliseconds: fixture.nowMilliseconds
        )
        XCTFail("private-key mutation \(crashAfterMutation) 后必须注入 crash")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      let partialMarker = await fixture.keyStore.value(for: fixture.recordKey)
      let partialValueCount = await fixture.keyStore.valueCount
      XCTAssertNil(partialMarker)
      XCTAssertEqual(partialValueCount, crashAfterMutation)

      await fixture.keyStore.clearFailure()
      let recovered = try await fixture.prepareActive()
      let recoveredMarker = await fixture.keyStore.value(for: fixture.recordKey)
      let recoveredValueCount = await fixture.keyStore.valueCount
      XCTAssertNotNil(recoveredMarker)
      XCTAssertEqual(recoveredValueCount, 4)

      let coldReadback = try await fixture.prepareActive()
      XCTAssertEqual(
        coldReadback.requestCarrier.canonicalBytes,
        recovered.requestCarrier.canonicalBytes
      )
      XCTAssertEqual(
        coldReadback.deviceSigningKey.rawRepresentation,
        recovered.deviceSigningKey.rawRepresentation
      )
      XCTAssertEqual(
        coldReadback.deviceHPKEPrivateKey.rawRepresentation,
        recovered.deviceHPKEPrivateKey.rawRepresentation
      )
    }
  }

  func testExpiredRecoveryIntentCleansEveryMarkerLastCrashCutWithoutTerminal()
    async throws
  {
    for crashAfterMutation in 1...3 {
      let fixture = try PendingPairingStoreFixture(index: UInt8(20 + crashAfterMutation))
      let store = try fixture.makeStore()
      await fixture.keyStore.failAfterMutation(crashAfterMutation)
      do {
        _ = try await store.prepare(
          invite: fixture.invite,
          authorizationRequest: fixture.authorization,
          nowMilliseconds: fixture.nowMilliseconds
        )
        XCTFail("marker-last crash cut \(crashAfterMutation) 必须注入")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      await fixture.keyStore.clearFailure()
      let coldStore = try fixture.makeStore()
      let candidates = try await coldStore.cleanupCandidates(
        nowMilliseconds: fixture.invite.expiresAtMilliseconds
      )
      XCTAssertEqual(candidates.count, 1)
      XCTAssertNil(candidates[0].record)
      XCTAssertNotNil(candidates[0].intent)
      try await coldStore.finishLocalCleanup(candidates[0])
      let finalValueCount = await fixture.keyStore.valueCount
      XCTAssertEqual(finalValueCount, 0)
    }
  }

  func testExpiredRequestPreparedCleanupDeletesExactStateWithoutForgingTerminal()
    async throws
  {
    let fixture = try PendingPairingStoreFixture(index: 30)
    _ = try await fixture.prepareActive()
    let coldStore = try fixture.makeStore()
    let candidates = try await coldStore.cleanupCandidates(
      nowMilliseconds: fixture.invite.expiresAtMilliseconds
    )
    XCTAssertEqual(candidates.count, 1)
    guard case .requestPrepared? = candidates[0].record?.phase else {
      return XCTFail("本地 expiry candidate 必须保留 requestPrepared，不能伪造 terminal")
    }
    try await coldStore.finishLocalCleanup(candidates[0])
    let finalValueCount = await fixture.keyStore.valueCount
    XCTAssertEqual(finalValueCount, 0)
  }

  func testStageResponseUsesExactCASForRetryAndRejectsConflict() async throws {
    let fixture = try PendingPairingStoreFixture()
    let prepared = try await fixture.prepareActive()
    let first = try pendingResponseState(index: 1, prepared: prepared)
    let second = try pendingResponseState(index: 2, prepared: prepared)
    let store = try fixture.makeStore()

    await fixture.keyStore.resetMutationTracking()
    await fixture.keyStore.failAfterMutation(1)
    do {
      _ = try await store.stageResponse(first, for: prepared)
      XCTFail("response CAS commit 后必须注入 outcome-unknown crash")
    } catch is PendingPairingInjectedCrash {
      // expected
    }
    await fixture.keyStore.clearFailure()

    let stagedMarker = await fixture.keyStore.value(for: fixture.recordKey)
    let stagedBytes = try XCTUnwrap(stagedMarker)
    let staged = try await fixture.prepareActive()
    guard case .responsePrepared(let stagedResponse) = staged.record.phase else {
      return XCTFail("restart 必须读回已提交的 responsePrepared")
    }
    XCTAssertEqual(stagedResponse, first)
    XCTAssertEqual(staged.canonicalRecord, stagedBytes)

    let exactRetry = try await store.stageResponse(first, for: prepared)
    XCTAssertEqual(exactRetry.canonicalRecord, stagedBytes)
    let markerAfterRetry = await fixture.keyStore.value(for: fixture.recordKey)
    XCTAssertEqual(markerAfterRetry, stagedBytes)

    do {
      _ = try await store.stageResponse(second, for: prepared)
      XCTFail("同一 request 的不同 response 必须作为 immutable conflict 拒绝")
    } catch {
      XCTAssertEqual(error as? PendingPairingStoreError, .immutableConflict)
    }
    let markerAfterConflict = await fixture.keyStore.value(for: fixture.recordKey)
    XCTAssertEqual(markerAfterConflict, stagedBytes)
  }

  func testColdOpenRejectsReceiptCarrierThatNoLongerMatchesDeviceAuditSignature()
    async throws
  {
    let fixture = try PendingPairingStoreFixture()
    let prepared = try await fixture.prepareActive()
    let response = try pendingResponseState(index: 9, prepared: prepared)
    let staged = try await fixture.makeStore().stageResponse(response, for: prepared)
    guard case .responsePrepared(let persisted) = staged.record.phase else {
      return XCTFail("fixture 必须进入 responsePrepared")
    }
    let envelope = try PairTerminalEnvelopeCodec.decode(persisted.receiptCarrier)
    var ciphertext = envelope.ciphertext
    ciphertext[ciphertext.startIndex] ^= 1
    let tamperedCarrier = try PairTerminalEnvelopeCodec.encode(
      CanonicalPairingControlEnvelopeV1(
        formatVersion: envelope.formatVersion,
        encapsulatedKey: envelope.encapsulatedKey,
        ciphertext: ciphertext
      )
    )
    let tamperedResponse = try PendingPairingResponseStateV1(
      responseHash: persisted.responseHash,
      machineRoute: persisted.machineRoute,
      deviceRoute: persisted.deviceRoute,
      createdAtMilliseconds: persisted.createdAtMilliseconds,
      promotionID: persisted.promotionID,
      storageKEK: persisted.storageKEK,
      pairedRecordCanonicalBytes: persisted.pairedRecordCanonicalBytes,
      receiptCarrier: tamperedCarrier,
      receiptAuditSignature: persisted.receiptAuditSignature
    )
    let tamperedRecord = try PendingPairingRecordV1(
      clientKind: staged.record.clientKind,
      installationID: staged.record.installationID,
      inviteHash: staged.record.inviteHash,
      expiresAtMilliseconds: staged.record.expiresAtMilliseconds,
      authorizationHash: staged.record.authorizationHash,
      requestHash: staged.record.requestHash,
      canonicalRequest: staged.record.canonicalRequest,
      deviceSignPublicKey: staged.record.deviceSignPublicKey,
      deviceHPKEPublicKey: staged.record.deviceHPKEPublicKey,
      phase: .responsePrepared(tamperedResponse)
    )
    await fixture.keyStore.force(
      try PendingPairingRecordCodec.encode(tamperedRecord),
      for: fixture.recordKey
    )

    do {
      _ = try await fixture.makeStore().prepare(
        invite: fixture.invite,
        authorizationRequest: fixture.authorization,
        nowMilliseconds: fixture.nowMilliseconds
      )
      XCTFail("cold-open 必须拒绝与 device audit signature 不匹配的 receipt")
    } catch {
      XCTAssertEqual(error as? PendingPairingStoreError, .persistenceMismatch)
    }
  }

  func testTerminalCleanupCrashCutsResumeFromDurableTerminal() async throws {
    for crashAfterMutation in 1...5 {
      let fixture = try PendingPairingStoreFixture(index: UInt8(crashAfterMutation))
      let prepared = try await fixture.prepareActive()
      let store = try fixture.makeStore()
      await fixture.keyStore.resetMutationTracking()
      await fixture.keyStore.failAfterMutation(crashAfterMutation)

      do {
        try await store.stageTerminal(.canceled, for: prepared)
        XCTFail("terminal cleanup mutation \(crashAfterMutation) 后必须注入 crash")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      await fixture.keyStore.clearFailure()
      if crashAfterMutation < 5 {
        let persistedMarker = await fixture.keyStore.value(for: fixture.recordKey)
        let markerBytes = try XCTUnwrap(persistedMarker)
        let marker = try PendingPairingRecordCodec.decode(markerBytes)
        XCTAssertEqual(marker.phase, .terminal(.canceled))

        let result = try await fixture.makeStore().prepare(
          invite: fixture.invite,
          authorizationRequest: fixture.authorization,
          nowMilliseconds: fixture.nowMilliseconds
        )
        guard case .terminal(.canceled) = result else {
          return XCTFail("restart 必须从 durable terminal 继续 cleanup")
        }
      }
      let valueCount = await fixture.keyStore.valueCount
      XCTAssertEqual(valueCount, 0)
    }
  }

  func testSignedTerminalAfterResponsePreparedReplacesResponseAndResumesCleanup() async throws {
    let fixture = try PendingPairingStoreFixture()
    let prepared = try await fixture.prepareActive()
    let store = try fixture.makeStore()
    let staged = try await store.stageResponse(
      pendingResponseState(index: 1, prepared: prepared),
      for: prepared
    )
    await fixture.keyStore.resetMutationTracking()
    await fixture.keyStore.failAfterMutation(1)

    do {
      try await store.stageTerminal(.expired, for: staged)
      XCTFail("responsePrepared → terminal CAS 后必须注入 outcome-unknown crash")
    } catch is PendingPairingInjectedCrash {
      // expected
    }

    let persistedMarker = await fixture.keyStore.value(for: fixture.recordKey)
    let markerBytes = try XCTUnwrap(persistedMarker)
    let marker = try PendingPairingRecordCodec.decode(markerBytes)
    XCTAssertEqual(marker.phase, .terminal(.expired))

    await fixture.keyStore.clearFailure()
    let result = try await fixture.makeStore().prepare(
      invite: fixture.invite,
      authorizationRequest: fixture.authorization,
      nowMilliseconds: fixture.nowMilliseconds
    )
    guard case .terminal(.expired) = result else {
      return XCTFail("restart 必须从 responsePrepared 后的 terminal 继续 cleanup")
    }
    let valueCount = await fixture.keyStore.valueCount
    XCTAssertEqual(valueCount, 0)
  }

  func testCompletedCleanupCrashCutsResumeFromDurableCompletion() async throws {
    for crashAfterMutation in 1...5 {
      let fixture = try PendingPairingStoreFixture(index: UInt8(crashAfterMutation))
      let prepared = try await fixture.prepareActive()
      let response = try pendingResponseState(
        index: UInt8(crashAfterMutation),
        prepared: prepared
      )
      let store = try fixture.makeStore()
      let staged = try await store.stageResponse(response, for: prepared)
      await fixture.keyStore.resetMutationTracking()
      await fixture.keyStore.failAfterMutation(crashAfterMutation)

      do {
        try await store.markCompleted(for: staged)
        XCTFail("completed cleanup mutation \(crashAfterMutation) 后必须注入 crash")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      await fixture.keyStore.clearFailure()
      if crashAfterMutation < 5 {
        let persistedMarker = await fixture.keyStore.value(for: fixture.recordKey)
        let markerBytes = try XCTUnwrap(persistedMarker)
        let marker = try PendingPairingRecordCodec.decode(markerBytes)
        XCTAssertEqual(marker.phase, .completed(response))

        let result = try await fixture.makeStore().prepare(
          invite: fixture.invite,
          authorizationRequest: fixture.authorization,
          nowMilliseconds: fixture.nowMilliseconds
        )
        guard case .completed(let machineRoute, let responseHash) = result else {
          return XCTFail("restart 必须从 durable completed 继续 cleanup")
        }
        XCTAssertEqual(machineRoute, response.machineRoute)
        XCTAssertEqual(responseHash, response.responseHash)
      }
      let valueCount = await fixture.keyStore.valueCount
      XCTAssertEqual(valueCount, 0)
    }
  }
}

struct PendingPairingStoreFixture {
  let nowMilliseconds: UInt64 = 1_700_000_000_000
  let clientKind: RelayClientKind = .iOSApp
  let installationID: UUID
  let keyStore = PendingPairingTestKeyStore()
  let invite: PairInviteV1
  let authorization: AuthorizationRequestV1
  let recordKey: KeyStoreKey

  init(index: UInt8 = 1) throws {
    installationID = UUID(
      uuidString: String(format: "40000000-0000-0000-0000-%012d", Int(index))
    )!
    let inviteHPKEKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x40 &+ index, count: 32)
    )
    let rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x50 &+ index, count: 32)
    )
    let rootPublic = rootKey.publicKey.rawRepresentation
    invite = try PairInviteV1(
      pairRoute: Data(repeating: 0x10 &+ index, count: 16),
      inviteSecret: Data(repeating: 0x20 &+ index, count: 32),
      inviteHPKEPublicKey: inviteHPKEKey.publicKey.rawRepresentation,
      wssURL: "wss://relay.example.test/",
      relayServerID: Data(repeating: 0x30 &+ index, count: 16),
      currentSPKIPin: Data(repeating: 0x60 &+ index, count: 32),
      nextSPKIPin: Data(repeating: 0x70 &+ index, count: 32),
      expiresAtMilliseconds: nowMilliseconds + 300_000,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: CanonicalCodec.sha256(rootPublic),
      dataSignCertificate: RelayV2SignedCertificate(
        subjectPubkey: Data(repeating: 0x80 &+ index, count: 32),
        certRole: .data,
        generation: 1,
        rootKeyId: Data(repeating: 0x90 &+ index, count: 16),
        trustEpoch: 1,
        notAfterMs: nowMilliseconds + 600_000,
        signature: Data(repeating: 0xA0 &+ index, count: 64)
      ),
      machineDisplayName: "Fixture \(index)"
    )
    authorization = try AuthorizationRequestV1(
      deviceDisplayName: "Test Device \(index)",
      capabilities: [.catalog],
      permissions: [.catalogRead]
    )
    recordKey = try KeyStoreKey.pending(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: invite.canonicalSHA256(),
      purpose: .pairingRecord
    )
  }

  func makeStore() throws -> PendingPairingStore {
    try PendingPairingStore(
      keyStore: keyStore,
      clientKind: clientKind,
      installationID: installationID
    )
  }

  func prepareActive() async throws -> PreparedPendingPairingV1 {
    let result = try await makeStore().prepare(
      invite: invite,
      authorizationRequest: authorization,
      nowMilliseconds: nowMilliseconds
    )
    guard case .active(let prepared) = result else {
      throw PendingPairingTestFailure.unexpectedPhase
    }
    return prepared
  }
}

actor PendingPairingTestKeyStore: PairedMarkerListingKeyStore {
  private var values: [KeyStoreKey: Data] = [:]
  private var mutationOrdinal = 0
  private var failureOrdinal: Int?
  private var mutationLog: [String] = []

  var valueCount: Int { values.count }

  var mutationCount: Int { mutationLog.count }

  var persistedPurposeSuffixes: [String] {
    mutationLog.compactMap { entry in
      guard entry.hasPrefix("persist:") else { return nil }
      return entry.dropFirst("persist:".count).split(separator: "/").last.map(String.init)
    }
  }

  func load(_ key: KeyStoreKey) async throws -> Data? {
    values[key]
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    if let current = values[key] {
      guard current == data else { throw KeyStoreError.immutableConflict }
      return .alreadyPresent
    }
    values[key] = data
    try didMutate("persist:\(key.account)")
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    guard let current = values[key] else {
      throw KeyStoreError.compareAndReplaceMissing
    }
    guard current == expected else {
      throw KeyStoreError.compareAndReplaceMismatch
    }
    values[key] = replacement
    try didMutate("cas:\(key.account)")
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard values[key] == expected else {
      throw KeyStoreError.deleteReadbackFailed
    }
    values.removeValue(forKey: key)
    try didMutate("delete:\(key.account)")
  }

  func pairedCommitMarkerKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pairedMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    return values.keys.filter {
      $0.account.hasPrefix(prefix)
        && $0.account.hasSuffix("/\(PairedKeyStorePurpose.commitMarker.rawValue)")
    }.sorted { $0.account < $1.account }
  }

  func pendingPairingRecoveryKeys(
    clientKind: RelayClientKind,
    installationID: UUID
  ) async throws -> [KeyStoreKey] {
    let prefix = KeyStoreKey.pendingMarkerPrefix(
      clientKind: clientKind,
      installationID: installationID
    )
    let suffixes = [
      "/\(PendingKeyStorePurpose.recoveryIntent.rawValue)",
      "/\(PendingKeyStorePurpose.pairingRecord.rawValue)",
    ]
    return values.keys.filter { key in
      key.account.hasPrefix(prefix)
        && suffixes.contains(where: key.account.hasSuffix)
    }.sorted { $0.account < $1.account }
  }

  func value(for key: KeyStoreKey) -> Data? {
    values[key]
  }

  func force(_ value: Data, for key: KeyStoreKey) {
    values[key] = value
  }

  func failAfterMutation(_ ordinal: Int) {
    mutationOrdinal = 0
    failureOrdinal = ordinal
  }

  func clearFailure() {
    mutationOrdinal = 0
    failureOrdinal = nil
  }

  func resetMutationTracking() {
    mutationOrdinal = 0
    mutationLog = []
    failureOrdinal = nil
  }

  private func didMutate(_ entry: String) throws {
    mutationOrdinal += 1
    mutationLog.append(entry)
    if mutationOrdinal == failureOrdinal {
      throw PendingPairingInjectedCrash()
    }
  }
}

struct PendingPairingInjectedCrash: Error {}

enum PendingPairingTestFailure: Error {
  case unexpectedPhase
}

private func pendingResponseState(
  index: UInt8,
  prepared: PreparedPendingPairingV1
) throws -> PendingPairingResponseStateV1 {
  let envelope = try PairTerminalEnvelopeCodec.encode(
    CanonicalPairingControlEnvelopeV1(
      formatVersion: 1,
      encapsulatedKey: Data(repeating: 0xB0 &+ index, count: 32),
      ciphertext: Data(repeating: 0xC0 &+ index, count: 48)
    )
  )
  let machineRoute = Data(repeating: 0x20 &+ index, count: 16)
  let deviceRoute = Data(repeating: 0x30 &+ index, count: 16)
  let createdAtMilliseconds = 1_700_000_000_000 + UInt64(index)
  let pairedRecord = try StoredPairedMachineRecordV1(
    clientKind: prepared.record.clientKind,
    installationID: prepared.record.installationID,
    machineID: PairingPromotionBuilder.machineID(
      rootFingerprint: prepared.invite.machineRootFingerprint
    ),
    machineName: prepared.invite.machineDisplayName,
    relayURL: URL(string: prepared.invite.wssURL)!,
    relayServerID: prepared.invite.relayServerID,
    machineRootPublicKey: prepared.invite.machineRootPublicKey,
    machineRootFingerprint: prepared.invite.machineRootFingerprint,
    machineDataCertificate: prepared.invite.dataSignCertificate,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    currentSPKIPin: prepared.invite.currentSPKIPin,
    nextSPKIPin: prepared.invite.nextSPKIPin,
    grantSerial: 1,
    trustEpoch: prepared.invite.dataSignCertificate.trustEpoch,
    createdAtMS: createdAtMilliseconds
  )
  let unsigned = try PendingPairingResponseStateV1(
    responseHash: Data(repeating: 0x10 &+ index, count: 32),
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    createdAtMilliseconds: createdAtMilliseconds,
    promotionID: Data(repeating: 0x40 &+ index, count: 32),
    storageKEK: Data(repeating: 0x50 &+ index, count: 32),
    pairedRecordCanonicalBytes: try PairedMachineRecordCodec.encode(pairedRecord),
    receiptCarrier: envelope,
    receiptAuditSignature: Data(repeating: 0, count: 64),
    requireAuditSignature: false
  )
  return try PairingPromotionBuilder.attestResponseStateForPersistence(
    unsigned,
    prepared: prepared
  )
}
