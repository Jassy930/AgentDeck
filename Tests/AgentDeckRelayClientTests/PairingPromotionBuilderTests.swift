import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PairingPromotionBuilderTests: XCTestCase {
  func testValidPairResponseAuditsDirectoryAndCompletesPairedPromotion() async throws {
    let fixture = try await PairingPromotionFixture()
    let response = try PairingPromotionBuilder.makeResponseState(
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      verified: fixture.verified,
      prepared: fixture.prepared,
      nowMilliseconds: fixture.nowMilliseconds
    )
    let staged = try await fixture.pendingStore.stageResponse(
      response,
      for: fixture.prepared
    )
    let promotion = try PairingPromotionBuilder.makePromotion(
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      verified: fixture.verified,
      prepared: staged,
      response: response
    )

    XCTAssertEqual(promotion.record.clientKind, fixture.clientKind)
    XCTAssertEqual(promotion.record.installationID, fixture.installationID)
    XCTAssertEqual(promotion.record.relayServerID, fixture.relayServerID)
    XCTAssertEqual(promotion.record.machineRoute, fixture.machineRoute)
    XCTAssertEqual(promotion.record.deviceRoute, fixture.deviceRoute)
    XCTAssertEqual(promotion.record.grantSerial, fixture.grantSerial)
    XCTAssertEqual(promotion.record.trustEpoch, fixture.trustEpoch)
    XCTAssertEqual(
      promotion.deviceSignPrivateKey,
      staged.deviceSigningKey.rawRepresentation
    )
    XCTAssertEqual(
      promotion.deviceHPKEPrivateKey,
      staged.deviceHPKEPrivateKey.rawRepresentation
    )
    XCTAssertEqual(
      promotion.deviceGrant,
      fixture.verified.plaintext.relayGrantCanonicalBytes
    )
    XCTAssertEqual(promotion.initialCryptoState.state.keyDirectory, fixture.directory)
    XCTAssertEqual(
      promotion.initialCryptoState.state.senderCounter.keyID.purpose,
      .deviceCommandTx
    )
    XCTAssertEqual(
      promotion.initialCryptoState.state.replayStates.map(\.scope.keyID.purpose),
      [.catalog, .deviceReplyTx]
    )
    XCTAssertTrue(promotion.initialCryptoState.state.streamStates.isEmpty)

    let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-pairing-promotion-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: rootURL) }
    let pairedStore = PairedMachineStore(
      keyStore: fixture.keyStore,
      stateRootURL: rootURL,
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )

    let promotionResult = try await pairedStore.stagePairingPromotion(promotion)
    XCTAssertEqual(promotionResult, .inserted)
    let stagedList = try await pairedStore.list()
    let stagedConnection = try await pairedStore.openConnectionMaterial(
      rootFingerprint: promotion.record.machineRootFingerprint,
      machineRoute: promotion.record.machineRoute
    )
    let stagedState = try await pairedStore.pairingPromotionState(
      prepared: staged,
      response: response
    )
    XCTAssertTrue(stagedList.isEmpty)
    XCTAssertNil(
      stagedConnection,
      "PairRoute terminal 前 staged material 不得进入机器列表或连接能力"
    )
    XCTAssertEqual(stagedState, .staged(promotion.record))

    let finalized = try await pairedStore.finalizePairingPromotion(
      prepared: staged,
      response: response
    )
    XCTAssertEqual(finalized, promotion.record)
    let listed = try await pairedStore.list()
    XCTAssertEqual(listed, [promotion.record])
    let committedConnection = try await pairedStore.openConnectionMaterial(
      rootFingerprint: promotion.record.machineRootFingerprint,
      machineRoute: promotion.record.machineRoute
    )
    XCTAssertNotNil(committedConnection)

    try await fixture.pendingStore.markCompleted(for: staged)
    let pendingMarker = await fixture.keyStore.value(for: fixture.pendingRecordKey)
    XCTAssertNil(pendingMarker)
    let pairedAfterPendingCleanup = try await pairedStore.list()
    XCTAssertEqual(pairedAfterPendingCleanup, [promotion.record])
  }

  func testCleanupJournalColdResumeConvergesEveryCrashCut() async throws {
    for crashAfterMutation in 1...7 {
      let fixture = try await PairingPromotionFixture()
      let response = try PairingPromotionBuilder.makeResponseState(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: fixture.prepared,
        nowMilliseconds: fixture.nowMilliseconds
      )
      let staged = try await fixture.pendingStore.stageResponse(
        response,
        for: fixture.prepared
      )
      let promotion = try PairingPromotionBuilder.makePromotion(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: staged,
        response: response
      )
      let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
        "agentdeck-pairing-cleanup-\(crashAfterMutation)-\(UUID().uuidString)",
        isDirectory: true
      )
      try FileManager.default.createDirectory(
        at: rootURL,
        withIntermediateDirectories: true
      )
      defer { try? FileManager.default.removeItem(at: rootURL) }
      let store = PairedMachineStore(
        keyStore: fixture.keyStore,
        stateRootURL: rootURL,
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
      )
      _ = try await store.promote(promotion)
      try await fixture.pendingStore.markCompleted(for: staged)
      let stateStore = try pairingPromotionStateStore(
        rootURL: rootURL,
        promotion: promotion
      )
      let stateBeforeCrash = try await stateStore.load()
      XCTAssertNotNil(stateBeforeCrash)
      let pairedOnlyValueCount = await fixture.keyStore.valueCount
      XCTAssertEqual(pairedOnlyValueCount, 6)

      await fixture.keyStore.resetMutationTracking()
      await fixture.keyStore.failAfterMutation(crashAfterMutation)
      do {
        try await store.deleteExact(promotion.record)
        XCTFail("paired cleanup mutation \(crashAfterMutation) 后必须注入 crash")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      let hiddenAfterCrash = try await store.list()
      XCTAssertTrue(hiddenAfterCrash.isEmpty)
      await fixture.keyStore.clearFailure()

      let coldStore = PairedMachineStore(
        keyStore: fixture.keyStore,
        stateRootURL: rootURL,
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
      )
      try await coldStore.resumeIncompleteCleanups()
      let finalList = try await coldStore.list()
      let finalState = try await stateStore.load()
      let finalValueCount = await fixture.keyStore.valueCount
      XCTAssertTrue(finalList.isEmpty)
      XCTAssertNil(finalState)
      XCTAssertEqual(finalValueCount, 0)
    }
  }

  func testPartialPromotionRestartThenTerminalCleanupConvergesEveryCrashMatrix()
    async throws
  {
    for promotionCrash in 1...5 {
      for terminalCleanupCrash in 1...promotionCrash {
        let fixture = try await PairingPromotionFixture()
        let response = try PairingPromotionBuilder.makeResponseState(
          clientKind: fixture.clientKind,
          installationID: fixture.installationID,
          verified: fixture.verified,
          prepared: fixture.prepared,
          nowMilliseconds: fixture.nowMilliseconds
        )
        let staged = try await fixture.pendingStore.stageResponse(
          response,
          for: fixture.prepared
        )
        let promotion = try PairingPromotionBuilder.makePromotion(
          clientKind: fixture.clientKind,
          installationID: fixture.installationID,
          verified: fixture.verified,
          prepared: staged,
          response: response
        )
        let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
          "agentdeck-partial-terminal-\(promotionCrash)-\(terminalCleanupCrash)-\(UUID().uuidString)",
          isDirectory: true
        )
        try FileManager.default.createDirectory(
          at: rootURL,
          withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let firstStore = PairedMachineStore(
          keyStore: fixture.keyStore,
          stateRootURL: rootURL,
          clientKind: fixture.clientKind,
          installationID: fixture.installationID,
          testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
        )
        await fixture.keyStore.resetMutationTracking()
        await fixture.keyStore.failAfterMutation(promotionCrash)
        do {
          _ = try await firstStore.stagePairingPromotion(promotion)
          XCTFail("promotion marker 前 mutation \(promotionCrash) 必须注入 crash")
        } catch is PendingPairingInjectedCrash {
          // expected
        }
        let visibleAfterPromotionCrash = try await firstStore.list()
        XCTAssertTrue(visibleAfterPromotionCrash.isEmpty)

        await fixture.keyStore.resetMutationTracking()
        await fixture.keyStore.failAfterMutation(terminalCleanupCrash)
        let restarted = PairedMachineStore(
          keyStore: fixture.keyStore,
          stateRootURL: rootURL,
          clientKind: fixture.clientKind,
          installationID: fixture.installationID,
          testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
        )
        do {
          try await restarted.abortPairingPromotion(
            prepared: staged,
            response: response
          )
          XCTFail(
            "partial promotion \(promotionCrash) 的 terminal cleanup mutation \(terminalCleanupCrash) 必须注入 crash"
          )
        } catch is PendingPairingInjectedCrash {
          // expected
        }

        await fixture.keyStore.clearFailure()
        let coldStore = PairedMachineStore(
          keyStore: fixture.keyStore,
          stateRootURL: rootURL,
          clientKind: fixture.clientKind,
          installationID: fixture.installationID,
          testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
        )
        try await coldStore.abortPairingPromotion(
          prepared: staged,
          response: response
        )
        try await fixture.pendingStore.stageTerminal(.expired, for: staged)
        let visibleAfterTerminal = try await coldStore.list()
        XCTAssertTrue(visibleAfterTerminal.isEmpty)
        let stateStore = try pairingPromotionStateStore(
          rootURL: rootURL,
          promotion: promotion
        )
        let finalState = try await stateStore.load()
        XCTAssertNil(finalState)
        let finalValueCount = await fixture.keyStore.valueCount
        XCTAssertEqual(finalValueCount, 0)
      }
    }
  }

  func testMarkerMissingPartialRollbackRejectsUnboundGuardWithoutMutation()
    async throws
  {
    for invalidGuard in InvalidPartialGuard.allCases {
      let fixture = try await PairingPromotionFixture()
      let response = try PairingPromotionBuilder.makeResponseState(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: fixture.prepared,
        nowMilliseconds: fixture.nowMilliseconds
      )
      let staged = try await fixture.pendingStore.stageResponse(
        response,
        for: fixture.prepared
      )
      let promotion = try PairingPromotionBuilder.makePromotion(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: staged,
        response: response
      )
      let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
        "agentdeck-invalid-partial-guard-\(invalidGuard.label)-\(UUID().uuidString)",
        isDirectory: true
      )
      try FileManager.default.createDirectory(
        at: rootURL,
        withIntermediateDirectories: true
      )
      defer { try? FileManager.default.removeItem(at: rootURL) }
      let store = PairedMachineStore(
        keyStore: fixture.keyStore,
        stateRootURL: rootURL,
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
      )

      await fixture.keyStore.resetMutationTracking()
      await fixture.keyStore.failAfterMutation(5)
      do {
        _ = try await store.stagePairingPromotion(promotion)
        XCTFail("CounterGuard durable 后必须注入 marker-missing crash")
      } catch is PendingPairingInjectedCrash {
        // expected
      }
      await fixture.keyStore.clearFailure()

      let guardKey = try pairingPromotionKey(
        promotion.record,
        purpose: .counterGuard
      )
      let markerKey = try pairingPromotionKey(
        promotion.record,
        purpose: .commitMarker
      )
      let loadedOriginalGuard = await fixture.keyStore.value(for: guardKey)
      let originalGuard = try XCTUnwrap(loadedOriginalGuard)
      let markerBeforeRollback = await fixture.keyStore.value(for: markerKey)
      XCTAssertNil(markerBeforeRollback)
      let replacement: Data
      switch invalidGuard {
      case .malformed:
        replacement = Data("malformed-counter-guard".utf8)
      case .foreignPromotion:
        replacement = try await makeForeignPromotionGuard(
          from: promotion,
          guardKey: guardKey
        )
      }
      XCTAssertNotEqual(replacement, originalGuard)
      await fixture.keyStore.force(replacement, for: guardKey)

      let durableKeys = try [
        pairingPromotionKey(promotion.record, purpose: .deviceStorageKEK),
        pairingPromotionKey(promotion.record, purpose: .deviceSignPrivateKey),
        pairingPromotionKey(promotion.record, purpose: .deviceHPKEPrivateKey),
        pairingPromotionKey(promotion.record, purpose: .deviceGrant),
        guardKey,
      ]
      var valuesBefore: [KeyStoreKey: Data] = [:]
      for key in durableKeys {
        let loaded = await fixture.keyStore.value(for: key)
        valuesBefore[key] = try XCTUnwrap(loaded)
      }
      let stateStore = try pairingPromotionStateStore(
        rootURL: rootURL,
        promotion: promotion
      )
      let loadedStateBefore = try await stateStore.load()
      let stateBefore = try XCTUnwrap(loadedStateBefore)
      let valueCountBefore = await fixture.keyStore.valueCount
      await fixture.keyStore.resetMutationTracking()

      do {
        try await store.abortPairingPromotion(
          prepared: staged,
          response: response
        )
        XCTFail("\(invalidGuard.label) CounterGuard 必须 fail-close")
      } catch {
        XCTAssertEqual(
          error as? PairedMachineStoreError,
          .persistenceMismatch,
          invalidGuard.label
        )
      }

      let mutationCountAfter = await fixture.keyStore.mutationCount
      let valueCountAfter = await fixture.keyStore.valueCount
      XCTAssertEqual(mutationCountAfter, 0, invalidGuard.label)
      XCTAssertEqual(valueCountAfter, valueCountBefore, invalidGuard.label)
      for key in durableKeys {
        let valueAfter = await fixture.keyStore.value(for: key)
        XCTAssertEqual(
          valueAfter,
          valuesBefore[key],
          invalidGuard.label
        )
      }
      let stateAfter = try await stateStore.load()
      let markerAfter = await fixture.keyStore.value(for: markerKey)
      XCTAssertEqual(stateAfter, stateBefore, invalidGuard.label)
      XCTAssertNil(markerAfter, invalidGuard.label)
    }
  }

  func testExpiredResponsePreparedRetainsDurableInvisiblePromotionForReconciliation()
    async throws
  {
    let fixture = try await PairingPromotionFixture()
    let response = try PairingPromotionBuilder.makeResponseState(
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      verified: fixture.verified,
      prepared: fixture.prepared,
      nowMilliseconds: fixture.nowMilliseconds
    )
    let staged = try await fixture.pendingStore.stageResponse(
      response,
      for: fixture.prepared
    )
    let promotion = try PairingPromotionBuilder.makePromotion(
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      verified: fixture.verified,
      prepared: staged,
      response: response
    )
    let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "agentdeck-expired-promotion-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: rootURL) }
    let firstStore = PairedMachineStore(
      keyStore: fixture.keyStore,
      stateRootURL: rootURL,
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    _ = try await firstStore.stagePairingPromotion(promotion)

    let coldStore = PairedMachineStore(
      keyStore: fixture.keyStore,
      stateRootURL: rootURL,
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
    try await coldStore.recoverPendingPairings(
      nowMilliseconds: fixture.invite.expiresAtMilliseconds
    )

    let listed = try await coldStore.list()
    let connection = try await coldStore.openConnectionMaterial(
      rootFingerprint: promotion.record.machineRootFingerprint,
      machineRoute: promotion.record.machineRoute
    )
    let recoveredState = try await coldStore.pairingPromotionState(
      prepared: staged,
      response: response
    )
    XCTAssertTrue(listed.isEmpty)
    XCTAssertNil(connection)
    XCTAssertEqual(
      recoveredState,
      .staged(promotion.record),
      "invite expiry 不得删除可能已在 Relay active 的长期 grant material"
    )
    guard
      case .active(let recovered)? = try await fixture.pendingStore.resumeIfPresent(
        invite: fixture.invite,
        authorizationRequest: fixture.authorization,
        nowMilliseconds: fixture.invite.expiresAtMilliseconds
      )
    else {
      return XCTFail("responsePrepared 必须可跨 absolute expiry 恢复")
    }
    XCTAssertEqual(recovered.record.phase, staged.record.phase)
  }

  func testExpiredResponsePreparedColdRecoversEveryPartialPromotionPrefix()
    async throws
  {
    for promotionCrash in 1...5 {
      let fixture = try await PairingPromotionFixture()
      let response = try PairingPromotionBuilder.makeResponseState(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: fixture.prepared,
        nowMilliseconds: fixture.nowMilliseconds
      )
      let staged = try await fixture.pendingStore.stageResponse(
        response,
        for: fixture.prepared
      )
      let promotion = try PairingPromotionBuilder.makePromotion(
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: staged,
        response: response
      )
      let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
        "agentdeck-expired-partial-\(promotionCrash)-\(UUID().uuidString)",
        isDirectory: true
      )
      try FileManager.default.createDirectory(
        at: rootURL,
        withIntermediateDirectories: true
      )
      defer { try? FileManager.default.removeItem(at: rootURL) }
      let firstStore = PairedMachineStore(
        keyStore: fixture.keyStore,
        stateRootURL: rootURL,
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
      )
      await fixture.keyStore.resetMutationTracking()
      await fixture.keyStore.failAfterMutation(promotionCrash)
      do {
        _ = try await firstStore.stagePairingPromotion(promotion)
        XCTFail("partial promotion crash cut \(promotionCrash) 必须注入")
      } catch is PendingPairingInjectedCrash {
        // expected
      }

      await fixture.keyStore.clearFailure()
      let coldStore = PairedMachineStore(
        keyStore: fixture.keyStore,
        stateRootURL: rootURL,
        clientKind: fixture.clientKind,
        installationID: fixture.installationID,
        testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
      )
      try await coldStore.recoverPendingPairings(
        nowMilliseconds: fixture.invite.expiresAtMilliseconds
      )
      let listedMachines = try await coldStore.list()
      XCTAssertTrue(listedMachines.isEmpty)
      let stateStore = try pairingPromotionStateStore(
        rootURL: rootURL,
        promotion: promotion
      )
      let persistedState = try await stateStore.load()
      XCTAssertNil(persistedState)
      let finalValueCount = await fixture.keyStore.valueCount
      XCTAssertEqual(finalValueCount, 0)
    }
  }

  func testRestartedPendingRecordRejectsWrongDurableNamespace() async throws {
    let fixture = try await PairingPromotionFixture()
    let reopened = try await fixture.reopenPrepared()
    XCTAssertEqual(reopened.canonicalRecord, fixture.prepared.canonicalRecord)

    let response = try PairingPromotionBuilder.makeResponseState(
      clientKind: fixture.clientKind,
      installationID: fixture.installationID,
      verified: fixture.verified,
      prepared: reopened,
      nowMilliseconds: fixture.nowMilliseconds
    )
    let wrongInstallationID = UUID(
      uuidString: "50000000-0000-0000-0000-000000000099"
    )!

    assertPromotionBuilderError(.invalidBinding) {
      _ = try PairingPromotionBuilder.makeResponseState(
        clientKind: .cli,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: reopened,
        nowMilliseconds: fixture.nowMilliseconds
      )
    }
    assertPromotionBuilderError(.invalidBinding) {
      _ = try PairingPromotionBuilder.makeResponseState(
        clientKind: fixture.clientKind,
        installationID: wrongInstallationID,
        verified: fixture.verified,
        prepared: reopened,
        nowMilliseconds: fixture.nowMilliseconds
      )
    }
    assertPromotionBuilderError(.invalidBinding) {
      _ = try PairingPromotionBuilder.makePromotion(
        clientKind: .cli,
        installationID: fixture.installationID,
        verified: fixture.verified,
        prepared: reopened,
        response: response
      )
    }
    assertPromotionBuilderError(.invalidBinding) {
      _ = try PairingPromotionBuilder.makePromotion(
        clientKind: fixture.clientKind,
        installationID: wrongInstallationID,
        verified: fixture.verified,
        prepared: reopened,
        response: response
      )
    }
  }
}

private enum InvalidPartialGuard: CaseIterable {
  case malformed
  case foreignPromotion

  var label: String {
    switch self {
    case .malformed: "malformed"
    case .foreignPromotion: "foreign-promotion"
    }
  }
}

private func pairingPromotionKey(
  _ record: StoredPairedMachineRecordV1,
  purpose: PairedKeyStorePurpose
) throws -> KeyStoreKey {
  try KeyStoreKey.paired(
    clientKind: record.clientKind,
    installationID: record.installationID,
    rootFingerprint: record.machineRootFingerprint,
    machineRoute: record.machineRoute,
    purpose: purpose
  )
}

private func makeForeignPromotionGuard(
  from promotion: PreparedPairedMachinePromotionV1,
  guardKey: KeyStoreKey
) async throws -> Data {
  let foreignPromotionID = Data(repeating: 0xFE, count: 32)
  precondition(foreignPromotionID != promotion.promotionID32)
  let foreignPromotion = try PreparedPairedMachinePromotionV1(
    record: promotion.record,
    promotionID32: foreignPromotionID,
    deviceSignPrivateKey: promotion.deviceSignPrivateKey,
    deviceHPKEPrivateKey: promotion.deviceHPKEPrivateKey,
    deviceGrant: promotion.deviceGrant,
    deviceStorageKEK: promotion.deviceStorageKEK,
    initialCryptoState: promotion.initialCryptoState
  )
  let foreignKeyStore = PendingPairingTestKeyStore()
  let foreignRootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "agentdeck-foreign-promotion-guard-\(UUID().uuidString)",
    isDirectory: true
  )
  try FileManager.default.createDirectory(
    at: foreignRootURL,
    withIntermediateDirectories: true
  )
  defer { try? FileManager.default.removeItem(at: foreignRootURL) }
  let foreignStore = PairedMachineStore(
    keyStore: foreignKeyStore,
    stateRootURL: foreignRootURL,
    clientKind: promotion.record.clientKind,
    installationID: promotion.record.installationID,
    testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
  )
  _ = try await foreignStore.promote(foreignPromotion)
  let loadedGuard = await foreignKeyStore.value(for: guardKey)
  return try XCTUnwrap(loadedGuard)
}

private func pairingPromotionStateStore(
  rootURL: URL,
  promotion: PreparedPairedMachinePromotionV1
) throws -> FileCryptoStateStore {
  let record = promotion.record
  let identity = try CryptoStateIdentity(
    clientKind: record.clientKind,
    installationID: record.installationID,
    machineID: record.machineID,
    machineRootFingerprint: record.machineRootFingerprint,
    machineRoute: record.machineRoute
  )
  return try FileCryptoStateStore(
    rootURL: rootURL,
    identity: identity,
    storageKey: promotion.deviceStorageKEK,
    testHooks: .none,
    testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
  )
}

private struct PairingPromotionFixture {
  let nowMilliseconds: UInt64 = 1_700_000_000_000
  let clientKind: RelayClientKind = .iOSApp
  let installationID = UUID(
    uuidString: "50000000-0000-0000-0000-000000000001"
  )!
  let relayServerID = Data(repeating: 0x31, count: 16)
  let pairRoute = Data(repeating: 0x32, count: 16)
  let machineRoute = Data(repeating: 0x33, count: 16)
  let deviceRoute = Data(repeating: 0x34, count: 16)
  let rootKeyID = Data(repeating: 0x35, count: 16)
  let grantSerial: UInt64 = 9
  let trustEpoch: UInt64 = 3
  let keyStore: PendingPairingTestKeyStore
  let pendingStore: PendingPairingStore
  let pendingRecordKey: KeyStoreKey
  let invite: PairInviteV1
  let authorization: AuthorizationRequestV1
  let prepared: PreparedPendingPairingV1
  let verified: VerifiedPendingPairResponseV1
  let directory: DeviceKeyDirectoryV1

  init() async throws {
    let rootKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x51, count: 32)
    )
    let dataKey = try Curve25519.Signing.PrivateKey(
      rawRepresentation: Data(repeating: 0x52, count: 32)
    )
    let inviteHPKEKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(repeating: 0x53, count: 32)
    )
    let rootPublic = rootKey.publicKey.rawRepresentation
    let rootFingerprint = CanonicalCodec.sha256(rootPublic)
    let certificate = try pairingPromotionCertificate(
      rootKey: rootKey,
      dataKey: dataKey,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      rootFingerprint: rootFingerprint,
      rootKeyID: rootKeyID,
      trustEpoch: trustEpoch,
      notAfterMilliseconds: nil
    )
    invite = try PairInviteV1(
      pairRoute: pairRoute,
      inviteSecret: Data(repeating: 0x54, count: 32),
      inviteHPKEPublicKey: inviteHPKEKey.publicKey.rawRepresentation,
      wssURL: "wss://relay.example.test/",
      relayServerID: relayServerID,
      currentSPKIPin: Data(repeating: 0x55, count: 32),
      nextSPKIPin: Data(repeating: 0x56, count: 32),
      expiresAtMilliseconds: nowMilliseconds + 300_000,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: rootFingerprint,
      dataSignCertificate: certificate,
      machineDisplayName: "Promotion Fixture"
    )
    authorization = try AuthorizationRequestV1(
      deviceDisplayName: "Fixture iPhone",
      capabilities: [.catalog],
      permissions: [.catalogRead]
    )
    keyStore = PendingPairingTestKeyStore()
    pendingStore = try PendingPairingStore(
      keyStore: keyStore,
      clientKind: clientKind,
      installationID: installationID
    )
    let prepareResult = try await pendingStore.prepare(
      invite: invite,
      authorizationRequest: authorization,
      nowMilliseconds: nowMilliseconds
    )
    guard case .active(let active) = prepareResult else {
      throw PairingPromotionTestError.unexpectedPhase
    }
    prepared = active
    pendingRecordKey = try KeyStoreKey.pending(
      clientKind: clientKind,
      installationID: installationID,
      inviteHash: invite.canonicalSHA256(),
      purpose: .pairingRecord
    )

    let verifiedCertificate = try MachineDataCertificateVerifier.verify(
      certificate,
      relayServerID: relayServerID,
      machineRoute: machineRoute,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: rootFingerprint,
      expectedRootKeyID: rootKeyID,
      expectedTrustEpoch: trustEpoch,
      minimumDataCertificateGeneration: certificate.generation,
      nowMilliseconds: nowMilliseconds
    )
    let record = try StoredPairedMachineRecordV1(
      clientKind: clientKind,
      installationID: installationID,
      machineID: "fixture-machine",
      machineName: invite.machineDisplayName,
      relayURL: URL(string: invite.wssURL)!,
      relayServerID: relayServerID,
      machineRootPublicKey: rootPublic,
      machineRootFingerprint: rootFingerprint,
      machineDataCertificate: certificate,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      currentSPKIPin: invite.currentSPKIPin,
      nextSPKIPin: invite.nextSPKIPin,
      grantSerial: grantSerial,
      trustEpoch: trustEpoch,
      createdAtMS: nowMilliseconds
    )
    let directoryVerifier = try KeyDirectoryVerifier(
      record: record,
      verifiedCertificate: verifiedCertificate,
      deviceHPKEPrivateKey: active.deviceHPKEPrivateKey
    )
    directory = try pairingPromotionDirectory(
      verifier: directoryVerifier,
      dataKey: dataKey,
      deviceHPKEPublicKey: active.deviceHPKEPrivateKey.publicKey,
      deviceRoute: deviceRoute
    )
    let canonicalResponse = try pairingPromotionResponse(
      invite: invite,
      authorization: authorization,
      prepared: active,
      rootKey: rootKey,
      dataKey: dataKey,
      certificate: certificate,
      directory: directory,
      machineRoute: machineRoute,
      deviceRoute: deviceRoute,
      grantSerial: grantSerial,
      trustEpoch: trustEpoch
    )
    verified = try PairResponseCrypto.openVerified(
      canonicalResponse: canonicalResponse,
      invite: invite,
      authorizationRequest: authorization,
      requestHash: active.record.requestHash,
      deviceSigningKey: active.deviceSigningKey,
      deviceHPKEPrivateKey: active.deviceHPKEPrivateKey,
      nowMilliseconds: nowMilliseconds
    )
  }

  func reopenPrepared() async throws -> PreparedPendingPairingV1 {
    let coldStore = try PendingPairingStore(
      keyStore: keyStore,
      clientKind: clientKind,
      installationID: installationID
    )
    let result = try await coldStore.prepare(
      invite: invite,
      authorizationRequest: authorization,
      nowMilliseconds: nowMilliseconds
    )
    guard case .active(let reopened) = result else {
      throw PairingPromotionTestError.unexpectedPhase
    }
    return reopened
  }
}

private func pairingPromotionCertificate(
  rootKey: Curve25519.Signing.PrivateKey,
  dataKey: Curve25519.Signing.PrivateKey,
  relayServerID: Data,
  machineRoute: Data,
  rootFingerprint: Data,
  rootKeyID: Data,
  trustEpoch: UInt64,
  notAfterMilliseconds: UInt64?
) throws -> RelayV2SignedCertificate {
  let unsigned = RelayV2SignedCertificate(
    subjectPubkey: dataKey.publicKey.rawRepresentation,
    certRole: .data,
    generation: 4,
    rootKeyId: rootKeyID,
    trustEpoch: trustEpoch,
    notAfterMs: notAfterMilliseconds,
    signature: Data(repeating: 0, count: 64)
  )
  let tbs = ToBeSignedV1(
    objectType: .dataCert,
    signatureFormatVersion: 1,
    relayProtocolVersion: relayProtocolVersionV2,
    runtimeProtocolVersion: runtimeProtocolVersionCurrent,
    e2eeFormatVersion: 1,
    relayServerID: relayServerID,
    machineRoute: machineRoute,
    deviceRoute: nil,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    roleScope: "machine-data",
    signingKeyFingerprint: rootFingerprint,
    rootKeyID: rootKeyID,
    trustEpoch: trustEpoch,
    serialOrGeneration: unsigned.generation,
    notAfterMS: notAfterMilliseconds,
    signedObjectSHA256: try SignedCertificateCanonicalCodec.unsignedCanonicalSHA256(
      unsigned
    )
  )
  return RelayV2SignedCertificate(
    subjectPubkey: unsigned.subjectPubkey,
    certRole: unsigned.certRole,
    generation: unsigned.generation,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    notAfterMs: unsigned.notAfterMs,
    signature: try RelayCrypto.sign(tbs, key: rootKey)
  )
}

private func pairingPromotionDirectory(
  verifier: KeyDirectoryVerifier,
  dataKey: Curve25519.Signing.PrivateKey,
  deviceHPKEPublicKey: Curve25519.KeyAgreement.PublicKey,
  deviceRoute: Data
) throws -> DeviceKeyDirectoryV1 {
  let revision: UInt64 = 1
  let materials: [(KeyIDV1, Data)] = [
    (KeyIDV1(purpose: .catalog, epoch: 1), Data(repeating: 0x61, count: 32)),
    (KeyIDV1(purpose: .deviceCommandTx, epoch: 1), Data(repeating: 0x62, count: 32)),
    (KeyIDV1(purpose: .deviceReplyTx, epoch: 1), Data(repeating: 0x63, count: 32)),
  ]
  let entries = try materials.map { keyID, material in
    let sealing = try verifier.sealingContext(
      keyDirectoryRevision: revision,
      keyID: keyID,
      streamRoute: nil
    )
    let envelope = try RelayCrypto.sealHPKE(
      material,
      recipient: deviceHPKEPublicKey,
      info: sealing.info,
      aad: CanonicalCodec.encodeAAD(sealing.outerContext)
    )
    return try DeviceWrappedKeyV1(
      keyID: keyID,
      deviceRoute: deviceRoute,
      streamRoute: nil,
      enc: envelope.enc,
      wrappedKey: envelope.ciphertext
    )
  }
  let unsigned = try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: Data(repeating: 1, count: 64)
  )
  return try DeviceKeyDirectoryV1(
    revision: revision,
    entries: entries,
    signature: dataKey.signature(for: verifier.directorySignatureTBS(unsigned))
  )
}

private func pairingPromotionResponse(
  invite: PairInviteV1,
  authorization: AuthorizationRequestV1,
  prepared: PreparedPendingPairingV1,
  rootKey: Curve25519.Signing.PrivateKey,
  dataKey: Curve25519.Signing.PrivateKey,
  certificate: RelayV2SignedCertificate,
  directory: DeviceKeyDirectoryV1,
  machineRoute: Data,
  deviceRoute: Data,
  grantSerial: UInt64,
  trustEpoch: UInt64
) throws -> Data {
  let unsignedGrant = RelayV2Grant(
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignPubkey: prepared.deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: grantSerial,
    rootKeyId: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: Data(repeating: 0, count: 64)
  )
  let grant = RelayV2Grant(
    machineRoute: unsignedGrant.machineRoute,
    deviceRoute: unsignedGrant.deviceRoute,
    deviceSignPubkey: unsignedGrant.deviceSignPubkey,
    grantSerial: unsignedGrant.grantSerial,
    rootKeyId: unsignedGrant.rootKeyId,
    trustEpoch: unsignedGrant.trustEpoch,
    signature: try RelayCrypto.sign(
      RelayGrantCredentialVerifier.toBeSigned(
        unsignedGrant,
        relayServerID: invite.relayServerID,
        machineRootFingerprint: invite.machineRootFingerprint
      ),
      key: rootKey
    )
  )
  let grantBytes = try RelayGrantCanonicalCodec.encode(grant)
  let unsignedAuthorization = try CanonicalDeviceAuthorizationV1(
    grantHash: CanonicalCodec.sha256(grantBytes),
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignFingerprint: CanonicalCodec.sha256(
      prepared.deviceSigningKey.publicKey.rawRepresentation
    ),
    grantSerial: grantSerial,
    deviceHPKEPublicKey: prepared.deviceHPKEPrivateKey.publicKey.rawRepresentation,
    capabilities: authorization.capabilities,
    permissions: authorization.permissions,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: Data(repeating: 0, count: 64),
    requireSignature: false
  )
  let authorizationTBS = ToBeSignedV1(
    objectType: .deviceAuthorization,
    signatureFormatVersion: 1,
    relayProtocolVersion: relayProtocolVersionV2,
    runtimeProtocolVersion: runtimeProtocolVersionCurrent,
    e2eeFormatVersion: 1,
    relayServerID: invite.relayServerID,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    streamRoute: nil,
    requestRoute: nil,
    streamGeneration: nil,
    streamCursor: nil,
    roleScope: "device-authorization",
    signingKeyFingerprint: invite.machineRootFingerprint,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    serialOrGeneration: grantSerial,
    notAfterMS: nil,
    signedObjectSHA256:
      try DeviceAuthorizationCanonicalCodec
      .unsignedCanonicalSHA256(unsignedAuthorization)
  )
  let deviceAuthorization = try CanonicalDeviceAuthorizationV1(
    grantHash: unsignedAuthorization.grantHash,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    deviceSignFingerprint: unsignedAuthorization.deviceSignFingerprint,
    grantSerial: grantSerial,
    deviceHPKEPublicKey: unsignedAuthorization.deviceHPKEPublicKey,
    capabilities: authorization.capabilities,
    permissions: authorization.permissions,
    rootKeyID: certificate.rootKeyId,
    trustEpoch: trustEpoch,
    signature: RelayCrypto.sign(authorizationTBS, key: rootKey)
  )
  let authorizationBytes = try DeviceAuthorizationCanonicalCodec.encode(
    deviceAuthorization
  )
  let directoryBytes = try KeyDirectoryCanonicalCodec.encode(directory)
  let plaintext = CanonicalPairResponsePlaintextV1(
    formatVersion: 1,
    requestHash: prepared.record.requestHash,
    relayGrant: grant,
    relayGrantCanonicalBytes: grantBytes,
    deviceAuthorization: deviceAuthorization,
    deviceAuthorizationCanonicalBytes: authorizationBytes,
    keyDirectory: directory,
    keyDirectoryCanonicalBytes: directoryBytes
  )
  let plaintextBytes = try PairResponsePlaintextCanonicalCodec.encode(plaintext)
  let info = try PairResponseInfoV1(
    relayServerID: invite.relayServerID,
    pairRoute: invite.pairRoute,
    inviteHash: invite.canonicalSHA256(),
    expiryMilliseconds: invite.expiresAtMilliseconds,
    requestHash: prepared.record.requestHash,
    machineRoute: machineRoute,
    deviceRoute: deviceRoute,
    grantSerial: grantSerial,
    rootTrustEpoch: trustEpoch
  )
  let context = pairingPromotionContext(
    kind: .pairResponse,
    pairRoute: invite.pairRoute
  )
  let envelope = try RelayCrypto.sealHPKE(
    plaintextBytes,
    recipient: prepared.deviceHPKEPrivateKey.publicKey,
    info: info.canonicalBytes(),
    aad: CanonicalCodec.encodeAAD(context)
  )
  let unsignedResponse = try CanonicalPairResponseV1(
    info: info,
    encapsulatedKey: envelope.enc,
    ciphertext: envelope.ciphertext,
    machineDataSignature: Data(repeating: 0, count: 64),
    requireSignature: false
  )
  let signatureTBS = try PairResponseCrypto.responseSignatureTBS(
    unsignedResponse,
    context: context,
    signingKeyFingerprint: CanonicalCodec.sha256(certificate.subjectPubkey),
    signingKeyGeneration: certificate.generation,
    signingCredentialSHA256: SignedCertificateCanonicalCodec.canonicalSHA256(
      certificate
    )
  )
  return try PairResponseCanonicalCodec.encode(
    CanonicalPairResponseV1(
      info: info,
      encapsulatedKey: envelope.enc,
      ciphertext: envelope.ciphertext,
      machineDataSignature: dataKey.signature(for: signatureTBS)
    )
  )
}

private func pairingPromotionContext(
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

private func assertPromotionBuilderError(
  _ expected: PairingPromotionBuilderError,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ body: () throws -> Void
) {
  do {
    try body()
    XCTFail("expected \(expected)", file: file, line: line)
  } catch {
    XCTAssertEqual(error as? PairingPromotionBuilderError, expected, file: file, line: line)
  }
}

private enum PairingPromotionTestError: Error {
  case unexpectedPhase
}
