import AgentDeckCore
import CryptoKit
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class PairedMachineStoreTests: XCTestCase {
  func testPreparedPromotionIsSendableRedactedAndModuleInternal() throws {
    requireSendable(StoredPairedMachineRecordV1.self)
    requireSendable(PreparedPairedMachinePromotionV1.self)
    requireSendable(PairedMachineStoreError.self)
    requireSendable(PairedMachineStore.self)

    let prepared = try makePrepared()
    XCTAssertEqual(prepared.record.pairedMachine.id, prepared.record.machineID)
    XCTAssertEqual(prepared.record.pairedMachine.name, prepared.record.machineName)
    XCTAssertEqual(prepared.record.pairedMachine.relayHost, "relay.example.com")
    XCTAssertEqual(
      prepared.record.pairedMachine.rootFingerprint,
      prepared.record.machineRootFingerprint
    )
    XCTAssertFalse(
      String(reflecting: prepared.record).contains(
        prepared.record.machineRoute.base64EncodedString()
      ))
    let reflected = String(reflecting: prepared)
    XCTAssertEqual(
      reflected,
      "PreparedPairedMachinePromotionV1(record: <redacted>, material: <redacted>)"
    )
    XCTAssertFalse(reflected.contains(prepared.deviceSignPrivateKey.base64EncodedString()))
    XCTAssertFalse(reflected.contains(prepared.deviceGrant.base64EncodedString()))

    let repositoryRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let source = try String(
      contentsOf: repositoryRoot.appendingPathComponent(
        "Sources/AgentDeckRelayClient/Storage/PairedMachineStore.swift"
      ),
      encoding: .utf8
    )
    XCTAssertFalse(source.contains("public func persist("))
    XCTAssertFalse(source.contains("public func promote("))
    XCTAssertFalse(source.contains("public struct PreparedPairedMachinePromotionV1"))
    let carrierStart = try XCTUnwrap(
      source.range(of: "struct PreparedPairedMachinePromotionV1")
    )
    let carrierEnd = try XCTUnwrap(
      source.range(of: "/// cold-open", range: carrierStart.upperBound..<source.endIndex)
    )
    let carrierSource = source[carrierStart.lowerBound..<carrierEnd.lowerBound]
    XCTAssertFalse(carrierSource.contains("public "))
  }

  func testRecordRejectsZeroTrustRoutesServerAndPins() throws {
    let zero16 = Data(repeating: 0, count: 16)
    let zero32 = Data(repeating: 0, count: 32)

    assertStoreError(.invalidRecord) { try makeRecord(relayServerID: zero16) }
    assertStoreError(.invalidRecord) { try makeRecord(machineRootFingerprint: zero32) }
    assertStoreError(.invalidRecord) { try makeRecord(machineRoute: zero16) }
    assertStoreError(.invalidRecord) { try makeRecord(deviceRoute: zero16) }
    assertStoreError(.invalidRecord) { try makeRecord(currentSPKIPin: zero32) }
    assertStoreError(.invalidRecord) { try makeRecord(nextSPKIPin: zero32) }
    assertStoreError(.invalidRecord) { try makeRecord(grantSerial: 0) }
    assertStoreError(.invalidRecord) { try makeRecord(trustEpoch: 0) }
    assertStoreError(.invalidRecord) {
      try makeRecord(
        installationID: UUID(
          uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )
      )
    }
  }

  func testRecordRejectsNoncanonicalRelayOriginAndWireInvalidDisplayName() throws {
    assertStoreError(.invalidRecord) {
      try makeRecord(relayURL: URL(string: "wss://relay.example.com:8443")!)
    }
    assertStoreError(.invalidRecord) {
      try makeRecord(relayURL: URL(string: "WSS://relay.example.com:8443/")!)
    }
    assertStoreError(.invalidRecord) {
      try makeRecord(relayURL: URL(string: "wss://relay.example.com:0/")!)
    }
    assertStoreError(.invalidRecord) {
      try makeRecord(relayURL: URL(string: "wss://relay.example.com:8443/?q=1")!)
    }
    assertStoreError(.invalidRecord) { try makeRecord(machineName: " Machine 1") }
    assertStoreError(.invalidRecord) { try makeRecord(machineName: "Machine\n1") }
    assertStoreError(.invalidRecord) {
      try makeRecord(machineName: String(repeating: "a", count: 129))
    }
  }

  func testPreparedPromotionRejectsBadSecretsAndMismatchedState() throws {
    let valid = try makePrepared()

    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: valid.record,
        promotionID32: Data(repeating: 0, count: 32),
        deviceSignPrivateKey: valid.deviceSignPrivateKey,
        deviceHPKEPrivateKey: valid.deviceHPKEPrivateKey,
        deviceGrant: valid.deviceGrant,
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }
    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: valid.record,
        promotionID32: valid.promotionID32,
        deviceSignPrivateKey: valid.deviceSignPrivateKey,
        deviceHPKEPrivateKey: valid.deviceHPKEPrivateKey,
        deviceGrant: corruptLastByte(valid.deviceGrant),
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }
    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: valid.record,
        promotionID32: valid.promotionID32,
        deviceSignPrivateKey: Data(repeating: 0, count: 32),
        deviceHPKEPrivateKey: valid.deviceHPKEPrivateKey,
        deviceGrant: valid.deviceGrant,
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }
    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: valid.record,
        promotionID32: valid.promotionID32,
        deviceSignPrivateKey: valid.deviceSignPrivateKey,
        deviceHPKEPrivateKey: Data(repeating: 0x42, count: 31),
        deviceGrant: valid.deviceGrant,
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }
    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: valid.record,
        promotionID32: valid.promotionID32,
        deviceSignPrivateKey: valid.deviceSignPrivateKey,
        deviceHPKEPrivateKey: valid.deviceHPKEPrivateKey,
        deviceGrant: Data(),
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }

    let otherRecord = try makeRecord(index: 2)
    assertStoreError(.invalidPromotion) {
      try PreparedPairedMachinePromotionV1(
        record: otherRecord,
        promotionID32: valid.promotionID32,
        deviceSignPrivateKey: valid.deviceSignPrivateKey,
        deviceHPKEPrivateKey: valid.deviceHPKEPrivateKey,
        deviceGrant: valid.deviceGrant,
        deviceStorageKEK: valid.deviceStorageKEK,
        initialCryptoState: valid.initialCryptoState
      )
    }
  }

  func testPromotionIsMarkerLastAuditsMutableStateAndRetriesIdempotently() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let store = environment.store(for: prepared.record)

    let first = try await store.promote(prepared)
    XCTAssertEqual(first, .inserted)
    let firstList = try await store.list()
    let loaded = try await store.load(
      rootFingerprint: prepared.record.machineRootFingerprint,
      machineRoute: prepared.record.machineRoute
    )
    let firstValueCount = await environment.keyStore.valueCount
    XCTAssertEqual(firstList, [prepared.record])
    XCTAssertEqual(loaded, prepared.record)
    XCTAssertEqual(firstValueCount, 6)

    let stateStore = try makeStateStore(environment: environment, prepared: prepared)
    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: environment.rootURL,
      identity: makeIdentity(prepared.record),
      stateStore: stateStore,
      keyStore: environment.keyStore,
      guardKey: try pairedKey(prepared.record, purpose: .counterGuard)
    )
    _ = try await coordinator.reserveCounterBlock()
    let reservedState = try await stateStore.load()
    XCTAssertNotEqual(reservedState, prepared.initialCryptoState)

    let afterReservation = try await store.list()
    let retry = try await store.promote(prepared)
    let afterRetry = try await store.list()
    XCTAssertEqual(afterReservation, [prepared.record])
    XCTAssertEqual(retry, .alreadyPresent)
    XCTAssertEqual(afterRetry, [prepared.record])
  }

  func testMarkerAuditUsesImmutableBootstrapEvidenceAfterNonceReuseRetiresGuard() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let store = environment.store(for: prepared.record)
    _ = try await store.promote(prepared)
    let stateStore = try makeStateStore(environment: environment, prepared: prepared)
    let guardKey = try pairedKey(prepared.record, purpose: .counterGuard)
    let coordinator = try DurableCryptoStateCoordinator(
      rootURL: environment.rootURL,
      identity: makeIdentity(prepared.record),
      stateStore: stateStore,
      keyStore: environment.keyStore,
      guardKey: guardKey
    )
    let scope = prepared.initialCryptoState.state.replayStates[0].scope
    let firstHash = Data(repeating: 0x61, count: 32)
    let firstDisposition = try await coordinator.admitReplay(
      scope: scope,
      counter: 7,
      ciphertextHash: firstHash,
      observedAtMS: 100
    )
    XCTAssertEqual(firstDisposition.disposition, .fresh)
    do {
      _ = try await coordinator.admitReplay(
        scope: scope,
        counter: 7,
        ciphertextHash: Data(repeating: 0x62, count: 32),
        observedAtMS: 200
      )
      XCTFail("nonce reuse 必须先 quarantine 并退休 guard")
    } catch {
      XCTAssertEqual(error as? RelayCryptoError, .nonceReuse)
    }

    let loadedGuardData = await environment.keyStore.value(for: guardKey)
    let guardData = try XCTUnwrap(loadedGuardData)
    XCTAssertEqual(guardData[6], 2, "CounterGuard 必须处于 retired phase")
    let loadedQuarantined = try await stateStore.load()
    let quarantined = try XCTUnwrap(loadedQuarantined)
    guard case .quarantined = quarantined.state.securityState else {
      return XCTFail("nonce reuse 必须保留 durable machine quarantine")
    }
    let listed = try await store.list()
    let loaded = try await store.load(
      rootFingerprint: prepared.record.machineRootFingerprint,
      machineRoute: prepared.record.machineRoute
    )
    XCTAssertEqual(listed, [prepared.record])
    XCTAssertEqual(loaded, prepared.record)
  }

  func testEveryPromotionKeychainCrashPointConvergesWithoutPartialVisibility() async throws {
    for crashAfterMutation in 1...6 {
      let environment = try TestEnvironment()
      defer { environment.removeSandbox() }
      let prepared = try makePrepared()
      let store = environment.store(for: prepared.record)
      await environment.keyStore.failAfterMutation(crashAfterMutation)

      do {
        _ = try await store.promote(prepared)
        XCTFail("mutation \(crashAfterMutation) 后必须注入崩溃")
      } catch is InjectedPairedStoreCrash {
        // expected
      }

      let visibleAfterCrash = try await store.list()
      if crashAfterMutation < 6 {
        XCTAssertTrue(visibleAfterCrash.isEmpty)
      } else {
        XCTAssertEqual(visibleAfterCrash, [prepared.record])
      }

      await environment.keyStore.clearFailure()
      _ = try await store.promote(prepared)
      let convergedList = try await store.list()
      let valueCount = await environment.keyStore.valueCount
      XCTAssertEqual(convergedList, [prepared.record])
      XCTAssertEqual(valueCount, 6)
    }
  }

  func testTwoStoreInstancesSerializePromotionWithoutNestedLeaseDeadlock() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let firstStore = environment.store(for: prepared.record)
    let secondStore = environment.store(for: prepared.record)

    async let first = firstStore.promote(prepared)
    async let second = secondStore.promote(prepared)
    let outcomes = try await [first, second]

    XCTAssertEqual(outcomes.filter { $0 == .inserted }.count, 1)
    XCTAssertEqual(outcomes.filter { $0 == .alreadyPresent }.count, 1)
    let visible = try await firstStore.list()
    XCTAssertEqual(visible, [prepared.record])
  }

  func testColdStartListsTwoMachinesFromNativeMarkers() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let first = try makePrepared(index: 1)
    let second = try makePrepared(index: 2)
    let writer = environment.store(for: first.record)

    _ = try await writer.promote(first)
    _ = try await writer.promote(second)

    let coldStore = environment.store(for: first.record)
    let coldList = try await coldStore.list()
    XCTAssertEqual(coldList, [first.record, second.record])
  }

  func testCopiedMarkerAtWrongBindingFailsClosed() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let first = try makePrepared(index: 1)
    let second = try makePrepared(index: 2)
    let store = environment.store(for: first.record)
    _ = try await store.promote(first)

    let firstMarker = try pairedKey(first.record, purpose: .commitMarker)
    let markerValue = await environment.keyStore.value(for: firstMarker)
    let copiedMarker = try XCTUnwrap(markerValue)
    let wrongKey = try pairedKey(second.record, purpose: .commitMarker)
    await environment.keyStore.force(copiedMarker, for: wrongKey)

    do {
      _ = try await store.list()
      XCTFail("复制到错误 binding 的 marker 必须失败")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .invalidBinding)
    }
  }

  func testMalformedMarkerAndTamperedMaterialFailClosed() async throws {
    let malformedEnvironment = try TestEnvironment()
    defer { malformedEnvironment.removeSandbox() }
    let prepared = try makePrepared()

    var legacyRecord = try PairedMachineRecordCodec.encode(prepared.record)
    XCTAssertEqual(legacyRecord.prefix(4), Data("ADPR".utf8))
    legacyRecord[5] = 1
    XCTAssertThrowsError(try PairedMachineRecordCodec.decode(legacyRecord)) { error in
      XCTAssertEqual(error as? PairedMachineStoreError, .invalidRecord)
    }

    let malformedStore = malformedEnvironment.store(for: prepared.record)
    await malformedEnvironment.keyStore.force(
      Data("not-a-marker".utf8),
      for: try pairedKey(prepared.record, purpose: .commitMarker)
    )
    do {
      _ = try await malformedStore.list()
      XCTFail("malformed marker 必须失败")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .invalidRecord)
    }

    let legacyEnvironment = try TestEnvironment()
    defer { legacyEnvironment.removeSandbox() }
    let legacyStore = legacyEnvironment.store(for: prepared.record)
    _ = try await legacyStore.promote(prepared)
    let legacyMarkerKey = try pairedKey(prepared.record, purpose: .commitMarker)
    let legacyMarkerValue = await legacyEnvironment.keyStore.value(for: legacyMarkerKey)
    var legacyMarker = try XCTUnwrap(legacyMarkerValue)
    XCTAssertEqual(legacyMarker.prefix(4), Data("ADPM".utf8))
    legacyMarker[5] = 1
    await legacyEnvironment.keyStore.force(legacyMarker, for: legacyMarkerKey)
    await legacyEnvironment.keyStore.resetMutationLog()
    do {
      _ = try await legacyStore.list()
      XCTFail("legacy v1 marker 必须零迁移 fail-close")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .invalidRecord)
    }
    let legacyMutationCount = await legacyEnvironment.keyStore.mutationCount
    let legacyValueCount = await legacyEnvironment.keyStore.valueCount
    XCTAssertEqual(legacyMutationCount, 0)
    XCTAssertEqual(legacyValueCount, 6)

    let tamperedEnvironment = try TestEnvironment()
    defer { tamperedEnvironment.removeSandbox() }
    let tamperedStore = tamperedEnvironment.store(for: prepared.record)
    _ = try await tamperedStore.promote(prepared)
    await tamperedEnvironment.keyStore.force(
      Data(repeating: 0xEE, count: 32),
      for: try pairedKey(prepared.record, purpose: .deviceSignPrivateKey)
    )
    do {
      _ = try await tamperedStore.list()
      XCTFail("material hash 不匹配必须失败")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .persistenceMismatch)
    }
  }

  func testListRejectsEveryMissingDependencyAndMissingState() async throws {
    let purposes: [PairedKeyStorePurpose] = [
      .deviceStorageKEK,
      .deviceSignPrivateKey,
      .deviceHPKEPrivateKey,
      .deviceGrant,
      .counterGuard,
    ]
    for purpose in purposes {
      let environment = try TestEnvironment()
      defer { environment.removeSandbox() }
      let prepared = try makePrepared()
      let store = environment.store(for: prepared.record)
      _ = try await store.promote(prepared)
      await environment.keyStore.forceRemove(try pairedKey(prepared.record, purpose: purpose))

      do {
        _ = try await store.list()
        XCTFail("缺少 \(purpose.rawValue) 必须拒绝 marker")
      } catch {
        XCTAssertNotNil(error)
      }
    }

    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let store = environment.store(for: prepared.record)
    _ = try await store.promote(prepared)
    let stateStore = try makeStateStore(environment: environment, prepared: prepared)
    let loadedState = try await stateStore.load()
    let current = try XCTUnwrap(loadedState)
    try await stateStore.deleteExact(expected: current)
    do {
      _ = try await store.list()
      XCTFail("缺少 sealed state 必须拒绝 marker")
    } catch {
      XCTAssertNotNil(error)
    }
  }

  func testCleanupJournalClosesVisibilityAndCrashRetriesInExactOrder() async throws {
    for crashAfterMutation in 1...7 {
      let environment = try TestEnvironment()
      defer { environment.removeSandbox() }
      let prepared = try makePrepared()
      let store = environment.store(for: prepared.record)
      _ = try await store.promote(prepared)
      let stateStore = try makeStateStore(environment: environment, prepared: prepared)
      await environment.keyStore.observeStateURLOnGuardDelete(stateStore.stateURL)
      await environment.keyStore.resetMutationLog()
      await environment.keyStore.failAfterMutation(crashAfterMutation)

      do {
        try await store.deleteExact(prepared.record)
        XCTFail("cleanup mutation \(crashAfterMutation) 后必须注入崩溃")
      } catch is InjectedPairedStoreCrash {
        // expected
      }
      let hiddenAfterCrash = try await store.list()
      XCTAssertTrue(hiddenAfterCrash.isEmpty)

      await environment.keyStore.clearFailure()
      try await store.deleteExact(prepared.record)
      let finalList = try await store.list()
      let finalValueCount = await environment.keyStore.valueCount
      let finalState = try await stateStore.load()
      let stateWasAbsent = await environment.keyStore.stateWasAbsentWhenGuardDeleted
      XCTAssertTrue(finalList.isEmpty)
      XCTAssertEqual(finalValueCount, 0)
      XCTAssertNil(finalState)
      XCTAssertTrue(stateWasAbsent)

      let deletedPurposes = await environment.keyStore.deletedPurposeSuffixes
      XCTAssertEqual(
        deletedPurposes,
        [
          PairedKeyStorePurpose.counterGuard.rawValue,
          PairedKeyStorePurpose.deviceGrant.rawValue,
          PairedKeyStorePurpose.deviceHPKEPrivateKey.rawValue,
          PairedKeyStorePurpose.deviceSignPrivateKey.rawValue,
          PairedKeyStorePurpose.deviceStorageKEK.rawValue,
          PairedKeyStorePurpose.commitMarker.rawValue,
        ]
      )
    }
  }

  func testTamperedStateOrGuardBeforeCleanupPerformsZeroDeletes() async throws {
    let stateEnvironment = try TestEnvironment()
    defer { stateEnvironment.removeSandbox() }
    let prepared = try makePrepared()
    let stateStore = stateEnvironment.store(for: prepared.record)
    _ = try await stateStore.promote(prepared)
    let markerKey = try pairedKey(prepared.record, purpose: .commitMarker)
    let committedMarkerValue = await stateEnvironment.keyStore.value(for: markerKey)
    let committedMarker = try XCTUnwrap(committedMarkerValue)
    let cryptoStateStore = try makeStateStore(
      environment: stateEnvironment,
      prepared: prepared
    )
    let sealed = try Data(contentsOf: cryptoStateStore.stateURL)
    try corruptLastByte(sealed).write(to: cryptoStateStore.stateURL)
    await stateEnvironment.keyStore.resetMutationLog()

    do {
      try await stateStore.deleteExact(prepared.record)
      XCTFail("tampered sealed state must block cleanup")
    } catch {
      XCTAssertNotNil(error)
    }
    let stateMutationCount = await stateEnvironment.keyStore.mutationCount
    let stateValueCount = await stateEnvironment.keyStore.valueCount
    let markerAfterStateFailure = await stateEnvironment.keyStore.value(for: markerKey)
    XCTAssertEqual(stateMutationCount, 0)
    XCTAssertEqual(stateValueCount, 6)
    XCTAssertEqual(markerAfterStateFailure, committedMarker)

    let guardEnvironment = try TestEnvironment()
    defer { guardEnvironment.removeSandbox() }
    let guardStore = guardEnvironment.store(for: prepared.record)
    _ = try await guardStore.promote(prepared)
    let guardMarkerValue = await guardEnvironment.keyStore.value(for: markerKey)
    let guardMarker = try XCTUnwrap(guardMarkerValue)
    await guardEnvironment.keyStore.force(
      Data("tampered-counter-guard".utf8),
      for: try pairedKey(prepared.record, purpose: .counterGuard)
    )
    await guardEnvironment.keyStore.resetMutationLog()

    do {
      try await guardStore.deleteExact(prepared.record)
      XCTFail("tampered guard must block cleanup")
    } catch {
      XCTAssertNotNil(error)
    }
    let guardMutationCount = await guardEnvironment.keyStore.mutationCount
    let guardValueCount = await guardEnvironment.keyStore.valueCount
    let markerAfterGuardFailure = await guardEnvironment.keyStore.value(for: markerKey)
    XCTAssertEqual(guardMutationCount, 0)
    XCTAssertEqual(guardValueCount, 6)
    XCTAssertEqual(markerAfterGuardFailure, guardMarker)
  }

  func testCleanupJournalFreezesStateAndGuardAcrossCrashResume() async throws {
    let guardEnvironment = try TestEnvironment()
    defer { guardEnvironment.removeSandbox() }
    let prepared = try makePrepared()
    let guardStore = guardEnvironment.store(for: prepared.record)
    _ = try await guardStore.promote(prepared)
    let guardKey = try pairedKey(prepared.record, purpose: .counterGuard)
    let originalGuardValue = await guardEnvironment.keyStore.value(for: guardKey)
    let originalGuard = try XCTUnwrap(originalGuardValue)
    await guardEnvironment.keyStore.failAfterMutation(1)
    do {
      try await guardStore.deleteExact(prepared.record)
      XCTFail("cleanup marker CAS 后注入 crash")
    } catch is InjectedPairedStoreCrash {
      // expected
    }
    await guardEnvironment.keyStore.clearFailure()
    await guardEnvironment.keyStore.force(Data(repeating: 0xFA, count: 32), for: guardKey)
    await guardEnvironment.keyStore.resetMutationLog()
    do {
      try await guardStore.deleteExact(prepared.record)
      XCTFail("cleanup journal 必须拒绝替换后的 guard")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .persistenceMismatch)
    }
    let guardRetryMutations = await guardEnvironment.keyStore.mutationCount
    let guardRetryState = try await makeStateStore(
      environment: guardEnvironment,
      prepared: prepared
    ).load()
    XCTAssertEqual(guardRetryMutations, 0)
    XCTAssertNotNil(guardRetryState)
    await guardEnvironment.keyStore.force(originalGuard, for: guardKey)
    try await guardStore.deleteExact(prepared.record)
    let guardFinalCount = await guardEnvironment.keyStore.valueCount
    XCTAssertEqual(guardFinalCount, 0)

    let stateEnvironment = try TestEnvironment()
    defer { stateEnvironment.removeSandbox() }
    let stateStore = stateEnvironment.store(for: prepared.record)
    _ = try await stateStore.promote(prepared)
    let cryptoStateStore = try makeStateStore(
      environment: stateEnvironment,
      prepared: prepared
    )
    let originalSealedState = try Data(contentsOf: cryptoStateStore.stateURL)
    await stateEnvironment.keyStore.failAfterMutation(1)
    do {
      try await stateStore.deleteExact(prepared.record)
      XCTFail("cleanup marker CAS 后注入 crash")
    } catch is InjectedPairedStoreCrash {
      // expected
    }
    await stateEnvironment.keyStore.clearFailure()
    try corruptLastByte(originalSealedState).write(to: cryptoStateStore.stateURL)
    await stateEnvironment.keyStore.resetMutationLog()
    do {
      try await stateStore.deleteExact(prepared.record)
      XCTFail("cleanup journal 必须拒绝替换后的 state")
    } catch {
      XCTAssertNotNil(error)
    }
    let stateRetryMutations = await stateEnvironment.keyStore.mutationCount
    let stateRetryCount = await stateEnvironment.keyStore.valueCount
    XCTAssertEqual(stateRetryMutations, 0)
    XCTAssertEqual(stateRetryCount, 6)
    try originalSealedState.write(to: cryptoStateStore.stateURL)
    try await stateStore.deleteExact(prepared.record)
    let stateFinalCount = await stateEnvironment.keyStore.valueCount
    XCTAssertEqual(stateFinalCount, 0)
  }

  func testStoreRejectsAnotherInstallationBeforeMutation() async throws {
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let store = PairedMachineStore(
      keyStore: environment.keyStore,
      stateRootURL: environment.rootURL,
      clientKind: .macOSApp,
      installationID: UUID(),
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )

    do {
      _ = try await store.promote(prepared)
      XCTFail("cross-installation promotion must fail")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .invalidBinding)
    }
    let valueCount = await environment.keyStore.valueCount
    XCTAssertEqual(valueCount, 0)
  }

  func testColdOpenReturnsOnlyFullyAuditedRedactedConnectionCapability() async throws {
    requireSendable(PairedMachineConnectionMaterial.self)
    let environment = try TestEnvironment()
    defer { environment.removeSandbox() }
    let prepared = try makePrepared()
    let store = environment.store(for: prepared.record)
    _ = try await store.promote(prepared)

    let opened = try await store.openConnectionMaterial(
      rootFingerprint: prepared.record.machineRootFingerprint,
      machineRoute: prepared.record.machineRoute
    )
    let material = try XCTUnwrap(opened)
    XCTAssertEqual(material.record, prepared.record)
    XCTAssertEqual(material.relayGrant.grant.machineRoute, prepared.record.machineRoute)
    XCTAssertEqual(
      material.machineDataCertificate.certificate,
      prepared.record.machineDataCertificate
    )

    let reflected = String(reflecting: material)
    XCTAssertTrue(reflected.contains("<redacted>"))
    for secret in [
      prepared.deviceSignPrivateKey,
      prepared.deviceHPKEPrivateKey,
      prepared.deviceGrant,
      prepared.deviceStorageKEK.rawRepresentation,
    ] {
      XCTAssertFalse(reflected.contains(secret.base64EncodedString()))
      XCTAssertFalse(reflected.contains(secret.map { String(format: "%02x", $0) }.joined()))
    }

    let deviceSignKey = try pairedKey(
      prepared.record,
      purpose: .deviceSignPrivateKey
    )
    await environment.keyStore.force(
      corruptLastByte(prepared.deviceSignPrivateKey),
      for: deviceSignKey
    )
    do {
      _ = try await store.openConnectionMaterial(
        rootFingerprint: prepared.record.machineRootFingerprint,
        machineRoute: prepared.record.machineRoute
      )
      XCTFail("cold-open must re-audit every bound dependency")
    } catch {
      XCTAssertEqual(error as? PairedMachineStoreError, .persistenceMismatch)
    }
  }

  func testColdOpenCapabilityAddsNoPublicRawSecretGetter() throws {
    let repositoryRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let source = try String(
      contentsOf: repositoryRoot.appendingPathComponent(
        "Sources/AgentDeckRelayClient/Storage/PairedMachineStore.swift"
      ),
      encoding: .utf8
    )

    // promotion carrier 与 cold-open capability 都不得公开 private-key 字段，
    // 更不得公开对称 key 或通用 secret getter。
    XCTAssertEqual(source.occurrences(of: "public let deviceSignPrivateKey"), 0)
    XCTAssertEqual(source.occurrences(of: "public let deviceHPKEPrivateKey"), 0)
    for forbidden in [
      "public var deviceSignPrivateKey",
      "public var deviceHPKEPrivateKey",
      "public let rawCommandKey",
      "public var rawCommandKey",
      "public let rawReceivingKey",
      "public var rawReceivingKey",
      "public func loadSecret",
      "public func getSecret",
      "public func rawRepresentation",
    ] {
      XCTAssertFalse(source.contains(forbidden), "forbidden raw getter: \(forbidden)")
    }
  }

  private func requireSendable<Value: Sendable>(_: Value.Type) {}
}

private struct TestEnvironment {
  let rootURL: URL
  let keyStore = MemoryPairedKeyStore()

  init() throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckPairedMachineStoreTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
  }

  func store(for record: StoredPairedMachineRecordV1) -> PairedMachineStore {
    PairedMachineStore(
      keyStore: keyStore,
      stateRootURL: rootURL,
      clientKind: record.clientKind,
      installationID: record.installationID,
      testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
    )
  }

  func removeSandbox() {
    try? FileManager.default.removeItem(at: rootURL)
  }
}

private actor MemoryPairedKeyStore: PairedMarkerListingKeyStore {
  private var values: [KeyStoreKey: Data] = [:]
  private var mutationOrdinal = 0
  private var failureOrdinal: Int?
  private var mutationLog: [Mutation] = []
  private var observedStateURL: URL?
  private(set) var stateWasAbsentWhenGuardDeleted = false

  var valueCount: Int { values.count }

  var mutationCount: Int { mutationLog.count }

  var deletedPurposeSuffixes: [String] {
    mutationLog.compactMap { mutation in
      guard case .delete(let account) = mutation else { return nil }
      return account.split(separator: "/").last.map(String.init)
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
    try didMutate(.persist(key.account))
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
    try didMutate(.compareAndReplace(key.account))
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    guard values[key] == expected else {
      throw KeyStoreError.deleteReadbackFailed
    }
    if key.account.hasSuffix("/\(PairedKeyStorePurpose.counterGuard.rawValue)"),
      let observedStateURL
    {
      stateWasAbsentWhenGuardDeleted = !FileManager.default.fileExists(
        atPath: observedStateURL.path
      )
    }
    values.removeValue(forKey: key)
    try didMutate(.delete(key.account))
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
    []
  }

  func failAfterMutation(_ ordinal: Int) {
    mutationOrdinal = 0
    failureOrdinal = ordinal
  }

  func clearFailure() {
    failureOrdinal = nil
    mutationOrdinal = 0
  }

  func resetMutationLog() {
    mutationLog = []
    mutationOrdinal = 0
    stateWasAbsentWhenGuardDeleted = false
  }

  func observeStateURLOnGuardDelete(_ url: URL) {
    observedStateURL = url
  }

  func value(for key: KeyStoreKey) -> Data? {
    values[key]
  }

  func force(_ data: Data, for key: KeyStoreKey) {
    values[key] = data
  }

  func forceRemove(_ key: KeyStoreKey) {
    values.removeValue(forKey: key)
  }

  private func didMutate(_ mutation: Mutation) throws {
    mutationOrdinal += 1
    mutationLog.append(mutation)
    if mutationOrdinal == failureOrdinal {
      throw InjectedPairedStoreCrash()
    }
  }
}

private enum Mutation {
  case persist(String)
  case compareAndReplace(String)
  case delete(String)
}

private struct InjectedPairedStoreCrash: Error {}

private func makePrepared(index: UInt8 = 1) throws -> PreparedPairedMachinePromotionV1 {
  let record = try makeRecord(index: index)
  let senderKeyID = KeyIDV1(purpose: .deviceCommandTx, epoch: UInt64(10 + index))
  let replayKeyID = KeyIDV1(purpose: .catalog, epoch: UInt64(20 + index))
  let replyKeyID = KeyIDV1(purpose: .deviceReplyTx, epoch: UInt64(25 + index))
  let streamRoute = Data(repeating: 0x70 &+ index, count: 16)
  let directoryRevision = UInt64(30 + index)
  let trust = try DeviceCryptoTrustScopeV1(
    relayServerID: record.relayServerID,
    machineRootFingerprint: record.machineRootFingerprint,
    machineRoute: record.machineRoute,
    deviceRoute: record.deviceRoute,
    grantSerial: record.grantSerial,
    trustEpoch: record.trustEpoch
  )
  let directory = try DeviceKeyDirectoryV1(
    revision: directoryRevision,
    entries: [
      DeviceWrappedKeyV1(
        keyID: replayKeyID,
        deviceRoute: record.deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xA0 &+ index, count: 32),
        wrappedKey: Data(repeating: 0xB0 &+ index, count: 48)
      ),
      DeviceWrappedKeyV1(
        keyID: senderKeyID,
        deviceRoute: record.deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xC0 &+ index, count: 32),
        wrappedKey: Data(repeating: 0xD0 &+ index, count: 48)
      ),
      DeviceWrappedKeyV1(
        keyID: replyKeyID,
        deviceRoute: record.deviceRoute,
        streamRoute: nil,
        enc: Data(repeating: 0xE0 &+ index, count: 32),
        wrappedKey: Data(repeating: 0xF0 &+ index, count: 48)
      ),
    ],
    signature: Data(repeating: 0x80 &+ index, count: 64)
  )
  let sender = try DeviceSenderCounterV1(
    keyID: senderKeyID,
    keyDirectoryRevision: directoryRevision,
    noncePrefix: Data([index, index &+ 1, index &+ 2, index &+ 3]),
    reservedHighWater: 0,
    reservationID: Data(repeating: 0, count: 16)
  )
  let replay = try DeviceReplayStateV1(
    scope: DeviceCryptoKeyScopeV1(keyID: replayKeyID, streamRoute: nil),
    window: ReplayWindowSnapshot(highWater: nil, floor: 0, entries: []),
    status: .active
  )
  let cursor = try DeviceStreamCursorStateV1(
    streamRoute: streamRoute,
    generation: Data(repeating: 0x90 &+ index, count: 16),
    outerCursor: .beforeFirst,
    innerCursor: .catalog(.beforeFirst)
  )
  let state = try DeviceCryptoStateV1(
    stateRevision: 1,
    trustScope: trust,
    keyDirectory: directory,
    senderCounter: sender,
    securityState: .active,
    replayStates: [replay],
    streamStates: [cursor]
  )
  let deviceSignPrivateKey = Data(repeating: 0xA0 &+ index, count: 32)
  let deviceSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: deviceSignPrivateKey
  )
  let unsignedGrant = RelayV2Grant(
    machineRoute: record.machineRoute,
    deviceRoute: record.deviceRoute,
    deviceSignPubkey: deviceSigningKey.publicKey.rawRepresentation,
    grantSerial: record.grantSerial,
    rootKeyId: record.machineDataCertificate.rootKeyId,
    trustEpoch: record.trustEpoch,
    signature: Data(repeating: 1, count: 64)
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
        relayServerID: record.relayServerID,
        machineRootFingerprint: record.machineRootFingerprint
      ),
      key: pairedMachineRootSigningKey(index: index)
    )
  )
  return try PreparedPairedMachinePromotionV1(
    record: record,
    promotionID32: Data(repeating: 0xE0 &+ index, count: 32),
    deviceSignPrivateKey: deviceSignPrivateKey,
    deviceHPKEPrivateKey: Data(repeating: 0xB0 &+ index, count: 32),
    deviceGrant: try RelayGrantCanonicalCodec.encode(grant),
    deviceStorageKEK: DeviceStorageKEK(
      rawRepresentation: Data(repeating: 0xC0 &+ index, count: 32)
    ),
    initialCryptoState: CryptoStateSnapshot(state)
  )
}

private func makeRecord(
  index: UInt8 = 1,
  installationID: UUID? = nil,
  machineName: String? = nil,
  relayURL: URL? = nil,
  relayServerID: Data? = nil,
  machineRootPublicKey: Data? = nil,
  machineRootFingerprint: Data? = nil,
  machineDataCertificate: RelayV2SignedCertificate? = nil,
  machineRoute: Data? = nil,
  deviceRoute: Data? = nil,
  currentSPKIPin: Data? = nil,
  nextSPKIPin: Data? = nil,
  grantSerial: UInt64? = nil,
  trustEpoch: UInt64? = nil
) throws -> StoredPairedMachineRecordV1 {
  let resolvedRelayServerID = relayServerID ?? Data(repeating: 0x10 &+ index, count: 16)
  let resolvedMachineRoute = machineRoute ?? Data(repeating: 0x30 &+ index, count: 16)
  let resolvedTrustEpoch = trustEpoch ?? UInt64(3 + index)
  let rootSigningKey = try pairedMachineRootSigningKey(index: index)
  let resolvedRootPublicKey =
    machineRootPublicKey ?? rootSigningKey.publicKey.rawRepresentation
  let resolvedRootFingerprint =
    machineRootFingerprint ?? CanonicalCodec.sha256(resolvedRootPublicKey)
  let resolvedDataCertificate: RelayV2SignedCertificate
  if let machineDataCertificate {
    resolvedDataCertificate = machineDataCertificate
  } else {
    resolvedDataCertificate = try pairedMachineDataCertificate(
      index: index,
      rootSigningKey: rootSigningKey,
      rootFingerprint: CanonicalCodec.sha256(rootSigningKey.publicKey.rawRepresentation),
      relayServerID: resolvedRelayServerID,
      machineRoute: resolvedMachineRoute,
      trustEpoch: resolvedTrustEpoch
    )
  }
  return try StoredPairedMachineRecordV1(
    clientKind: .macOSApp,
    installationID: installationID
      ?? UUID(uuidString: "20000000-0000-0000-0000-000000000001")!,
    machineID: "machine-\(index)",
    machineName: machineName ?? "Machine \(index)",
    relayURL: relayURL ?? URL(string: "wss://relay.example.com:8443/")!,
    relayServerID: resolvedRelayServerID,
    machineRootPublicKey: resolvedRootPublicKey,
    machineRootFingerprint: resolvedRootFingerprint,
    machineDataCertificate: resolvedDataCertificate,
    machineRoute: resolvedMachineRoute,
    deviceRoute: deviceRoute ?? Data(repeating: 0x40 &+ index, count: 16),
    currentSPKIPin: currentSPKIPin ?? Data(repeating: 0x50 &+ index, count: 32),
    nextSPKIPin: nextSPKIPin ?? Data(repeating: 0x60 &+ index, count: 32),
    grantSerial: grantSerial ?? UInt64(7 + index),
    trustEpoch: resolvedTrustEpoch,
    createdAtMS: 1_750_000_000_000 + UInt64(index)
  )
}

private func pairedMachineRootSigningKey(
  index: UInt8
) throws -> Curve25519.Signing.PrivateKey {
  try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x70 &+ index, count: 32)
  )
}

private func pairedMachineDataCertificate(
  index: UInt8,
  rootSigningKey: Curve25519.Signing.PrivateKey,
  rootFingerprint: Data,
  relayServerID: Data,
  machineRoute: Data,
  trustEpoch: UInt64
) throws -> RelayV2SignedCertificate {
  let dataSigningKey = try Curve25519.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0x78 &+ index, count: 32)
  )
  let rootKeyID = Data(repeating: 0x68 &+ index, count: 16)
  let unsigned = RelayV2SignedCertificate(
    subjectPubkey: dataSigningKey.publicKey.rawRepresentation,
    certRole: .data,
    generation: UInt64(2 + index),
    rootKeyId: rootKeyID,
    trustEpoch: trustEpoch,
    notAfterMs: 4_000_000_000_000,
    signature: Data(repeating: 1, count: 64)
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
    notAfterMS: unsigned.notAfterMs,
    signedObjectSHA256: CanonicalCodec.sha256(
      pairedCertificateUnsignedCanonicalBytes(unsigned)
    )
  )
  return RelayV2SignedCertificate(
    subjectPubkey: unsigned.subjectPubkey,
    certRole: unsigned.certRole,
    generation: unsigned.generation,
    rootKeyId: unsigned.rootKeyId,
    trustEpoch: unsigned.trustEpoch,
    notAfterMs: unsigned.notAfterMs,
    signature: try RelayCrypto.sign(tbs, key: rootSigningKey)
  )
}

private func pairedCertificateUnsignedCanonicalBytes(
  _ certificate: RelayV2SignedCertificate
) -> Data {
  var output = Data("AgentDeck/SignedCertificateUnsignedV1\0".utf8)
  appendPairedBytes(certificate.subjectPubkey, to: &output)
  output.append(certificate.certRole == .link ? 0 : 1)
  appendPairedInteger(certificate.generation, to: &output)
  appendPairedBytes(certificate.rootKeyId, to: &output)
  appendPairedInteger(certificate.trustEpoch, to: &output)
  if let notAfterMS = certificate.notAfterMs {
    output.append(1)
    appendPairedInteger(notAfterMS, to: &output)
  } else {
    output.append(0)
  }
  return output
}

private func appendPairedBytes(_ value: Data, to output: inout Data) {
  appendPairedInteger(UInt32(value.count), to: &output)
  output.append(value)
}

private func appendPairedInteger<Value: FixedWidthInteger>(
  _ value: Value,
  to output: inout Data
) {
  var encoded = value.bigEndian
  Swift.withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
}

private func corruptLastByte(_ input: Data) -> Data {
  var corrupted = input
  let index = corrupted.index(before: corrupted.endIndex)
  corrupted[index] ^= 0x01
  return corrupted
}

private func makeIdentity(_ record: StoredPairedMachineRecordV1) throws -> CryptoStateIdentity {
  try CryptoStateIdentity(
    clientKind: record.clientKind,
    installationID: record.installationID,
    machineID: record.machineID,
    machineRootFingerprint: record.machineRootFingerprint,
    machineRoute: record.machineRoute
  )
}

private func makeStateStore(
  environment: TestEnvironment,
  prepared: PreparedPairedMachinePromotionV1
) throws -> FileCryptoStateStore {
  try FileCryptoStateStore(
    rootURL: environment.rootURL,
    identity: makeIdentity(prepared.record),
    storageKey: prepared.deviceStorageKEK,
    testHooks: .none,
    testingFileProtectionPolicy: .completeUntilFirstUserAuthentication
  )
}

private func pairedKey(
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

private func assertStoreError<Result>(
  _ expected: PairedMachineStoreError,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ operation: () throws -> Result
) {
  do {
    _ = try operation()
    XCTFail("expected \(expected)", file: file, line: line)
  } catch {
    XCTAssertEqual(error as? PairedMachineStoreError, expected, file: file, line: line)
  }
}

extension String {
  fileprivate func occurrences(of needle: String) -> Int {
    guard !needle.isEmpty else { return 0 }
    var count = 0
    var remainder = self[...]
    while let range = remainder.range(of: needle) {
      count += 1
      remainder = remainder[range.upperBound...]
    }
    return count
  }
}
