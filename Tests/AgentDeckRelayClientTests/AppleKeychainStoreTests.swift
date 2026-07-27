import CryptoKit
import Foundation
import Security
import XCTest
@testable import AgentDeckRelayClient

final class AppleKeychainStoreTests: XCTestCase {
  func testTypedFactoriesSeparateMacOSIOSAndCLINamespacesAndBoundAccounts() throws {
    let installationID = UUID()
    let inviteHash = try randomNonzeroData(count: 32)
    let rootFingerprint = try randomNonzeroData(count: 32)
    let machineRoute = try randomNonzeroData(count: 16)

    let pendingPurposes: [PendingKeyStorePurpose] = [
      .recoveryIntent,
      .pairingRecord,
      .deviceSignPrivateKey,
      .deviceHPKEPrivateKey,
    ]
    let pairedPurposes: [PairedKeyStorePurpose] = [
      .deviceSignPrivateKey,
      .deviceHPKEPrivateKey,
      .deviceGrant,
      .deviceStorageKEK,
      .counterGuard,
      .commitMarker,
    ]

    let clientKinds: [RelayClientKind] = [.macOSApp, .iOSApp, .cli]
    for purpose in pendingPurposes {
      let accounts = try clientKinds.map { clientKind in
        try KeyStoreKey.pending(
          clientKind: clientKind,
          installationID: installationID,
          inviteHash: inviteHash,
          purpose: purpose
        ).account
      }

      XCTAssertEqual(Set(accounts).count, clientKinds.count)
      XCTAssertTrue(accounts[0].hasPrefix("pending/macos-app/"), accounts[0])
      XCTAssertTrue(accounts[1].hasPrefix("pending/ios-app/"), accounts[1])
      XCTAssertTrue(accounts[2].hasPrefix("pending/cli/"), accounts[2])
      for account in accounts { assertCanonicalAccountBound(account) }
    }

    for purpose in pairedPurposes {
      let accounts = try clientKinds.map { clientKind in
        try KeyStoreKey.paired(
          clientKind: clientKind,
          installationID: installationID,
          rootFingerprint: rootFingerprint,
          machineRoute: machineRoute,
          purpose: purpose
        ).account
      }

      XCTAssertEqual(Set(accounts).count, clientKinds.count)
      XCTAssertTrue(accounts[0].hasPrefix("macos-app/"), accounts[0])
      XCTAssertTrue(accounts[1].hasPrefix("ios-app/"), accounts[1])
      XCTAssertTrue(accounts[2].hasPrefix("cli/"), accounts[2])
      for account in accounts { assertCanonicalAccountBound(account) }
    }

    XCTAssertThrowsError(
      try KeyStoreKey.pending(
        clientKind: .macOSApp,
        installationID: installationID,
        inviteHash: Data(repeating: 1, count: 31),
        purpose: .pairingRecord
      )
    )
    XCTAssertThrowsError(
      try KeyStoreKey.paired(
        clientKind: .cli,
        installationID: installationID,
        rootFingerprint: Data(repeating: 1, count: 31),
        machineRoute: machineRoute,
        purpose: .counterGuard
      )
    )
    XCTAssertThrowsError(
      try KeyStoreKey.paired(
        clientKind: .cli,
        installationID: installationID,
        rootFingerprint: rootFingerprint,
        machineRoute: Data(repeating: 1, count: 15),
        purpose: .counterGuard
      )
    )
    let nilInstallationID = UUID(
      uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    XCTAssertThrowsError(
      try KeyStoreKey.pending(
        clientKind: .iOSApp,
        installationID: nilInstallationID,
        inviteHash: inviteHash,
        purpose: .pairingRecord
      )
    )
    XCTAssertThrowsError(
      try KeyStoreKey.paired(
        clientKind: .macOSApp,
        installationID: installationID,
        rootFingerprint: Data(repeating: 0, count: 32),
        machineRoute: machineRoute,
        purpose: .counterGuard
      )
    )
    XCTAssertThrowsError(
      try KeyStoreKey.paired(
        clientKind: .macOSApp,
        installationID: installationID,
        rootFingerprint: rootFingerprint,
        machineRoute: Data(repeating: 0, count: 16),
        purpose: .counterGuard
      )
    )
  }

  func testInjectedBackendPersistsCommitmentAndFixedPolicy() async throws {
    let backend = InMemoryAppleKeychainSecurityBackend()
    let store = AppleKeychainStore(backend: backend)
    let key = try randomPairedKey(purpose: .deviceGrant)
    let secret = Data("injected-secret-\(UUID())".utf8)

    let persistence = try await store.persistImmutable(secret, for: key)

    XCTAssertEqual(persistence, .inserted)
    let repeatedPersistence = try await store.persistImmutable(secret, for: key)
    XCTAssertEqual(repeatedPersistence, .alreadyPresent)
    do {
      _ = try await store.persistImmutable(Data("conflict".utf8), for: key)
      XCTFail("immutable item must reject different bytes")
    } catch let error as KeyStoreError {
      XCTAssertEqual(error, .immutableConflict)
    }
    let attributes = try XCTUnwrap(backend.item(account: key.account))
    XCTAssertEqual(attributes[kSecValueData as String] as? Data, secret)
    XCTAssertEqual(
      attributes[kSecAttrGeneric as String] as? Data,
      Data(SHA256.hash(data: secret))
    )
    XCTAssertEqual(
      attributes[kSecAttrAccessible as String] as? String,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    )
    XCTAssertEqual(
      (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue,
      false
    )
    XCTAssertTrue(backend.allQueriesUseFixedDataProtectionPolicy())
  }

  func testInjectedBackendCASDistinguishesMissingAndMismatchWithoutMutation()
    async throws
  {
    let backend = InMemoryAppleKeychainSecurityBackend()
    let store = AppleKeychainStore(backend: backend)
    let key = try randomPairedKey(purpose: .counterGuard)
    let original = Data("cas-original-\(UUID())".utf8)
    let mismatch = Data("cas-mismatch-\(UUID())".utf8)
    let replacement = Data("cas-replacement-\(UUID())".utf8)

    let missingOutcome = await casOutcome(
      store: store,
      expected: original,
      replacement: replacement,
      key: key
    )
    XCTAssertEqual(missingOutcome, .failure(.compareAndReplaceMissing))

    _ = try await store.persistImmutable(original, for: key)
    let mismatchOutcome = await casOutcome(
      store: store,
      expected: mismatch,
      replacement: replacement,
      key: key
    )
    XCTAssertEqual(mismatchOutcome, .failure(.compareAndReplaceMismatch))
    let loaded = try await store.load(key)
    XCTAssertEqual(loaded, original)
  }

  func testInjectedBackendLoadRejectsWeakOrMisbindingItems() async throws {
    let key = try randomPairedKey(purpose: .deviceSignPrivateKey)
    let secret = Data("policy-secret-\(UUID())".utf8)

    let violations: [(String, (inout [CFString: Any]) -> Void)] = [
      (
        "accessible",
        { $0[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }
      ),
      ("synchronizable", { $0[kSecAttrSynchronizable] = kCFBooleanTrue as Any }),
      ("commitment", { $0[kSecAttrGeneric] = Data(repeating: 0xA5, count: 32) }),
    ]

    for (name, violate) in violations {
      let backend = InMemoryAppleKeychainSecurityBackend()
      var attributes = keychainAttributes(for: key, data: secret)
      violate(&attributes)
      backend.seed(attributes)
      let store = AppleKeychainStore(backend: backend)

      await assertPersistenceReadbackFailure(
        name,
        operation: { try await store.load(key) }
      )
      XCTAssertTrue(backend.allQueriesUseFixedDataProtectionPolicy(), name)
    }

    for field in [kSecAttrService, kSecAttrAccount] {
      let backend = InMemoryAppleKeychainSecurityBackend()
      var malformed = exportedKeychainAttributes(for: key, data: secret)
      malformed[field as String] = "misbound-\(UUID())"
      backend.forceCopyResult(malformed)
      let store = AppleKeychainStore(backend: backend)

      await assertPersistenceReadbackFailure(
        field as String,
        operation: { try await store.load(key) }
      )
      XCTAssertTrue(backend.allQueriesUseFixedDataProtectionPolicy())
    }
  }

  func testInjectedBackendCASIsDigestLinearizedAcrossStoreInstances() async throws {
    let backend = InMemoryAppleKeychainSecurityBackend()
    let firstStore = AppleKeychainStore(backend: backend)
    let secondStore = AppleKeychainStore(backend: backend)
    let key = try randomPairedKey(purpose: .counterGuard)
    let expected = Data("cas-expected-\(UUID())".utf8)
    let replacementA = Data("cas-replacement-a-\(UUID())".utf8)
    let replacementB = Data("cas-replacement-b-\(UUID())".utf8)
    _ = try await firstStore.persistImmutable(expected, for: key)

    async let outcomeA = casOutcome(
      store: firstStore,
      expected: expected,
      replacement: replacementA,
      key: key
    )
    async let outcomeB = casOutcome(
      store: secondStore,
      expected: expected,
      replacement: replacementB,
      key: key
    )
    let outcomes = await [outcomeA, outcomeB]

    XCTAssertEqual(outcomes.filter { $0 == .success }.count, 1, "\(outcomes)")
    XCTAssertEqual(
      outcomes.filter { $0 == .failure(.compareAndReplaceMismatch) }.count,
      1,
      "\(outcomes)"
    )
    let loaded = try await firstStore.load(key)
    XCTAssertTrue(loaded == replacementA || loaded == replacementB)

    let updateQueries = backend.updateQueries()
    XCTAssertEqual(updateQueries.count, 2)
    for query in updateQueries {
      XCTAssertEqual(
        query[kSecAttrGeneric as String] as? Data,
        Data(SHA256.hash(data: expected))
      )
    }
    let updateAttributes = backend.updateAttributes()
    XCTAssertEqual(updateAttributes.count, 2)
    for attributes in updateAttributes {
      let replacement = try XCTUnwrap(attributes[kSecValueData as String] as? Data)
      XCTAssertEqual(
        attributes[kSecAttrGeneric as String] as? Data,
        Data(SHA256.hash(data: replacement))
      )
    }
  }

  func testInjectedBackendDeleteMatchesCurrentCommitmentAndRefusesRacedReplacement()
    async throws
  {
    let backend = InMemoryAppleKeychainSecurityBackend()
    let store = AppleKeychainStore(backend: backend)
    let key = try randomPairedKey(purpose: .deviceStorageKEK)
    let original = Data("delete-original-\(UUID())".utf8)
    let raced = Data("delete-raced-\(UUID())".utf8)
    _ = try await store.persistImmutable(original, for: key)

    backend.replaceBeforeNextDelete(with: keychainAttributes(for: key, data: raced))
    do {
      try await store.deleteExact(key)
      XCTFail("exact delete must not remove a concurrently replaced value")
    } catch let error as KeyStoreError {
      XCTAssertEqual(error, .deleteReadbackFailed)
    }
    let loadedAfterRace = try await store.load(key)
    XCTAssertEqual(loadedAfterRace, raced)

    let deleteQuery = try XCTUnwrap(backend.deleteQueries().last)
    XCTAssertEqual(
      deleteQuery[kSecAttrGeneric as String] as? Data,
      Data(SHA256.hash(data: original))
    )
  }

  func testInjectedBackendListsOnlyCurrentInstallationMarkersAndAuditsPolicy()
    async throws
  {
    let backend = InMemoryAppleKeychainSecurityBackend()
    let store = AppleKeychainStore(backend: backend)
    let installationID = UUID()
    let first = try KeyStoreKey.paired(
      clientKind: .macOSApp,
      installationID: installationID,
      rootFingerprint: randomNonzeroData(count: 32),
      machineRoute: randomNonzeroData(count: 16),
      purpose: .commitMarker
    )
    let second = try KeyStoreKey.paired(
      clientKind: .macOSApp,
      installationID: installationID,
      rootFingerprint: randomNonzeroData(count: 32),
      machineRoute: randomNonzeroData(count: 16),
      purpose: .commitMarker
    )
    let otherInstallation = try KeyStoreKey.paired(
      clientKind: .macOSApp,
      installationID: UUID(),
      rootFingerprint: randomNonzeroData(count: 32),
      machineRoute: randomNonzeroData(count: 16),
      purpose: .commitMarker
    )
    let nonMarker = try KeyStoreKey.paired(
      clientKind: .macOSApp,
      installationID: installationID,
      rootFingerprint: randomNonzeroData(count: 32),
      machineRoute: randomNonzeroData(count: 16),
      purpose: .deviceGrant
    )
    for (index, key) in [first, second, otherInstallation, nonMarker].enumerated() {
      _ = try await store.persistImmutable(Data("item-\(index)".utf8), for: key)
    }

    let markers = try await store.pairedCommitMarkerKeys(
      clientKind: .macOSApp,
      installationID: installationID
    )
    XCTAssertEqual(markers.map(\.account), [first.account, second.account].sorted())

    let inviteHash = try randomNonzeroData(count: 32)
    let recoveryIntent = try KeyStoreKey.pending(
      clientKind: .macOSApp,
      installationID: installationID,
      inviteHash: inviteHash,
      purpose: .recoveryIntent
    )
    let pendingRecord = try KeyStoreKey.pending(
      clientKind: .macOSApp,
      installationID: installationID,
      inviteHash: inviteHash,
      purpose: .pairingRecord
    )
    let pendingPrivateKey = try KeyStoreKey.pending(
      clientKind: .macOSApp,
      installationID: installationID,
      inviteHash: inviteHash,
      purpose: .deviceSignPrivateKey
    )
    for (index, key) in [recoveryIntent, pendingRecord, pendingPrivateKey].enumerated() {
      _ = try await store.persistImmutable(Data("pending-\(index)".utf8), for: key)
    }
    let pendingMarkers = try await store.pendingPairingRecoveryKeys(
      clientKind: .macOSApp,
      installationID: installationID
    )
    XCTAssertEqual(
      pendingMarkers.map(\.account),
      [recoveryIntent.account, pendingRecord.account].sorted()
    )

    let weakMarker = try KeyStoreKey.paired(
      clientKind: .macOSApp,
      installationID: installationID,
      rootFingerprint: randomNonzeroData(count: 32),
      machineRoute: randomNonzeroData(count: 16),
      purpose: .commitMarker
    )
    var weakAttributes = keychainAttributes(
      for: weakMarker,
      data: Data("weak-marker".utf8)
    )
    weakAttributes[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    backend.seed(weakAttributes)
    await assertPersistenceReadbackFailure("marker-list-policy") {
      try await store.pairedCommitMarkerKeys(
        clientKind: .macOSApp,
        installationID: installationID
      )
    }
  }

  func testImmutablePersistIsIdempotentAndConflictNeverOverwrites() async throws {
    try await withDataProtectionKeychainEntitlement {
      let store = AppleKeychainStore()
      let key = try randomPairedKey(purpose: .deviceGrant)
      defer { removeKeychainItem(account: key.account) }

      let original = Data("original-secret-\(UUID())".utf8)
      let conflicting = Data("conflicting-secret-\(UUID())".utf8)
      let initiallyLoaded = try await store.load(key)
      XCTAssertNil(initiallyLoaded)

      let inserted = try await store.persistImmutable(original, for: key)
      guard case .inserted = inserted else {
        return XCTFail("first immutable persist must report inserted")
      }
      let retry = try await store.persistImmutable(original, for: key)
      guard case .alreadyPresent = retry else {
        return XCTFail("same-bytes retry must report alreadyPresent")
      }

      do {
        _ = try await store.persistImmutable(conflicting, for: key)
        XCTFail("different bytes must not overwrite an immutable item")
      } catch let error as KeyStoreError {
        try rethrowMissingEntitlement(error)
        guard case .immutableConflict = error else {
          return XCTFail("unexpected error: \(String(reflecting: error))")
        }
        assertRedacted(error, key: key, secrets: [original, conflicting])
      }
      let loadedAfterConflict = try await store.load(key)
      XCTAssertEqual(loadedAfterConflict, original)
    }
  }

  func testCompareAndReplaceIsExistingOnlyAndExpectedExact() async throws {
    try await withDataProtectionKeychainEntitlement {
      let store = AppleKeychainStore()
      let key = try randomPairedKey(purpose: .counterGuard)
      defer { removeKeychainItem(account: key.account) }

      let expected = Data("expected-secret-\(UUID())".utf8)
      let mismatch = Data("mismatch-secret-\(UUID())".utf8)
      let replacement = Data("replacement-secret-\(UUID())".utf8)

      do {
        try await store.compareAndReplaceExact(
          expected: expected,
          replacement: replacement,
          for: key
        )
        XCTFail("compare-and-replace must not create a missing item")
      } catch let error as KeyStoreError {
        try rethrowMissingEntitlement(error)
        guard case .compareAndReplaceMissing = error else {
          return XCTFail("unexpected error: \(String(reflecting: error))")
        }
        assertRedacted(error, key: key, secrets: [expected, replacement])
      }

      _ = try await store.persistImmutable(expected, for: key)
      do {
        try await store.compareAndReplaceExact(
          expected: mismatch,
          replacement: replacement,
          for: key
        )
        XCTFail("compare-and-replace must reject an expected-bytes mismatch")
      } catch let error as KeyStoreError {
        try rethrowMissingEntitlement(error)
        guard case .compareAndReplaceMismatch = error else {
          return XCTFail("unexpected error: \(String(reflecting: error))")
        }
        assertRedacted(error, key: key, secrets: [mismatch, replacement])
      }
      let loadedAfterMismatch = try await store.load(key)
      XCTAssertEqual(loadedAfterMismatch, expected)

      try await store.compareAndReplaceExact(
        expected: expected,
        replacement: replacement,
        for: key
      )
      let loadedAfterReplacement = try await store.load(key)
      XCTAssertEqual(loadedAfterReplacement, replacement)
    }
  }

  func testDeleteExactReadsBackAbsentAndMissingDeleteIsIdempotent() async throws {
    try await withDataProtectionKeychainEntitlement {
      let store = AppleKeychainStore()
      let key = try randomPairedKey(purpose: .deviceStorageKEK)
      defer { removeKeychainItem(account: key.account) }

      _ = try await store.persistImmutable(try randomNonzeroData(count: 32), for: key)
      try await store.deleteExact(key)
      let loadedAfterDelete = try await store.load(key)
      XCTAssertNil(loadedAfterDelete)
      XCTAssertEqual(copyKeychainAttributes(account: key.account).status, errSecItemNotFound)

      try await store.deleteExact(key)
      let loadedAfterRepeatedDelete = try await store.load(key)
      XCTAssertNil(loadedAfterRepeatedDelete)
    }
  }

  func testEveryItemUsesFixedDataProtectionKeychainPolicy() async throws {
    XCTAssertEqual(AppleKeychainStore.service, "com.agentdeck.remote.v1")

    try await withDataProtectionKeychainEntitlement {
      let store = AppleKeychainStore()
      let key = try randomPairedKey(purpose: .deviceSignPrivateKey)
      defer { removeKeychainItem(account: key.account) }

      let secret = try randomNonzeroData(count: 32)
      _ = try await store.persistImmutable(secret, for: key)

      let copied = copyKeychainAttributes(account: key.account)
      XCTAssertEqual(copied.status, errSecSuccess)
      let attributes = try XCTUnwrap(copied.attributes)
      XCTAssertEqual(
        attributes[kSecAttrService as String] as? String,
        "com.agentdeck.remote.v1"
      )
      XCTAssertEqual(attributes[kSecAttrAccount as String] as? String, key.account)
      XCTAssertEqual(
        attributes[kSecAttrAccessible as String] as? String,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
      )
      XCTAssertEqual(
        (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue,
        false
      )
      XCTAssertEqual(
        attributes[kSecAttrGeneric as String] as? Data,
        Data(SHA256.hash(data: secret))
      )
    }
  }

  func testPublicStorageTypesAreSendableAndDebugOutputDoesNotLeakSecrets() throws {
    let store = AppleKeychainStore()
    let key = try randomPairedKey(purpose: .deviceHPKEPrivateKey)
    let secret = Data("sendable-secret-\(UUID())".utf8)

    assertSendable(RelayClientKind.macOSApp)
    assertSendable(RelayClientKind.iOSApp)
    assertSendable(key)
    assertSendable(store)
    assertSendable(KeyStorePersistence.inserted)
    assertSendable(KeyStoreError.immutableConflict)

    let errors: [KeyStoreError] = [
      .invalidAccount,
      .invalidLength(field: "inviteHash", expected: 32, actual: 31),
      .immutableConflict,
      .compareAndReplaceMissing,
      .compareAndReplaceMismatch,
      .persistenceReadbackFailed,
      .deleteReadbackFailed,
      .backendUnavailable(status: errSecMissingEntitlement),
    ]
    let debugDescriptions =
      [String(reflecting: store), String(reflecting: key)]
      + errors.flatMap { [String(describing: $0), String(reflecting: $0)] }
    for debug in debugDescriptions {
      XCTAssertFalse(debug.contains(key.account), debug)
      XCTAssertFalse(debug.contains(String(decoding: secret, as: UTF8.self)), debug)
      XCTAssertFalse(debug.lowercased().contains(secret.hexString), debug)
    }
  }
}

private func assertCanonicalAccountBound(
  _ account: String,
  file: StaticString = #filePath,
  line: UInt = #line
) {
  XCTAssertTrue(account.utf8.allSatisfy { $0 < 0x80 }, account, file: file, line: line)
  XCTAssertLessThanOrEqual(account.utf8.count, 160, account, file: file, line: line)
  XCTAssertFalse(account.contains("="), account, file: file, line: line)
}

private func assertRedacted(
  _ error: KeyStoreError,
  key: KeyStoreKey,
  secrets: [Data],
  file: StaticString = #filePath,
  line: UInt = #line
) {
  let descriptions = [String(describing: error), String(reflecting: error)]
  for description in descriptions {
    XCTAssertFalse(description.contains(key.account), description, file: file, line: line)
    for secret in secrets {
      XCTAssertFalse(
        description.contains(String(decoding: secret, as: UTF8.self)),
        description,
        file: file,
        line: line
      )
      XCTAssertFalse(
        description.lowercased().contains(secret.hexString),
        description,
        file: file,
        line: line
      )
    }
  }
}

private func randomPairedKey(purpose: PairedKeyStorePurpose) throws -> KeyStoreKey {
  try KeyStoreKey.paired(
    clientKind: .macOSApp,
    installationID: UUID(),
    rootFingerprint: randomNonzeroData(count: 32),
    machineRoute: randomNonzeroData(count: 16),
    purpose: purpose
  )
}

private func randomNonzeroData(count: Int) throws -> Data {
  var data = Data(repeating: 0, count: count)
  let status = data.withUnsafeMutableBytes { bytes in
    SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
  }
  guard status == errSecSuccess else {
    throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
  }
  if data.allSatisfy({ $0 == 0 }) {
    data[0] = 1
  }
  return data
}

private func withDataProtectionKeychainEntitlement(
  _ operation: () async throws -> Void
) async throws {
  do {
    try await operation()
  } catch KeyStoreError.backendUnavailable(let status)
    where status == errSecMissingEntitlement
  {
    throw XCTSkip(
      "当前 SwiftPM runner 缺少 Data Protection Keychain entitlement；"
        + "production-signed Keychain 属 post-MVP BLOCKED，本用例不计为 PASS"
    )
  }
}

private func rethrowMissingEntitlement(_ error: KeyStoreError) throws {
  if case .backendUnavailable(let status) = error, status == errSecMissingEntitlement {
    throw error
  }
}

private func copyKeychainAttributes(account: String) -> (
  status: OSStatus, attributes: [String: Any]?
) {
  let query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: AppleKeychainStore.service,
    kSecAttrAccount: account,
    kSecAttrSynchronizable: kSecAttrSynchronizableAny,
    kSecUseDataProtectionKeychain: true,
    kSecReturnAttributes: true,
    kSecMatchLimit: kSecMatchLimitOne,
  ]
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  return (status, result as? [String: Any])
}

private func removeKeychainItem(account: String) {
  let query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: AppleKeychainStore.service,
    kSecAttrAccount: account,
    kSecAttrSynchronizable: kSecAttrSynchronizableAny,
    kSecUseDataProtectionKeychain: true,
  ]
  let status = SecItemDelete(query as CFDictionary)
  if status == errSecMissingEntitlement {
    return
  }
  XCTAssertTrue(
    status == errSecSuccess || status == errSecItemNotFound,
    "failed to remove test Keychain item: OSStatus \(status)"
  )
}

private func assertSendable<T: Sendable>(_: T) {}

private enum CASOutcome: Equatable, Sendable, CustomStringConvertible {
  case success
  case failure(KeyStoreError)
  case unexpected(String)

  var description: String {
    switch self {
    case .success:
      "success"
    case .failure(let error):
      "failure(\(error))"
    case .unexpected(let error):
      "unexpected(\(error))"
    }
  }
}

private func casOutcome(
  store: AppleKeychainStore,
  expected: Data,
  replacement: Data,
  key: KeyStoreKey
) async -> CASOutcome {
  do {
    try await store.compareAndReplaceExact(
      expected: expected,
      replacement: replacement,
      for: key
    )
    return .success
  } catch let error as KeyStoreError {
    return .failure(error)
  } catch {
    return .unexpected(String(reflecting: error))
  }
}

private func assertPersistenceReadbackFailure<T: Sendable>(
  _ context: String,
  operation: () async throws -> T,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await operation()
    XCTFail("\(context): weak Keychain item must be rejected", file: file, line: line)
  } catch let error as KeyStoreError {
    XCTAssertEqual(error, .persistenceReadbackFailed, context, file: file, line: line)
  } catch {
    XCTFail("\(context): unexpected error \(error)", file: file, line: line)
  }
}

private func keychainAttributes(for key: KeyStoreKey, data: Data) -> [CFString: Any] {
  [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: AppleKeychainStore.service,
    kSecAttrAccount: key.account,
    kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrSynchronizable: kCFBooleanFalse as Any,
    kSecAttrGeneric: Data(SHA256.hash(data: data)),
    kSecValueData: data,
  ]
}

private func exportedKeychainAttributes(
  for key: KeyStoreKey,
  data: Data
) -> [String: Any] {
  Dictionary(
    uniqueKeysWithValues: keychainAttributes(for: key, data: data).map {
      ($0.key as String, $0.value)
    }
  )
}

private final class InMemoryAppleKeychainSecurityBackend:
  AppleKeychainSecurityBackend, @unchecked Sendable
{
  private let lock = NSLock()
  private var items: [[CFString: Any]] = []
  private var copiedQueries: [[CFString: Any]] = []
  private var recordedAddAttributes: [[CFString: Any]] = []
  private var recordedUpdateQueries: [[CFString: Any]] = []
  private var recordedUpdateAttributes: [[CFString: Any]] = []
  private var recordedDeleteQueries: [[CFString: Any]] = []
  private var forcedCopy: [String: Any]?
  private var replacementBeforeDelete: [CFString: Any]?

  func seed(_ attributes: [CFString: Any]) {
    lock.lock()
    defer { lock.unlock() }
    items.append(attributes)
  }

  func forceCopyResult(_ attributes: [String: Any]) {
    lock.lock()
    defer { lock.unlock() }
    forcedCopy = attributes
  }

  func replaceBeforeNextDelete(with attributes: [CFString: Any]) {
    lock.lock()
    defer { lock.unlock() }
    replacementBeforeDelete = attributes
  }

  func item(account: String) -> [String: Any]? {
    lock.lock()
    defer { lock.unlock() }
    guard let item = items.first(where: { string($0[kSecAttrAccount]) == account }) else {
      return nil
    }
    return export(item)
  }

  func updateQueries() -> [[String: Any]] {
    lock.lock()
    defer { lock.unlock() }
    return recordedUpdateQueries.map(export)
  }

  func updateAttributes() -> [[String: Any]] {
    lock.lock()
    defer { lock.unlock() }
    return recordedUpdateAttributes.map(export)
  }

  func deleteQueries() -> [[String: Any]] {
    lock.lock()
    defer { lock.unlock() }
    return recordedDeleteQueries.map(export)
  }

  func allQueriesUseFixedDataProtectionPolicy() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    #if os(macOS)
      let allQueries =
        copiedQueries + recordedAddAttributes + recordedUpdateQueries + recordedDeleteQueries
      return
        !allQueries.isEmpty
        && allQueries.allSatisfy {
          boolean($0[kSecUseDataProtectionKeychain]) == true
        }
    #else
      // iOS Keychain 本身使用 Data Protection；macOS 才有选择旧 file Keychain 的
      // query selector。
      return true
    #endif
  }

  func copyMatching(_ query: [CFString: Any]) -> AppleKeychainSecurityResult {
    lock.lock()
    defer { lock.unlock() }
    copiedQueries.append(query)
    if let forcedCopy {
      return AppleKeychainSecurityResult(status: errSecSuccess, value: [forcedCopy])
    }

    let matches = items.filter { itemMatches($0, query: query) }
    guard !matches.isEmpty else {
      return AppleKeychainSecurityResult(status: errSecItemNotFound, value: nil)
    }
    if string(query[kSecMatchLimit]) == kSecMatchLimitAll as String {
      return AppleKeychainSecurityResult(
        status: errSecSuccess,
        value: matches.map(export)
      )
    }
    return AppleKeychainSecurityResult(status: errSecSuccess, value: export(matches[0]))
  }

  func add(_ attributes: [CFString: Any]) -> OSStatus {
    lock.lock()
    defer { lock.unlock() }
    recordedAddAttributes.append(attributes)
    if items.contains(where: { sameIdentity($0, attributes) }) {
      return errSecDuplicateItem
    }
    items.append(persistentAttributes(attributes))
    return errSecSuccess
  }

  func update(
    _ query: [CFString: Any],
    attributesToUpdate: [CFString: Any]
  ) -> OSStatus {
    lock.lock()
    defer { lock.unlock() }
    recordedUpdateQueries.append(query)
    recordedUpdateAttributes.append(attributesToUpdate)
    guard let index = items.firstIndex(where: { itemMatches($0, query: query) }) else {
      return errSecItemNotFound
    }
    for (key, value) in attributesToUpdate {
      items[index][key] = value
    }
    return errSecSuccess
  }

  func delete(_ query: [CFString: Any]) -> OSStatus {
    lock.lock()
    defer { lock.unlock() }
    recordedDeleteQueries.append(query)
    if let replacementBeforeDelete {
      items.removeAll { sameIdentity($0, replacementBeforeDelete) }
      items.append(replacementBeforeDelete)
      self.replacementBeforeDelete = nil
    }
    guard let index = items.firstIndex(where: { itemMatches($0, query: query) }) else {
      return errSecItemNotFound
    }
    items.remove(at: index)
    return errSecSuccess
  }

  private func itemMatches(
    _ item: [CFString: Any],
    query: [CFString: Any]
  ) -> Bool {
    for key in [kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrAccessible] {
      if let expected = query[key], string(item[key]) != string(expected) {
        return false
      }
    }
    if let expected = query[kSecAttrGeneric] as? Data,
      item[kSecAttrGeneric] as? Data != expected
    {
      return false
    }
    if let expected = query[kSecAttrSynchronizable],
      string(expected) != kSecAttrSynchronizableAny as String,
      boolean(item[kSecAttrSynchronizable]) != boolean(expected)
    {
      return false
    }
    return true
  }

  private func sameIdentity(
    _ lhs: [CFString: Any],
    _ rhs: [CFString: Any]
  ) -> Bool {
    string(lhs[kSecClass]) == string(rhs[kSecClass])
      && string(lhs[kSecAttrService]) == string(rhs[kSecAttrService])
      && string(lhs[kSecAttrAccount]) == string(rhs[kSecAttrAccount])
  }

  private func persistentAttributes(_ attributes: [CFString: Any]) -> [CFString: Any] {
    var result = attributes
    result.removeValue(forKey: kSecUseDataProtectionKeychain)
    return result
  }

  private func export(_ attributes: [CFString: Any]) -> [String: Any] {
    Dictionary(uniqueKeysWithValues: attributes.map { ($0.key as String, $0.value) })
  }

  private func string(_ value: Any?) -> String? {
    value as? String
  }

  private func boolean(_ value: Any?) -> Bool? {
    (value as? NSNumber)?.boolValue
  }
}

extension Data {
  fileprivate var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
