import CryptoKit
import Foundation
import Security
import XCTest

@testable import AgentDeckRelayClient

final class RelayClientStorageIntegrationTests: XCTestCase {
  func testCommitLoadRestartAndIOSFileAttributes() async throws {
    let fixture = try makeFixture()
    defer { fixture.remove() }

    let keyBytes = randomData(count: 32)
    let snapshot = try makeSnapshot(identity: fixture.identity, variant: 0x31)
    let protectionRecorder = ProtectionApplicationRecorder()
    let store = try makeStore(
      fixture: fixture,
      keyBytes: keyBytes,
      testHooks: FileCryptoStateStoreTestHooks(
        protectionDidApply: { url, protection in
          protectionRecorder.record(url: url, protection: protection)
        }
      )
    )

    _ = try await store.commitInitial(snapshot)
    let loaded = try await store.load()
    XCTAssertEqual(loaded, snapshot)
    let appliedProtection = try XCTUnwrap(protectionRecorder.value())
    XCTAssertEqual(appliedProtection.protection, .complete)
    XCTAssertEqual(
      appliedProtection.url.deletingLastPathComponent(),
      store.stateURL.deletingLastPathComponent()
    )

    let stateURL = store.stateURL
    let attributes = try stateURL.resourceValues(forKeys: [
      .isExcludedFromBackupKey,
      .fileProtectionKey,
    ])
    XCTAssertEqual(attributes.isExcludedFromBackup, true)
    #if targetEnvironment(simulator)
      // Simulator 固定回报 CompleteUntilFirstUserAuthentication，不能证明真机锁屏语义；
      // hook 同时证明 setter 路径真实执行；物理锁屏语义仍留 P6.3。
      XCTAssertEqual(FileCryptoStateStore.fileProtectionPolicy, .complete)
    #else
      XCTAssertEqual(attributes.fileProtection, .complete)
    #endif

    let reopened = try makeStore(fixture: fixture, keyBytes: keyBytes)
    let reopenedSnapshot = try await reopened.load()
    XCTAssertEqual(reopenedSnapshot, snapshot)
  }

  func testRestartWithWrongStorageKeyFailsClosedWithoutChangingStateFile() async throws {
    let fixture = try makeFixture()
    defer { fixture.remove() }

    let keyBytes = randomData(count: 32)
    let store = try makeStore(fixture: fixture, keyBytes: keyBytes)
    _ = try await store.commitInitial(
      makeSnapshot(identity: fixture.identity, variant: 0x32)
    )
    let committed = try Data(contentsOf: store.stateURL)

    var wrongKeyBytes = keyBytes
    wrongKeyBytes[wrongKeyBytes.startIndex] ^= 0x01
    let wrongKeyStore = try makeStore(fixture: fixture, keyBytes: wrongKeyBytes)
    await assertLoadFailsClosed(wrongKeyStore, expected: .authenticationFailed)
    XCTAssertEqual(try Data(contentsOf: store.stateURL), committed)
  }

  func testAuthenticatedStateTamperFailsClosedWithoutRepairingFile() async throws {
    let fixture = try makeFixture()
    defer { fixture.remove() }

    let keyBytes = randomData(count: 32)
    let store = try makeStore(fixture: fixture, keyBytes: keyBytes)
    _ = try await store.commitInitial(
      makeSnapshot(identity: fixture.identity, variant: 0x33)
    )

    try flipOneByteInPlace(at: store.stateURL)
    let tampered = try Data(contentsOf: store.stateURL)

    let reopened = try makeStore(fixture: fixture, keyBytes: keyBytes)
    await assertLoadFailsClosed(reopened, expected: .authenticationFailed)
    XCTAssertEqual(try Data(contentsOf: store.stateURL), tampered)
  }

  func testAppleKeychainRoundTripCASAndThisDeviceOnlyPolicy() async throws {
    let fixture = try makeFixture()
    defer { fixture.remove() }
    let key = try KeyStoreKey.paired(
      clientKind: fixture.identity.clientKind,
      installationID: fixture.identity.installationID,
      rootFingerprint: fixture.identity.machineRootFingerprint,
      machineRoute: fixture.identity.machineRoute,
      purpose: .counterGuard
    )
    let store = AppleKeychainStore()
    try await store.deleteExact(key)
    do {
      let initial = randomData(count: 96)
      let replacement = randomData(count: 104)
      let persistence = try await store.persistImmutable(initial, for: key)
      let initialReadback = try await store.load(key)
      XCTAssertEqual(persistence, .inserted)
      XCTAssertEqual(initialReadback, initial)
      try await store.compareAndReplaceExact(
        expected: initial,
        replacement: replacement,
        for: key
      )
      let replacementReadback = try await store.load(key)
      XCTAssertEqual(replacementReadback, replacement)

      let attributes = try XCTUnwrap(copyKeychainAttributes(account: key.account))
      XCTAssertEqual(
        attributes[kSecAttrService as String] as? String,
        AppleKeychainStore.service
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
        Data(SHA256.hash(data: replacement))
      )
      try await store.deleteExact(key)
      let deletedReadback = try await store.load(key)
      XCTAssertNil(deletedReadback)
    } catch {
      try? await store.deleteExact(key)
      throw error
    }
  }

  func testPublicStorageBoundaryIsSendable() {
    requireSendable(RelayClientKind.self)
    requireSendable(CryptoStateIdentity.self)
    requireSendable(CryptoStateSnapshot.self)
    requireSendable(DeviceStorageKEK.self)
    requireSendable(FileCryptoStateStore.self)
  }

  private func makeFixture() throws -> StorageFixture {
    let sandboxURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("AgentDeckMobileStorageTests-\(UUID().uuidString)", isDirectory: true)
    let rootURL =
      sandboxURL
      .appendingPathComponent("Library", isDirectory: true)
      .appendingPathComponent("Application Support", isDirectory: true)
      .appendingPathComponent("AgentDeck", isDirectory: true)
    try FileManager.default.createDirectory(
      at: rootURL,
      withIntermediateDirectories: true
    )
    return StorageFixture(
      sandboxURL: sandboxURL,
      rootURL: rootURL,
      identity: try CryptoStateIdentity(
        clientKind: .iOSApp,
        installationID: UUID(),
        machineID: UUID().uuidString,
        machineRootFingerprint: randomData(count: 32),
        machineRoute: randomData(count: 16)
      )
    )
  }

  private func makeStore(
    fixture: StorageFixture,
    keyBytes: Data,
    testHooks: FileCryptoStateStoreTestHooks = .none
  ) throws -> FileCryptoStateStore {
    try FileCryptoStateStore(
      rootURL: fixture.rootURL,
      identity: fixture.identity,
      storageKey: DeviceStorageKEK(rawRepresentation: keyBytes),
      testHooks: testHooks
    )
  }

  private func assertLoadFailsClosed(
    _ store: FileCryptoStateStore,
    expected: CryptoStateStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    do {
      _ = try await store.load()
      XCTFail("认证失败的 crypto state 不得被加载", file: file, line: line)
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, expected, file: file, line: line)
    }
  }

  private func flipOneByteInPlace(at url: URL) throws {
    let bytes = try Data(contentsOf: url)
    guard bytes.count > 1 else {
      throw StorageIntegrationHarnessError.sealedStateTooSmall
    }
    let offset = UInt64(bytes.count / 2)
    let flipped = Data([bytes[Int(offset)] ^ 0x01])
    let handle = try FileHandle(forUpdating: url)
    defer { try? handle.close() }
    try handle.seek(toOffset: offset)
    try handle.write(contentsOf: flipped)
    try handle.synchronize()
  }

  private func randomData(count: Int) -> Data {
    var generator = SystemRandomNumberGenerator()
    var data = Data(
      (0..<count).map { _ in
        UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
      })
    if data.allSatisfy({ $0 == 0 }), !data.isEmpty {
      data[0] = 1
    }
    return data
  }

  private func makeSnapshot(
    identity: CryptoStateIdentity,
    variant: UInt8
  ) throws -> CryptoStateSnapshot {
    let deviceRoute = Data(repeating: 0x44, count: 16)
    let keyID = KeyIDV1(purpose: .deviceCommandTx, epoch: 1)
    let catalogKeyID = KeyIDV1(purpose: .catalog, epoch: 2)
    let replyKeyID = KeyIDV1(purpose: .deviceReplyTx, epoch: 3)
    let directory = try DeviceKeyDirectoryV1(
      revision: 1,
      entries: [
        DeviceWrappedKeyV1(
          keyID: catalogKeyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: variant, count: 32),
          wrappedKey: Data(repeating: variant &+ 1, count: 48)
        ),
        DeviceWrappedKeyV1(
          keyID: keyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: variant &+ 2, count: 32),
          wrappedKey: Data(repeating: variant &+ 3, count: 48)
        ),
        DeviceWrappedKeyV1(
          keyID: replyKeyID,
          deviceRoute: deviceRoute,
          streamRoute: nil,
          enc: Data(repeating: variant &+ 4, count: 32),
          wrappedKey: Data(repeating: variant &+ 5, count: 48)
        ),
      ],
      signature: Data(repeating: variant, count: 64)
    )
    return try CryptoStateSnapshot(
      DeviceCryptoStateV1(
        stateRevision: 1,
        trustScope: DeviceCryptoTrustScopeV1(
          relayServerID: Data(repeating: 0x33, count: 16),
          machineRootFingerprint: identity.machineRootFingerprint,
          machineRoute: identity.machineRoute,
          deviceRoute: deviceRoute,
          grantSerial: 1,
          trustEpoch: 1
        ),
        keyDirectory: directory,
        senderCounter: DeviceSenderCounterV1(
          keyID: keyID,
          keyDirectoryRevision: directory.revision,
          noncePrefix: Data([0x10, 0x20, 0x30, variant]),
          reservedHighWater: 0,
          reservationID: Data(repeating: 0, count: 16)
        ),
        securityState: .active,
        replayStates: [],
        streamStates: []
      )
    )
  }

  private func requireSendable<Value: Sendable>(_ type: Value.Type) {}
}

private func copyKeychainAttributes(account: String) -> [String: Any]? {
  let query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: AppleKeychainStore.service,
    kSecAttrAccount: account,
    kSecAttrSynchronizable: kSecAttrSynchronizableAny,
    kSecReturnAttributes: true,
    kSecMatchLimit: kSecMatchLimitOne,
  ]
  var result: CFTypeRef?
  guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
    return nil
  }
  return result as? [String: Any]
}

private final class ProtectionApplicationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recorded: (url: URL, protection: FileProtectionType)?

  func record(url: URL, protection: FileProtectionType) {
    lock.lock()
    recorded = (url, protection)
    lock.unlock()
  }

  func value() -> (url: URL, protection: FileProtectionType)? {
    lock.lock()
    defer { lock.unlock() }
    return recorded
  }
}

private struct StorageFixture {
  let sandboxURL: URL
  let rootURL: URL
  let identity: CryptoStateIdentity

  func remove() {
    try? FileManager.default.removeItem(at: sandboxURL)
  }
}

private enum StorageIntegrationHarnessError: Error {
  case sealedStateTooSmall
}
