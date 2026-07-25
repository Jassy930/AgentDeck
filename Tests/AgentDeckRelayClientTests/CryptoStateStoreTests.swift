import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import AgentDeckRelayClient

final class CryptoStateStoreTests: XCTestCase {
  func testPublicPersistenceSeamIsSendableAndUses128MiBLogicalLimit() throws {
    requireSendable(RelayClientKind.self)
    requireSendable(CryptoStateIdentity.self)
    requireSendable(DeviceStorageKEK.self)
    requireSendable(CryptoStateSnapshot.self)
    requireSendable(CryptoStateCommit.self)
    requireSendable(CryptoStateStoreError.self)
    requireSendable((any CryptoStateStore).self)
    requireSendable(FileCryptoStateStore.self)

    XCTAssertEqual(CryptoStateSnapshot.maximumDataBytes, 128 * 1024 * 1024)
    XCTAssertEqual(RelayClientKind.macOSApp.rawValue, "macos-app")
    XCTAssertEqual(RelayClientKind.iOSApp.rawValue, "ios-app")
    XCTAssertEqual(RelayClientKind.cli.rawValue, "cli")

    let firstKey = try DeviceStorageKEK.generate()
    let secondKey = try DeviceStorageKEK.generate()
    XCTAssertEqual(firstKey.rawRepresentation.count, 32)
    XCTAssertEqual(secondKey.rawRepresentation.count, 32)
    XCTAssertNotEqual(firstKey.rawRepresentation, secondKey.rawRepresentation)

    _ = CryptoStateStoreConformanceProbe()
  }

  func testIdentityAndStorageKeyLengthsFailClosed() throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }

    var invalidRoot = identityFixture()
    invalidRoot.machineRootFingerprint = Data(repeating: 1, count: 31)
    XCTAssertThrowsError(try invalidRoot.identity())

    var invalidRoute = identityFixture()
    invalidRoute.machineRoute = Data(repeating: 1, count: 15)
    XCTAssertThrowsError(try invalidRoute.identity())

    var nilInstallation = identityFixture()
    nilInstallation.installationID = UUID(
      uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    )
    XCTAssertThrowsError(try nilInstallation.identity())

    XCTAssertThrowsError(
      try makeStore(
        rootURL: sandbox.rootURL,
        fixture: identityFixture(),
        keyBytes: Data(repeating: 1, count: 31)
      )
    )
  }

  func testSealedFileUsesRandomNonceBinaryAADAndHidesTypedCanonicalState() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let fixture = identityFixture()
    let keyBytes = Data(repeating: 0x44, count: 32)
    let snapshot = try makeSnapshot(fixture: fixture, variant: 0xA5)
    let canonicalState = snapshot.canonicalBytes

    let first = try makeStore(
      rootURL: sandbox.rootURL.appendingPathComponent("first", isDirectory: true),
      fixture: fixture,
      keyBytes: keyBytes
    )
    let second = try makeStore(
      rootURL: sandbox.rootURL.appendingPathComponent("second", isDirectory: true),
      fixture: fixture,
      keyBytes: keyBytes
    )
    let firstCommit = try await first.commitInitial(snapshot)
    let secondCommit = try await second.commitInitial(snapshot)
    XCTAssertEqual(firstCommit, .created)
    XCTAssertEqual(secondCommit, .created)

    let firstSealed = try Data(contentsOf: first.stateURL)
    let secondSealed = try Data(contentsOf: second.stateURL)
    assertV1Header(firstSealed, plaintextLength: canonicalState.count)
    assertV1Header(secondSealed, plaintextLength: canonicalState.count)
    XCTAssertNotEqual(firstSealed, secondSealed)
    XCTAssertNotEqual(
      firstSealed.subdata(in: 12..<24),
      secondSealed.subdata(in: 12..<24),
      "每次 seal 必须使用独立随机 nonce"
    )
    XCTAssertNil(firstSealed.range(of: canonicalState))
    XCTAssertNil(secondSealed.range(of: canonicalState))

    XCTAssertEqual(
      try openV1File(firstSealed, fixture: fixture, keyBytes: keyBytes),
      canonicalState,
      "文件必须使用固定长度前缀二进制 AAD，而不是 JSON AAD"
    )
    XCTAssertEqual(
      try openV1File(secondSealed, fixture: fixture, keyBytes: keyBytes),
      canonicalState
    )
  }

  func testAADBindsClientInstallationMachineRootAndRouteAxes() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let originalFixture = identityFixture()
    let keyBytes = Data(repeating: 0x55, count: 32)
    let originalStore = try makeStore(
      rootURL: sandbox.rootURL.appendingPathComponent("original", isDirectory: true),
      fixture: originalFixture,
      keyBytes: keyBytes
    )
    let snapshot = try makeSnapshot(fixture: originalFixture, variant: 0x71)
    _ = try await originalStore.commitInitial(snapshot)
    let originalSealed = try Data(contentsOf: originalStore.stateURL)

    var wrongClient = originalFixture
    wrongClient.clientKind = .cli
    var wrongInstallation = originalFixture
    wrongInstallation.installationID = UUID(uuidString: "10000000-0000-0000-0000-000000000002")!
    var wrongMachine = originalFixture
    wrongMachine.machineID = "machine-beta"
    var wrongRoot = originalFixture
    wrongRoot.machineRootFingerprint[0] ^= 1
    var wrongRoute = originalFixture
    wrongRoute.machineRoute[0] ^= 1

    let wrongFixtures = [
      wrongClient,
      wrongInstallation,
      wrongMachine,
      wrongRoot,
      wrongRoute,
    ]
    for (index, wrongFixture) in wrongFixtures.enumerated() {
      let wrongStore = try makeStore(
        rootURL: sandbox.rootURL.appendingPathComponent("wrong-\(index)", isDirectory: true),
        fixture: wrongFixture,
        keyBytes: keyBytes
      )
      _ = try await wrongStore.commitInitial(
        try makeSnapshot(fixture: wrongFixture, variant: UInt8(index + 1))
      )
      try overwriteInPlace(originalSealed, at: wrongStore.stateURL)
      await assertLoadFails(wrongStore, expected: .authenticationFailed)
      XCTAssertEqual(try Data(contentsOf: wrongStore.stateURL), originalSealed)
    }
  }

  func testMagicVersionLengthAndCiphertextTamperFailClosed() async throws {
    try await assertCorruptionFails(expected: .invalidFormat) { sealed in
      sealed[0] ^= 0xFF
    }
    try await assertCorruptionFails(expected: .invalidFormat) { sealed in
      sealed[4] = 2
    }
    try await assertCorruptionFails(expected: .invalidFormat) { sealed in
      sealed[11] &+= 1
    }
    try await assertCorruptionFails(expected: .authenticationFailed) { sealed in
      sealed[sealed.index(before: sealed.endIndex)] ^= 1
    }
  }

  func test128MiBHardCapRejectsOversizedDurableFileBeforeReadOrRepair() async throws {
    XCTAssertEqual(CryptoStateSnapshot.maximumDataBytes, 128 * 1024 * 1024)
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let fixture = identityFixture()
    let store = try makeStore(rootURL: sandbox.rootURL, fixture: fixture)
    let initial = try makeSnapshot(fixture: fixture, variant: 0x31)
    _ = try await store.commitInitial(initial)
    let durableBefore = try Data(contentsOf: store.stateURL)
    let sealedOverhead = durableBefore.count - initial.canonicalBytes.count
    XCTAssertEqual(sealedOverhead, 40)
    let oversizedFileBytes =
      CryptoStateSnapshot.maximumDataBytes + sealedOverhead + 1
    let originalInode = try inode(at: store.stateURL)

    let descriptor = Darwin.open(
      store.stateURL.path,
      O_WRONLY | O_CLOEXEC | O_NOFOLLOW
    )
    XCTAssertGreaterThanOrEqual(descriptor, 0)
    guard descriptor >= 0 else { return }
    XCTAssertEqual(Darwin.ftruncate(descriptor, off_t(oversizedFileBytes)), 0)
    XCTAssertEqual(Darwin.fsync(descriptor), 0)
    XCTAssertEqual(Darwin.close(descriptor), 0)

    await assertLoadFails(store, expected: .inputTooLarge)
    let attributes = try FileManager.default.attributesOfItem(atPath: store.stateURL.path)
    XCTAssertEqual((attributes[.size] as? NSNumber)?.intValue, oversizedFileBytes)
    XCTAssertEqual(try inode(at: store.stateURL), originalInode)
  }

  func testInitialCommitCASDeleteAndFileAttributesAreExactAndDurable() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let store = try makeStore(rootURL: sandbox.rootURL, fixture: identityFixture())
    let initial = try makeSnapshot(fixture: identityFixture(), variant: 0x41)
    let conflict = try makeSnapshot(fixture: identityFixture(), variant: 0x42)
    let replacement = try makeSnapshot(fixture: identityFixture(), variant: 0x43)

    let initiallyLoaded = try await store.load()
    XCTAssertNil(initiallyLoaded)
    let created = try await store.commitInitial(initial)
    XCTAssertEqual(created, .created)
    let firstFile = try Data(contentsOf: store.stateURL)
    let firstInode = try inode(at: store.stateURL)

    let retry = try await store.commitInitial(initial)
    XCTAssertEqual(retry, .alreadyPresent)
    XCTAssertEqual(
      try Data(contentsOf: store.stateURL),
      firstFile,
      "same-bytes retry must not reseal or consume another nonce"
    )
    do {
      _ = try await store.commitInitial(conflict)
      XCTFail("different initial bytes must not overwrite durable state")
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, .immutableConflict)
    }

    do {
      try await store.compareAndReplaceExact(expected: conflict, replacement: replacement)
      XCTFail("CAS must compare exact authenticated plaintext")
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, .compareAndReplaceMismatch)
    }
    let loadedAfterConflict = try await store.load()
    XCTAssertEqual(loadedAfterConflict, initial)

    try await store.compareAndReplaceExact(expected: initial, replacement: replacement)
    let loadedAfterReplace = try await store.load()
    XCTAssertEqual(loadedAfterReplace, replacement)
    XCTAssertNotEqual(try inode(at: store.stateURL), firstInode)
    let siblings = try FileManager.default.contentsOfDirectory(
      at: store.stateURL.deletingLastPathComponent(),
      includingPropertiesForKeys: nil
    )
    XCTAssertEqual(siblings.map(\.lastPathComponent), [store.stateURL.lastPathComponent])

    let fileAttributes = try FileManager.default.attributesOfItem(atPath: store.stateURL.path)
    let permissions = try XCTUnwrap(fileAttributes[.posixPermissions] as? NSNumber)
    XCTAssertEqual(permissions.intValue & 0o777, 0o600)
    let resourceValues = try store.stateURL.resourceValues(forKeys: [
      .isExcludedFromBackupKey,
      .fileProtectionKey,
    ])
    XCTAssertEqual(resourceValues.isExcludedFromBackup, true)
    #if os(macOS)
      if let protection = resourceValues.fileProtection {
        XCTAssertEqual(protection, .complete)
      }
    #else
      XCTAssertEqual(resourceValues.fileProtection, .complete)
    #endif

    do {
      try await store.deleteExact(expected: initial)
      XCTFail("delete must compare exact authenticated plaintext")
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, .compareAndReplaceMismatch)
    }
    let loadedAfterWrongDelete = try await store.load()
    XCTAssertEqual(loadedAfterWrongDelete, replacement)

    try await store.deleteExact(expected: replacement)
    let loadedAfterDelete = try await store.load()
    XCTAssertNil(loadedAfterDelete)
    XCTAssertFalse(FileManager.default.fileExists(atPath: store.stateURL.path))
  }

  func testTwoStoreInstancesLinearizeConcurrentCASAndDeleteTransactions() async throws {
    for iteration in 0..<8 {
      let sandbox = try makeSandbox()
      defer { sandbox.remove() }
      let rootURL = sandbox.rootURL.appendingPathComponent(
        "cas-\(iteration)",
        isDirectory: true
      )
      let firstStore = try makeStore(rootURL: rootURL, fixture: identityFixture())
      let secondStore = try makeStore(rootURL: rootURL, fixture: identityFixture())
      let initial = try makeSnapshot(
        fixture: identityFixture(),
        variant: UInt8(0x10 + iteration)
      )
      let firstReplacement = try makeSnapshot(
        fixture: identityFixture(),
        variant: UInt8(0x30 + iteration)
      )
      let secondReplacement = try makeSnapshot(
        fixture: identityFixture(),
        variant: UInt8(0x50 + iteration)
      )
      _ = try await firstStore.commitInitial(initial)

      async let firstOutcome = captureCryptoMutation {
        try await firstStore.compareAndReplaceExact(
          expected: initial,
          replacement: firstReplacement
        )
      }
      async let secondOutcome = captureCryptoMutation {
        try await secondStore.compareAndReplaceExact(
          expected: initial,
          replacement: secondReplacement
        )
      }
      let casOutcomes = await [firstOutcome, secondOutcome]
      XCTAssertEqual(casOutcomes.filter(\.isSuccess).count, 1)
      XCTAssertEqual(
        casOutcomes.filter { $0.error == .compareAndReplaceMismatch }.count,
        1
      )
      let loadedWinner = try await firstStore.load()
      let winner = try XCTUnwrap(loadedWinner)
      XCTAssertTrue(winner == firstReplacement || winner == secondReplacement)

      let afterDeleteReplacement = try makeSnapshot(
        fixture: identityFixture(),
        variant: UInt8(0x70 + iteration)
      )
      async let replaceOutcome = captureCryptoMutation {
        try await firstStore.compareAndReplaceExact(
          expected: winner,
          replacement: afterDeleteReplacement
        )
      }
      async let deleteOutcome = captureCryptoMutation {
        try await secondStore.deleteExact(expected: winner)
      }
      let deleteRaceOutcomes = await [replaceOutcome, deleteOutcome]
      XCTAssertEqual(deleteRaceOutcomes.filter(\.isSuccess).count, 1)
      let failures = deleteRaceOutcomes.compactMap(\.error)
      XCTAssertEqual(failures.count, 1)
      XCTAssertTrue(
        failures[0] == .compareAndReplaceMismatch || failures[0] == .missingState
      )
      let final = try await firstStore.load()
      XCTAssertTrue(final == nil || final == afterDeleteReplacement)
    }
  }

  func testLoadWithoutStateCleansOrphanAndDurablySyncsParentDirectory() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let recorder = DirectorySyncRecorder()
    let store = try makeStore(
      rootURL: sandbox.rootURL,
      fixture: identityFixture(),
      testHooks: FileCryptoStateStoreTestHooks(
        directoryDidSync: { recorder.record($0) }
      )
    )

    let initialLoad = try await store.load()
    XCTAssertNil(initialLoad)
    let devicesURL = store.stateURL.deletingLastPathComponent()
    let orphanURL = devicesURL.appendingPathComponent(
      ".\(store.stateURL.lastPathComponent).crash-orphan.tmp"
    )
    XCTAssertTrue(
      FileManager.default.createFile(
        atPath: orphanURL.path,
        contents: Data("sealed-orphan".utf8),
        attributes: [.posixPermissions: NSNumber(value: 0o600)]
      )
    )
    recorder.reset()

    let loadAfterOrphan = try await store.load()
    XCTAssertNil(loadAfterOrphan)
    XCTAssertFalse(FileManager.default.fileExists(atPath: orphanURL.path))
    XCTAssertTrue(
      recorder.urls().contains(devicesURL),
      "unlink orphan 后必须 fsync retained parent dirfd"
    )
  }

  func testRejectsSymlinkAndOverlyBroadDirectoryEntries() async throws {
    let containerURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckCryptoStateUnsafeRoot-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: containerURL, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: containerURL) }
    let targetURL = containerURL.appendingPathComponent("target", isDirectory: true)
    let symlinkRootURL = containerURL.appendingPathComponent("root-link", isDirectory: true)
    try FileManager.default.createDirectory(at: targetURL, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(at: symlinkRootURL, withDestinationURL: targetURL)
    let symlinkRootStore = try makeStore(
      rootURL: symlinkRootURL,
      fixture: identityFixture()
    )
    await assertLoadFails(symlinkRootStore, expected: .unsafeFile)

    let broadRootURL = containerURL.appendingPathComponent("broad-root", isDirectory: true)
    try FileManager.default.createDirectory(at: broadRootURL, withIntermediateDirectories: false)
    try FileManager.default.setAttributes(
      [.posixPermissions: NSNumber(value: 0o777)],
      ofItemAtPath: broadRootURL.path
    )
    let broadRootStore = try makeStore(rootURL: broadRootURL, fixture: identityFixture())
    await assertLoadFails(broadRootStore, expected: .unsafeFile)

    let symlinkChildRoot = containerURL.appendingPathComponent(
      "symlink-child-root",
      isDirectory: true
    )
    let redirectedRemote = containerURL.appendingPathComponent(
      "redirected-remote",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: symlinkChildRoot,
      withIntermediateDirectories: false
    )
    try FileManager.default.createDirectory(
      at: redirectedRemote,
      withIntermediateDirectories: false
    )
    try FileManager.default.createSymbolicLink(
      at: symlinkChildRoot.appendingPathComponent("remote-state-v1"),
      withDestinationURL: redirectedRemote
    )
    let symlinkChildStore = try makeStore(
      rootURL: symlinkChildRoot,
      fixture: identityFixture()
    )
    await assertLoadFails(symlinkChildStore, expected: .unsafeFile)

    let broadChildRoot = containerURL.appendingPathComponent(
      "broad-child-root",
      isDirectory: true
    )
    let broadChildStore = try makeStore(
      rootURL: broadChildRoot,
      fixture: identityFixture()
    )
    let broadChildInitialLoad = try await broadChildStore.load()
    XCTAssertNil(broadChildInitialLoad)
    let remoteURL = broadChildRoot.appendingPathComponent(
      "remote-state-v1",
      isDirectory: true
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: NSNumber(value: 0o755)],
      ofItemAtPath: remoteURL.path
    )
    await assertLoadFails(broadChildStore, expected: .unsafeFile)
  }

  func testRejectsHardlinkedStateLockAndTemporaryFiles() async throws {
    let stateSandbox = try makeSandbox()
    defer { stateSandbox.remove() }
    let stateStore = try makeStore(
      rootURL: stateSandbox.rootURL,
      fixture: identityFixture()
    )
    _ = try await stateStore.commitInitial(
      makeSnapshot(fixture: identityFixture(), variant: 0x81)
    )
    try FileManager.default.linkItem(
      at: stateStore.stateURL,
      to: stateSandbox.rootURL.appendingPathComponent("state-hardlink")
    )
    await assertLoadFails(stateStore, expected: .unsafeFile)

    let lockSandbox = try makeSandbox()
    defer { lockSandbox.remove() }
    let lockStore = try makeStore(rootURL: lockSandbox.rootURL, fixture: identityFixture())
    let lockInitialLoad = try await lockStore.load()
    XCTAssertNil(lockInitialLoad)
    let lockURL = try XCTUnwrap(try onlyLockURL(for: lockStore))
    try FileManager.default.linkItem(
      at: lockURL,
      to: lockSandbox.rootURL.appendingPathComponent("lock-hardlink")
    )
    await assertLoadFails(lockStore, expected: .unsafeFile)

    let tempSandbox = try makeSandbox()
    defer { tempSandbox.remove() }
    let tempStore = try makeStore(rootURL: tempSandbox.rootURL, fixture: identityFixture())
    let tempInitialLoad = try await tempStore.load()
    XCTAssertNil(tempInitialLoad)
    let orphanURL = tempStore.stateURL.deletingLastPathComponent().appendingPathComponent(
      ".\(tempStore.stateURL.lastPathComponent).hardlink.tmp"
    )
    XCTAssertTrue(
      FileManager.default.createFile(
        atPath: orphanURL.path,
        contents: Data("hardlinked-temp".utf8),
        attributes: [.posixPermissions: NSNumber(value: 0o600)]
      )
    )
    try FileManager.default.linkItem(
      at: orphanURL,
      to: tempSandbox.rootURL.appendingPathComponent("temp-hardlink")
    )
    await assertLoadFails(tempStore, expected: .unsafeFile)
  }

  func testRejectsSymlinkAndBroadModeStateLockAndTemporaryFiles() async throws {
    let stateSandbox = try makeSandbox()
    defer { stateSandbox.remove() }
    let stateStore = try makeStore(
      rootURL: stateSandbox.rootURL,
      fixture: identityFixture()
    )
    let stateInitialLoad = try await stateStore.load()
    XCTAssertNil(stateInitialLoad)
    let stateTarget = stateSandbox.rootURL.appendingPathComponent("state-target")
    XCTAssertTrue(
      FileManager.default.createFile(
        atPath: stateTarget.path,
        contents: Data("not-state".utf8),
        attributes: [.posixPermissions: NSNumber(value: 0o600)]
      )
    )
    try FileManager.default.createSymbolicLink(
      at: stateStore.stateURL,
      withDestinationURL: stateTarget
    )
    await assertLoadFails(stateStore, expected: .unsafeFile)

    let lockSandbox = try makeSandbox()
    defer { lockSandbox.remove() }
    let lockStore = try makeStore(rootURL: lockSandbox.rootURL, fixture: identityFixture())
    let lockInitialLoad = try await lockStore.load()
    XCTAssertNil(lockInitialLoad)
    let lockURL = try XCTUnwrap(try onlyLockURL(for: lockStore))
    try FileManager.default.setAttributes(
      [.posixPermissions: NSNumber(value: 0o644)],
      ofItemAtPath: lockURL.path
    )
    await assertLoadFails(lockStore, expected: .unsafeFile)

    let tempSandbox = try makeSandbox()
    defer { tempSandbox.remove() }
    let tempStore = try makeStore(rootURL: tempSandbox.rootURL, fixture: identityFixture())
    let tempInitialLoad = try await tempStore.load()
    XCTAssertNil(tempInitialLoad)
    let tempURL = tempStore.stateURL.deletingLastPathComponent().appendingPathComponent(
      ".\(tempStore.stateURL.lastPathComponent).wide-mode.tmp"
    )
    XCTAssertTrue(
      FileManager.default.createFile(
        atPath: tempURL.path,
        contents: Data("wide-temp".utf8),
        attributes: [.posixPermissions: NSNumber(value: 0o644)]
      )
    )
    await assertLoadFails(tempStore, expected: .unsafeFile)
  }

  func testRejectsPathSwapAfterOpeningStateDescriptor() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let fixture = identityFixture()
    let writer = try makeStore(rootURL: sandbox.rootURL, fixture: fixture)
    let snapshot = try makeSnapshot(fixture: fixture, variant: 0x82)
    _ = try await writer.commitInitial(snapshot)

    let movedURL = sandbox.rootURL.appendingPathComponent("opened-state-inode")
    let replacementURL = sandbox.rootURL.appendingPathComponent("replacement-state-inode")
    try FileManager.default.copyItem(at: writer.stateURL, to: replacementURL)
    let swap = OneShotPathSwap(movedURL: movedURL, replacementURL: replacementURL)
    let reader = try makeStore(
      rootURL: sandbox.rootURL,
      fixture: fixture,
      testHooks: FileCryptoStateStoreTestHooks(
        stateFileDidOpen: { swap.swap(pathURL: $0) }
      )
    )

    await assertLoadFails(reader, expected: .unsafeFile)
    XCTAssertNil(swap.failure())
    XCTAssertTrue(FileManager.default.fileExists(atPath: movedURL.path))
  }

  func testFactoryNeverGeneratesReplacementKEKForExistingState() async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let fixture = identityFixture()
    let identity = try fixture.identity()
    let store = try makeStore(rootURL: sandbox.rootURL, fixture: fixture)
    _ = try await store.commitInitial(
      makeSnapshot(fixture: fixture, variant: 0x83)
    )
    let durableBefore = try Data(contentsOf: store.stateURL)
    let missingKeyStore = MissingStorageKeyStore()

    do {
      _ = try await CryptoStateStoreFactory.openExisting(
        rootURL: sandbox.rootURL,
        identity: identity,
        keyStore: missingKeyStore
      )
      XCTFail("existing state without its KEK must fail closed")
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, .missingStorageKey)
    }
    XCTAssertEqual(try Data(contentsOf: store.stateURL), durableBefore)
    let firstMutationCount = await missingKeyStore.mutationCount()
    let loadedAccounts = await missingKeyStore.loadedAccounts()
    XCTAssertEqual(firstMutationCount, 0)
    XCTAssertTrue(loadedAccounts.contains { $0.hasSuffix("/device-storage-kek.v1") })

    let emptyRoot = sandbox.rootURL.appendingPathComponent("empty", isDirectory: true)
    let absent = try await CryptoStateStoreFactory.openExisting(
      rootURL: emptyRoot,
      identity: identity,
      keyStore: missingKeyStore
    )
    XCTAssertNil(absent)
    let finalMutationCount = await missingKeyStore.mutationCount()
    XCTAssertEqual(finalMutationCount, 0)
  }

  private func assertCorruptionFails(
    expected: CryptoStateStoreError,
    mutate: (inout Data) -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async throws {
    let sandbox = try makeSandbox()
    defer { sandbox.remove() }
    let store = try makeStore(rootURL: sandbox.rootURL, fixture: identityFixture())
    _ = try await store.commitInitial(
      makeSnapshot(fixture: identityFixture(), variant: 0x84)
    )
    var sealed = try Data(contentsOf: store.stateURL)
    mutate(&sealed)
    try overwriteInPlace(sealed, at: store.stateURL)

    await assertLoadFails(store, expected: expected, file: file, line: line)
    XCTAssertEqual(try Data(contentsOf: store.stateURL), sealed, file: file, line: line)
  }

  private func assertLoadFails(
    _ store: FileCryptoStateStore,
    expected: CryptoStateStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    do {
      _ = try await store.load()
      XCTFail("invalid crypto state must fail closed", file: file, line: line)
    } catch {
      XCTAssertEqual(error as? CryptoStateStoreError, expected, file: file, line: line)
    }
  }

  private func makeStore(
    rootURL: URL,
    fixture: IdentityFixture,
    keyBytes: Data = Data(repeating: 0x33, count: 32),
    testHooks: FileCryptoStateStoreTestHooks = .none
  ) throws -> FileCryptoStateStore {
    try FileCryptoStateStore(
      rootURL: rootURL,
      identity: fixture.identity(),
      storageKey: DeviceStorageKEK(rawRepresentation: keyBytes),
      testHooks: testHooks
    )
  }

  private func makeSnapshot(
    fixture: IdentityFixture,
    variant: UInt8
  ) throws -> CryptoStateSnapshot {
    precondition(variant != 0)
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
    let state = try DeviceCryptoStateV1(
      stateRevision: UInt64(variant),
      trustScope: DeviceCryptoTrustScopeV1(
        relayServerID: Data(repeating: 0x33, count: 16),
        machineRootFingerprint: fixture.machineRootFingerprint,
        machineRoute: fixture.machineRoute,
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
    return try CryptoStateSnapshot(state)
  }

  private func onlyLockURL(for store: FileCryptoStateStore) throws -> URL? {
    let locksURL =
      store.stateURL
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("locks", isDirectory: true)
    let entries = try FileManager.default.contentsOfDirectory(
      at: locksURL,
      includingPropertiesForKeys: nil
    )
    guard entries.count == 1 else { return nil }
    return entries[0]
  }

  private func identityFixture() -> IdentityFixture {
    IdentityFixture(
      clientKind: .macOSApp,
      installationID: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
      machineID: "machine-alpha",
      machineRootFingerprint: Data(repeating: 0x11, count: 32),
      machineRoute: Data(repeating: 0x22, count: 16)
    )
  }

  private func makeSandbox() throws -> CryptoStateSandbox {
    let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "AgentDeckCryptoStateTests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: true)
    return CryptoStateSandbox(rootURL: rootURL)
  }

  private func assertV1Header(
    _ sealed: Data,
    plaintextLength: Int,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(sealed.count, 24 + plaintextLength + 16, file: file, line: line)
    guard sealed.count >= 40 else { return }
    XCTAssertEqual(sealed.prefix(4), Data("ADCS".utf8), file: file, line: line)
    XCTAssertEqual(sealed[4], 1, file: file, line: line)
    XCTAssertEqual(sealed[5], 1, file: file, line: line)
    XCTAssertEqual(sealed.subdata(in: 6..<8), Data([0, 0]), file: file, line: line)
    XCTAssertEqual(
      readUInt32BigEndian(sealed.subdata(in: 8..<12)),
      UInt32(plaintextLength),
      file: file,
      line: line
    )
  }

  private func openV1File(
    _ sealed: Data,
    fixture: IdentityFixture,
    keyBytes: Data
  ) throws -> Data {
    guard sealed.count >= 40 else {
      throw CryptoStateTestHarnessError.sealedStateTooSmall
    }
    let header = sealed.subdata(in: 0..<24)
    let nonce = try ChaChaPoly.Nonce(data: header.subdata(in: 12..<24))
    let ciphertext = sealed.subdata(in: 24..<(sealed.count - 16))
    let tag = sealed.suffix(16)
    let box = try ChaChaPoly.SealedBox(
      nonce: nonce,
      ciphertext: ciphertext,
      tag: tag
    )
    return try ChaChaPoly.open(
      box,
      using: SymmetricKey(data: keyBytes),
      authenticating: binaryAAD(fixture: fixture, header: header)
    )
  }

  private func binaryAAD(fixture: IdentityFixture, header: Data) -> Data {
    let fields = [
      Data("AgentDeck/CryptoStateFileV1\u{0}".utf8),
      Data(fixture.clientKind.rawValue.utf8),
      uuidBytes(fixture.installationID),
      Data(fixture.machineID.utf8),
      fixture.machineRootFingerprint,
      fixture.machineRoute,
      Data("crypto-state.v1".utf8),
      header,
    ]
    var aad = Data()
    for field in fields {
      var length = UInt32(field.count).bigEndian
      withUnsafeBytes(of: &length) { aad.append(contentsOf: $0) }
      aad.append(field)
    }
    return aad
  }

  private func uuidBytes(_ value: UUID) -> Data {
    var bytes = value.uuid
    return withUnsafeBytes(of: &bytes) { Data($0) }
  }

  private func readUInt32BigEndian(_ data: Data) -> UInt32 {
    data.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  }

  private func overwriteInPlace(_ data: Data, at url: URL) throws {
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.truncate(atOffset: 0)
    try handle.write(contentsOf: data)
    try handle.synchronize()
  }

  private func inode(at url: URL) throws -> UInt64 {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return try XCTUnwrap((attributes[.systemFileNumber] as? NSNumber)?.uint64Value)
  }

  private func requireSendable<Value: Sendable>(_: Value.Type) {}
}

private struct IdentityFixture {
  var clientKind: RelayClientKind
  var installationID: UUID
  var machineID: String
  var machineRootFingerprint: Data
  var machineRoute: Data

  func identity() throws -> CryptoStateIdentity {
    try CryptoStateIdentity(
      clientKind: clientKind,
      installationID: installationID,
      machineID: machineID,
      machineRootFingerprint: machineRootFingerprint,
      machineRoute: machineRoute
    )
  }
}

private struct CryptoStateSandbox {
  let rootURL: URL

  func remove() {
    try? FileManager.default.removeItem(at: rootURL)
  }
}

private actor CryptoStateStoreConformanceProbe: CryptoStateStore {
  func load() async throws -> CryptoStateSnapshot? { nil }

  func commitInitial(_ snapshot: CryptoStateSnapshot) async throws -> CryptoStateCommit {
    _ = snapshot
    return .created
  }

  func compareAndReplaceExact(
    expected: CryptoStateSnapshot,
    replacement: CryptoStateSnapshot
  ) async throws {
    _ = (expected, replacement)
  }

  func deleteExact(expected: CryptoStateSnapshot) async throws {
    _ = expected
  }
}

private actor MissingStorageKeyStore: KeyStore {
  private var loaded: [String] = []
  private var mutations = 0

  func load(_ key: KeyStoreKey) async throws -> Data? {
    loaded.append(key.account)
    return nil
  }

  func persistImmutable(
    _ data: Data,
    for key: KeyStoreKey
  ) async throws -> KeyStorePersistence {
    _ = (data, key)
    mutations += 1
    return .inserted
  }

  func compareAndReplaceExact(
    expected: Data,
    replacement: Data,
    for key: KeyStoreKey
  ) async throws {
    _ = (expected, replacement, key)
    mutations += 1
  }

  func deleteExact(expected: Data, for key: KeyStoreKey) async throws {
    _ = (expected, key)
    mutations += 1
  }

  func loadedAccounts() -> [String] { loaded }

  func mutationCount() -> Int { mutations }
}

private enum CryptoMutationOutcome: Equatable, Sendable {
  case success
  case failure(CryptoStateStoreError)
  case unexpected(String)

  var isSuccess: Bool {
    self == .success
  }

  var error: CryptoStateStoreError? {
    guard case .failure(let error) = self else { return nil }
    return error
  }
}

private func captureCryptoMutation(
  _ body: @escaping @Sendable () async throws -> Void
) async -> CryptoMutationOutcome {
  do {
    try await body()
    return .success
  } catch let error as CryptoStateStoreError {
    return .failure(error)
  } catch {
    return .unexpected(String(describing: error))
  }
}

private final class DirectorySyncRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recordedURLs: [URL] = []

  func record(_ url: URL) {
    lock.withLock {
      recordedURLs.append(url)
    }
  }

  func reset() {
    lock.withLock {
      recordedURLs.removeAll()
    }
  }

  func urls() -> [URL] {
    lock.withLock { recordedURLs }
  }
}

private final class OneShotPathSwap: @unchecked Sendable {
  private let lock = NSLock()
  private let movedURL: URL
  private let replacementURL: URL
  private var didRun = false
  private var recordedFailure: String?

  init(movedURL: URL, replacementURL: URL) {
    self.movedURL = movedURL
    self.replacementURL = replacementURL
  }

  func swap(pathURL: URL) {
    lock.withLock {
      guard !didRun else { return }
      didRun = true
      do {
        try FileManager.default.moveItem(at: pathURL, to: movedURL)
        try FileManager.default.moveItem(at: replacementURL, to: pathURL)
      } catch {
        recordedFailure = String(describing: error)
      }
    }
  }

  func failure() -> String? {
    lock.withLock { recordedFailure }
  }
}

private enum CryptoStateTestHarnessError: Error {
  case sealedStateTooSmall
}
