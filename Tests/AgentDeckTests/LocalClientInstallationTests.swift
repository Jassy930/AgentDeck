import Darwin
import Foundation
import XCTest

@testable import AgentDeck

final class LocalClientInstallationTests: XCTestCase {
  private let canonicalUUID = "123e4567-e89b-12d3-a456-426614174000"

  func testProductionPathsComeFromCurrentOSAccountAndIgnoreHOME() throws {
    let installation = try LocalClientInstallation.forOSAccount()

    XCTAssertTrue(installation.homeDirectory.path.hasPrefix("/"))
    XCTAssertEqual(
      installation.recordPath.path,
      installation.homeDirectory
        .appendingPathComponent("Library", isDirectory: true)
        .appendingPathComponent("Application Support", isDirectory: true)
        .appendingPathComponent("AgentDeck", isDirectory: true)
        .appendingPathComponent("clients", isDirectory: true)
        .appendingPathComponent("macos-app", isDirectory: true)
        .appendingPathComponent("installation-id.v1", isDirectory: false)
        .path
    )
    XCTAssertEqual(
      installation.daemonSocketPath.path,
      installation.homeDirectory
        .appendingPathComponent("Library", isDirectory: true)
        .appendingPathComponent("Application Support", isDirectory: true)
        .appendingPathComponent("AgentDeck", isDirectory: true)
        .appendingPathComponent("agentdeckd.sock", isDirectory: false)
        .path
    )

    let source = try String(contentsOf: productionSourceURL, encoding: .utf8)
    XCTAssertTrue(source.contains("getpwuid_r("))
    XCTAssertTrue(source.contains("geteuid()"))
    for forbidden in [
      "NSHomeDirectory(",
      "homeDirectoryForCurrentUser",
      "getenv(\"HOME\")",
      "environment[\"HOME\"]",
    ] {
      XCTAssertFalse(source.contains(forbidden), "production must not trust \(forbidden)")
    }
  }

  func testFirstCreationIsStableCanonicalAndPrivate() throws {
    let home = try makePrivateHome()
    let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)

    let first = try installation.loadOrCreate()
    let second = try installation.loadOrCreate()
    XCTAssertEqual(first, second)
    XCTAssertEqual(first.rawValue.count, 36)
    XCTAssertEqual(first.rawValue, first.rawValue.lowercased())
    XCTAssertEqual(UUID(uuidString: first.rawValue)?.uuidString.lowercased(), first.rawValue)
    XCTAssertNotEqual(first.rawValue, "00000000-0000-0000-0000-000000000000")

    let bytes = try Data(contentsOf: installation.recordPath)
    XCTAssertEqual(bytes.count, 37)
    XCTAssertEqual(bytes, Data("\(first.rawValue)\n".utf8))

    let record = try lstatEntry(installation.recordPath)
    XCTAssertEqual(record.st_mode & mode_t(S_IFMT), mode_t(S_IFREG))
    XCTAssertEqual(record.st_mode & 0o7777, 0o600)
    XCTAssertEqual(record.st_uid, geteuid())
    XCTAssertEqual(record.st_nlink, 1)

    let privateDirectories = [
      installation.recordPath.deletingLastPathComponent(),
      installation.recordPath.deletingLastPathComponent().deletingLastPathComponent(),
      installation.recordPath.deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent(),
    ]
    for directory in privateDirectories {
      let entry = try lstatEntry(directory)
      XCTAssertEqual(entry.st_mode & mode_t(S_IFMT), mode_t(S_IFDIR), directory.path)
      XCTAssertEqual(entry.st_mode & 0o7777, 0o700, directory.path)
      XCTAssertEqual(entry.st_uid, geteuid(), directory.path)
    }
  }

  func testTwentyFourConcurrentCreatorsReadOneWinnerAndCleanTemps() throws {
    let home = try makePrivateHome()
    let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)
    let results = ConcurrentInstallationResults()

    DispatchQueue.concurrentPerform(iterations: 24) { _ in
      do {
        results.append(value: try installation.loadOrCreate().rawValue)
      } catch {
        results.append(error: String(describing: error))
      }
    }

    let snapshot = results.snapshot()
    XCTAssertTrue(snapshot.errors.isEmpty, snapshot.errors.joined(separator: "\n"))
    XCTAssertEqual(snapshot.values.count, 24)
    XCTAssertEqual(Set(snapshot.values).count, 1)
    XCTAssertEqual(
      try directoryEntryNames(at: installation.recordPath.deletingLastPathComponent()),
      [
        "installation-id.v1"
      ])
  }

  func testUnsafeRecordShapesAndContentsFailClosedWithoutRotation() throws {
    let cases = [
      "symlink", "hardlink", "fifo", "mode", "setuid", "setgid", "sticky", "corrupt",
      "uppercase", "nil", "too-long",
    ]

    for testCase in cases {
      let home = try makePrivateHome()
      let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)
      let original = try installation.loadOrCreate()
      let path = installation.recordPath
      var auxiliaryPath: URL?

      switch testCase {
      case "symlink":
        let target = path.deletingLastPathComponent().appendingPathComponent("target")
        try Data("\(original.rawValue)\n".utf8).write(to: target)
        try FileManager.default.removeItem(at: path)
        try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target)
        auxiliaryPath = target
      case "hardlink":
        let second = path.deletingLastPathComponent().appendingPathComponent("second-link")
        try requirePOSIX(link(path.path, second.path), operation: "link")
        auxiliaryPath = second
      case "fifo":
        try FileManager.default.removeItem(at: path)
        try requirePOSIX(mkfifo(path.path, 0o600), operation: "mkfifo")
      case "mode":
        try requirePOSIX(chmod(path.path, 0o644), operation: "chmod 0644")
      case "setuid":
        try requirePOSIX(chmod(path.path, 0o4600), operation: "chmod setuid")
      case "setgid":
        try requirePOSIX(chmod(path.path, 0o2600), operation: "chmod setgid")
      case "sticky":
        try requirePOSIX(chmod(path.path, 0o1600), operation: "chmod sticky")
      case "corrupt":
        try overwrite(path, with: Data("not-a-canonical-installation-id\n".utf8))
      case "uppercase":
        try overwrite(path, with: Data("\(canonicalUUID.uppercased())\n".utf8))
      case "nil":
        try overwrite(path, with: Data("00000000-0000-0000-0000-000000000000\n".utf8))
      case "too-long":
        try overwrite(path, with: Data("\(canonicalUUID)x\n".utf8))
      default:
        XCTFail("unhandled test case \(testCase)")
      }

      let before = try lstatEntry(path)
      let beforeBytes = try readableBytesIfRegular(path, entry: before)
      let auxiliaryBytes = try auxiliaryPath.map { try Data(contentsOf: $0) }

      XCTAssertThrowsError(try installation.loadOrCreate(), testCase)

      let after = try lstatEntry(path)
      XCTAssertEqual(before.st_dev, after.st_dev, testCase)
      XCTAssertEqual(before.st_ino, after.st_ino, testCase)
      XCTAssertEqual(before.st_mode, after.st_mode, testCase)
      XCTAssertEqual(before.st_nlink, after.st_nlink, testCase)
      XCTAssertEqual(try readableBytesIfRegular(path, entry: after), beforeBytes, testCase)
      if let auxiliaryPath, let auxiliaryBytes {
        XCTAssertEqual(try Data(contentsOf: auxiliaryPath), auxiliaryBytes, testCase)
      }
      XCTAssertFalse(
        try directoryEntryNames(at: path.deletingLastPathComponent()).contains {
          $0.hasPrefix(".installation-id.v1.") && $0.hasSuffix(".tmp")
        },
        testCase
      )
    }
  }

  func testPrivateDirectoryModeTamperFailsWithoutTouchingRecord() throws {
    for mode: mode_t in [0o755, 0o1700, 0o2700, 0o4700] {
      let home = try makePrivateHome()
      let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)
      _ = try installation.loadOrCreate()
      let path = installation.recordPath
      let parent = path.deletingLastPathComponent()
      let before = try lstatEntry(path)
      let beforeBytes = try Data(contentsOf: path)

      try requirePOSIX(chmod(parent.path, mode), operation: "tamper parent mode")
      XCTAssertThrowsError(try installation.loadOrCreate(), "mode \(String(mode, radix: 8))")

      let after = try lstatEntry(path)
      XCTAssertEqual(before.st_dev, after.st_dev)
      XCTAssertEqual(before.st_ino, after.st_ino)
      XCTAssertEqual(try Data(contentsOf: path), beforeBytes)
    }
  }

  func testIntermediateDirectorySymlinkFailsClosed() throws {
    let home = try makePrivateHome()
    let installation = LocalClientInstallation.injectedForTesting(homeDirectory: home)
    _ = try installation.loadOrCreate()
    let macOSApp = installation.recordPath.deletingLastPathComponent()
    let clients = macOSApp.deletingLastPathComponent()
    let relocated = clients.appendingPathComponent("relocated-macos-app", isDirectory: true)
    try FileManager.default.moveItem(at: macOSApp, to: relocated)
    try FileManager.default.createSymbolicLink(at: macOSApp, withDestinationURL: relocated)
    let relocatedRecord = relocated.appendingPathComponent("installation-id.v1")
    let before = try lstatEntry(relocatedRecord)
    let beforeBytes = try Data(contentsOf: relocatedRecord)

    XCTAssertThrowsError(try installation.loadOrCreate())

    let after = try lstatEntry(relocatedRecord)
    XCTAssertEqual(before.st_dev, after.st_dev)
    XCTAssertEqual(before.st_ino, after.st_ino)
    XCTAssertEqual(try Data(contentsOf: relocatedRecord), beforeBytes)
  }

  func testCurrentUIDOwnershipIsValidated() throws {
    let home = try makePrivateHome()
    let wrongUID = geteuid() == uid_t.max ? geteuid() - 1 : geteuid() + 1
    let installation = LocalClientInstallation.injectedForTesting(
      homeDirectory: home,
      expectedUID: wrongUID
    )

    XCTAssertThrowsError(try installation.loadOrCreate()) { error in
      XCTAssertEqual(
        (error as? LocalClientInstallationError)?.code,
        "daemon.client.installation_parent_unsafe"
      )
    }
  }

  private var productionSourceURL: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("Sources/AgentDeck/LocalClientInstallation.swift")
  }

  private func makePrivateHome() throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent(
        "agentdeck-installation-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    try requirePOSIX(chmod(url.path, 0o700), operation: "chmod test home")
    addTeardownBlock {
      try? FileManager.default.removeItem(at: url)
    }
    return url
  }

  private func lstatEntry(_ url: URL) throws -> stat {
    var entry = stat()
    let result = url.path.withCString { pointer in
      lstat(pointer, &entry)
    }
    try requirePOSIX(result, operation: "lstat \(url.path)")
    return entry
  }

  private func readableBytesIfRegular(_ url: URL, entry: stat) throws -> Data? {
    guard entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else { return nil }
    return try Data(contentsOf: url)
  }

  private func overwrite(_ url: URL, with data: Data) throws {
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.truncate(atOffset: 0)
    try handle.write(contentsOf: data)
    try handle.synchronize()
  }

  private func directoryEntryNames(at url: URL) throws -> [String] {
    try FileManager.default.contentsOfDirectory(atPath: url.path).sorted()
  }

  private func requirePOSIX(
    _ result: Int32,
    operation: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    guard result == 0 else {
      let message = String(cString: strerror(errno))
      XCTFail("\(operation): \(message)", file: file, line: line)
      throw POSIXTestError(operation: operation, status: errno)
    }
  }
}

private struct POSIXTestError: Error {
  let operation: String
  let status: Int32
}

private final class ConcurrentInstallationResults: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String] = []
  private var errors: [String] = []

  func append(value: String) {
    lock.lock()
    values.append(value)
    lock.unlock()
  }

  func append(error: String) {
    lock.lock()
    errors.append(error)
    lock.unlock()
  }

  func snapshot() -> (values: [String], errors: [String]) {
    lock.lock()
    defer { lock.unlock() }
    return (values, errors)
  }
}
