import Darwin
import Foundation

/// 本机 App 的安装级 identity。它只划分审计、配额与幂等 owner，并非认证 secret。
struct LocalClientInstallationID: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
  let rawValue: String

  init?(rawValue: String) {
    guard
      rawValue.utf8.count == 36,
      rawValue == rawValue.lowercased(),
      let uuid = UUID(uuidString: rawValue),
      uuid != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
      uuid.uuidString.lowercased() == rawValue
    else {
      return nil
    }
    self.rawValue = rawValue
  }

  var description: String { rawValue }

  fileprivate static func generate() -> Self {
    // UUID() 不会生成 nil UUID；仍通过同一个 canonical parser 收口格式不变量。
    Self(rawValue: UUID().uuidString.lowercased())!
  }
}

enum LocalClientInstallationError: Error, Sendable, CustomStringConvertible {
  case homeLookup(status: Int32)
  case homeUnavailable
  case unsafeDirectory(path: String, reason: String)
  case unsafeRecord(path: String, reason: String)
  case corruptRecord(path: String)
  case io(operation: String, path: String, status: Int32)

  var code: String {
    switch self {
    case .homeLookup, .homeUnavailable:
      "daemon.client.installation_home_failed"
    case .unsafeDirectory:
      "daemon.client.installation_parent_unsafe"
    case .unsafeRecord:
      "daemon.client.installation_record_unsafe"
    case .corruptRecord:
      "daemon.client.installation_record_corrupt"
    case .io:
      "daemon.client.installation_io_failed"
    }
  }

  var description: String {
    switch self {
    case .homeLookup(let status):
      "getpwuid_r failed with status \(status)"
    case .homeUnavailable:
      "the current OS account has no absolute home directory"
    case .unsafeDirectory(let path, let reason):
      "unsafe installation directory \(path): \(reason)"
    case .unsafeRecord(let path, let reason):
      "unsafe installation record \(path): \(reason)"
    case .corruptRecord(let path):
      "corrupt installation record \(path)"
    case .io(let operation, let path, let status):
      "\(operation) \(path) failed with errno \(status)"
    }
  }
}

/// App 自有 installation record。生产构造器只信任当前 EUID 的 passwd record。
struct LocalClientInstallation: Sendable {
  let homeDirectory: URL
  private let expectedUID: uid_t

  static func forOSAccount() throws -> Self {
    let account = try currentOSAccount()
    return Self(homeDirectory: account.home, expectedUID: account.uid)
  }

  /// 仅供 test/harness 显式注入隔离 home；生产 default 不接受环境覆盖。
  static func injectedForTesting(
    homeDirectory: URL,
    expectedUID: uid_t = geteuid()
  ) -> Self {
    Self(homeDirectory: homeDirectory, expectedUID: expectedUID)
  }

  var recordPath: URL {
    installationDirectoryComponents.reduce(homeDirectory) { path, component in
      path.appendingPathComponent(component.name, isDirectory: true)
    }
    .appendingPathComponent(installationRecordName, isDirectory: false)
  }

  var daemonSocketPath: URL {
    homeDirectory
      .appendingPathComponent("Library", isDirectory: true)
      .appendingPathComponent("Application Support", isDirectory: true)
      .appendingPathComponent("AgentDeck", isDirectory: true)
      .appendingPathComponent("agentdeckd.sock", isDirectory: false)
  }

  /// 读回或首次原子创建；任何已存在的损坏或不安全 entry 都直接拒绝，绝不轮换。
  func loadOrCreate() throws -> LocalClientInstallationID {
    guard homeDirectory.path.hasPrefix("/") else {
      throw LocalClientInstallationError.homeUnavailable
    }
    let directory = try openRecordDirectory()
    if let existing = try readRecord(directoryFD: directory.rawValue) {
      return existing
    }
    return try createRecord(directoryFD: directory.rawValue)
  }

  private func openRecordDirectory() throws -> InstallationFileDescriptor {
    let homePath = homeDirectory.path
    let homeFD = homePath.withCString {
      open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard homeFD >= 0 else {
      throw posixError("open installation home", path: homePath)
    }
    var directory = InstallationFileDescriptor(homeFD)
    try validateDirectory(directory.rawValue, path: homePath, privateMode: false)

    var path = homeDirectory
    for component in installationDirectoryComponents {
      path.appendPathComponent(component.name, isDirectory: true)
      directory = try openOrCreateDirectory(
        parentFD: directory.rawValue,
        component: component,
        path: path.path
      )
    }
    return directory
  }

  private func openOrCreateDirectory(
    parentFD: Int32,
    component: InstallationDirectoryComponent,
    path: String
  ) throws -> InstallationFileDescriptor {
    let created = component.name.withCString { mkdirat(parentFD, $0, 0o700) } == 0
    if !created {
      let status = errno
      guard status == EEXIST else {
        throw posixError("create installation directory", path: path, status: status)
      }
    } else {
      try synchronize(parentFD, operation: "sync installation directory parent", path: path)
    }

    let fd = component.name.withCString {
      openat(parentFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else {
      throw posixError("open installation directory component", path: path)
    }
    let directory = InstallationFileDescriptor(fd)
    try validateDirectory(fd, path: path, privateMode: component.privateMode)
    return directory
  }

  private func validateDirectory(_ fd: Int32, path: String, privateMode: Bool) throws {
    let entry = try fileStatus(fd, operation: "stat installation directory", path: path)
    guard entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
      throw LocalClientInstallationError.unsafeDirectory(
        path: path,
        reason: "entry is not a directory"
      )
    }
    guard entry.st_uid == expectedUID else {
      throw LocalClientInstallationError.unsafeDirectory(
        path: path,
        reason: "directory owner is not current EUID"
      )
    }
    guard !privateMode || entry.st_mode & 0o7777 == 0o700 else {
      throw LocalClientInstallationError.unsafeDirectory(
        path: path,
        reason: "directory mode is not exactly 0700"
      )
    }
  }

  private func readRecord(directoryFD: Int32) throws -> LocalClientInstallationID? {
    let path = recordPath.path
    let fd = installationRecordName.withCString {
      openat(directoryFD, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else {
      let status = errno
      if status == ENOENT { return nil }
      if status == ELOOP {
        throw LocalClientInstallationError.unsafeRecord(
          path: path,
          reason: "record is a symlink"
        )
      }
      throw posixError("open installation record", path: path, status: status)
    }
    let record = InstallationFileDescriptor(fd)
    try validateRecord(record.rawValue, path: path)
    return try parseRecord(try readBounded(record.rawValue, path: path), path: path)
  }

  private func validateRecord(_ fd: Int32, path: String) throws {
    let entry = try fileStatus(fd, operation: "stat installation record", path: path)
    let reason: String?
    if entry.st_mode & mode_t(S_IFMT) != mode_t(S_IFREG) {
      reason = "record is not a regular file"
    } else if entry.st_uid != expectedUID {
      reason = "record owner is not current EUID"
    } else if entry.st_mode & 0o7777 != 0o600 {
      reason = "record mode is not exactly 0600"
    } else if entry.st_nlink != 1 {
      reason = "record must have exactly one hard link"
    } else {
      reason = nil
    }
    if let reason {
      throw LocalClientInstallationError.unsafeRecord(path: path, reason: reason)
    }
  }

  private func parseRecord(_ bytes: [UInt8], path: String) throws -> LocalClientInstallationID {
    guard
      bytes.count == installationRecordByteCount,
      bytes.last == 0x0A,
      let value = String(bytes: bytes.dropLast(), encoding: .utf8),
      let identifier = LocalClientInstallationID(rawValue: value)
    else {
      throw LocalClientInstallationError.corruptRecord(path: path)
    }
    return identifier
  }

  private func createRecord(directoryFD: Int32) throws -> LocalClientInstallationID {
    let candidate = LocalClientInstallationID.generate()
    let content = Array("\(candidate.rawValue)\n".utf8)
    let tempName = ".installation-id.v1.\(UUID().uuidString.lowercased()).tmp"
    let tempPath = recordPath.deletingLastPathComponent()
      .appendingPathComponent(tempName, isDirectory: false).path
    let tempFD = tempName.withCString {
      openat(
        directoryFD,
        $0,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0o600
      )
    }
    guard tempFD >= 0 else {
      throw posixError("create installation record temp", path: tempPath)
    }
    let temp = InstallationFileDescriptor(tempFD)
    defer {
      tempName.withCString { _ = unlinkat(directoryFD, $0, 0) }
    }

    try validateRecord(temp.rawValue, path: tempPath)
    try writeAll(content, to: temp.rawValue, path: tempPath)
    try synchronize(temp.rawValue, operation: "sync installation record temp", path: tempPath)
    guard lseek(temp.rawValue, 0, SEEK_SET) == 0 else {
      throw posixError("rewind installation record temp", path: tempPath)
    }
    guard try readBounded(temp.rawValue, path: tempPath) == content else {
      throw LocalClientInstallationError.corruptRecord(path: tempPath)
    }
    try validateRecord(temp.rawValue, path: tempPath)

    let renameResult = tempName.withCString { source in
      installationRecordName.withCString { target in
        renameatx_np(
          directoryFD,
          source,
          directoryFD,
          target,
          UInt32(RENAME_EXCL)
        )
      }
    }
    if renameResult == 0 {
      try synchronize(
        directoryFD,
        operation: "sync installation record parent",
        path: recordPath.deletingLastPathComponent().path
      )
    } else {
      let status = errno
      guard status == EEXIST else {
        throw posixError("publish installation record", path: recordPath.path, status: status)
      }
      let unlinkResult = tempName.withCString { unlinkat(directoryFD, $0, 0) }
      if unlinkResult != 0, errno != ENOENT {
        throw posixError("remove installation race temp", path: tempPath)
      }
      try synchronize(
        directoryFD,
        operation: "sync installation race cleanup",
        path: recordPath.deletingLastPathComponent().path
      )
    }

    guard let winner = try readRecord(directoryFD: directoryFD) else {
      throw LocalClientInstallationError.corruptRecord(path: recordPath.path)
    }
    return winner
  }

  private func readBounded(_ fd: Int32, path: String) throws -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: installationRecordByteCount + 1)
    var offset = 0
    while offset < bytes.count {
      let count = bytes.withUnsafeMutableBytes { buffer in
        read(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
      }
      if count > 0 {
        offset += count
      } else if count == 0 {
        break
      } else if errno != EINTR {
        throw posixError("read installation record", path: path)
      }
    }
    return Array(bytes.prefix(offset))
  }

  private func writeAll(_ bytes: [UInt8], to fd: Int32, path: String) throws {
    var offset = 0
    while offset < bytes.count {
      let count = bytes.withUnsafeBytes { buffer in
        write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
      }
      if count > 0 {
        offset += count
      } else if count < 0, errno == EINTR {
        continue
      } else {
        throw posixError("write installation record temp", path: path)
      }
    }
  }

  private func fileStatus(_ fd: Int32, operation: String, path: String) throws -> stat {
    var entry = stat()
    guard fstat(fd, &entry) == 0 else {
      throw posixError(operation, path: path)
    }
    return entry
  }

  private func synchronize(_ fd: Int32, operation: String, path: String) throws {
    guard fsync(fd) == 0 else {
      throw posixError(operation, path: path)
    }
  }

  private func posixError(
    _ operation: String,
    path: String,
    status: Int32 = errno
  ) -> LocalClientInstallationError {
    .io(operation: operation, path: path, status: status)
  }
}

private struct InstallationDirectoryComponent: Sendable {
  let name: String
  let privateMode: Bool
}

private let installationDirectoryComponents = [
  InstallationDirectoryComponent(name: "Library", privateMode: false),
  InstallationDirectoryComponent(name: "Application Support", privateMode: false),
  InstallationDirectoryComponent(name: "AgentDeck", privateMode: true),
  InstallationDirectoryComponent(name: "clients", privateMode: true),
  InstallationDirectoryComponent(name: "macos-app", privateMode: true),
]
private let installationRecordName = "installation-id.v1"
private let installationRecordByteCount = 37

private final class InstallationFileDescriptor {
  let rawValue: Int32

  init(_ rawValue: Int32) {
    self.rawValue = rawValue
  }

  deinit {
    _ = close(rawValue)
  }
}

private func currentOSAccount() throws -> (home: URL, uid: uid_t) {
  let uid = geteuid()
  let suggested = sysconf(_SC_GETPW_R_SIZE_MAX)
  var capacity = suggested > 0 ? Int(suggested) : 16 * 1024
  capacity = min(max(capacity, 1_024), 1_024 * 1_024)

  while true {
    var account = passwd()
    var result: UnsafeMutablePointer<passwd>?
    var buffer = [CChar](repeating: 0, count: capacity)
    let status = buffer.withUnsafeMutableBufferPointer { storage in
      getpwuid_r(uid, &account, storage.baseAddress, storage.count, &result)
    }
    if status == ERANGE, capacity < 1_024 * 1_024 {
      capacity = min(capacity * 2, 1_024 * 1_024)
      continue
    }
    guard status == 0 else {
      throw LocalClientInstallationError.homeLookup(status: status)
    }
    guard
      result != nil,
      let directory = account.pw_dir,
      let path = String(validatingCString: directory),
      path.hasPrefix("/")
    else {
      throw LocalClientInstallationError.homeUnavailable
    }
    return (URL(fileURLWithPath: path, isDirectory: true), uid)
  }
}
