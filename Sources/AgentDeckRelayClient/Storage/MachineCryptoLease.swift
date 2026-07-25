import Darwin
import Foundation

/// 独立于 state-file 单次 CAS lock 的 machine transaction lease。
///
/// CounterGuard → sealed state → CounterGuard 的完整序列必须持有此 lease，避免两个
/// coordinator 在不同 durable stores 之间交错。阻塞式 `flock` 在专用 GCD work item
/// 中等待，不占用 Swift cooperative executor。
struct MachineCryptoLeaseManager: Sendable {
  private let rootURL: URL
  private let identity: CryptoStateIdentity

  init(rootURL: URL, identity: CryptoStateIdentity) throws {
    guard rootURL.isFileURL, rootURL.path.hasPrefix("/") else {
      throw CryptoStateStoreError.invalidIdentity
    }
    self.rootURL = rootURL.standardizedFileURL
    self.identity = identity
  }

  var identifier: String { transactionLockName() }

  func acquire() async throws -> MachineCryptoLease {
    try await withCheckedThrowingContinuation { continuation in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          continuation.resume(returning: try acquireBlocking())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  private func acquireBlocking() throws -> MachineCryptoLease {
    let root = try openRoot()
    defer { Darwin.close(root) }
    let remote = try openOrCreateDirectory(
      parent: root,
      name: "remote-state-v1",
      exactMode: 0o700
    )
    defer { Darwin.close(remote) }
    let installation = try openOrCreateDirectory(
      parent: remote,
      name: identity.installationID.uuidString.lowercased(),
      exactMode: 0o700
    )
    defer { Darwin.close(installation) }
    let transactions = try openOrCreateDirectory(
      parent: installation,
      name: "transactions",
      exactMode: 0o700
    )
    defer { Darwin.close(transactions) }

    let lockName = transactionLockName()
    var created = false
    var descriptor = lockName.withCString {
      Darwin.openat(transactions, $0, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
    }
    if descriptor < 0, errno == ENOENT {
      descriptor = lockName.withCString {
        Darwin.openat(
          transactions,
          $0,
          O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
          0o600
        )
      }
      if descriptor >= 0 {
        created = true
      } else if errno == EEXIST {
        descriptor = lockName.withCString {
          Darwin.openat(transactions, $0, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        }
      }
    }
    guard descriptor >= 0 else { throw unsafeOrIO(errno) }
    var transferred = false
    defer {
      if !transferred { Darwin.close(descriptor) }
    }

    if created {
      guard Darwin.fchmod(descriptor, 0o600) == 0,
        Darwin.fsync(descriptor) == 0,
        Darwin.fsync(transactions) == 0
      else {
        throw CryptoStateStoreError.io(code: errno)
      }
    }
    try verifyLockIdentity(descriptor, parent: transactions, name: lockName)
    while machineCryptoFlock(descriptor, LOCK_EX) != 0 {
      guard errno == EINTR else { throw CryptoStateStoreError.io(code: errno) }
    }
    do {
      try verifyLockIdentity(descriptor, parent: transactions, name: lockName)
    } catch {
      _ = machineCryptoFlock(descriptor, LOCK_UN)
      throw error
    }
    transferred = true
    return MachineCryptoLease(descriptor: descriptor, identifier: lockName)
  }

  private func openRoot() throws -> Int32 {
    var created = false
    var descriptor = rootURL.path.withCString {
      Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    if descriptor < 0, errno == ENOENT {
      let result = rootURL.path.withCString { Darwin.mkdir($0, 0o700) }
      if result == 0 {
        created = true
      } else if errno != EEXIST {
        throw CryptoStateStoreError.io(code: errno)
      }
      descriptor = rootURL.path.withCString {
        Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
      }
    }
    guard descriptor >= 0 else { throw unsafeOrIO(errno) }
    do {
      try auditDirectory(descriptor, exactMode: created ? 0o700 : nil)
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private func openOrCreateDirectory(
    parent: Int32,
    name: String,
    exactMode: mode_t
  ) throws -> Int32 {
    let result = name.withCString { Darwin.mkdirat(parent, $0, exactMode) }
    if result == 0 {
      guard Darwin.fsync(parent) == 0 else {
        throw CryptoStateStoreError.io(code: errno)
      }
    } else if errno != EEXIST {
      throw unsafeOrIO(errno)
    }
    let descriptor = name.withCString {
      Darwin.openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { throw unsafeOrIO(errno) }
    do {
      try auditDirectory(descriptor, exactMode: exactMode)
      var pathMetadata = stat()
      guard
        name.withCString({
          Darwin.fstatat(parent, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
        }) == 0
      else {
        throw unsafeOrIO(errno)
      }
      var descriptorMetadata = stat()
      guard Darwin.fstat(descriptor, &descriptorMetadata) == 0 else {
        throw CryptoStateStoreError.io(code: errno)
      }
      guard sameFile(descriptorMetadata, pathMetadata) else {
        throw CryptoStateStoreError.unsafeFile
      }
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private func auditDirectory(_ descriptor: Int32, exactMode: mode_t?) throws {
    var metadata = stat()
    guard Darwin.fstat(descriptor, &metadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    let mode = metadata.st_mode & 0o777
    guard metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_uid == geteuid(),
      metadata.st_nlink >= 1,
      exactMode.map({ mode == $0 }) ?? (mode & 0o022 == 0)
    else {
      throw CryptoStateStoreError.unsafeFile
    }
  }

  private func verifyLockIdentity(
    _ descriptor: Int32,
    parent: Int32,
    name: String
  ) throws {
    var descriptorMetadata = stat()
    guard Darwin.fstat(descriptor, &descriptorMetadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    var pathMetadata = stat()
    guard
      name.withCString({
        Darwin.fstatat(parent, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
      }) == 0
    else {
      throw unsafeOrIO(errno)
    }
    guard sameFile(descriptorMetadata, pathMetadata),
      descriptorMetadata.st_mode & S_IFMT == S_IFREG,
      descriptorMetadata.st_uid == geteuid(),
      descriptorMetadata.st_nlink == 1,
      descriptorMetadata.st_mode & 0o777 == 0o600
    else {
      throw CryptoStateStoreError.unsafeFile
    }
  }

  private func transactionLockName() -> String {
    var input = Data("AgentDeck/MachineCryptoTransactionLeaseV1\0".utf8)
    input.append(Data(identity.clientKind.rawValue.utf8))
    var uuid = identity.installationID.uuid
    Swift.withUnsafeBytes(of: &uuid) { input.append(contentsOf: $0) }
    input.append(Data(identity.machineID.utf8))
    input.append(identity.machineRootFingerprint)
    input.append(identity.machineRoute)
    return CanonicalCodec.sha256(input).map { String(format: "%02x", $0) }.joined()
      + ".lock"
  }

  private func unsafeOrIO(_ code: Int32) -> CryptoStateStoreError {
    switch code {
    case ELOOP, ENOTDIR:
      .unsafeFile
    default:
      .io(code: code)
    }
  }

  private func sameFile(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
  }
}

actor MachineCryptoLease {
  private var descriptor: Int32?
  private let identifier: String

  init(descriptor: Int32, identifier: String) {
    self.descriptor = descriptor
    self.identifier = identifier
  }

  func isActive(for expectedIdentifier: String) -> Bool {
    descriptor != nil && identifier == expectedIdentifier
  }

  func release() {
    guard let descriptor else { return }
    self.descriptor = nil
    _ = machineCryptoFlock(descriptor, LOCK_UN)
    Darwin.close(descriptor)
  }
}

@_silgen_name("flock")
private func machineCryptoFlock(_ descriptor: Int32, _ operation: Int32) -> Int32
