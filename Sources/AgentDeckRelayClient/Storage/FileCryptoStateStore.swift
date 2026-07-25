import CryptoKit
import Darwin
import Foundation
import Security

/// `CryptoStateFileV1` 的 identity-bound、ChaChaPoly sealed durable store。
public actor FileCryptoStateStore: CryptoStateStore {
  public static let fileProtectionPolicy: URLFileProtection = .complete

  private static let formatVersion: UInt8 = 1
  private static let algorithmChaChaPoly: UInt8 = 1
  private static let headerLength = 24
  private static let tagLength = 16
  private static let aadDomain = Data("AgentDeck/CryptoStateFileV1\0".utf8)
  private static let aadPurpose = Data("crypto-state.v1".utf8)

  public nonisolated let stateURL: URL

  private nonisolated let rootURL: URL
  private nonisolated let lockURL: URL
  private nonisolated let identity: CryptoStateIdentity
  private nonisolated let storageKey: DeviceStorageKEK
  private nonisolated let ioQueue: DispatchQueue
  private nonisolated let testHooks: FileCryptoStateStoreTestHooks

  public init(
    rootURL: URL,
    identity: CryptoStateIdentity,
    storageKey: DeviceStorageKEK
  ) throws {
    guard rootURL.isFileURL, rootURL.path.hasPrefix("/") else {
      throw CryptoStateStoreError.invalidIdentity
    }
    let standardizedRoot = rootURL.standardizedFileURL
    self.rootURL = standardizedRoot
    self.identity = identity
    self.storageKey = storageKey
    stateURL = Self.stateURL(rootURL: standardizedRoot, identity: identity)
    lockURL = Self.lockURL(rootURL: standardizedRoot, identity: identity)
    ioQueue = DispatchQueue(
      label: "com.agentdeck.crypto-state-file.\(stateURL.lastPathComponent)"
    )
    testHooks = .none
  }

  init(
    rootURL: URL,
    identity: CryptoStateIdentity,
    storageKey: DeviceStorageKEK,
    testHooks: FileCryptoStateStoreTestHooks
  ) throws {
    guard rootURL.isFileURL, rootURL.path.hasPrefix("/") else {
      throw CryptoStateStoreError.invalidIdentity
    }
    let standardizedRoot = rootURL.standardizedFileURL
    self.rootURL = standardizedRoot
    self.identity = identity
    self.storageKey = storageKey
    stateURL = Self.stateURL(rootURL: standardizedRoot, identity: identity)
    lockURL = Self.lockURL(rootURL: standardizedRoot, identity: identity)
    ioQueue = DispatchQueue(
      label: "com.agentdeck.crypto-state-file.\(stateURL.lastPathComponent)"
    )
    self.testHooks = testHooks
  }

  public nonisolated func load() async throws -> CryptoStateSnapshot? {
    try await performFileIO {
      let directories = try self.prepareDirectories()
      return try self.withExclusiveLock(directories: directories) {
        try self.cleanupOrphanedTemporaryFiles(directories: directories)
        return try self.loadUnlocked(directories: directories)?.snapshot
      }
    }
  }

  public nonisolated func commitInitial(
    _ snapshot: CryptoStateSnapshot
  ) async throws -> CryptoStateCommit {
    try validateSize(snapshot)
    return try await performFileIO {
      let directories = try self.prepareDirectories()
      return try self.withExclusiveLock(directories: directories) {
        try self.cleanupOrphanedTemporaryFiles(directories: directories)
        if let existing = try self.loadUnlocked(directories: directories) {
          guard existing.snapshot == snapshot else {
            throw CryptoStateStoreError.immutableConflict
          }
          return .alreadyPresent
        }

        let sealed = try self.seal(snapshot)
        let temporary = try self.writeDurableTemporary(
          sealed,
          directories: directories
        )
        var published = false
        defer {
          if !published {
            try? self.removeTemporary(temporary, directories: directories)
          }
        }

        try self.verifyTemporary(temporary, directories: directories)
        let result = temporary.name.withCString { source in
          self.stateURL.lastPathComponent.withCString { destination in
            Darwin.renameatx_np(
              directories.devicesDescriptor,
              source,
              directories.devicesDescriptor,
              destination,
              UInt32(RENAME_EXCL)
            )
          }
        }
        if result == 0 {
          published = true
          try self.verifyPublishedTemporary(temporary, directories: directories)
          try self.syncDirectory(
            directories.devicesDescriptor,
            url: directories.devicesURL
          )
          guard
            try self.loadUnlocked(directories: directories)?.snapshot == snapshot
          else {
            throw CryptoStateStoreError.persistenceReadbackFailed
          }
          return .created
        }

        let code = errno
        guard code == EEXIST else {
          throw CryptoStateStoreError.io(code: code)
        }
        try self.removeTemporary(temporary, directories: directories)
        published = true
        try self.syncDirectory(
          directories.devicesDescriptor,
          url: directories.devicesURL
        )
        guard let raced = try self.loadUnlocked(directories: directories) else {
          throw CryptoStateStoreError.persistenceReadbackFailed
        }
        guard raced.snapshot == snapshot else {
          throw CryptoStateStoreError.immutableConflict
        }
        return .alreadyPresent
      }
    }
  }

  public nonisolated func compareAndReplaceExact(
    expected: CryptoStateSnapshot,
    replacement: CryptoStateSnapshot
  ) async throws {
    try validateSize(expected)
    try validateSize(replacement)
    try await performFileIO {
      let directories = try self.prepareDirectories()
      try self.withExclusiveLock(directories: directories) {
        try self.cleanupOrphanedTemporaryFiles(directories: directories)
        guard let current = try self.loadUnlocked(directories: directories) else {
          throw CryptoStateStoreError.missingState
        }
        guard current.snapshot == expected else {
          throw CryptoStateStoreError.compareAndReplaceMismatch
        }

        let sealed = try self.seal(replacement)
        let temporary = try self.writeDurableTemporary(
          sealed,
          directories: directories
        )
        var published = false
        defer {
          if !published {
            try? self.removeTemporary(temporary, directories: directories)
          }
        }

        try self.verifyTemporary(temporary, directories: directories)
        try self.verifyCurrentStateIdentity(
          current.fileIdentity,
          directories: directories
        )
        let result = temporary.name.withCString { source in
          self.stateURL.lastPathComponent.withCString { destination in
            Darwin.renameat(
              directories.devicesDescriptor,
              source,
              directories.devicesDescriptor,
              destination
            )
          }
        }
        guard result == 0 else {
          throw CryptoStateStoreError.io(code: errno)
        }
        published = true
        try self.verifyPublishedTemporary(temporary, directories: directories)
        try self.syncDirectory(
          directories.devicesDescriptor,
          url: directories.devicesURL
        )
        guard
          try self.loadUnlocked(directories: directories)?.snapshot == replacement
        else {
          throw CryptoStateStoreError.persistenceReadbackFailed
        }
      }
    }
  }

  public nonisolated func deleteExact(expected: CryptoStateSnapshot) async throws {
    try validateSize(expected)
    try await performFileIO {
      let directories = try self.prepareDirectories()
      try self.withExclusiveLock(directories: directories) {
        try self.cleanupOrphanedTemporaryFiles(directories: directories)
        guard let current = try self.loadUnlocked(directories: directories) else {
          return
        }
        guard current.snapshot == expected else {
          throw CryptoStateStoreError.compareAndReplaceMismatch
        }
        try self.verifyCurrentStateIdentity(
          current.fileIdentity,
          directories: directories
        )
        let result = self.stateURL.lastPathComponent.withCString {
          Darwin.unlinkat(directories.devicesDescriptor, $0, 0)
        }
        guard result == 0 else {
          throw CryptoStateStoreError.io(code: errno)
        }
        try self.syncDirectory(
          directories.devicesDescriptor,
          url: directories.devicesURL
        )
        guard try self.loadUnlocked(directories: directories) == nil else {
          throw CryptoStateStoreError.persistenceReadbackFailed
        }
      }
    }
  }

  static func stateURL(rootURL: URL, identity: CryptoStateIdentity) -> URL {
    let root = rootURL.standardizedFileURL
    let installation = identity.installationID.uuidString.lowercased()
    let component = stateFileComponent(identity: identity)
    return
      root
      .appendingPathComponent("remote-state-v1", isDirectory: true)
      .appendingPathComponent(installation, isDirectory: true)
      .appendingPathComponent("devices", isDirectory: true)
      .appendingPathComponent(component, isDirectory: false)
  }

  private static func lockURL(rootURL: URL, identity: CryptoStateIdentity) -> URL {
    let root = rootURL.standardizedFileURL
    let installation = identity.installationID.uuidString.lowercased()
    let component = stateFileComponent(identity: identity) + ".lock"
    return
      root
      .appendingPathComponent("remote-state-v1", isDirectory: true)
      .appendingPathComponent(installation, isDirectory: true)
      .appendingPathComponent("locks", isDirectory: true)
      .appendingPathComponent(component, isDirectory: false)
  }

  private static func stateFileComponent(identity: CryptoStateIdentity) -> String {
    let fields = [
      Data("AgentDeck/CryptoStatePathV1\0".utf8),
      Data(identity.clientKind.rawValue.utf8),
      uuidBytes(identity.installationID),
      Data(identity.machineID.utf8),
      identity.machineRootFingerprint,
      identity.machineRoute,
    ]
    return CanonicalCodec.sha256(lengthPrefixed(fields)).hexString + ".state"
  }

  private nonisolated func loadUnlocked(
    directories: CryptoStateDirectories
  ) throws -> LoadedCryptoState? {
    guard let sealedFile = try readBoundedStateFile(directories: directories) else {
      return nil
    }
    return LoadedCryptoState(
      snapshot: try open(sealedFile.data),
      fileIdentity: sealedFile.fileIdentity
    )
  }

  private nonisolated func seal(_ snapshot: CryptoStateSnapshot) throws -> Data {
    try validateSize(snapshot)
    var nonceBytes = Data(repeating: 0, count: 12)
    let randomStatus = nonceBytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard randomStatus == errSecSuccess else {
      throw CryptoStateStoreError.entropyUnavailable
    }

    var header = Data("ADCS".utf8)
    header.append(Self.formatVersion)
    header.append(Self.algorithmChaChaPoly)
    header.append(contentsOf: [0, 0])
    header.appendUInt32BigEndian(UInt32(snapshot.canonicalBytes.count))
    header.append(nonceBytes)

    do {
      let box = try ChaChaPoly.seal(
        snapshot.canonicalBytes,
        using: SymmetricKey(data: storageKey.rawRepresentation),
        nonce: ChaChaPoly.Nonce(data: nonceBytes),
        authenticating: aad(header: header)
      )
      var sealed = header
      sealed.append(box.ciphertext)
      sealed.append(box.tag)
      return sealed
    } catch let error as CryptoStateStoreError {
      throw error
    } catch {
      throw CryptoStateStoreError.authenticationFailed
    }
  }

  private nonisolated func open(_ sealed: Data) throws -> CryptoStateSnapshot {
    guard sealed.count >= Self.headerLength + Self.tagLength,
      sealed.prefix(4) == Data("ADCS".utf8),
      sealed[4] == Self.formatVersion,
      sealed[5] == Self.algorithmChaChaPoly,
      sealed[6] == 0,
      sealed[7] == 0
    else {
      throw CryptoStateStoreError.invalidFormat
    }
    let declaredLength = Int(sealed.readUInt32BigEndian(at: 8))
    guard declaredLength <= CryptoStateSnapshot.maximumDataBytes,
      sealed.count == Self.headerLength + declaredLength + Self.tagLength
    else {
      throw declaredLength > CryptoStateSnapshot.maximumDataBytes
        ? CryptoStateStoreError.inputTooLarge
        : CryptoStateStoreError.invalidFormat
    }

    let header = sealed.subdata(in: 0..<Self.headerLength)
    let nonceBytes = header.subdata(in: 12..<24)
    let ciphertextEnd = sealed.count - Self.tagLength
    do {
      let box = try ChaChaPoly.SealedBox(
        nonce: ChaChaPoly.Nonce(data: nonceBytes),
        ciphertext: sealed.subdata(in: Self.headerLength..<ciphertextEnd),
        tag: sealed.suffix(Self.tagLength)
      )
      let plaintext = try ChaChaPoly.open(
        box,
        using: SymmetricKey(data: storageKey.rawRepresentation),
        authenticating: aad(header: header)
      )
      guard plaintext.count == declaredLength else {
        throw CryptoStateStoreError.invalidFormat
      }
      let snapshot = try CryptoStateSnapshot(authenticatedCanonicalBytes: plaintext)
      try validateSnapshotBinding(snapshot)
      return snapshot
    } catch let error as CryptoStateStoreError {
      throw error
    } catch {
      throw CryptoStateStoreError.authenticationFailed
    }
  }

  private nonisolated func aad(header: Data) -> Data {
    Self.lengthPrefixed([
      Self.aadDomain,
      Data(identity.clientKind.rawValue.utf8),
      Self.uuidBytes(identity.installationID),
      Data(identity.machineID.utf8),
      identity.machineRootFingerprint,
      identity.machineRoute,
      Self.aadPurpose,
      header,
    ])
  }

  private static func lengthPrefixed(_ fields: [Data]) -> Data {
    var output = Data()
    for field in fields {
      output.appendUInt32BigEndian(UInt32(field.count))
      output.append(field)
    }
    return output
  }

  private static func uuidBytes(_ value: UUID) -> Data {
    var bytes = value.uuid
    return Swift.withUnsafeBytes(of: &bytes) { Data($0) }
  }

  private nonisolated func validateSize(_ snapshot: CryptoStateSnapshot) throws {
    guard snapshot.canonicalBytes.count <= CryptoStateSnapshot.maximumDataBytes else {
      throw CryptoStateStoreError.inputTooLarge
    }
    try validateSnapshotBinding(snapshot)
  }

  private nonisolated func validateSnapshotBinding(
    _ snapshot: CryptoStateSnapshot
  ) throws {
    guard
      snapshot.state.trustScope.machineRootFingerprint == identity.machineRootFingerprint,
      snapshot.state.trustScope.machineRoute == identity.machineRoute
    else {
      throw CryptoStateStoreError.invalidIdentity
    }
  }

  /// 每次事务都保留 root 及私有子目录的 fd，后续 state/lock/temp 操作走 `*at`
  /// API。它只缩小祖先 TOCTOU 窗口；同 UID 在线攻击仍是设计明确接受的
  /// residual risk，path/fd 双检用于 fail closed，不宣称消除该竞态。
  private nonisolated func prepareDirectories() throws -> CryptoStateDirectories {
    let rootDescriptor = try openRootDirectory()
    var descriptors = [rootDescriptor]
    var transferred = false
    defer {
      if !transferred {
        for descriptor in descriptors.reversed() {
          Darwin.close(descriptor)
        }
      }
    }

    let remoteURL = rootURL.appendingPathComponent(
      "remote-state-v1",
      isDirectory: true
    )
    let remoteDescriptor = try openOrCreatePrivateDirectory(
      parentDescriptor: rootDescriptor,
      name: "remote-state-v1",
      url: remoteURL,
      parentURL: rootURL
    )
    descriptors.append(remoteDescriptor)

    let installationName = identity.installationID.uuidString.lowercased()
    let installationURL = remoteURL.appendingPathComponent(
      installationName,
      isDirectory: true
    )
    let installationDescriptor = try openOrCreatePrivateDirectory(
      parentDescriptor: remoteDescriptor,
      name: installationName,
      url: installationURL,
      parentURL: remoteURL
    )
    descriptors.append(installationDescriptor)

    let devicesURL = installationURL.appendingPathComponent(
      "devices",
      isDirectory: true
    )
    let devicesDescriptor = try openOrCreatePrivateDirectory(
      parentDescriptor: installationDescriptor,
      name: "devices",
      url: devicesURL,
      parentURL: installationURL
    )
    descriptors.append(devicesDescriptor)

    let locksURL = installationURL.appendingPathComponent(
      "locks",
      isDirectory: true
    )
    let locksDescriptor = try openOrCreatePrivateDirectory(
      parentDescriptor: installationDescriptor,
      name: "locks",
      url: locksURL,
      parentURL: installationURL
    )
    descriptors.append(locksDescriptor)

    transferred = true
    return CryptoStateDirectories(
      rootDescriptor: rootDescriptor,
      remoteDescriptor: remoteDescriptor,
      installationDescriptor: installationDescriptor,
      devicesDescriptor: devicesDescriptor,
      locksDescriptor: locksDescriptor,
      devicesURL: devicesURL,
      locksURL: locksURL
    )
  }

  private nonisolated func openRootDirectory() throws -> Int32 {
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
      try auditDirectoryDescriptor(
        descriptor,
        pathURL: rootURL,
        requirePrivate: created
      )
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private nonisolated func openOrCreatePrivateDirectory(
    parentDescriptor: Int32,
    name: String,
    url: URL,
    parentURL: URL
  ) throws -> Int32 {
    let createResult = name.withCString {
      Darwin.mkdirat(parentDescriptor, $0, 0o700)
    }
    if createResult == 0 {
      try syncDirectory(parentDescriptor, url: parentURL)
    } else if errno != EEXIST {
      throw unsafeOrIO(errno)
    }

    let descriptor = name.withCString {
      Darwin.openat(
        parentDescriptor,
        $0,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
      )
    }
    guard descriptor >= 0 else { throw unsafeOrIO(errno) }
    do {
      try auditDirectoryDescriptor(descriptor, pathURL: nil, requirePrivate: true)
      try verifyDescriptorIdentity(
        descriptor,
        parentDescriptor: parentDescriptor,
        name: name,
        pathURL: url,
        expected: .directory(privateMode: true)
      )
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private nonisolated func auditDirectoryDescriptor(
    _ descriptor: Int32,
    pathURL: URL?,
    requirePrivate: Bool
  ) throws {
    var metadata = stat()
    guard Darwin.fstat(descriptor, &metadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    let permissions = metadata.st_mode & 0o777
    guard metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_uid == geteuid(),
      metadata.st_nlink >= 1,
      requirePrivate ? permissions == 0o700 : permissions & 0o022 == 0
    else {
      throw CryptoStateStoreError.unsafeFile
    }
    if let pathURL {
      var pathMetadata = stat()
      guard pathURL.path.withCString({ Darwin.lstat($0, &pathMetadata) }) == 0 else {
        throw unsafeOrIO(errno)
      }
      guard FileIdentity(metadata) == FileIdentity(pathMetadata) else {
        throw CryptoStateStoreError.unsafeFile
      }
    }
  }

  private nonisolated func withExclusiveLock<Value: Sendable>(
    directories: CryptoStateDirectories,
    _ body: () throws -> Value
  ) throws -> Value {
    let lockName = lockURL.lastPathComponent
    var created = false
    var descriptor = lockName.withCString {
      Darwin.openat(
        directories.locksDescriptor,
        $0,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW
      )
    }
    if descriptor < 0, errno == ENOENT {
      descriptor = lockName.withCString {
        Darwin.openat(
          directories.locksDescriptor,
          $0,
          O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
          0o600
        )
      }
      if descriptor >= 0 {
        created = true
      } else if errno == EEXIST {
        descriptor = lockName.withCString {
          Darwin.openat(
            directories.locksDescriptor,
            $0,
            O_RDWR | O_CLOEXEC | O_NOFOLLOW
          )
        }
      }
    }
    guard descriptor >= 0 else { throw unsafeOrIO(errno) }
    defer { Darwin.close(descriptor) }

    if created {
      guard Darwin.fchmod(descriptor, 0o600) == 0,
        Darwin.fsync(descriptor) == 0
      else {
        throw CryptoStateStoreError.io(code: errno)
      }
      try syncDirectory(
        directories.locksDescriptor,
        url: directories.locksURL
      )
    }

    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.locksDescriptor,
      name: lockName,
      pathURL: lockURL,
      expected: .regularFile(mode: 0o600)
    )
    while agentDeckFlock(descriptor, LOCK_EX) != 0 {
      guard errno == EINTR else { throw CryptoStateStoreError.io(code: errno) }
    }
    defer { _ = agentDeckFlock(descriptor, LOCK_UN) }

    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.locksDescriptor,
      name: lockName,
      pathURL: lockURL,
      expected: .regularFile(mode: 0o600)
    )
    return try body()
  }

  private nonisolated func cleanupOrphanedTemporaryFiles(
    directories: CryptoStateDirectories
  ) throws {
    let duplicate = Darwin.dup(directories.devicesDescriptor)
    guard duplicate >= 0 else { throw CryptoStateStoreError.io(code: errno) }
    guard let stream = Darwin.fdopendir(duplicate) else {
      Darwin.close(duplicate)
      throw CryptoStateStoreError.io(code: errno)
    }
    defer { Darwin.closedir(stream) }

    let prefix = ".\(stateURL.lastPathComponent)."
    let suffix = ".tmp"
    var removed = false
    while true {
      errno = 0
      guard let entry = Darwin.readdir(stream) else {
        if errno != 0 { throw CryptoStateStoreError.io(code: errno) }
        break
      }
      let name = withUnsafeBytes(of: entry.pointee.d_name) { bytes in
        String(cString: bytes.baseAddress!.assumingMemoryBound(to: CChar.self))
      }
      guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { continue }

      var metadata = stat()
      let status = name.withCString {
        Darwin.fstatat(
          directories.devicesDescriptor,
          $0,
          &metadata,
          AT_SYMLINK_NOFOLLOW
        )
      }
      if status != 0, errno == ENOENT { continue }
      guard status == 0 else { throw CryptoStateStoreError.io(code: errno) }
      try auditRegularFile(metadata, exactMode: 0o600)
      guard
        name.withCString({
          Darwin.unlinkat(directories.devicesDescriptor, $0, 0)
        }) == 0
      else {
        throw CryptoStateStoreError.io(code: errno)
      }
      removed = true
    }
    if removed {
      try syncDirectory(
        directories.devicesDescriptor,
        url: directories.devicesURL
      )
    }
  }

  static func entryExistsNoFollow(at url: URL) throws -> Bool {
    var metadata = stat()
    if url.path.withCString({ Darwin.lstat($0, &metadata) }) == 0 { return true }
    if errno == ENOENT { return false }
    throw CryptoStateStoreError.io(code: errno)
  }

  private nonisolated func writeDurableTemporary(
    _ data: Data,
    directories: CryptoStateDirectories
  ) throws -> CryptoStateTemporaryFile {
    let name = ".\(stateURL.lastPathComponent).\(UUID().uuidString).tmp"
    let temporaryURL = directories.devicesURL.appendingPathComponent(
      name,
      isDirectory: false
    )
    let descriptor = name.withCString {
      Darwin.openat(
        directories.devicesDescriptor,
        $0,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0o600
      )
    }
    guard descriptor >= 0 else {
      throw unsafeOrIO(errno)
    }
    let temporary = CryptoStateTemporaryFile(
      name: name,
      url: temporaryURL,
      descriptor: descriptor
    )
    var succeeded = false
    defer {
      if !succeeded {
        try? removeTemporary(temporary, directories: directories)
      }
    }

    try writeAll(data, to: descriptor)
    guard Darwin.fchmod(descriptor, 0o600) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    try applyAndReadBackProtection(to: temporary, directories: directories)
    guard Darwin.fsync(descriptor) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    try verifyTemporary(temporary, directories: directories)
    succeeded = true
    return temporary
  }

  private nonisolated func applyAndReadBackProtection(
    to temporary: CryptoStateTemporaryFile,
    directories: CryptoStateDirectories
  ) throws {
    do {
      try verifyTemporary(temporary, directories: directories)
      var mutableURL = temporary.url
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try mutableURL.setResourceValues(values)
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete],
        ofItemAtPath: temporary.url.path
      )
      testHooks.protectionDidApply(temporary.url, .complete)

      try verifyTemporary(temporary, directories: directories)
      try verifyProtectionAttributes(at: temporary.url)
      try verifyTemporary(temporary, directories: directories)
    } catch let error as CryptoStateStoreError {
      throw error
    } catch {
      throw mapIO(error)
    }
  }

  private nonisolated var resourceKeys: Set<URLResourceKey> {
    [.isExcludedFromBackupKey, .fileProtectionKey]
  }

  private nonisolated func readBoundedStateFile(
    directories: CryptoStateDirectories
  ) throws -> SealedCryptoStateFile? {
    let name = stateURL.lastPathComponent
    let descriptor = name.withCString {
      Darwin.openat(
        directories.devicesDescriptor,
        $0,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
      )
    }
    guard descriptor >= 0 else {
      if errno == ENOENT { return nil }
      throw unsafeOrIO(errno)
    }
    defer { Darwin.close(descriptor) }

    var metadata = stat()
    guard Darwin.fstat(descriptor, &metadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditRegularFile(metadata, exactMode: 0o600)
    let fileIdentity = FileIdentity(metadata)
    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: name,
      pathURL: stateURL,
      expected: .regularFile(mode: 0o600)
    )

    testHooks.stateFileDidOpen(stateURL)
    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: name,
      pathURL: stateURL,
      expected: .regularFile(mode: 0o600)
    )
    try verifyProtectionAttributes(at: stateURL)
    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: name,
      pathURL: stateURL,
      expected: .regularFile(mode: 0o600)
    )

    guard metadata.st_size >= 0 else {
      throw CryptoStateStoreError.invalidFormat
    }
    let size = Int(metadata.st_size)
    let maximumFileBytes =
      Self.headerLength
      + CryptoStateSnapshot.maximumDataBytes
      + Self.tagLength
    guard size <= maximumFileBytes else {
      throw CryptoStateStoreError.inputTooLarge
    }
    guard size >= Self.headerLength + Self.tagLength else {
      throw CryptoStateStoreError.invalidFormat
    }
    let data = try readExactly(count: size, from: descriptor)
    var readbackMetadata = stat()
    guard Darwin.fstat(descriptor, &readbackMetadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    guard FileIdentity(readbackMetadata) == fileIdentity,
      readbackMetadata.st_size == metadata.st_size
    else {
      throw CryptoStateStoreError.unsafeFile
    }
    try verifyDescriptorIdentity(
      descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: name,
      pathURL: stateURL,
      expected: .regularFile(mode: 0o600)
    )
    return SealedCryptoStateFile(data: data, fileIdentity: fileIdentity)
  }

  private nonisolated func verifyProtectionAttributes(at url: URL) throws {
    let readback: URLResourceValues
    do {
      readback = try url.resourceValues(forKeys: resourceKeys)
    } catch {
      throw mapIO(error)
    }
    guard readback.isExcludedFromBackup == true else {
      throw CryptoStateStoreError.backupExclusionMissing
    }
    #if !targetEnvironment(simulator)
      guard readback.fileProtection == Self.fileProtectionPolicy else {
        throw CryptoStateStoreError.fileProtectionMissing
      }
    #endif
  }

  private nonisolated func verifyDescriptorIdentity(
    _ descriptor: Int32,
    parentDescriptor: Int32,
    name: String,
    pathURL: URL,
    expected: FileSystemEntryExpectation
  ) throws {
    var descriptorMetadata = stat()
    guard Darwin.fstat(descriptor, &descriptorMetadata) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditEntry(descriptorMetadata, expected: expected)

    var directoryMetadata = stat()
    let directoryStatus = name.withCString {
      Darwin.fstatat(
        parentDescriptor,
        $0,
        &directoryMetadata,
        AT_SYMLINK_NOFOLLOW
      )
    }
    guard directoryStatus == 0 else {
      if errno == ENOENT { throw CryptoStateStoreError.unsafeFile }
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditEntry(directoryMetadata, expected: expected)

    var pathMetadata = stat()
    guard pathURL.path.withCString({ Darwin.lstat($0, &pathMetadata) }) == 0 else {
      if errno == ENOENT { throw CryptoStateStoreError.unsafeFile }
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditEntry(pathMetadata, expected: expected)

    let descriptorIdentity = FileIdentity(descriptorMetadata)
    guard descriptorIdentity == FileIdentity(directoryMetadata),
      descriptorIdentity == FileIdentity(pathMetadata)
    else {
      throw CryptoStateStoreError.unsafeFile
    }
  }

  private nonisolated func verifyCurrentStateIdentity(
    _ expectedIdentity: FileIdentity,
    directories: CryptoStateDirectories
  ) throws {
    let name = stateURL.lastPathComponent
    var directoryMetadata = stat()
    let status = name.withCString {
      Darwin.fstatat(
        directories.devicesDescriptor,
        $0,
        &directoryMetadata,
        AT_SYMLINK_NOFOLLOW
      )
    }
    guard status == 0 else {
      if errno == ENOENT { throw CryptoStateStoreError.compareAndReplaceMismatch }
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditRegularFile(directoryMetadata, exactMode: 0o600)

    var pathMetadata = stat()
    guard stateURL.path.withCString({ Darwin.lstat($0, &pathMetadata) }) == 0 else {
      if errno == ENOENT { throw CryptoStateStoreError.compareAndReplaceMismatch }
      throw CryptoStateStoreError.io(code: errno)
    }
    try auditRegularFile(pathMetadata, exactMode: 0o600)
    guard FileIdentity(directoryMetadata) == expectedIdentity,
      FileIdentity(pathMetadata) == expectedIdentity
    else {
      throw CryptoStateStoreError.compareAndReplaceMismatch
    }
  }

  private nonisolated func verifyTemporary(
    _ temporary: CryptoStateTemporaryFile,
    directories: CryptoStateDirectories
  ) throws {
    try verifyDescriptorIdentity(
      temporary.descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: temporary.name,
      pathURL: temporary.url,
      expected: .regularFile(mode: 0o600)
    )
  }

  private nonisolated func verifyPublishedTemporary(
    _ temporary: CryptoStateTemporaryFile,
    directories: CryptoStateDirectories
  ) throws {
    try verifyDescriptorIdentity(
      temporary.descriptor,
      parentDescriptor: directories.devicesDescriptor,
      name: stateURL.lastPathComponent,
      pathURL: stateURL,
      expected: .regularFile(mode: 0o600)
    )
  }

  private nonisolated func removeTemporary(
    _ temporary: CryptoStateTemporaryFile,
    directories: CryptoStateDirectories
  ) throws {
    let status = temporary.name.withCString {
      Darwin.unlinkat(directories.devicesDescriptor, $0, 0)
    }
    guard status == 0 || errno == ENOENT else {
      throw CryptoStateStoreError.io(code: errno)
    }
  }

  private nonisolated func auditEntry(
    _ metadata: stat,
    expected: FileSystemEntryExpectation
  ) throws {
    switch expected {
    case .directory(let privateMode):
      let permissions = metadata.st_mode & 0o777
      guard metadata.st_mode & S_IFMT == S_IFDIR,
        metadata.st_uid == geteuid(),
        metadata.st_nlink >= 1,
        privateMode ? permissions == 0o700 : permissions & 0o022 == 0
      else {
        throw CryptoStateStoreError.unsafeFile
      }
    case .regularFile(let mode):
      try auditRegularFile(metadata, exactMode: mode)
    }
  }

  private nonisolated func auditRegularFile(
    _ metadata: stat,
    exactMode: mode_t
  ) throws {
    guard metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_uid == geteuid(),
      metadata.st_nlink == 1,
      metadata.st_mode & 0o777 == exactMode
    else {
      throw CryptoStateStoreError.unsafeFile
    }
  }

  private nonisolated func writeAll(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else { return }
      var offset = 0
      while offset < buffer.count {
        let written = Darwin.write(
          descriptor,
          base.advanced(by: offset),
          buffer.count - offset
        )
        if written < 0, errno == EINTR { continue }
        guard written > 0 else {
          throw CryptoStateStoreError.io(code: errno)
        }
        offset += written
      }
    }
  }

  private nonisolated func readExactly(
    count: Int,
    from descriptor: Int32
  ) throws -> Data {
    var data = Data(count: count)
    try data.withUnsafeMutableBytes { buffer in
      guard let base = buffer.baseAddress else { return }
      var offset = 0
      while offset < count {
        let readCount = Darwin.read(
          descriptor,
          base.advanced(by: offset),
          count - offset
        )
        if readCount < 0, errno == EINTR { continue }
        guard readCount > 0 else {
          throw readCount == 0
            ? CryptoStateStoreError.invalidFormat
            : CryptoStateStoreError.io(code: errno)
        }
        offset += readCount
      }
    }
    return data
  }

  private nonisolated func syncDirectory(_ descriptor: Int32, url: URL) throws {
    guard Darwin.fsync(descriptor) == 0 else {
      throw CryptoStateStoreError.io(code: errno)
    }
    testHooks.directoryDidSync(url)
  }

  private nonisolated func performFileIO<Value: Sendable>(
    _ body: @escaping @Sendable () throws -> Value
  ) async throws -> Value {
    try await withCheckedThrowingContinuation { continuation in
      ioQueue.async {
        do {
          continuation.resume(returning: try body())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  private nonisolated func unsafeOrIO(_ code: Int32) -> CryptoStateStoreError {
    switch code {
    case ELOOP, ENOTDIR:
      .unsafeFile
    default:
      .io(code: code)
    }
  }

  private nonisolated func mapIO(_ error: Error) -> CryptoStateStoreError {
    if let typed = error as? CryptoStateStoreError { return typed }
    return .io(code: Int32((error as NSError).code))
  }
}

struct FileCryptoStateStoreTestHooks: Sendable {
  let directoryDidSync: @Sendable (URL) -> Void
  let stateFileDidOpen: @Sendable (URL) -> Void
  let protectionDidApply: @Sendable (URL, FileProtectionType) -> Void

  init(
    directoryDidSync: @escaping @Sendable (URL) -> Void = { _ in },
    stateFileDidOpen: @escaping @Sendable (URL) -> Void = { _ in },
    protectionDidApply: @escaping @Sendable (URL, FileProtectionType) -> Void = { _, _ in }
  ) {
    self.directoryDidSync = directoryDidSync
    self.stateFileDidOpen = stateFileDidOpen
    self.protectionDidApply = protectionDidApply
  }

  static let none = FileCryptoStateStoreTestHooks()
}

private final class CryptoStateDirectories: Sendable {
  let rootDescriptor: Int32
  let remoteDescriptor: Int32
  let installationDescriptor: Int32
  let devicesDescriptor: Int32
  let locksDescriptor: Int32
  let devicesURL: URL
  let locksURL: URL

  init(
    rootDescriptor: Int32,
    remoteDescriptor: Int32,
    installationDescriptor: Int32,
    devicesDescriptor: Int32,
    locksDescriptor: Int32,
    devicesURL: URL,
    locksURL: URL
  ) {
    self.rootDescriptor = rootDescriptor
    self.remoteDescriptor = remoteDescriptor
    self.installationDescriptor = installationDescriptor
    self.devicesDescriptor = devicesDescriptor
    self.locksDescriptor = locksDescriptor
    self.devicesURL = devicesURL
    self.locksURL = locksURL
  }

  deinit {
    Darwin.close(locksDescriptor)
    Darwin.close(devicesDescriptor)
    Darwin.close(installationDescriptor)
    Darwin.close(remoteDescriptor)
    Darwin.close(rootDescriptor)
  }
}

private final class CryptoStateTemporaryFile: Sendable {
  let name: String
  let url: URL
  let descriptor: Int32

  init(name: String, url: URL, descriptor: Int32) {
    self.name = name
    self.url = url
    self.descriptor = descriptor
  }

  deinit {
    Darwin.close(descriptor)
  }
}

private struct FileIdentity: Equatable, Sendable {
  let device: UInt64
  let inode: UInt64

  init(_ metadata: stat) {
    device = UInt64(metadata.st_dev)
    inode = UInt64(metadata.st_ino)
  }
}

private struct LoadedCryptoState: Sendable {
  let snapshot: CryptoStateSnapshot
  let fileIdentity: FileIdentity
}

private struct SealedCryptoStateFile: Sendable {
  let data: Data
  let fileIdentity: FileIdentity
}

private enum FileSystemEntryExpectation: Sendable {
  case directory(privateMode: Bool)
  case regularFile(mode: mode_t)
}

@_silgen_name("flock")
private func agentDeckFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

extension Data {
  fileprivate mutating func appendUInt32BigEndian(_ value: UInt32) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
  }

  fileprivate func readUInt32BigEndian(at offset: Int) -> UInt32 {
    self[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
  }

  fileprivate var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
