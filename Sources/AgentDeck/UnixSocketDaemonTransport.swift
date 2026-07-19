import Darwin
import Foundation

/// shared-daemon UDS 客户端的传输层故障。错误码稳定，detail 只用于本地诊断。
enum UnixSocketDaemonTransportError: Error, Sendable, CustomStringConvertible {
  case socketPathInvalid(String)
  case socketMissing(String)
  case socketParentUnsafe(String)
  case socketUnsafe(String)
  case connectFailed(Int32)
  case socketOptionFailed(Int32)
  case prefaceInvalid(String)
  case prefaceFailed(String)
  case notStarted
  case connectionClosed
  case frameInvalid(String)
  case frameTooLarge
  case frameUnterminated
  case frameInvalidUTF8
  case readFailed(Int32)
  case writeCancelled
  case writeTimedOut
  case writeFailed(Int32)

  var code: String {
    switch self {
    case .socketPathInvalid: "daemon.client.socket_path_invalid"
    case .socketMissing: "daemon.client.socket_missing"
    case .socketParentUnsafe: "daemon.client.socket_parent_unsafe"
    case .socketUnsafe: "daemon.client.socket_unsafe"
    case .connectFailed: "daemon.client.connect_failed"
    case .socketOptionFailed: "daemon.client.socket_option_failed"
    case .prefaceInvalid: "daemon.client.preface_invalid"
    case .prefaceFailed: "daemon.client.preface_failed"
    case .notStarted: "daemon.client.not_started"
    case .connectionClosed: "daemon.client.connection_closed"
    case .frameInvalid: "daemon.client.frame_invalid"
    case .frameTooLarge: "daemon.client.frame_too_large"
    case .frameUnterminated: "daemon.client.frame_unterminated"
    case .frameInvalidUTF8: "daemon.client.frame_invalid_utf8"
    case .readFailed: "daemon.client.read_failed"
    case .writeCancelled: "daemon.client.write_cancelled"
    case .writeTimedOut: "daemon.client.write_timeout"
    case .writeFailed: "daemon.client.write_failed"
    }
  }

  var description: String {
    switch self {
    case .socketPathInvalid(let detail),
      .socketMissing(let detail),
      .socketParentUnsafe(let detail),
      .socketUnsafe(let detail),
      .prefaceInvalid(let detail),
      .prefaceFailed(let detail),
      .frameInvalid(let detail):
      "\(code): \(detail)"
    case .connectFailed(let status),
      .socketOptionFailed(let status),
      .readFailed(let status),
      .writeFailed(let status):
      "\(code): errno=\(status)"
    case .notStarted,
      .connectionClosed,
      .frameTooLarge,
      .frameUnterminated,
      .frameInvalidUTF8,
      .writeCancelled,
      .writeTimedOut:
      code
    }
  }
}

enum UnixSocketWriteAttempt: Sendable {
  case written(Int)
  case interrupted
  case wouldBlock
  case failed(Int32)
}

enum UnixSocketWaitAttempt: Sendable {
  case writable
  case interrupted
  case timedOut
  case failed(Int32)
}

/// 将 write/poll 的一次尝试抽出来，让测试能确定性覆盖 partial/EINTR/EAGAIN；
/// production 始终使用 `.live`。
struct UnixSocketWriteOperations: Sendable {
  let write: @Sendable (Int32, Data, Int) -> UnixSocketWriteAttempt
  let waitWritable: @Sendable (Int32, Int32) -> UnixSocketWaitAttempt

  static let live = Self(
    write: { fd, bytes, offset in
      bytes.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return .written(0) }
        let count = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
        if count >= 0 { return .written(count) }
        if errno == EINTR { return .interrupted }
        if errno == EAGAIN || errno == EWOULDBLOCK { return .wouldBlock }
        return .failed(errno)
      }
    },
    waitWritable: { fd, timeoutMilliseconds in
      var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
      let result = poll(&descriptor, 1, timeoutMilliseconds)
      if result > 0 {
        if descriptor.revents & Int16(POLLOUT) != 0 { return .writable }
        if descriptor.revents & Int16(POLLNVAL | POLLERR | POLLHUP) != 0 {
          return .failed(EPIPE)
        }
        return .timedOut
      }
      if result == 0 { return .timedOut }
      if errno == EINTR { return .interrupted }
      return .failed(errno)
    }
  )
}

/// Runtime v2 JSONL over a pre-existing, same-user Unix domain socket。
///
/// production 构造器只接受 `LocalClientInstallation` 派生的 canonical endpoint；
/// 显式 pathname 构造器只供隔离测试。该类型不查找或 spawn daemon，`close()` 也只关闭
/// 当前 client fd。
final class UnixSocketDaemonTransport: @unchecked Sendable {
  static let maximumFrameBytes = 1 << 20
  static let maximumPrefaceBytes = 4 << 10

  private static let readChunkBytes = 16 * 1024
  private static let cancellationPollMilliseconds: Int32 = 25

  private let socketPath: String
  private let writeTimeout: TimeInterval
  private let writeOperations: UnixSocketWriteOperations
  private let connection = UnixSocketConnectionState()
  private let writeLock = NSLock()

  convenience init(
    installation: LocalClientInstallation,
    writeTimeout: TimeInterval = 5
  ) {
    self.init(
      uncheckedSocketPath: installation.daemonSocketPath.path,
      writeTimeout: writeTimeout,
      writeOperations: .live
    )
  }

  /// 显式 endpoint 注入只供 tests/harness；production composition 必须使用 installation 构造器。
  @available(*, deprecated, message: "仅供测试注入")
  convenience init(
    socketPath: String,
    writeTimeout: TimeInterval = 5
  ) {
    self.init(
      uncheckedSocketPath: socketPath,
      writeTimeout: writeTimeout,
      writeOperations: .live
    )
  }

  /// 可注入 write/poll script 的 scoped test seam；production composition 不可调用。
  convenience init(
    testSocketPath socketPath: String,
    writeTimeout: TimeInterval = 5,
    writeOperations: UnixSocketWriteOperations = .live
  ) {
    self.init(
      uncheckedSocketPath: socketPath,
      writeTimeout: writeTimeout,
      writeOperations: writeOperations
    )
  }

  private init(
    uncheckedSocketPath socketPath: String,
    writeTimeout: TimeInterval,
    writeOperations: UnixSocketWriteOperations
  ) {
    self.socketPath = socketPath
    self.writeTimeout = writeTimeout
    self.writeOperations = writeOperations
  }

  deinit {
    close()
  }

  var isStarted: Bool { connection.isStarted }
  var isAlive: Bool { connection.isAlive }

  /// 验证 endpoint、connect，并在返回前完整写出 strict local preface。
  /// Runtime `Hello` 由上层 client 在本方法返回后作为第一条 application frame 发送。
  func start(
    installationID: UUID,
    incomingHandler: @escaping @Sendable (String) -> Void,
    disconnectHandler: @escaping @Sendable (UnixSocketDaemonTransportError) -> Void
  ) throws {
    guard installationID != Self.nilUUID else {
      throw UnixSocketDaemonTransportError.prefaceInvalid(
        "client installation UUID must be non-nil"
      )
    }
    guard writeTimeout.isFinite, writeTimeout > 0 else {
      throw UnixSocketDaemonTransportError.prefaceInvalid(
        "write timeout must be finite and positive"
      )
    }

    writeLock.lock()
    defer { writeLock.unlock() }
    guard
      try connection.beginStart(
        incomingHandler: incomingHandler,
        disconnectHandler: disconnectHandler
      )
    else {
      return
    }

    var socketFD: Int32 = -1
    do {
      try Self.validateSocketPath(socketPath)
      socketFD = try Self.connectSocket(path: socketPath, timeout: writeTimeout)
      let preface = try Self.prefaceBytes(installationID: installationID)
      do {
        try Self.writeAll(
          preface,
          to: socketFD,
          timeout: writeTimeout,
          cancellationCheck: { false },
          operations: writeOperations
        )
      } catch {
        throw UnixSocketDaemonTransportError.prefaceFailed(String(describing: error))
      }
      connection.activate(fd: socketFD)
      Self.startReader(fd: socketFD, connection: connection, closeLock: writeLock)
    } catch {
      if socketFD >= 0 {
        _ = Darwin.shutdown(socketFD, SHUT_RDWR)
        Darwin.close(socketFD)
      }
      connection.failStart()
      throw error
    }
  }

  /// 避免 production caller 把已验证的 installation record 再经宽松字符串路径转换。
  func start(
    installationID: LocalClientInstallationID,
    incomingHandler: @escaping @Sendable (String) -> Void,
    disconnectHandler: @escaping @Sendable (UnixSocketDaemonTransportError) -> Void
  ) throws {
    guard let uuid = UUID(uuidString: installationID.rawValue),
      uuid != Self.nilUUID,
      uuid.uuidString.lowercased() == installationID.rawValue
    else {
      throw UnixSocketDaemonTransportError.prefaceInvalid(
        "client installation ID is not a canonical non-nil UUID"
      )
    }
    try start(
      installationID: uuid,
      incomingHandler: incomingHandler,
      disconnectHandler: disconnectHandler
    )
  }

  /// 完整发送一条 `<1 MiB` UTF-8 frame 与其 LF。任何取消、超时或部分写失败都
  /// poison 并关闭当前连接，后续 frame 不得越过失败边界。
  func sendFrame(
    _ frame: String,
    cancellationCheck: @escaping @Sendable () -> Bool = { false }
  ) throws {
    let raw = Data(frame.utf8)
    guard raw.count < Self.maximumFrameBytes else {
      throw UnixSocketDaemonTransportError.frameTooLarge
    }
    guard !raw.isEmpty, !raw.contains(0x0A), !raw.contains(0x0D) else {
      throw UnixSocketDaemonTransportError.frameInvalid(
        "a JSONL frame must be non-empty and contain no CR/LF"
      )
    }

    writeLock.lock()
    defer { writeLock.unlock() }
    let fd = try connection.fileDescriptorForWrite()
    do {
      try Self.writeAll(
        raw,
        to: fd,
        timeout: writeTimeout,
        cancellationCheck: cancellationCheck,
        operations: writeOperations
      )
    } catch let error as UnixSocketDaemonTransportError {
      connection.terminate(error: error, notify: true)
      throw error
    } catch {
      let fault = UnixSocketDaemonTransportError.writeFailed(EIO)
      connection.terminate(error: fault, notify: true)
      throw fault
    }
  }

  /// 只 teardown 当前 fd；不发送任何 Runtime/daemon shutdown frame。
  func close() {
    writeLock.lock()
    defer { writeLock.unlock() }
    connection.terminate(error: nil, notify: false)
  }

  private static let nilUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

  private static func prefaceBytes(installationID: UUID) throws -> Data {
    let canonicalID = installationID.uuidString.lowercased()
    let raw = Data(
      "{\"localProtocolVersion\":1,\"clientInstallationId\":\"\(canonicalID)\"}\n".utf8
    )
    // The daemon cap is exclusive for JSON bytes and inclusive of LF at 4 KiB.
    guard raw.count <= maximumPrefaceBytes, raw.count - 1 < maximumPrefaceBytes else {
      throw UnixSocketDaemonTransportError.prefaceInvalid(
        "local preface reached the exclusive 4 KiB payload cap"
      )
    }
    return raw
  }

  private static func validateSocketPath(_ path: String) throws {
    guard path.hasPrefix("/"), !path.utf8.contains(0) else {
      throw UnixSocketDaemonTransportError.socketPathInvalid(
        "daemon socket pathname must be absolute and contain no NUL"
      )
    }
    let nsPath = path as NSString
    let parentPath = nsPath.deletingLastPathComponent
    let entryName = nsPath.lastPathComponent
    guard !parentPath.isEmpty,
      entryName != ".",
      entryName != "..",
      !entryName.isEmpty,
      Array(path.utf8).count < Self.unixPathCapacity
    else {
      throw UnixSocketDaemonTransportError.socketPathInvalid(
        "daemon socket pathname is not representable as sockaddr_un"
      )
    }

    let parentFD = Darwin.open(
      parentPath,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard parentFD >= 0 else {
      if errno == ENOENT {
        throw UnixSocketDaemonTransportError.socketMissing(path)
      }
      throw UnixSocketDaemonTransportError.socketParentUnsafe(
        "cannot open endpoint parent without following links (errno=\(errno))"
      )
    }
    defer { Darwin.close(parentFD) }

    var parent = stat()
    guard fstat(parentFD, &parent) == 0 else {
      throw UnixSocketDaemonTransportError.socketParentUnsafe(
        "cannot inspect endpoint parent (errno=\(errno))"
      )
    }
    let expectedUID = geteuid()
    guard Self.fileType(parent.st_mode) == mode_t(S_IFDIR),
      parent.st_uid == expectedUID,
      Self.permissionBits(parent.st_mode) == 0o700
    else {
      throw UnixSocketDaemonTransportError.socketParentUnsafe(
        "endpoint parent must be current-EUID exact-0700 directory"
      )
    }

    var entry = stat()
    let status = entryName.withCString {
      fstatat(parentFD, $0, &entry, AT_SYMLINK_NOFOLLOW)
    }
    guard status == 0 else {
      if errno == ENOENT {
        throw UnixSocketDaemonTransportError.socketMissing(path)
      }
      throw UnixSocketDaemonTransportError.socketUnsafe(
        "cannot inspect socket entry without following links (errno=\(errno))"
      )
    }
    guard Self.fileType(entry.st_mode) == mode_t(S_IFSOCK),
      entry.st_uid == expectedUID,
      Self.permissionBits(entry.st_mode) == 0o600,
      entry.st_nlink == 1
    else {
      throw UnixSocketDaemonTransportError.socketUnsafe(
        "endpoint must be current-EUID exact-0600 single-link socket"
      )
    }
  }

  private static func connectSocket(path: String, timeout: TimeInterval) throws -> Int32 {
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
      throw UnixSocketDaemonTransportError.connectFailed(errno)
    }
    do {
      try configureSocket(fd)
      var address = try unixAddress(path: path)
      let result = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
      }
      if result != 0 {
        guard errno == EINPROGRESS || errno == EALREADY || errno == EAGAIN else {
          throw UnixSocketDaemonTransportError.connectFailed(errno)
        }
        let deadline = Self.deadline(after: timeout)
        try Self.waitForWritable(fd: fd, deadline: deadline, cancellationCheck: { false })
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 else {
          throw UnixSocketDaemonTransportError.connectFailed(errno)
        }
        guard socketError == 0 else {
          throw UnixSocketDaemonTransportError.connectFailed(socketError)
        }
      }
      return fd
    } catch {
      Darwin.close(fd)
      throw error
    }
  }

  private static func configureSocket(_ fd: Int32) throws {
    var enabled: Int32 = 1
    guard
      setsockopt(
        fd,
        SOL_SOCKET,
        SO_NOSIGPIPE,
        &enabled,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    else {
      throw UnixSocketDaemonTransportError.socketOptionFailed(errno)
    }
    let descriptorFlags = fcntl(fd, F_GETFD)
    guard descriptorFlags >= 0,
      fcntl(fd, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0
    else {
      throw UnixSocketDaemonTransportError.socketOptionFailed(errno)
    }
    let statusFlags = fcntl(fd, F_GETFL)
    guard statusFlags >= 0,
      fcntl(fd, F_SETFL, statusFlags | O_NONBLOCK) == 0
    else {
      throw UnixSocketDaemonTransportError.socketOptionFailed(errno)
    }
  }

  private static func writeAll(
    _ frameWithoutLF: Data,
    to fd: Int32,
    timeout: TimeInterval,
    cancellationCheck: @escaping @Sendable () -> Bool,
    operations: UnixSocketWriteOperations = .live
  ) throws {
    var bytes = frameWithoutLF
    if bytes.last != 0x0A { bytes.append(0x0A) }
    let deadline = Self.deadline(after: timeout)
    var offset = 0

    while offset < bytes.count {
      guard !cancellationCheck() else {
        throw UnixSocketDaemonTransportError.writeCancelled
      }
      guard Self.remainingMilliseconds(until: deadline) > 0 else {
        throw UnixSocketDaemonTransportError.writeTimedOut
      }
      switch operations.write(fd, bytes, offset) {
      case .written(let count) where count > 0 && count <= bytes.count - offset:
        offset += count
      case .written:
        throw UnixSocketDaemonTransportError.writeFailed(EIO)
      case .interrupted:
        continue
      case .wouldBlock:
        try Self.waitForWritable(
          fd: fd,
          deadline: deadline,
          cancellationCheck: cancellationCheck,
          operations: operations
        )
      case .failed(let status):
        throw UnixSocketDaemonTransportError.writeFailed(status)
      }
    }
  }

  private static func waitForWritable(
    fd: Int32,
    deadline: UInt64,
    cancellationCheck: @escaping @Sendable () -> Bool,
    operations: UnixSocketWriteOperations = .live
  ) throws {
    while true {
      guard !cancellationCheck() else {
        throw UnixSocketDaemonTransportError.writeCancelled
      }
      let remaining = Self.remainingMilliseconds(until: deadline)
      guard remaining > 0 else {
        throw UnixSocketDaemonTransportError.writeTimedOut
      }
      switch operations.waitWritable(
        fd,
        min(remaining, Self.cancellationPollMilliseconds)
      ) {
      case .writable:
        return
      case .interrupted, .timedOut:
        continue
      case .failed(let status):
        throw UnixSocketDaemonTransportError.writeFailed(status)
      }
    }
  }

  private static func startReader(
    fd: Int32,
    connection: UnixSocketConnectionState,
    closeLock: NSLock
  ) {
    DispatchQueue(
      label: "com.agentdeck.unix-socket-reader.\(fd)",
      qos: .userInitiated
    ).async {
      readLoop(fd: fd, connection: connection, closeLock: closeLock)
    }
  }

  private static func readLoop(
    fd: Int32,
    connection: UnixSocketConnectionState,
    closeLock: NSLock
  ) {
    var buffer = Data()
    var scratch = [UInt8](repeating: 0, count: readChunkBytes)
    defer { connection.readerFinished(fd: fd, closeLock: closeLock) }

    while connection.shouldRead(fd: fd) {
      var descriptor = pollfd(
        fd: fd,
        events: Int16(POLLIN | POLLHUP | POLLERR),
        revents: 0
      )
      let polled = poll(&descriptor, 1, 250)
      if polled < 0 {
        if errno == EINTR { continue }
        connection.terminate(error: .readFailed(errno), notify: true)
        return
      }
      if polled == 0 { continue }
      if descriptor.revents & Int16(POLLNVAL) != 0 {
        if connection.shouldRead(fd: fd) {
          connection.terminate(error: .readFailed(EBADF), notify: true)
        }
        return
      }

      let count = scratch.withUnsafeMutableBytes { raw in
        Darwin.read(fd, raw.baseAddress, raw.count)
      }
      if count > 0 {
        buffer.append(contentsOf: scratch.prefix(count))
        if !Self.deliverCompleteLines(buffer: &buffer, connection: connection) {
          return
        }
        continue
      }
      if count == 0 {
        let error: UnixSocketDaemonTransportError =
          buffer.isEmpty
          ? .connectionClosed
          : .frameUnterminated
        connection.terminate(error: error, notify: true)
        return
      }
      if errno == EINTR { continue }
      if errno == EAGAIN || errno == EWOULDBLOCK { continue }
      if !connection.shouldRead(fd: fd) { return }
      connection.terminate(error: .readFailed(errno), notify: true)
      return
    }
  }

  private static func deliverCompleteLines(
    buffer: inout Data,
    connection: UnixSocketConnectionState
  ) -> Bool {
    while let newline = buffer.firstIndex(of: 0x0A) {
      let frameByteCount = buffer.distance(from: buffer.startIndex, to: newline)
      guard frameByteCount < maximumFrameBytes else {
        connection.terminate(error: .frameTooLarge, notify: true)
        return false
      }
      let raw = buffer.subdata(in: buffer.startIndex..<newline)
      buffer.removeSubrange(buffer.startIndex...newline)
      guard !raw.isEmpty else {
        connection.terminate(
          error: .frameInvalid("received an empty JSONL frame"),
          notify: true
        )
        return false
      }
      guard let frame = String(data: raw, encoding: .utf8) else {
        connection.terminate(error: .frameInvalidUTF8, notify: true)
        return false
      }
      guard connection.deliver(frame: frame) else { return false }
    }
    guard buffer.count < maximumFrameBytes else {
      connection.terminate(error: .frameTooLarge, notify: true)
      return false
    }
    return true
  }

  private static func unixAddress(path: String) throws -> sockaddr_un {
    let bytes = Array(path.utf8)
    guard bytes.count < unixPathCapacity else {
      throw UnixSocketDaemonTransportError.socketPathInvalid(
        "daemon socket pathname exceeds sockaddr_un.sun_path"
      )
    }
    var address = sockaddr_un()
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutablePointer(to: &address.sun_path) { pointer in
      pointer.withMemoryRebound(to: UInt8.self, capacity: bytes.count + 1) { target in
        for (index, byte) in bytes.enumerated() { target[index] = byte }
        target[bytes.count] = 0
      }
    }
    return address
  }

  private static var unixPathCapacity: Int {
    MemoryLayout.size(ofValue: sockaddr_un().sun_path)
  }

  private static func fileType(_ mode: mode_t) -> mode_t {
    mode & mode_t(S_IFMT)
  }

  private static func permissionBits(_ mode: mode_t) -> mode_t {
    mode & 0o7777
  }

  private static func deadline(after interval: TimeInterval) -> UInt64 {
    let nanoseconds = interval * 1_000_000_000
    let now = DispatchTime.now().uptimeNanoseconds
    let delta = UInt64(min(nanoseconds, Double(UInt64.max - now)))
    return now + delta
  }

  private static func remainingMilliseconds(until deadline: UInt64) -> Int32 {
    let now = DispatchTime.now().uptimeNanoseconds
    guard deadline > now else { return 0 }
    let remaining = deadline - now
    let roundedUp = (remaining + 999_999) / 1_000_000
    return Int32(min(roundedUp, UInt64(Int32.max)))
  }
}

private final class UnixSocketConnectionState: @unchecked Sendable {
  private enum Phase {
    case idle
    case starting
    case alive(Int32)
    case terminal
  }

  private let lock = NSLock()
  private var phase: Phase = .idle
  private var readerOwnsFD = false
  private var incomingHandler: (@Sendable (String) -> Void)?
  private var disconnectHandler: (@Sendable (UnixSocketDaemonTransportError) -> Void)?
  private var disconnectDelivered = false

  var isStarted: Bool {
    lock.lock()
    defer { lock.unlock() }
    if case .alive = phase { return true }
    return false
  }

  var isAlive: Bool { isStarted }

  func beginStart(
    incomingHandler: @escaping @Sendable (String) -> Void,
    disconnectHandler: @escaping @Sendable (UnixSocketDaemonTransportError) -> Void
  ) throws -> Bool {
    lock.lock()
    defer { lock.unlock() }
    switch phase {
    case .alive, .starting:
      return false
    case .terminal:
      throw UnixSocketDaemonTransportError.connectionClosed
    case .idle:
      phase = .starting
      self.incomingHandler = incomingHandler
      self.disconnectHandler = disconnectHandler
      return true
    }
  }

  func activate(fd: Int32) {
    lock.lock()
    phase = .alive(fd)
    readerOwnsFD = true
    lock.unlock()
  }

  func failStart() {
    lock.lock()
    if case .starting = phase {
      phase = .idle
      incomingHandler = nil
      disconnectHandler = nil
    }
    lock.unlock()
  }

  func fileDescriptorForWrite() throws -> Int32 {
    lock.lock()
    defer { lock.unlock() }
    guard case .alive(let fd) = phase else {
      if case .idle = phase {
        throw UnixSocketDaemonTransportError.notStarted
      }
      throw UnixSocketDaemonTransportError.connectionClosed
    }
    return fd
  }

  func shouldRead(fd: Int32) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard case .alive(let activeFD) = phase else { return false }
    return activeFD == fd
  }

  func deliver(frame: String) -> Bool {
    lock.lock()
    guard case .alive = phase else {
      lock.unlock()
      return false
    }
    let handler = incomingHandler
    lock.unlock()
    handler?(frame)
    return true
  }

  func terminate(error: UnixSocketDaemonTransportError?, notify: Bool) {
    lock.lock()
    guard case .alive(let fd) = phase else {
      if case .starting = phase { phase = .terminal }
      lock.unlock()
      return
    }
    phase = .terminal
    let ownsFD = readerOwnsFD
    let handler: (@Sendable (UnixSocketDaemonTransportError) -> Void)?
    if notify, error != nil, !disconnectDelivered {
      disconnectDelivered = true
      handler = disconnectHandler
    } else {
      handler = nil
    }
    lock.unlock()

    _ = Darwin.shutdown(fd, SHUT_RDWR)
    if !ownsFD { Darwin.close(fd) }
    if let error { handler?(error) }
  }

  func readerFinished(fd: Int32, closeLock: NSLock) {
    // 与 sendFrame/close 共用同一顺序：writer handoff 未结束时 reader 只能
    // shutdown/标 terminal，不能 close raw fd 并让编号被 OS 复用。
    closeLock.lock()
    defer { closeLock.unlock() }
    lock.lock()
    let shouldClose = readerOwnsFD
    readerOwnsFD = false
    if case .alive(let activeFD) = phase, activeFD == fd {
      phase = .terminal
    }
    lock.unlock()
    if shouldClose { Darwin.close(fd) }
  }
}
