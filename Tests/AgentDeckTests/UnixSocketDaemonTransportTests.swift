import Darwin
import Foundation
import XCTest

@testable import AgentDeck

final class UnixSocketDaemonTransportTests: XCTestCase {
  func testStartWritesCanonicalPrefaceBeforeApplicationFrame() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let installationID = try XCTUnwrap(
      LocalClientInstallationID(rawValue: "4c20fe52-cc71-4e07-9ed8-a2903ec62a63")
    )

    try transport.start(
      installationID: installationID,
      incomingHandler: { _ in },
      disconnectHandler: { _ in }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }

    try transport.sendFrame(
      #"{"version":3,"messageId":"hello","body":{"request":{"hello":{"runtimeProtocolVersion":3}}}}"#
    )

    let preface = try XCTUnwrap(peer.readLine(from: connection))
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(preface.utf8)) as? [String: Any]
    )
    XCTAssertEqual(Set(object.keys), ["localProtocolVersion", "clientInstallationId"])
    XCTAssertEqual(object["localProtocolVersion"] as? Int, 1)
    XCTAssertEqual(
      object["clientInstallationId"] as? String,
      "4c20fe52-cc71-4e07-9ed8-a2903ec62a63"
    )
    XCTAssertEqual(
      try peer.readLine(from: connection),
      #"{"version":3,"messageId":"hello","body":{"request":{"hello":{"runtimeProtocolVersion":3}}}}"#
    )
    transport.close()
  }

  func testReaderSplitsAndCoalescesCompleteLines() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let received = LockedValues<String>()
    let delivered = expectation(description: "three complete frames")
    delivered.expectedFulfillmentCount = 3

    try transport.start(
      installationID: UUID(),
      incomingHandler: {
        received.append($0)
        delivered.fulfill()
      },
      disconnectHandler: { _ in }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    try peer.write(Data(#"{"n":1}"#.utf8), to: connection)
    try peer.write(Data("\n{\"n\":2}\n{\"n\":".utf8), to: connection)
    try peer.write(Data("3}\n".utf8), to: connection)

    wait(for: [delivered], timeout: 2)
    XCTAssertEqual(received.snapshot, [#"{"n":1}"#, #"{"n":2}"#, #"{"n":3}"#])
    transport.close()
  }

  func testReaderAcceptsBelowCapThenRejectsExactOneMiBFrame() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let delivered = expectation(description: "below-cap delivery")
    let receivedLengths = LockedValues<Int>()
    let disconnected = expectation(description: "oversize disconnect")
    let fault = LockedValues<UnixSocketDaemonTransportError>()

    try transport.start(
      installationID: UUID(),
      incomingHandler: {
        receivedLengths.append($0.utf8.count)
        delivered.fulfill()
      },
      disconnectHandler: {
        fault.append($0)
        disconnected.fulfill()
      }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    var belowCap = Data(
      repeating: 0x61,
      count: UnixSocketDaemonTransport.maximumFrameBytes - 1
    )
    belowCap.append(0x0A)
    try peer.write(belowCap, to: connection)
    wait(for: [delivered], timeout: 2)

    var exactCap = Data(repeating: 0x61, count: UnixSocketDaemonTransport.maximumFrameBytes)
    exactCap.append(0x0A)
    try peer.write(exactCap, to: connection)

    wait(for: [disconnected], timeout: 2)
    XCTAssertEqual(receivedLengths.snapshot, [UnixSocketDaemonTransport.maximumFrameBytes - 1])
    XCTAssertEqual(fault.snapshot.first?.code, "daemon.client.frame_too_large")
    XCTAssertFalse(transport.isAlive)
  }

  func testReaderClassifiesCleanEOFAndPartialEOF() throws {
    try assertEOFFault(payload: Data(), expectedCode: "daemon.client.connection_closed")
    try assertEOFFault(
      payload: Data(#"{"partial":true}"#.utf8),
      expectedCode: "daemon.client.frame_unterminated"
    )
  }

  func testReaderRejectsInvalidUTF8() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let disconnected = expectation(description: "invalid UTF-8 disconnect")
    let fault = LockedValues<UnixSocketDaemonTransportError>()

    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in XCTFail("invalid UTF-8 must not be delivered") },
      disconnectHandler: {
        fault.append($0)
        disconnected.fulfill()
      }
    )
    let connection = try peer.acceptConnection()
    _ = try peer.readLine(from: connection)
    try peer.write(Data([0xC3, 0x28, 0x0A]), to: connection)

    wait(for: [disconnected], timeout: 2)
    XCTAssertEqual(fault.snapshot.first?.code, "daemon.client.frame_invalid_utf8")
    Darwin.close(connection)
  }

  func testOutboundExactCapAndEmbeddedLFAreRejectedBeforeWrite() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: { _ in }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    XCTAssertThrowsError(
      try transport.sendFrame(String(repeating: "a", count: 1 << 20))
    ) { error in
      XCTAssertEqual(
        (error as? UnixSocketDaemonTransportError)?.code,
        "daemon.client.frame_too_large"
      )
    }
    XCTAssertThrowsError(try transport.sendFrame("{}\n{}")) { error in
      XCTAssertEqual(
        (error as? UnixSocketDaemonTransportError)?.code,
        "daemon.client.frame_invalid"
      )
    }
    transport.close()
  }

  func testCancelledWritePoisonsConnection() throws {
    let peer = try UnixSocketTransportPeer()
    let applicationWrites = LockedValues<Int>()
    let operations = UnixSocketWriteOperations(
      write: { fd, bytes, offset in
        if bytes.starts(with: Self.prefacePrefix) {
          return UnixSocketWriteOperations.live.write(fd, bytes, offset)
        }
        applicationWrites.append(offset)
        return .written(1)
      },
      waitWritable: UnixSocketWriteOperations.live.waitWritable
    )
    let transport = UnixSocketDaemonTransport(
      testSocketPath: peer.socketPath,
      writeOperations: operations
    )
    let disconnected = expectation(description: "cancel poison")
    let faults = LockedValues<UnixSocketDaemonTransportError>()
    let cancellationChecks = LockedCounter()
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: {
        faults.append($0)
        disconnected.fulfill()
      }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    XCTAssertThrowsError(
      try transport.sendFrame(
        "{}",
        cancellationCheck: { cancellationChecks.next() > 0 }
      )
    ) { error in
      XCTAssertEqual(
        (error as? UnixSocketDaemonTransportError)?.code,
        "daemon.client.write_cancelled"
      )
    }
    wait(for: [disconnected], timeout: 2)
    XCTAssertEqual(faults.snapshot.first?.code, "daemon.client.write_cancelled")
    XCTAssertEqual(applicationWrites.snapshot, [0])
    XCTAssertFalse(transport.isAlive)
  }

  func testWriteRetriesPartialEINTRAndEAGAINAndCompletesLF() throws {
    let peer = try UnixSocketTransportPeer()
    let applicationOffsets = LockedValues<Int>()
    let applicationPayloads = LockedValues<Data>()
    let waitCalls = LockedCounter()
    let noSigPipe = LockedValues<Int32>()
    let callIndex = LockedCounter()
    let operations = UnixSocketWriteOperations(
      write: { fd, bytes, offset in
        if bytes.starts(with: Self.prefacePrefix) {
          var value: Int32 = 0
          var length = socklen_t(MemoryLayout<Int32>.size)
          if getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, &length) == 0 {
            noSigPipe.append(value)
          }
          return UnixSocketWriteOperations.live.write(fd, bytes, offset)
        }
        applicationOffsets.append(offset)
        applicationPayloads.append(bytes)
        switch callIndex.next() {
        case 0: return .written(2)
        case 1: return .interrupted
        case 2: return .wouldBlock
        default: return .written(bytes.count - offset)
        }
      },
      waitWritable: { _, _ in
        _ = waitCalls.next()
        return .writable
      }
    )
    let transport = UnixSocketDaemonTransport(
      testSocketPath: peer.socketPath,
      writeOperations: operations
    )
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: { _ in }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    try transport.sendFrame(#"{"partial":true}"#)

    XCTAssertEqual(applicationOffsets.snapshot, [0, 2, 2, 2])
    XCTAssertEqual(waitCalls.value, 1)
    XCTAssertTrue(applicationPayloads.snapshot.allSatisfy { $0.last == 0x0A })
    XCTAssertEqual(noSigPipe.snapshot.last, 1)
    XCTAssertTrue(transport.isAlive)
    transport.close()
  }

  func testPartialWriteTimeoutPoisonsConnection() throws {
    let peer = try UnixSocketTransportPeer()
    let callIndex = LockedCounter()
    let operations = UnixSocketWriteOperations(
      write: { fd, bytes, offset in
        if bytes.starts(with: Self.prefacePrefix) {
          return UnixSocketWriteOperations.live.write(fd, bytes, offset)
        }
        return callIndex.next() == 0 ? .written(1) : .wouldBlock
      },
      waitWritable: { _, _ in
        usleep(5_000)
        return .timedOut
      }
    )
    let transport = UnixSocketDaemonTransport(
      testSocketPath: peer.socketPath,
      writeTimeout: 0.001,
      writeOperations: operations
    )
    let disconnected = expectation(description: "write timeout poison")
    let faults = LockedValues<UnixSocketDaemonTransportError>()
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: {
        faults.append($0)
        disconnected.fulfill()
      }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    XCTAssertThrowsError(try transport.sendFrame(#"{"timeout":true}"#)) { error in
      XCTAssertEqual(
        (error as? UnixSocketDaemonTransportError)?.code,
        "daemon.client.write_timeout"
      )
    }
    wait(for: [disconnected], timeout: 1)
    XCTAssertEqual(faults.snapshot.first?.code, "daemon.client.write_timeout")
    XCTAssertFalse(transport.isAlive)
  }

  func testConcurrentCloseWaitsForPartialFrameHandoff() throws {
    let peer = try UnixSocketTransportPeer()
    let callIndex = LockedCounter()
    let partialCompleted = DispatchSemaphore(value: 0)
    let secondWriteEntered = DispatchSemaphore(value: 0)
    let releaseWrite = DispatchSemaphore(value: 0)
    let clientFDs = LockedValues<Int32>()
    let operations = UnixSocketWriteOperations(
      write: { fd, bytes, offset in
        if bytes.starts(with: Self.prefacePrefix) {
          return UnixSocketWriteOperations.live.write(fd, bytes, offset)
        }
        clientFDs.append(fd)
        switch callIndex.next() {
        case 0:
          partialCompleted.signal()
          return .written(1)
        default:
          secondWriteEntered.signal()
          releaseWrite.wait()
          return .written(bytes.count - offset)
        }
      },
      waitWritable: UnixSocketWriteOperations.live.waitWritable
    )
    let transport = UnixSocketDaemonTransport(
      testSocketPath: peer.socketPath,
      writeOperations: operations
    )
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: { _ in }
    )
    let connection = try peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try peer.readLine(from: connection)

    let sendFinished = expectation(description: "partial send completes")
    let sendErrors = LockedValues<String>()
    DispatchQueue.global().async {
      do {
        try transport.sendFrame(#"{"close":"after-frame"}"#)
      } catch {
        sendErrors.append(String(describing: error))
      }
      sendFinished.fulfill()
    }
    XCTAssertEqual(partialCompleted.wait(timeout: .now() + 2), .success)
    XCTAssertEqual(secondWriteEntered.wait(timeout: .now() + 2), .success)

    let closeStarted = DispatchSemaphore(value: 0)
    let closeFinished = expectation(description: "close waits for writer")
    let closeReturns = LockedCounter()
    DispatchQueue.global().async {
      closeStarted.signal()
      transport.close()
      _ = closeReturns.next()
      closeFinished.fulfill()
    }
    XCTAssertEqual(closeStarted.wait(timeout: .now() + 2), .success)
    usleep(50_000)
    XCTAssertEqual(closeReturns.value, 0)
    XCTAssertGreaterThanOrEqual(fcntl(try XCTUnwrap(clientFDs.snapshot.first), F_GETFD), 0)

    releaseWrite.signal()
    wait(for: [sendFinished, closeFinished], timeout: 2)
    XCTAssertTrue(sendErrors.snapshot.isEmpty)
    XCTAssertEqual(closeReturns.value, 1)
    XCTAssertFalse(transport.isAlive)
  }

  func testPeerEOFDoesNotCloseFDWhilePartialWriterOwnsLease() throws {
    let peer = try UnixSocketTransportPeer()
    let callIndex = LockedCounter()
    let secondWriteEntered = DispatchSemaphore(value: 0)
    let releaseWrite = DispatchSemaphore(value: 0)
    let clientFDs = LockedValues<Int32>()
    let operations = UnixSocketWriteOperations(
      write: { fd, bytes, offset in
        if bytes.starts(with: Self.prefacePrefix) {
          return UnixSocketWriteOperations.live.write(fd, bytes, offset)
        }
        clientFDs.append(fd)
        if callIndex.next() == 0 { return .written(1) }
        secondWriteEntered.signal()
        releaseWrite.wait()
        return .failed(EPIPE)
      },
      waitWritable: UnixSocketWriteOperations.live.waitWritable
    )
    let transport = UnixSocketDaemonTransport(
      testSocketPath: peer.socketPath,
      writeOperations: operations
    )
    let disconnected = expectation(description: "peer EOF observed")
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: { _ in disconnected.fulfill() }
    )
    let connection = try peer.acceptConnection()
    _ = try peer.readLine(from: connection)

    let sendFinished = expectation(description: "poisoned send returns")
    let sendCodes = LockedValues<String>()
    DispatchQueue.global().async {
      do {
        try transport.sendFrame(#"{"peer":"closed"}"#)
      } catch let error as UnixSocketDaemonTransportError {
        sendCodes.append(error.code)
      } catch {
        sendCodes.append("unexpected")
      }
      sendFinished.fulfill()
    }
    XCTAssertEqual(secondWriteEntered.wait(timeout: .now() + 2), .success)
    let clientFD = try XCTUnwrap(clientFDs.snapshot.first)
    Darwin.close(connection)
    wait(for: [disconnected], timeout: 2)

    // reader 已把连接标为 terminal 并 shutdown，但最终 close 必须等 writer lease。
    XCTAssertGreaterThanOrEqual(fcntl(clientFD, F_GETFD), 0)
    releaseWrite.signal()
    wait(for: [sendFinished], timeout: 2)
    XCTAssertEqual(sendCodes.snapshot, ["daemon.client.write_failed"])

    let closeDeadline = DispatchTime.now() + .seconds(1)
    while fcntl(clientFD, F_GETFD) >= 0, DispatchTime.now() < closeDeadline {
      usleep(1_000)
    }
    XCTAssertEqual(fcntl(clientFD, F_GETFD), -1)
    XCTAssertEqual(errno, EBADF)
  }

  func testCloseOnlyClosesClientAndLeavesListenerUsable() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in },
      disconnectHandler: { _ in }
    )
    let first = try peer.acceptConnection()
    _ = try peer.readLine(from: first)
    transport.close()
    Darwin.close(first)

    let second = try peer.connectClient()
    XCTAssertGreaterThanOrEqual(second, 0)
    Darwin.close(second)
  }

  func testStartRejectsUnsafeParentAndSocketMetadata() throws {
    do {
      let peer = try UnixSocketTransportPeer()
      XCTAssertEqual(chmod(peer.rootPath, 0o755), 0)
      let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
      XCTAssertThrowsError(
        try transport.start(
          installationID: UUID(),
          incomingHandler: { _ in },
          disconnectHandler: { _ in }
        )
      ) { error in
        XCTAssertEqual(
          (error as? UnixSocketDaemonTransportError)?.code,
          "daemon.client.socket_parent_unsafe"
        )
      }
    }

    do {
      let peer = try UnixSocketTransportPeer()
      XCTAssertEqual(chmod(peer.socketPath, 0o644), 0)
      let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
      XCTAssertThrowsError(
        try transport.start(
          installationID: UUID(),
          incomingHandler: { _ in },
          disconnectHandler: { _ in }
        )
      ) { error in
        XCTAssertEqual(
          (error as? UnixSocketDaemonTransportError)?.code,
          "daemon.client.socket_unsafe"
        )
      }
    }
  }

  func testStartRejectsSymlinkRegularFileAndMultipleLinks() throws {
    do {
      let peer = try UnixSocketTransportPeer()
      let alias = peer.rootPath + "/alias"
      XCTAssertEqual(symlink(peer.socketPath, alias), 0)
      let transport = UnixSocketDaemonTransport(testSocketPath: alias)
      XCTAssertThrowsError(
        try transport.start(
          installationID: UUID(),
          incomingHandler: { _ in },
          disconnectHandler: { _ in }
        )
      ) { error in
        XCTAssertEqual(
          (error as? UnixSocketDaemonTransportError)?.code,
          "daemon.client.socket_unsafe"
        )
      }
    }

    do {
      let root = try UnixSocketTransportPeer.makePrivateRoot()
      defer { try? FileManager.default.removeItem(atPath: root) }
      let file = root + "/regular"
      XCTAssertTrue(FileManager.default.createFile(atPath: file, contents: Data()))
      XCTAssertEqual(chmod(file, 0o600), 0)
      let transport = UnixSocketDaemonTransport(testSocketPath: file)
      XCTAssertThrowsError(
        try transport.start(
          installationID: UUID(),
          incomingHandler: { _ in },
          disconnectHandler: { _ in }
        )
      ) { error in
        XCTAssertEqual(
          (error as? UnixSocketDaemonTransportError)?.code,
          "daemon.client.socket_unsafe"
        )
      }
    }

    do {
      let peer = try UnixSocketTransportPeer()
      let alias = peer.rootPath + "/hardlink"
      XCTAssertEqual(link(peer.socketPath, alias), 0)
      let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
      XCTAssertThrowsError(
        try transport.start(
          installationID: UUID(),
          incomingHandler: { _ in },
          disconnectHandler: { _ in }
        )
      ) { error in
        XCTAssertEqual(
          (error as? UnixSocketDaemonTransportError)?.code,
          "daemon.client.socket_unsafe"
        )
      }
    }
  }

  func testNilInstallationUUIDIsRejectedBeforeConnect() throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let nilUUID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-000000000000"))

    XCTAssertThrowsError(
      try transport.start(
        installationID: nilUUID,
        incomingHandler: { _ in },
        disconnectHandler: { _ in }
      )
    ) { error in
      XCTAssertEqual(
        (error as? UnixSocketDaemonTransportError)?.code,
        "daemon.client.preface_invalid"
      )
    }
  }

  private func assertEOFFault(payload: Data, expectedCode: String) throws {
    let peer = try UnixSocketTransportPeer()
    let transport = UnixSocketDaemonTransport(testSocketPath: peer.socketPath)
    let disconnected = expectation(description: expectedCode)
    let faults = LockedValues<UnixSocketDaemonTransportError>()
    try transport.start(
      installationID: UUID(),
      incomingHandler: { _ in XCTFail("unterminated bytes must not be delivered") },
      disconnectHandler: {
        faults.append($0)
        disconnected.fulfill()
      }
    )
    let connection = try peer.acceptConnection()
    _ = try peer.readLine(from: connection)
    if !payload.isEmpty {
      try peer.write(payload, to: connection)
    }
    XCTAssertEqual(shutdown(connection, SHUT_WR), 0)

    wait(for: [disconnected], timeout: 2)
    XCTAssertEqual(faults.snapshot.first?.code, expectedCode)
    Darwin.close(connection)
  }

  private static let prefacePrefix = Data(#"{"localProtocolVersion"#.utf8)
}

private final class LockedValues<Element>: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [Element] = []

  var snapshot: [Element] {
    lock.withLock { values }
  }

  func append(_ value: Element) {
    lock.withLock { values.append(value) }
  }
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  var value: Int { lock.withLock { count } }

  func next() -> Int {
    lock.withLock {
      defer { count += 1 }
      return count
    }
  }
}

private final class UnixSocketTransportPeer {
  let rootPath: String
  let socketPath: String
  private let listener: Int32

  init() throws {
    rootPath = try Self.makePrivateRoot()
    socketPath = rootPath + "/s"
    listener = try Self.makeListener(path: socketPath)
  }

  deinit {
    Darwin.close(listener)
    unlink(socketPath)
    try? FileManager.default.removeItem(atPath: rootPath)
  }

  static func makePrivateRoot() throws -> String {
    let root = "/tmp/ad-swift-\(UUID().uuidString.prefix(12).lowercased())"
    guard mkdir(root, 0o700) == 0 else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return root
  }

  func acceptConnection(timeoutMilliseconds: Int32 = 2_000) throws -> Int32 {
    try Self.wait(fd: listener, events: Int16(POLLIN), timeoutMilliseconds: timeoutMilliseconds)
    let fd = accept(listener, nil, nil)
    guard fd >= 0 else { throw Self.posixError() }
    return fd
  }

  func connectClient() throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw Self.posixError() }
    do {
      try Self.connect(fd: fd, path: socketPath)
      return fd
    } catch {
      Darwin.close(fd)
      throw error
    }
  }

  func readLine(from fd: Int32) throws -> String? {
    var data = Data()
    while true {
      try Self.wait(fd: fd, events: Int16(POLLIN), timeoutMilliseconds: 2_000)
      var byte: UInt8 = 0
      let count = Darwin.read(fd, &byte, 1)
      if count == 0 { return data.isEmpty ? nil : String(data: data, encoding: .utf8) }
      if count < 0 {
        if errno == EINTR { continue }
        throw Self.posixError()
      }
      if byte == 0x0A { return String(data: data, encoding: .utf8) }
      data.append(byte)
    }
  }

  func write(_ data: Data, to fd: Int32) throws {
    try data.withUnsafeBytes { raw in
      var offset = 0
      while offset < raw.count {
        let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
        if count > 0 {
          offset += count
        } else if count < 0, errno == EINTR {
          continue
        } else {
          throw Self.posixError()
        }
      }
    }
  }

  private static func makeListener(path: String) throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw posixError() }
    do {
      var address = try unixAddress(path: path)
      let length = socklen_t(MemoryLayout<sockaddr_un>.size)
      let status = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          bind(fd, $0, length)
        }
      }
      guard status == 0 else { throw posixError() }
      guard chmod(path, 0o600) == 0 else { throw posixError() }
      guard listen(fd, 8) == 0 else { throw posixError() }
      return fd
    } catch {
      Darwin.close(fd)
      throw error
    }
  }

  private static func connect(fd: Int32, path: String) throws {
    var address = try unixAddress(path: path)
    let length = socklen_t(MemoryLayout<sockaddr_un>.size)
    let status = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(fd, $0, length)
      }
    }
    guard status == 0 else { throw posixError() }
  }

  private static func unixAddress(path: String) throws -> sockaddr_un {
    let bytes = Array(path.utf8)
    guard bytes.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
      throw POSIXError(.ENAMETOOLONG)
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

  private static func wait(fd: Int32, events: Int16, timeoutMilliseconds: Int32) throws {
    var descriptor = pollfd(fd: fd, events: events, revents: 0)
    while true {
      let result = poll(&descriptor, 1, timeoutMilliseconds)
      if result > 0 { return }
      if result == 0 { throw POSIXError(.ETIMEDOUT) }
      if errno == EINTR { continue }
      throw posixError()
    }
  }

  private static func posixError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
}
