import AgentDeckCore
import CryptoKit
import Darwin
import Foundation
import XCTest

@testable import AgentDeck

final class LocalRuntimeWireSessionTests: XCTestCase {
  func testUnaryRequestReturnsOrdinaryReplyAndPreservesTypedFailureCode() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: [
        "11111111-1111-4111-8111-111111111111",
        "12222222-2222-4222-8222-222222222222",
        "13333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let ordinary = Task { try await harness.session.request(.describeAgents) }
    let ordinaryRequest = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: ordinaryRequest.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "daemon.test.exact",
              message: "exact business failure",
              diagnosticRef: "diag-1"
            )
          )
        )
      ),
      to: connection
    )
    guard case .failure(let failure) = try await ordinary.value else {
      return XCTFail("ordinary failure reply lost its Runtime v2 type")
    }
    XCTAssertEqual(failure.code, "daemon.test.exact")
    XCTAssertEqual(failure.message, "exact business failure")
    XCTAssertEqual(failure.diagnosticRef, "diag-1")

    let duplicate = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: ordinaryRequest.messageID,
      body: .reply(
        .failure(
          RuntimeFailureV1(
            code: "daemon.test.duplicate",
            message: "second terminal",
            diagnosticRef: nil
          )
        )
      )
    )
    try harness.peer.writeEnvelope(duplicate, to: connection)
    let fault = try await harness.waitForFault()
    XCTAssertEqual(fault.code, "daemon.client.reply_uncorrelated")
    await harness.session.close()
  }

  func testUnaryTransferDecodesStrictCatalogPayloadIntoExactReply() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: [
        "21111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let pending = Task { try await harness.session.request(.catalog(pageCursor: nil)) }
    let request = try harness.peer.readEnvelope(from: connection)
    let payload = try localRuntimeJSONData([
      "baseCatalogCursor": "beforeFirst",
      "entries": [
        [
          "conversationId": "conversation-transfer",
          "agentKind": "codex",
          "title": "Transferred",
          "cwd": "/tmp/project",
          "lastActiveMs": 9,
          "archived": false,
          "entryRevision": 3,
        ] as [String: Any]
      ],
      "nextPageCursor": NSNull(),
    ])
    try harness.peer.writeTransfer(
      channel: .reply,
      messageID: request.messageID.rawValue,
      transferID: "catalog-transfer",
      payload: payload,
      to: connection
    )

    guard case .catalog(let catalog) = try await pending.value else {
      return XCTFail("transfer payload was not decoded as RuntimeReplyV2.catalog")
    }
    XCTAssertEqual(catalog.entries.count, 1)
    XCTAssertEqual(catalog.entries[0].conversationID.rawValue, "conversation-transfer")
    XCTAssertEqual(catalog.entries[0].title, "Transferred")
    XCTAssertNil(catalog.nextPageCursor)
    await harness.session.close()
  }

  func testSynchronizedRequestRetainsBackfillThenSyncCompleteTerminal() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: [
        "31111111-1111-4111-8111-111111111111",
        "32222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let sequence = try await harness.session.beginSynchronizedRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let request = try harness.peer.readEnvelope(from: connection)
    XCTAssertEqual(sequence.messageID, request.messageID)
    let payload = try localRuntimeJSONData([
      "scope": "catalog",
      "range": ["after": "beforeFirst", "through": ["at": 0]],
      "deltas": [["catalogRevision": 0, "changes": []]],
    ])
    try harness.peer.writeTransfer(
      channel: .reply,
      messageID: request.messageID.rawValue,
      transferID: "backfill-transfer",
      payload: payload,
      to: connection
    )
    try harness.peer.writeRawReply(
      messageID: request.messageID.rawValue,
      payload: [
        "reply": "syncComplete",
        "streamGeneration": "generation-1",
        "streamCursor": ["at": 7],
        "innerCursor": ["scope": "catalog", "cursor": ["at": 0]],
        "keyDirectoryRevision": 4,
      ],
      to: connection
    )

    guard case .backfill(.catalog(let range, let deltas)) = try await sequence.next() else {
      return XCTFail("first synchronized reply was not exact catalog backfill")
    }
    XCTAssertEqual(range.after, .beforeFirst)
    XCTAssertEqual(range.through, .at(0))
    XCTAssertEqual(deltas.count, 1)
    XCTAssertEqual(deltas[0].catalogRevision, 0)

    guard case .syncComplete(let terminal) = try await sequence.next() else {
      return XCTFail("synchronized reply lost SyncComplete terminal")
    }
    XCTAssertEqual(terminal.streamCursor, .at(7))
    let afterTerminal = try await sequence.next()
    XCTAssertNil(afterTerminal)
    await harness.session.close()
  }

  func testUnaryAndSynchronizedAPIsRejectWrongRequestModeExactly() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: ["41111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    do {
      _ = try await harness.session.request(.backfill(.catalog(after: .beforeFirst)))
      XCTFail("unary API accepted a synchronized request")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.sequence_required")
    }
    do {
      _ = try await harness.session.beginSynchronizedRequest(.describeAgents)
      XCTFail("synchronized API accepted a unary request")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.synchronized_request_required")
    }
    await harness.session.close()
  }

  func testTransferredStreamDecodesStrictPayloadAndPreservesMessageID() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: ["51111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let pending = Task { try await harness.session.nextStream() }
    let payload = try localRuntimeJSONData([
      "catalogRevision": 12,
      "changes": [
        [
          "kind": "removed",
          "conversation_id": "conversation-removed",
        ]
      ],
    ])
    try harness.peer.writeTransfer(
      channel: .stream,
      messageID: "stream-transfer-message",
      transferID: "stream-transfer",
      payload: payload,
      to: connection
    )

    let frame = try await pending.value
    XCTAssertEqual(frame.messageID.rawValue, "stream-transfer-message")
    guard case .catalogDelta(let delta) = frame.item else {
      return XCTFail("transfer payload was not decoded as catalogDelta")
    }
    XCTAssertEqual(delta.catalogRevision, 12)
    guard case .removed(let conversationID) = try XCTUnwrap(delta.changes.first) else {
      return XCTFail("catalog change lost exact removed variant")
    }
    XCTAssertEqual(conversationID.rawValue, "conversation-removed")
    await harness.session.close()
  }

  func testMalformedTransferFailsClosedAndLatchesExactCode() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: [
        "61111111-1111-4111-8111-111111111111",
        "62222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let pending = Task { try await harness.session.request(.catalog(pageCursor: nil)) }
    let request = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeTransfer(
      channel: .reply,
      messageID: request.messageID.rawValue,
      transferID: "malformed-transfer",
      payload: Data(#"{"future":true}"#.utf8),
      to: connection
    )
    do {
      _ = try await pending.value
      XCTFail("malformed transfer payload was accepted")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.transfer_invalid")
    }
    do {
      _ = try await harness.session.request(.catalog(pageCursor: nil))
      XCTFail("facade fault was not latched")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.transfer_invalid")
    }
    let latchedFault = await harness.session.fault()
    XCTAssertEqual(latchedFault?.code, "daemon.client.transfer_invalid")
  }

  func testFacadeOwnsExactlyOneNextStreamWaiter() async throws {
    let gate = LocalRuntimeWireGate()
    let harness = try LocalRuntimeWireHarness(
      messageIDs: ["71111111-1111-4111-8111-111111111111"],
      beforeStreamRead: { await gate.enterAndWait() }
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let first = Task { try await harness.session.nextStream() }
    await gate.waitUntilEntered()
    do {
      _ = try await harness.session.nextStream()
      XCTFail("facade accepted a second stream owner")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.stream_consumer_duplicate")
    }
    await gate.release()
    do {
      _ = try await first.value
      XCTFail("first waiter did not observe the latched duplicate-owner fault")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.stream_consumer_duplicate")
    }
  }

  func testCloseOnlyClosesClientFDWithoutSendingShutdownRequest() async throws {
    let harness = try LocalRuntimeWireHarness(
      messageIDs: ["81111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    await harness.session.close()
    XCTAssertNil(try harness.peer.readLine(from: connection))
  }

  @MainActor
  func testSessionModelUsesFreshLocalWireForFirstActionAfterUDSEOF() async throws {
    let first = try LocalRuntimeWireHarness(
      messageIDs: [
        "91111111-1111-4111-8111-111111111111",
        "92222222-2222-4222-8222-222222222222",
        "93333333-3333-4333-8333-333333333333",
        "94444444-4444-4444-8444-444444444444",
      ]
    )
    let second = try LocalRuntimeWireHarness(
      messageIDs: [
        "a1111111-1111-4111-8111-111111111111",
        "a2222222-2222-4222-8222-222222222222",
        "a3333333-3333-4333-8333-333333333333",
        "a4444444-4444-4444-8444-444444444444",
      ]
    )
    let firstEOFGate = LocalRuntimeWireGate()
    let secondCompletionGate = LocalRuntimeWireGate()
    let sessions: [any AppRuntimeWireSession] = [first.session, second.session]
    var factoryConstructionCount = 0
    let model = SessionModel(runtimeWireFactory: {
      precondition(factoryConstructionCount < sessions.count)
      defer { factoryConstructionCount += 1 }
      return sessions[factoryConstructionCount]
    })
    defer {
      model.teardown()
      Task {
        await firstEOFGate.release()
        await secondCompletionGate.release()
      }
    }

    let firstPeer = first.peer
    let firstServer = Task.detached {
      try await localRuntimeServeInitialCatalogSession(
        peer: firstPeer,
        closeGate: firstEOFGate
      )
    }
    model.loadHistory()
    try await localRuntimeWaitUntilGateEntered(firstEOFGate)
    try await localRuntimeWaitUntil { !model.isLoadingHistory }
    XCTAssertNil(model.historyErrorMessage)
    XCTAssertEqual(factoryConstructionCount, 1)

    await firstEOFGate.release()
    try await firstServer.value
    try await localRuntimeWaitUntil {
      model.warningMessage == "Local daemon connection closed; the next action will reconnect"
    }
    let firstFault = await first.session.fault()
    XCTAssertEqual(firstFault?.code, "daemon.client.connection_closed")
    XCTAssertEqual(factoryConstructionCount, 1, "idle EOF must not hot-loop a replacement")

    let secondPeer = second.peer
    let secondServer = Task.detached {
      try await localRuntimeServeReconnectCatalogSession(
        peer: secondPeer,
        closeGate: secondCompletionGate
      )
    }
    model.loadHistory()
    try await localRuntimeWaitUntilGateEntered(secondCompletionGate)
    try await localRuntimeWaitUntil { !model.isLoadingHistory }

    XCTAssertNil(model.historyErrorMessage)
    XCTAssertEqual(factoryConstructionCount, 2)
    model.teardown()
    await secondCompletionGate.release()
    try await secondServer.value
  }
}

private func localRuntimeServeInitialCatalogSession(
  peer: LocalRuntimeWirePeer,
  closeGate: LocalRuntimeWireGate
) async throws {
  let connection = try peer.acceptRuntimeConnection()
  defer { Darwin.close(connection) }

  let describe = try peer.readRequest(from: connection)
  guard case .describeAgents = describe.request else {
    throw localRuntimeUnexpectedRequest("DescribeAgents")
  }
  try peer.writeReply(
    .agents(try RuntimeAgentDescriptionsV2(agents: [])),
    to: describe.envelope,
    on: connection
  )

  let catalog = try peer.readRequest(from: connection)
  guard case .catalog = catalog.request else {
    throw localRuntimeUnexpectedRequest("Catalog")
  }
  try peer.writeReply(
    .catalog(
      try RuntimeCatalogSnapshotV2(
        baseCatalogCursor: .beforeFirst,
        entries: [],
        nextPageCursor: nil
      )
    ),
    to: catalog.envelope,
    on: connection
  )

  try peer.replyToCatalogSynchronization(from: connection, expectsBackfill: false)
  await closeGate.enterAndWait()
}

private func localRuntimeServeReconnectCatalogSession(
  peer: LocalRuntimeWirePeer,
  closeGate: LocalRuntimeWireGate
) async throws {
  let connection = try peer.acceptRuntimeConnection()
  defer { Darwin.close(connection) }

  let describe = try peer.readRequest(from: connection)
  guard case .describeAgents = describe.request else {
    throw localRuntimeUnexpectedRequest("DescribeAgents after reconnect")
  }
  try peer.writeReply(
    .agents(try RuntimeAgentDescriptionsV2(agents: [])),
    to: describe.envelope,
    on: connection
  )

  try peer.replyToCatalogSynchronization(from: connection, expectsBackfill: false)
  try peer.replyToCatalogSynchronization(from: connection, expectsBackfill: true)
  await closeGate.enterAndWait()
}

@MainActor
private func localRuntimeWaitUntil(
  _ predicate: @escaping @MainActor () -> Bool
) async throws {
  for _ in 0..<400 {
    if predicate() { return }
    try await Task.sleep(for: .milliseconds(5))
  }
  throw RuntimeEnvelopeClientFailure(
    code: "test.timeout",
    message: "SessionModel did not reach the expected UDS state"
  )
}

private func localRuntimeWaitUntilGateEntered(_ gate: LocalRuntimeWireGate) async throws {
  for _ in 0..<400 {
    if await gate.hasEntered() { return }
    try await Task.sleep(for: .milliseconds(5))
  }
  throw RuntimeEnvelopeClientFailure(
    code: "test.timeout",
    message: "scripted UDS peer did not reach its completion gate"
  )
}

private func localRuntimeUnexpectedRequest(_ expected: String) -> RuntimeEnvelopeClientFailure {
  RuntimeEnvelopeClientFailure(
    code: "test.unexpected_request",
    message: "expected \(expected) Runtime request"
  )
}

private struct LocalRuntimeWireHarness {
  let peer: LocalRuntimeWirePeer
  let session: LocalRuntimeWireSession

  init(
    messageIDs: [String],
    beforeStreamRead: @escaping @Sendable () async -> Void = {}
  ) throws {
    peer = try LocalRuntimeWirePeer()
    let ids = LocalRuntimeWireMessageIDs(messageIDs)
    let client = RuntimeEnvelopeClient(
      transport: UnixSocketDaemonTransport(testSocketPath: peer.socketPath),
      installationID: UUID(),
      messageIDGenerator: { ids.next() }
    )
    session = LocalRuntimeWireSession(
      client: client,
      beforeStreamRead: beforeStreamRead
    )
  }

  func startAndAccept() async throws -> Int32 {
    let server = Task.detached { () throws -> Int32 in
      let connection = try peer.acceptConnection()
      _ = try peer.readLine(from: connection)
      let hello = try peer.readEnvelope(from: connection)
      try peer.writeEnvelope(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: hello.messageID,
          body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
        ),
        to: connection
      )
      return connection
    }
    try await session.start()
    return try await server.value
  }

  func waitForFault() async throws -> RuntimeEnvelopeClientFailure {
    for _ in 0..<200 {
      if let fault = await session.fault() { return fault }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw RuntimeEnvelopeClientFailure(
      code: "test.timeout",
      message: "wire session fault did not arrive"
    )
  }
}

private final class LocalRuntimeWireMessageIDs: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String]

  init(_ values: [String]) { self.values = values }

  func next() -> String {
    lock.withLock {
      precondition(!values.isEmpty, "test messageId sequence exhausted")
      return values.removeFirst()
    }
  }
}

private actor LocalRuntimeWireGate {
  private var entered = false
  private var enterWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func enterAndWait() async {
    entered = true
    let waiters = enterWaiters
    enterWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func waitUntilEntered() async {
    if entered { return }
    await withCheckedContinuation { enterWaiters.append($0) }
  }

  func hasEntered() -> Bool { entered }

  func release() {
    let waiters = releaseWaiters
    releaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
  }
}

private enum LocalRuntimeWireTransferChannel {
  case reply
  case stream
}

private final class LocalRuntimeWirePeer: @unchecked Sendable {
  let rootPath: String
  let socketPath: String
  private let listener: Int32

  init() throws {
    rootPath = "/tmp/ad-wire-session-\(UUID().uuidString.prefix(12).lowercased())"
    guard mkdir(rootPath, 0o700) == 0 else { throw Self.posixError() }
    socketPath = rootPath + "/s"
    listener = try Self.makeListener(path: socketPath)
  }

  deinit {
    Darwin.close(listener)
    unlink(socketPath)
    try? FileManager.default.removeItem(atPath: rootPath)
  }

  func acceptConnection() throws -> Int32 {
    try Self.wait(fd: listener, events: Int16(POLLIN))
    let connection = accept(listener, nil, nil)
    guard connection >= 0 else { throw Self.posixError() }
    return connection
  }

  func acceptRuntimeConnection() throws -> Int32 {
    let connection = try acceptConnection()
    do {
      _ = try readLine(from: connection)
      let hello = try readEnvelope(from: connection)
      guard case .request(.hello(let version)) = hello.body,
        version == runtimeProtocolVersionCurrent
      else {
        throw localRuntimeUnexpectedRequest("Hello")
      }
      try writeEnvelope(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: hello.messageID,
          body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
        ),
        to: connection
      )
      return connection
    } catch {
      Darwin.close(connection)
      throw error
    }
  }

  func readRequest(
    from descriptor: Int32
  ) throws -> (envelope: RuntimeEnvelopeV2, request: RuntimeRequestV2) {
    let envelope = try readEnvelope(from: descriptor)
    guard case .request(let request) = envelope.body else {
      throw localRuntimeUnexpectedRequest("request envelope")
    }
    return (envelope, request)
  }

  func writeReply(
    _ reply: RuntimeReplyV2,
    to request: RuntimeEnvelopeV2,
    on descriptor: Int32
  ) throws {
    try writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: request.messageID,
        body: .reply(reply)
      ),
      to: descriptor
    )
  }

  func replyToCatalogSynchronization(
    from descriptor: Int32,
    expectsBackfill: Bool
  ) throws {
    let synchronization = try readRequest(from: descriptor)
    let cursor: RuntimeStreamCursorV1
    if expectsBackfill {
      guard case .backfill(.catalog(let backfillCursor)) = synchronization.request else {
        throw localRuntimeUnexpectedRequest("Catalog Backfill")
      }
      cursor = backfillCursor
    } else {
      guard case .subscribe(let innerCursor) = synchronization.request,
        case .catalog(let catalogCursor) = innerCursor
      else {
        throw localRuntimeUnexpectedRequest("Catalog Subscribe")
      }
      cursor = catalogCursor
      try writeReply(
        .subscription(
          .subscribed(
            streamGeneration: RuntimeStreamGeneration(rawValue: "generation-uds-eof")
          )
        ),
        to: synchronization.envelope,
        on: descriptor
      )
    }
    try writeReply(
      .syncComplete(try localRuntimeCatalogSyncComplete(cursor: cursor)),
      to: synchronization.envelope,
      on: descriptor
    )
  }

  func readLine(from descriptor: Int32) throws -> String? {
    var data = Data()
    while true {
      try Self.wait(fd: descriptor, events: Int16(POLLIN | POLLHUP))
      var byte: UInt8 = 0
      let count = Darwin.read(descriptor, &byte, 1)
      if count == 0 { return data.isEmpty ? nil : String(data: data, encoding: .utf8) }
      if count < 0 {
        if errno == EINTR { continue }
        throw Self.posixError()
      }
      if byte == 0x0A { return String(data: data, encoding: .utf8) }
      data.append(byte)
    }
  }

  func readEnvelope(from descriptor: Int32) throws -> RuntimeEnvelopeV2 {
    let line = try XCTUnwrap(readLine(from: descriptor))
    return try RuntimeV2WireCodec.decodeEnvelope(Data(line.utf8))
  }

  func writeEnvelope(_ envelope: RuntimeEnvelopeV2, to descriptor: Int32) throws {
    var data = try RuntimeV2WireCodec.encode(envelope)
    data.append(0x0A)
    try write(data, to: descriptor)
  }

  func writeRawReply(
    messageID: String,
    payload: [String: Any],
    to descriptor: Int32
  ) throws {
    let object: [String: Any] = [
      "version": runtimeProtocolVersionCurrent,
      "messageId": messageID,
      "body": ["message": "reply", "payload": payload],
    ]
    var data = try localRuntimeJSONData(object)
    data.append(0x0A)
    try write(data, to: descriptor)
  }

  func writeTransfer(
    channel: LocalRuntimeWireTransferChannel,
    messageID: String,
    transferID: String,
    payload: Data,
    to descriptor: Int32
  ) throws {
    let transfer = try TransferEnvelopeV2(
      transferID: RuntimeTransferID(rawValue: transferID),
      partIndex: 0,
      partCount: 1,
      totalSHA256: Data(SHA256.hash(data: payload)),
      totalBytes: UInt64(payload.count),
      part: payload
    )
    let body: RuntimeMessageV2 =
      switch channel {
      case .reply: .reply(.transferPart(transfer))
      case .stream: .stream(.transferPart(transfer))
      }
    try writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: messageID),
        body: body
      ),
      to: descriptor
    )
  }

  private func write(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return }
      var offset = 0
      while offset < raw.count {
        let count = Darwin.write(
          descriptor,
          base.advanced(by: offset),
          raw.count - offset
        )
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
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw posixError() }
    do {
      var address = try unixAddress(path: path)
      let status = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
      }
      guard status == 0, chmod(path, 0o600) == 0, listen(descriptor, 8) == 0 else {
        throw posixError()
      }
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  private static func unixAddress(path: String) throws -> sockaddr_un {
    guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
      throw RuntimeEnvelopeClientFailure(
        code: "test.path_too_long",
        message: "test socket path is too long"
      )
    }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
      raw.initializeMemory(as: UInt8.self, repeating: 0)
      raw.copyBytes(from: path.utf8)
    }
    return address
  }

  private static func wait(fd: Int32, events: Int16) throws {
    var descriptor = pollfd(fd: fd, events: events, revents: 0)
    while true {
      let status = Darwin.poll(&descriptor, 1, 5_000)
      if status > 0 { return }
      if status < 0, errno == EINTR { continue }
      if status == 0 {
        throw RuntimeEnvelopeClientFailure(
          code: "test.timeout",
          message: "test socket operation timed out"
        )
      }
      throw posixError()
    }
  }

  private static func posixError() -> Error {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
}

private func localRuntimeJSONData(_ object: Any) throws -> Data {
  try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func localRuntimeCatalogSyncComplete(
  cursor: RuntimeStreamCursorV1
) throws -> RuntimeSyncCompleteV1 {
  let cursorObject: Any =
    switch cursor {
    case .beforeFirst: "beforeFirst"
    case .at(let sequence): ["at": sequence]
    }
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: try localRuntimeJSONData([
      "streamGeneration": "generation-uds-eof",
      "streamCursor": cursorObject,
      "innerCursor": [
        "scope": "catalog",
        "cursor": cursorObject,
      ],
      "keyDirectoryRevision": 0,
    ])
  )
}
