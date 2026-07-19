import AgentDeckCore
import CryptoKit
import Darwin
import Foundation
import XCTest

@testable import AgentDeck

final class RuntimeEnvelopeClientTests: XCTestCase {
  func testStartSendsCanonicalHelloFirstAndPreservesInstallationIdentity() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: ["11111111-1111-4111-8111-111111111111"]
    )
    let start = Task { try await harness.client.start() }
    let connection = try harness.peer.acceptConnection()
    defer { Darwin.close(connection) }

    let preface = try XCTUnwrap(harness.peer.readJSONObject(from: connection))
    XCTAssertEqual(preface["localProtocolVersion"] as? Int, 1)
    XCTAssertEqual(
      preface["clientInstallationId"] as? String,
      harness.installationID.uuidString.lowercased()
    )
    let hello = try harness.peer.readEnvelope(from: connection)
    XCTAssertEqual(hello.messageID.rawValue, "11111111-1111-4111-8111-111111111111")
    guard case .request(.hello(let version)) = hello.body else {
      return XCTFail("first application frame must be Hello")
    }
    XCTAssertEqual(version, runtimeProtocolVersionCurrent)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: hello.messageID,
        body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
      ),
      to: connection
    )
    try await start.value
    let currentInstallationID = await harness.client.currentInstallationID()
    XCTAssertEqual(currentInstallationID, harness.installationID.uuidString.lowercased())
    await harness.client.close()
  }

  func testHelloCannotReviveClientClosedDuringAwaitReentrancy() async throws {
    let gate = RuntimeClientAsyncGate()
    await gate.arm()
    let harness = try RuntimeClientHarness(
      messageIDs: ["1a111111-1111-4111-8111-111111111111"],
      beforeHelloReady: { await gate.waitIfArmed() }
    )
    let start = Task { try await harness.client.start() }
    let connection = try harness.peer.acceptConnection()
    defer { Darwin.close(connection) }
    _ = try harness.peer.readLine(from: connection)
    let hello = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: hello.messageID,
        body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
      ),
      to: connection
    )
    await gate.waitUntilEntered()
    await harness.client.close()
    await gate.release()

    do {
      try await start.value
      XCTFail("close during Hello continuation must prevent Ready resurrection")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.connection_closed")
    }
    do {
      _ = try await harness.client.beginRequest(.describeAgents)
      XCTFail("closed client must remain non-ready")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.connection_closed")
    }
  }

  func testConcurrentUnaryRepliesCorrelateExactlyWhenServerRepliesInReverse() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "21111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "23333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    async let helloResult = harness.client.request(
      RuntimeRequestV2.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent)
    )
    async let catalogResult = harness.client.request(
      RuntimeRequestV2.catalog(pageCursor: nil)
    )
    let first = try harness.peer.readEnvelope(from: connection)
    let second = try harness.peer.readEnvelope(from: connection)
    let requests = [first, second]
    let helloRequest = try XCTUnwrap(
      requests.first { envelope in
        if case .request(.hello) = envelope.body { return true }
        return false
      })
    let catalogRequest = try XCTUnwrap(
      requests.first { envelope in
        if case .request(.catalog) = envelope.body { return true }
        return false
      })

    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: catalogRequest.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.catalog",
              message: "catalog terminal",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: helloRequest.messageID,
        body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
      ),
      to: connection
    )

    guard case .reply(.hello(let version)) = try await helloResult else {
      return XCTFail("Hello request received another messageId reply")
    }
    XCTAssertEqual(version, runtimeProtocolVersionCurrent)
    guard case .reply(.failure(let failure)) = try await catalogResult else {
      return XCTFail("Catalog request received another messageId reply")
    }
    XCTAssertEqual(failure.code, "test.catalog")
    await harness.client.close()
  }

  func testSubscribeAndBackfillSequencesRequireExplicitTerminal() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "31111111-1111-4111-8111-111111111111",
        "32222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    let subscribe = try await harness.client.beginRequest(
      .subscribe(innerCursor: .catalog(cursor: .beforeFirst))
    )
    let subscribeRequest = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeRawEnvelope(
      messageID: subscribeRequest.messageID.rawValue,
      payload: [
        "reply": "subscription",
        "status": "subscribed",
        "streamGeneration": "generation-1",
      ],
      to: connection
    )
    try harness.peer.writeRawEnvelope(
      messageID: subscribeRequest.messageID.rawValue,
      payload: RuntimeClientTestPeer.syncCompletePayload(generation: "generation-1"),
      to: connection
    )
    guard case .reply(.subscription) = try await subscribe.next() else {
      return XCTFail("subscription receipt must be nonterminal")
    }
    guard case .reply(.syncComplete) = try await subscribe.next() else {
      return XCTFail("SyncComplete must terminate Subscribe")
    }
    let afterSubscribeTerminal = try await subscribe.next()
    XCTAssertNil(afterSubscribeTerminal)

    let backfill = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let backfillRequest = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: backfillRequest.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.backfill.terminal",
              message: "typed terminal",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    guard case .reply(.failure(let failure)) = try await backfill.next() else {
      return XCTFail("Failure must terminate Backfill")
    }
    XCTAssertEqual(failure.code, "test.backfill.terminal")
    let afterBackfillTerminal = try await backfill.next()
    XCTAssertNil(afterBackfillTerminal)
    await harness.client.close()
  }

  func testSynchronousDropTokenDrainsNineFrameBurstWithoutFalseBackpressure() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "3a111111-1111-4111-8111-111111111111",
        "3a222222-2222-4222-8222-222222222222",
        "3a333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    var sequence: RuntimeEnvelopeReplySequence? = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let droppedRequest = try harness.peer.readEnvelope(from: connection)
    sequence = nil
    XCTAssertNil(sequence)

    for index in 0..<9 {
      try harness.peer.writeRawEnvelope(
        messageID: droppedRequest.messageID.rawValue,
        payload: [
          "reply": "subscription",
          "status": "subscribed",
          "streamGeneration": "drop-burst-\(index)",
        ],
        to: connection
      )
    }
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: droppedRequest.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.drop.terminal",
              message: "drained terminal",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    try await Task.sleep(for: .milliseconds(25))
    let burstFault = await harness.client.fault()
    XCTAssertNil(burstFault)

    let proof = Task { try await harness.client.request(.describeAgents) }
    let proofRequest = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: proofRequest.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.connection.still.alive",
              message: "alive",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    guard case .reply(.failure(let terminal)) = try await proof.value else {
      return XCTFail("connection did not survive dropped sequence burst")
    }
    XCTAssertEqual(terminal.code, "test.connection.still.alive")
    await harness.client.close()
  }

  func testEOFFailsSequenceBeforeTerminalAndDoesNotReturnCleanNil() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "41111111-1111-4111-8111-111111111111",
        "42222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    let sequence = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    _ = try harness.peer.readEnvelope(from: connection)
    XCTAssertEqual(shutdown(connection, SHUT_RDWR), 0)
    Darwin.close(connection)

    do {
      _ = try await sequence.next()
      XCTFail("EOF before terminal must be typed failure")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.connection_closed")
    }
    let clientFault = await harness.client.fault()
    XCTAssertEqual(clientFault?.code, "daemon.client.connection_closed")
  }

  func testTerminalFrameImmediatelyBeforeEOFIsDeliveredBeforeDisconnectFault() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "4a111111-1111-4111-8111-111111111111",
        "4a222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    let request = Task { try await harness.client.request(.describeAgents) }
    let outbound = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: outbound.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.terminal.before.eof",
              message: "terminal wins wire order",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    XCTAssertEqual(shutdown(connection, SHUT_RDWR), 0)
    Darwin.close(connection)
    guard case .reply(.failure(let terminal)) = try await request.value else {
      return XCTFail("terminal was skipped by later EOF")
    }
    XCTAssertEqual(terminal.code, "test.terminal.before.eof")
    let eventualFault = try await harness.waitForFault()
    XCTAssertEqual(eventualFault.code, "daemon.client.connection_closed")
  }

  func testQueuedTerminalAndStreamRemainConsumableAfterFollowingEOF() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "4b111111-1111-4111-8111-111111111111",
        "4b222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    let sequence = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let outbound = try harness.peer.readEnvelope(from: connection)
    try harness.peer.writeEnvelope(
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: outbound.messageID,
        body: .reply(
          .failure(
            RuntimeFailureV1(
              code: "test.queued.before.eof",
              message: "retained terminal",
              diagnosticRef: nil
            )
          )
        )
      ),
      to: connection
    )
    try harness.peer.writeStreamTransfer(
      messageID: "queued-stream-before-eof",
      transferID: "queued-stream-before-eof-transfer",
      bytes: Data("retained-stream".utf8),
      to: connection
    )
    XCTAssertEqual(shutdown(connection, SHUT_RDWR), 0)
    Darwin.close(connection)
    let fault = try await harness.waitForFault()
    XCTAssertEqual(fault.code, "daemon.client.connection_closed")

    guard case .reply(.failure(let terminal)) = try await sequence.next() else {
      return XCTFail("queued terminal was erased by later EOF")
    }
    XCTAssertEqual(terminal.code, "test.queued.before.eof")
    let stream = try await harness.client.nextStream()
    guard case .transferComplete(let bytes) = stream.item else {
      return XCTFail("queued stream was erased by later EOF")
    }
    XCTAssertEqual(bytes, Data("retained-stream".utf8))
  }

  func testBoundedStreamQueueFailsClosedOnOverflow() async throws {
    let limits = RuntimeEnvelopeClientLimits(streamFrames: 1)
    let harness = try RuntimeClientHarness(
      limits: limits,
      messageIDs: ["51111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    try harness.peer.writeStreamTransfer(
      messageID: "stream-1",
      transferID: "transfer-stream-1",
      bytes: Data("one".utf8),
      to: connection
    )
    try harness.peer.writeStreamTransfer(
      messageID: "stream-2",
      transferID: "transfer-stream-2",
      bytes: Data("two".utf8),
      to: connection
    )
    let failure = try await harness.waitForFault()
    XCTAssertEqual(failure.code, "daemon.client.stream_backpressure")
  }

  func testDroppedDisconnectKeepsExactTransportCodeAndIngressOverflowWinsImmediately()
    async throws
  {
    do {
      let gate = RuntimeClientAsyncGate()
      let limits = RuntimeEnvelopeClientLimits(
        queuedReplyFrames: 1,
        streamFrames: 1
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: ["5b111111-1111-4111-8111-111111111111"],
        beforeIngressConsume: { await gate.waitIfArmed() }
      )
      let connection = try await harness.startAndAccept()
      await gate.arm()
      try harness.peer.writeStreamTransfer(
        messageID: "disconnect-head",
        transferID: "disconnect-head-transfer",
        bytes: Data("head".utf8),
        to: connection
      )
      await gate.waitUntilEntered()
      for index in 0..<3 {
        try harness.peer.writeStreamTransfer(
          messageID: "disconnect-buffer-\(index)",
          transferID: "disconnect-buffer-transfer-\(index)",
          bytes: Data("buffer".utf8),
          to: connection
        )
      }
      try harness.peer.write(Data([0xC3, 0x28, 0x0A]), to: connection)
      let latched = try await harness.waitForFault()
      XCTAssertEqual(latched.code, "daemon.client.frame_invalid_utf8")
      await gate.release()
      let consumed = try await harness.waitForFault()
      XCTAssertEqual(consumed.code, "daemon.client.frame_invalid_utf8")
      Darwin.close(connection)
    }

    do {
      let gate = RuntimeClientAsyncGate()
      let limits = RuntimeEnvelopeClientLimits(
        queuedReplyFrames: 1,
        streamFrames: 1
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: ["5b222222-2222-4222-8222-222222222222"],
        beforeIngressConsume: { await gate.waitIfArmed() }
      )
      let connection = try await harness.startAndAccept()
      await gate.arm()
      try harness.peer.writeStreamTransfer(
        messageID: "overflow-head",
        transferID: "overflow-head-transfer",
        bytes: Data("head".utf8),
        to: connection
      )
      await gate.waitUntilEntered()
      try harness.peer.writeEnvelope(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: RuntimeMessageID(rawValue: "later-malicious-request"),
          body: .request(.describeAgents)
        ),
        to: connection
      )
      for index in 0..<3 {
        try harness.peer.writeStreamTransfer(
          messageID: "overflow-buffer-\(index)",
          transferID: "overflow-buffer-transfer-\(index)",
          bytes: Data("buffer".utf8),
          to: connection
        )
      }
      let latched = try await harness.waitForFault()
      XCTAssertEqual(latched.code, "daemon.client.reply_backpressure")
      await gate.release()
      let consumed = try await harness.waitForFault()
      XCTAssertEqual(consumed.code, "daemon.client.reply_backpressure")
      Darwin.close(connection)
    }
  }

  func testStreamRetainedByteBudgetAllowsTwoTransfersThenRejectsTheNextByte() async throws {
    let limits = RuntimeEnvelopeClientLimits(
      streamFrames: 64,
      queuedStreamBytes: 6
    )
    let harness = try RuntimeClientHarness(
      limits: limits,
      messageIDs: ["5a111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }

    try harness.peer.writeStreamTransfer(
      messageID: "stream-byte-1",
      transferID: "stream-byte-transfer-1",
      bytes: Data("aaa".utf8),
      to: connection
    )
    try harness.peer.writeStreamTransfer(
      messageID: "stream-byte-2",
      transferID: "stream-byte-transfer-2",
      bytes: Data("bbb".utf8),
      to: connection
    )
    try harness.peer.writeStreamTransfer(
      messageID: "stream-byte-3",
      transferID: "stream-byte-transfer-3",
      bytes: Data("c".utf8),
      to: connection
    )
    let failure = try await harness.waitForFault()
    XCTAssertEqual(failure.code, "daemon.client.stream_backpressure")
  }

  func testServerRequestUncorrelatedReplyAndSecondTerminalFailClosed() async throws {
    try await assertProtocolFault(expected: "daemon.client.server_request_forbidden") {
      messageID in
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: messageID),
        body: .request(.describeAgents)
      )
    }
    try await assertProtocolFault(expected: "daemon.client.reply_uncorrelated") {
      messageID in
      RuntimeEnvelopeV2(
        version: runtimeProtocolVersionCurrent,
        messageID: RuntimeMessageID(rawValue: messageID),
        body: .reply(.hello(runtimeProtocolVersion: runtimeProtocolVersionCurrent))
      )
    }

    let harness = try RuntimeClientHarness(
      messageIDs: [
        "61111111-1111-4111-8111-111111111111",
        "62222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    let request = Task { try await harness.client.request(.describeAgents) }
    let outbound = try harness.peer.readEnvelope(from: connection)
    let terminal = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: outbound.messageID,
      body: .reply(
        .failure(
          RuntimeFailureV1(
            code: "test.first",
            message: "first terminal",
            diagnosticRef: nil
          )
        )
      )
    )
    try harness.peer.writeEnvelope(terminal, to: connection)
    _ = try await request.value
    try harness.peer.writeEnvelope(terminal, to: connection)
    let secondTerminalFault = try await harness.waitForFault()
    XCTAssertEqual(secondTerminalFault.code, "daemon.client.reply_uncorrelated")
  }

  func testReplyAndStreamTransfersReassembleOutOfOrderWithExactBinding() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: [
        "71111111-1111-4111-8111-111111111111",
        "72222222-2222-4222-8222-222222222222",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    let sequence = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let outbound = try harness.peer.readEnvelope(from: connection)
    let replyBytes = Data("reply-transfer-body".utf8)
    try harness.peer.writeTransferParts(
      channel: .reply,
      messageID: outbound.messageID.rawValue,
      transferID: "reply-transfer",
      bytes: replyBytes,
      reverse: true,
      to: connection
    )
    try harness.peer.writeRawEnvelope(
      messageID: outbound.messageID.rawValue,
      payload: RuntimeClientTestPeer.syncCompletePayload(generation: "transfer-generation"),
      to: connection
    )
    guard case .transferComplete(let receivedReply) = try await sequence.next() else {
      return XCTFail("reply transfer did not complete")
    }
    XCTAssertEqual(receivedReply, replyBytes)
    guard case .reply(.syncComplete) = try await sequence.next() else {
      return XCTFail("reply transfer sequence did not reach SyncComplete")
    }

    let streamBytes = Data("stream-transfer-body".utf8)
    try harness.peer.writeTransferParts(
      channel: .stream,
      messageID: "stream-transfer-message",
      transferID: "stream-transfer",
      bytes: streamBytes,
      reverse: true,
      to: connection
    )
    let stream = try await harness.client.nextStream()
    guard case .transferComplete(let receivedStream) = stream.item else {
      return XCTFail("stream transfer did not complete")
    }
    XCTAssertEqual(receivedStream, streamBytes)
    await harness.client.close()
  }

  func testActiveAndCompletedTransferDuplicateConflictsFailClosed() async throws {
    do {
      let harness = try RuntimeClientHarness(
        messageIDs: [
          "7a111111-1111-4111-8111-111111111111",
          "7a222222-2222-4222-8222-222222222222",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let sequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let outbound = try harness.peer.readEnvelope(from: connection)
      let hash = Data(SHA256.hash(data: Data("ab".utf8)))
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "active-duplicate",
        index: 0,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("a".utf8),
        to: connection
      )
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "active-duplicate",
        index: 0,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("x".utf8),
        to: connection
      )
      let fault = try await harness.waitForFault()
      XCTAssertEqual(fault.code, "daemon.client.transfer_invalid")
      _ = sequence
    }

    do {
      let harness = try RuntimeClientHarness(
        messageIDs: [
          "7a333333-3333-4333-8333-333333333333",
          "7a444444-4444-4444-8444-444444444444",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let sequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let outbound = try harness.peer.readEnvelope(from: connection)
      let original = Data("abc".utf8)
      let metadataHash = Data(SHA256.hash(data: original))
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "completed-duplicate",
        index: 0,
        count: 1,
        totalHash: metadataHash,
        totalBytes: 3,
        part: original,
        to: connection
      )
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "completed-duplicate",
        index: 0,
        count: 1,
        totalHash: metadataHash,
        totalBytes: 3,
        part: Data("xyz".utf8),
        to: connection
      )
      let fault = try await harness.waitForFault()
      XCTAssertEqual(fault.code, "daemon.client.transfer_invalid")
      _ = sequence
    }
  }

  func testAssemblyPeakIncludesCachedPartsAndTheAssemblyCopy() async throws {
    let limits = RuntimeEnvelopeClientLimits(reassemblyBytes: 5)
    let harness = try RuntimeClientHarness(
      limits: limits,
      messageIDs: [
        "7b111111-1111-4111-8111-111111111111",
        "7b222222-2222-4222-8222-222222222222",
        "7b333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    let first = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let second = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    let firstOutbound = try harness.peer.readEnvelope(from: connection)
    let secondOutbound = try harness.peer.readEnvelope(from: connection)
    let firstBody = Data("aabb".utf8)
    try harness.peer.writeTransferPart(
      channel: .reply,
      messageID: firstOutbound.messageID.rawValue,
      transferID: "assembly-other",
      index: 0,
      count: 2,
      totalHash: Data(SHA256.hash(data: firstBody)),
      totalBytes: 4,
      part: Data("aa".utf8),
      to: connection
    )
    let secondBody = Data("cc".utf8)
    try harness.peer.writeTransferPart(
      channel: .reply,
      messageID: secondOutbound.messageID.rawValue,
      transferID: "assembly-completing",
      index: 0,
      count: 1,
      totalHash: Data(SHA256.hash(data: secondBody)),
      totalBytes: 2,
      part: secondBody,
      to: connection
    )
    _ = first
    _ = second
    let fault = try await harness.waitForFault()
    XCTAssertEqual(fault.code, "daemon.client.transfer_backpressure")
  }

  func testTransferHashBindingPartBudgetAndTTLFailClosed() async throws {
    do {
      let harness = try RuntimeClientHarness(
        messageIDs: [
          "81111111-1111-4111-8111-111111111111",
          "82222222-2222-4222-8222-222222222222",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      _ = try await harness.client.beginRequest(.backfill(.catalog(after: .beforeFirst)))
      let outbound = try harness.peer.readEnvelope(from: connection)
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "bad-hash",
        index: 0,
        count: 1,
        totalHash: Data(repeating: 0, count: 32),
        totalBytes: 3,
        part: Data("bad".utf8),
        to: connection
      )
      let hashFault = try await harness.waitForFault()
      XCTAssertEqual(hashFault.code, "daemon.client.transfer_invalid")
    }

    do {
      let limits = RuntimeEnvelopeClientLimits(activeTransferParts: 1)
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "83333333-3333-4333-8333-333333333333",
          "84444444-4444-4444-8444-444444444444",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      _ = try await harness.client.beginRequest(.backfill(.catalog(after: .beforeFirst)))
      let outbound = try harness.peer.readEnvelope(from: connection)
      let body = Data("ab".utf8)
      let hash = Data(SHA256.hash(data: body))
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "part-budget",
        index: 0,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("a".utf8),
        to: connection
      )
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "part-budget",
        index: 1,
        count: 2,
        totalHash: hash,
        totalBytes: 2,
        part: Data("b".utf8),
        to: connection
      )
      let partFault = try await harness.waitForFault()
      XCTAssertEqual(partFault.code, "daemon.client.transfer_backpressure")
    }

    do {
      let clock = RuntimeClientTestClock()
      let limits = RuntimeEnvelopeClientLimits(
        replyTimeoutMilliseconds: 10_000,
        transferTTLMilliseconds: 10,
        housekeepingMilliseconds: 5
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "85555555-5555-4555-8555-555555555555",
          "86666666-6666-4666-8666-666666666666",
        ],
        nowMilliseconds: { clock.value }
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      _ = try await harness.client.beginRequest(.backfill(.catalog(after: .beforeFirst)))
      let outbound = try harness.peer.readEnvelope(from: connection)
      let body = Data("ab".utf8)
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "ttl-transfer",
        index: 0,
        count: 2,
        totalHash: Data(SHA256.hash(data: body)),
        totalBytes: 2,
        part: Data("a".utf8),
        to: connection
      )
      try await Task.sleep(for: .milliseconds(10))
      clock.advance(to: 10)
      let transferTTL = try await harness.waitForFault()
      XCTAssertEqual(transferTTL.code, "daemon.client.transfer_expired")
    }
  }

  func testPendingPerSequenceGlobalReplyAndDrainingBoundsAreTyped() async throws {
    let limits = RuntimeEnvelopeClientLimits(
      pendingRequests: 1,
      perSequenceFrames: 1,
      queuedReplyFrames: 1,
      queuedReplyBytes: 1_024
    )
    let harness = try RuntimeClientHarness(
      limits: limits,
      messageIDs: [
        "91111111-1111-4111-8111-111111111111",
        "92222222-2222-4222-8222-222222222222",
        "93333333-3333-4333-8333-333333333333",
      ]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    let first = try await harness.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    _ = try harness.peer.readEnvelope(from: connection)
    do {
      _ = try await harness.client.beginRequest(.describeAgents)
      XCTFail("pending request bound must reject the second request")
    } catch let failure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(failure.code, "daemon.client.reply_backpressure")
    }
    _ = first
    await harness.client.close()

    let clock = RuntimeClientTestClock()
    let drainingLimits = RuntimeEnvelopeClientLimits(
      replyTimeoutMilliseconds: 10_000,
      drainTTLMilliseconds: 10,
      housekeepingMilliseconds: 5
    )
    let draining = try RuntimeClientHarness(
      limits: drainingLimits,
      messageIDs: [
        "94444444-4444-4444-8444-444444444444",
        "95555555-5555-4555-8555-555555555555",
      ],
      nowMilliseconds: { clock.value }
    )
    let drainingConnection = try await draining.startAndAccept()
    defer { Darwin.close(drainingConnection) }
    var dropped: RuntimeEnvelopeReplySequence? = try await draining.client.beginRequest(
      .backfill(.catalog(after: .beforeFirst))
    )
    _ = try draining.peer.readEnvelope(from: drainingConnection)
    dropped = nil
    XCTAssertNil(dropped)
    try await Task.sleep(for: .milliseconds(10))
    clock.advance(to: 10)
    let drainingFault = try await draining.waitForFault()
    XCTAssertEqual(drainingFault.code, "daemon.client.reply_drain_expired")
  }

  func testReplyQueueExactEightAndGlobalFrameByteBounds() async throws {
    do {
      let limits = RuntimeEnvelopeClientLimits(
        perSequenceFrames: 8,
        queuedReplyFrames: 16
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9a111111-1111-4111-8111-111111111111",
          "9a222222-2222-4222-8222-222222222222",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let sequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let outbound = try harness.peer.readEnvelope(from: connection)
      for index in 0..<8 {
        try harness.peer.writeRawEnvelope(
          messageID: outbound.messageID.rawValue,
          payload: [
            "reply": "subscription", "status": "subscribed",
            "streamGeneration": "exact-eight-\(index)",
          ],
          to: connection
        )
      }
      try await Task.sleep(for: .milliseconds(20))
      let exactEightFault = await harness.client.fault()
      XCTAssertNil(exactEightFault)
      try harness.peer.writeRawEnvelope(
        messageID: outbound.messageID.rawValue,
        payload: [
          "reply": "subscription", "status": "subscribed",
          "streamGeneration": "ninth",
        ],
        to: connection
      )
      let ninthFault = try await harness.waitForFault()
      XCTAssertEqual(ninthFault.code, "daemon.client.reply_sequence_backpressure")
      _ = sequence
    }

    do {
      let limits = RuntimeEnvelopeClientLimits(
        queuedReplyFrames: 1
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9a333333-3333-4333-8333-333333333333",
          "9a444444-4444-4444-8444-444444444444",
          "9a555555-5555-4555-8555-555555555555",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let firstSequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let secondSequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let first = try harness.peer.readEnvelope(from: connection)
      let second = try harness.peer.readEnvelope(from: connection)
      for outbound in [first, second] {
        try harness.peer.writeRawEnvelope(
          messageID: outbound.messageID.rawValue,
          payload: [
            "reply": "subscription", "status": "subscribed",
            "streamGeneration": "global-frame",
          ],
          to: connection
        )
      }
      let globalFrameFault = try await harness.waitForFault()
      XCTAssertEqual(globalFrameFault.code, "daemon.client.reply_sequence_backpressure")
      _ = firstSequence
      _ = secondSequence
    }

    do {
      let limits = RuntimeEnvelopeClientLimits(queuedReplyBytes: 256)
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9a666666-6666-4666-8666-666666666666",
          "9a777777-7777-4777-8777-777777777777",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let sequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let outbound = try harness.peer.readEnvelope(from: connection)
      try harness.peer.writeEnvelope(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: outbound.messageID,
          body: .reply(
            .failure(
              RuntimeFailureV1(
                code: "test.large.failure",
                message: String(repeating: "x", count: 512),
                diagnosticRef: nil
              )
            )
          )
        ),
        to: connection
      )
      let globalByteFault = try await harness.waitForFault()
      XCTAssertEqual(globalByteFault.code, "daemon.client.reply_sequence_backpressure")
      _ = sequence
    }
  }

  func testWaitingReplyAndStreamStillConsumeRetainedBudgets() async throws {
    do {
      let limits = RuntimeEnvelopeClientLimits(queuedReplyBytes: 256)
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9b111111-1111-4111-8111-111111111111",
          "9b222222-2222-4222-8222-222222222222",
        ]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let waiting = Task { try await harness.client.request(.describeAgents) }
      let outbound = try harness.peer.readEnvelope(from: connection)
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "waiting-reply-transfer",
        index: 0,
        count: 1,
        totalHash: Data(SHA256.hash(data: Data(repeating: 0x41, count: 512))),
        totalBytes: 512,
        part: Data(repeating: 0x41, count: 512),
        to: connection
      )
      do {
        _ = try await waiting.value
        XCTFail("waiting reply must not bypass byte budget")
      } catch let failure as RuntimeEnvelopeClientFailure {
        XCTAssertEqual(failure.code, "daemon.client.reply_sequence_backpressure")
      }
    }

    do {
      let limits = RuntimeEnvelopeClientLimits(queuedStreamBytes: 256)
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: ["9b333333-3333-4333-8333-333333333333"]
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let waiting = Task { try await harness.client.nextStream() }
      try harness.peer.writeStreamTransfer(
        messageID: "waiting-stream",
        transferID: "waiting-stream-transfer",
        bytes: Data(repeating: 0x42, count: 512),
        to: connection
      )
      do {
        _ = try await waiting.value
        XCTFail("waiting stream must not bypass byte budget")
      } catch let failure as RuntimeEnvelopeClientFailure {
        XCTAssertEqual(failure.code, "daemon.client.stream_backpressure")
      }
    }
  }

  func testTerminalQueuedBeatsDeadlineAndClockRollbackDoesNotExpireTransfer() async throws {
    do {
      let clock = RuntimeClientTestClock()
      let limits = RuntimeEnvelopeClientLimits(
        replyTimeoutMilliseconds: 10,
        synchronizedReplyTimeoutMilliseconds: 10,
        housekeepingMilliseconds: 5
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9c111111-1111-4111-8111-111111111111",
          "9c222222-2222-4222-8222-222222222222",
        ],
        nowMilliseconds: { clock.value }
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      let sequence = try await harness.client.beginRequest(
        .backfill(.catalog(after: .beforeFirst))
      )
      let outbound = try harness.peer.readEnvelope(from: connection)
      try harness.peer.writeEnvelope(
        RuntimeEnvelopeV2(
          version: runtimeProtocolVersionCurrent,
          messageID: outbound.messageID,
          body: .reply(
            .failure(
              RuntimeFailureV1(
                code: "test.terminal.queued",
                message: "queued before deadline",
                diagnosticRef: nil
              )
            )
          )
        ),
        to: connection
      )
      try harness.peer.writeStreamTransfer(
        messageID: "terminal-queue-marker",
        transferID: "terminal-queue-marker-transfer",
        bytes: Data("marker".utf8),
        to: connection
      )
      _ = try await harness.client.nextStream()
      clock.advance(to: 20)
      try await Task.sleep(for: .milliseconds(15))
      let terminalDeadlineFault = await harness.client.fault()
      XCTAssertNil(terminalDeadlineFault)
      guard case .reply(.failure(let terminal)) = try await sequence.next() else {
        return XCTFail("queued terminal was lost after request deadline")
      }
      XCTAssertEqual(terminal.code, "test.terminal.queued")
      await harness.client.close()
    }

    do {
      let clock = RuntimeClientTestClock()
      clock.advance(to: 100)
      let limits = RuntimeEnvelopeClientLimits(
        synchronizedReplyTimeoutMilliseconds: 1_000,
        transferTTLMilliseconds: 10,
        housekeepingMilliseconds: 5
      )
      let harness = try RuntimeClientHarness(
        limits: limits,
        messageIDs: [
          "9c333333-3333-4333-8333-333333333333",
          "9c444444-4444-4444-8444-444444444444",
        ],
        nowMilliseconds: { clock.value }
      )
      let connection = try await harness.startAndAccept()
      defer { Darwin.close(connection) }
      _ = try await harness.client.beginRequest(.backfill(.catalog(after: .beforeFirst)))
      let outbound = try harness.peer.readEnvelope(from: connection)
      let body = Data("ab".utf8)
      try harness.peer.writeTransferPart(
        channel: .reply,
        messageID: outbound.messageID.rawValue,
        transferID: "rollback-transfer",
        index: 0,
        count: 2,
        totalHash: Data(SHA256.hash(data: body)),
        totalBytes: 2,
        part: Data("a".utf8),
        to: connection
      )
      try harness.peer.writeStreamTransfer(
        messageID: "rollback-marker",
        transferID: "rollback-marker-transfer",
        bytes: Data("marker".utf8),
        to: connection
      )
      _ = try await harness.client.nextStream()
      clock.advance(to: 90)
      try await Task.sleep(for: .milliseconds(15))
      let rollbackFault = await harness.client.fault()
      XCTAssertNil(rollbackFault)
      clock.advance(to: 111)
      let expiry = try await harness.waitForFault()
      XCTAssertEqual(expiry.code, "daemon.client.transfer_expired")
    }
  }

  func testIngressRetainedByteBudgetRejectsSecondReservedFrame() async throws {
    let gate = RuntimeClientAsyncGate()
    let incoming = RuntimeEnvelopeV2(
      version: runtimeProtocolVersionCurrent,
      messageID: RuntimeMessageID(rawValue: "retained-ingress"),
      body: .request(.describeAgents)
    )
    let encodedBytes = try RuntimeWireCodec.encode(incoming).count
    let limits = RuntimeEnvelopeClientLimits(
      queuedIngressBytes: encodedBytes * 2 - 1
    )
    let harness = try RuntimeClientHarness(
      limits: limits,
      messageIDs: [
        "9d111111-1111-4111-8111-111111111111",
        "9d222222-2222-4222-8222-222222222222",
      ],
      beforeIngressConsume: { await gate.waitIfArmed() }
    )
    let connection = try await harness.startAndAccept()
    await gate.arm()
    try harness.peer.writeEnvelope(incoming, to: connection)
    await gate.waitUntilEntered()
    try harness.peer.writeEnvelope(incoming, to: connection)
    let latchedFailure = try await harness.waitForFault()
    XCTAssertEqual(latchedFailure.code, "daemon.client.reply_backpressure")
    do {
      _ = try await harness.client.beginRequest(.describeAgents)
      XCTFail("latched ingress fault must reject a new request before actor consumption")
    } catch let requestFailure as RuntimeEnvelopeClientFailure {
      XCTAssertEqual(requestFailure, latchedFailure)
    }
    await gate.release()
    Darwin.close(connection)
  }

  func testCloseOnlyWritesNoShutdownFrameAndLeavesListenerReachable() async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: ["a1111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    await harness.client.close()
    XCTAssertNil(try harness.peer.readLine(from: connection))
    Darwin.close(connection)
    let second = try harness.peer.connectClient()
    Darwin.close(second)
  }

  func testFrozenProductionLimitsMatchRuntimeJSONContract() {
    XCTAssertEqual(RuntimeEnvelopeClient.maximumPendingRequests, 128)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumReplySequenceFrames, 8)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumQueuedReplyFrames, 128)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumQueuedReplyBytes, 128 * 1024 * 1024)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumStreamFrames, 64)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumQueuedStreamBytes, 128 * 1024 * 1024)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumQueuedIngressBytes, 16 * 1024 * 1024)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumTransferBytes, 64 * 1024 * 1024)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumTransferParts, 94)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumReassemblyBytes, 128 * 1024 * 1024)
    XCTAssertEqual(RuntimeEnvelopeClient.maximumActiveTransferParts, 128)
    XCTAssertEqual(TransferEnvelopeV2.maxJSONPartCount, 94)
    XCTAssertEqual(TransferEnvelopeV2.maxTotalBytes, 64 * 1024 * 1024)
  }

  private func assertProtocolFault(
    expected: String,
    envelope: (String) -> RuntimeEnvelopeV2
  ) async throws {
    let harness = try RuntimeClientHarness(
      messageIDs: ["b1111111-1111-4111-8111-111111111111"]
    )
    let connection = try await harness.startAndAccept()
    defer { Darwin.close(connection) }
    try harness.peer.writeEnvelope(
      envelope("uncorrelated-message"),
      to: connection
    )
    let fault = try await harness.waitForFault()
    XCTAssertEqual(fault.code, expected)
  }
}

private struct RuntimeClientHarness {
  let peer: RuntimeClientTestPeer
  let installationID: UUID
  let client: RuntimeEnvelopeClient

  init(
    limits: RuntimeEnvelopeClientLimits = .production,
    messageIDs: [String],
    nowMilliseconds: @escaping @Sendable () -> UInt64 = {
      UInt64(Date().timeIntervalSince1970 * 1_000)
    },
    beforeIngressConsume: @escaping @Sendable () async -> Void = {},
    beforeHelloReady: @escaping @Sendable () async -> Void = {}
  ) throws {
    peer = try RuntimeClientTestPeer()
    installationID = UUID()
    let generator = RuntimeClientMessageIDs(messageIDs)
    client = RuntimeEnvelopeClient(
      transport: UnixSocketDaemonTransport(testSocketPath: peer.socketPath),
      installationID: installationID,
      limits: limits,
      messageIDGenerator: { generator.next() },
      nowMilliseconds: nowMilliseconds,
      beforeIngressConsume: beforeIngressConsume,
      beforeHelloReady: beforeHelloReady
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
    try await client.start()
    return try await server.value
  }

  func waitForFault() async throws -> RuntimeEnvelopeClientFailure {
    for _ in 0..<200 {
      if let fault = await client.fault() { return fault }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw RuntimeEnvelopeClientFailure(
      code: "test.timeout",
      message: "client fault did not arrive"
    )
  }
}

private final class RuntimeClientMessageIDs: @unchecked Sendable {
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

private final class RuntimeClientTestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var milliseconds: UInt64 = 0

  var value: UInt64 { lock.withLock { milliseconds } }

  func advance(to value: UInt64) {
    lock.withLock { milliseconds = value }
  }
}

private actor RuntimeClientAsyncGate {
  private var armed = false
  private var entered = false
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func arm() {
    armed = true
    entered = false
  }

  func waitIfArmed() async {
    guard armed else { return }
    entered = true
    let waiters = enteredWaiters
    enteredWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      releaseWaiters.append(continuation)
    }
  }

  func waitUntilEntered() async {
    if entered { return }
    await withCheckedContinuation { continuation in
      enteredWaiters.append(continuation)
    }
  }

  func release() {
    armed = false
    let waiters = releaseWaiters
    releaseWaiters.removeAll(keepingCapacity: false)
    for waiter in waiters { waiter.resume() }
  }
}

private enum RuntimeClientTestTransferChannel {
  case reply
  case stream
}

private final class RuntimeClientTestPeer: @unchecked Sendable {
  let rootPath: String
  let socketPath: String
  private let listener: Int32

  init() throws {
    rootPath = "/tmp/ad-client-\(UUID().uuidString.prefix(12).lowercased())"
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

  func connectClient() throws -> Int32 {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw Self.posixError() }
    do {
      var address = try Self.unixAddress(path: socketPath)
      let status = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          Darwin.connect(
            descriptor,
            $0,
            socklen_t(MemoryLayout<sockaddr_un>.size)
          )
        }
      }
      guard status == 0 else { throw Self.posixError() }
      return descriptor
    } catch {
      Darwin.close(descriptor)
      throw error
    }
  }

  func readLine(from descriptor: Int32) throws -> String? {
    var data = Data()
    while true {
      try Self.wait(fd: descriptor, events: Int16(POLLIN))
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
    return try JSONDecoder().decode(RuntimeEnvelopeV2.self, from: Data(line.utf8))
  }

  func readJSONObject(from descriptor: Int32) throws -> [String: Any]? {
    guard let line = try readLine(from: descriptor) else { return nil }
    return try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
  }

  func writeEnvelope(_ envelope: RuntimeEnvelopeV2, to descriptor: Int32) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var data = try encoder.encode(envelope)
    data.append(0x0A)
    try write(data, to: descriptor)
  }

  func writeRawEnvelope(
    messageID: String,
    payload: [String: Any],
    to descriptor: Int32
  ) throws {
    let object: [String: Any] = [
      "version": runtimeProtocolVersionCurrent,
      "messageId": messageID,
      "body": ["message": "reply", "payload": payload],
    ]
    var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    data.append(0x0A)
    try write(data, to: descriptor)
  }

  func writeStreamTransfer(
    messageID: String,
    transferID: String,
    bytes: Data,
    to descriptor: Int32
  ) throws {
    try writeTransferPart(
      channel: .stream,
      messageID: messageID,
      transferID: transferID,
      index: 0,
      count: 1,
      totalHash: Data(SHA256.hash(data: bytes)),
      totalBytes: UInt64(bytes.count),
      part: bytes,
      to: descriptor
    )
  }

  func writeTransferParts(
    channel: RuntimeClientTestTransferChannel,
    messageID: String,
    transferID: String,
    bytes: Data,
    reverse: Bool,
    to descriptor: Int32
  ) throws {
    let split = max(1, bytes.count / 2)
    let parts = [Data(bytes.prefix(split)), Data(bytes.suffix(from: split))]
    let indices = reverse ? [1, 0] : [0, 1]
    let hash = Data(SHA256.hash(data: bytes))
    for index in indices {
      try writeTransferPart(
        channel: channel,
        messageID: messageID,
        transferID: transferID,
        index: UInt32(index),
        count: UInt32(parts.count),
        totalHash: hash,
        totalBytes: UInt64(bytes.count),
        part: parts[index],
        to: descriptor
      )
    }
  }

  func writeTransferPart(
    channel: RuntimeClientTestTransferChannel,
    messageID: String,
    transferID: String,
    index: UInt32,
    count: UInt32,
    totalHash: Data,
    totalBytes: UInt64,
    part: Data,
    to descriptor: Int32
  ) throws {
    let transfer = try TransferEnvelopeV2(
      transferID: RuntimeTransferID(rawValue: transferID),
      partIndex: index,
      partCount: count,
      totalSHA256: totalHash,
      totalBytes: totalBytes,
      part: part
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

  func write(_ data: Data, to descriptor: Int32) throws {
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

  static func syncCompletePayload(generation: String) -> [String: Any] {
    [
      "reply": "syncComplete",
      "streamGeneration": generation,
      "streamCursor": "beforeFirst",
      "innerCursor": ["scope": "catalog", "cursor": "beforeFirst"],
      "keyDirectoryRevision": 0,
    ]
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

  private static func wait(fd: Int32, events: Int16) throws {
    var descriptor = pollfd(fd: fd, events: events, revents: 0)
    while true {
      let result = poll(&descriptor, 1, 2_000)
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
