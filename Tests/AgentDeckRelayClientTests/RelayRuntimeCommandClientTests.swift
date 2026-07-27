import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

@testable import AgentDeckRelayClient

final class RelayRuntimeCommandClientTests: XCTestCase {
  func testSubscriptionForwardsExactTypedIntentAndRejectsUnsafeInputs() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    let client = try RelayRuntimeCommandClient(
      endpoints: ["machine-1": endpoint]
    )
    let requestID = RuntimeMessageID(rawValue: "catalog-subscription-1")
    try await client.subscribe(
      machineID: "machine-1",
      target: .catalog,
      after: .beforeFirst,
      requestID: requestID
    )
    let subscriptions = await endpoint.subscriptionRecords()
    XCTAssertEqual(subscriptions.count, 1)
    XCTAssertEqual(subscriptions[0].requestID, requestID)
    XCTAssertEqual(subscriptions[0].after, .beforeFirst)
    guard case .catalog = subscriptions[0].target else {
      return XCTFail("catalog target must remain typed")
    }

    await assertSessionFailure(.machineOffline) {
      try await client.subscribe(
        machineID: "missing-machine",
        target: .catalog,
        after: .beforeFirst,
        requestID: requestID
      )
    }
    await assertSessionFailure(.securityError) {
      try await client.subscribe(
        machineID: "machine-1",
        target: .catalog,
        after: .at(UInt64.max),
        requestID: requestID
      )
    }
  }

  func testUnsubscribeForwardsExactTargetAndFreshRequestIdentity() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    let client = try RelayRuntimeCommandClient(
      endpoints: ["machine-1": endpoint],
      messageIDGenerator: {
        RuntimeMessageID(rawValue: "unsubscribe-request-1")
      }
    )
    let target = RuntimeSubscriptionTargetV1.conversation(
      conversationID: RuntimeConversationID(rawValue: "conversation-1")
    )

    try await client.unsubscribe(machineID: "machine-1", target: target)

    let records = await endpoint.unsubscriptionRecords()
    XCTAssertEqual(records.count, 1)
    guard case .conversation(let conversationID) = records[0].target else {
      return XCTFail("unsubscribe target 必须保持 typed conversation")
    }
    XCTAssertEqual(conversationID.rawValue, "conversation-1")
    XCTAssertEqual(records[0].requestID.rawValue, "unsubscribe-request-1")
  }

  func testShutdownForwardsToPairingOwner() async throws {
    let pairing = RuntimePairingHandlerSpy()
    let client = try RelayRuntimeCommandClient(endpoints: [:], pairing: pairing)

    await client.shutdown()

    let shutdownCount = await pairing.shutdownCount()
    XCTAssertEqual(shutdownCount, 1)
  }

  func testPromptUsesIdempotentEnvelopeAndRevisionBoundContract() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    await endpoint.enqueue(
      .command(
        .accepted(
          commandID: RuntimeCommandID(rawValue: "command-1"),
          queuePosition: 2,
          configurationRevision: 9
        )
      )
    )
    let client = try RelayRuntimeCommandClient(endpoints: ["machine-1": endpoint])
    let idempotencyKey = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    let receipt = try await client.sendPrompt(
      machineID: "machine-1",
      conversationID: "conversation-1",
      text: "hello relay",
      idempotencyKey: idempotencyKey,
      expectedConfigurationRevision: 9
    )
    guard case .accepted(let commandID, let queuePosition, let revision) = receipt else {
      return XCTFail("exact command receipt must pass through")
    }
    XCTAssertEqual(commandID.rawValue, "command-1")
    XCTAssertEqual(queuePosition, 2)
    XCTAssertEqual(revision, 9)

    let records = await endpoint.directedRecords()
    XCTAssertEqual(records.count, 1)
    XCTAssertEqual(
      records[0].envelope.messageID.rawValue,
      "relay-command-11111111-2222-3333-4444-555555555555"
    )
    XCTAssertEqual(
      records[0].contract,
      .command(expectedConfigurationRevision: 9)
    )
    guard
      case .request(
        .sendPrompt(
          let conversationID,
          let runtimeIdempotencyKey,
          let expectedRevision,
          let prompt
        )
      ) = records[0].envelope.body
    else {
      return XCTFail("prompt must be one strict Runtime request envelope")
    }
    XCTAssertEqual(conversationID.rawValue, "conversation-1")
    XCTAssertEqual(runtimeIdempotencyKey.rawValue, idempotencyKey.uuidString.lowercased())
    XCTAssertEqual(expectedRevision, 9)
    XCTAssertEqual(prompt.rawValue, "hello relay")
  }

  func testFacadeRejectsEndpointReplyThatViolatesExactContract() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    await endpoint.enqueue(
      .command(
        .replayed(
          commandID: RuntimeCommandID(rawValue: "wrong-revision"),
          configurationRevision: 10
        )
      )
    )
    let client = try RelayRuntimeCommandClient(endpoints: ["machine-1": endpoint])
    await assertSessionFailure(.securityError) {
      _ = try await client.sendPrompt(
        machineID: "machine-1",
        conversationID: "conversation-1",
        text: "hello",
        idempotencyKey: UUID(),
        expectedConfigurationRevision: 9
      )
    }
  }

  func testApprovalAndRetryBindApprovalIDDecisionAndAllowedReceipt() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    await endpoint.enqueue(
      .approval(.applied(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await endpoint.enqueue(
      .approval(
        .alreadyHandled(
          approvalID: RuntimeApprovalID(rawValue: "approval-1"),
          decision: .approve,
          state: .applying
        )
      )
    )
    let client = try RelayRuntimeCommandClient(
      endpoints: ["machine-1": endpoint],
      messageIDGenerator: {
        RuntimeMessageID(rawValue: "generated-retry-message")
      }
    )
    let idempotencyKey = UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!
    _ = try await client.resolveApproval(
      machineID: "machine-1",
      conversationID: "conversation-1",
      turnID: "turn-1",
      approvalID: "approval-1",
      requestID: "daemon-request-1",
      decision: .deny,
      idempotencyKey: idempotencyKey
    )
    _ = try await client.retryApprovalDelivery(
      machineID: "machine-1",
      conversationID: "conversation-1",
      approvalID: "approval-1"
    )

    let records = await endpoint.directedRecords()
    XCTAssertEqual(records.count, 2)
    XCTAssertEqual(
      records[0].contract,
      .approval(
        expectedApprovalID: RuntimeApprovalID(rawValue: "approval-1"),
        isRetry: false
      )
    )
    XCTAssertEqual(
      records[1].contract,
      .approval(
        expectedApprovalID: RuntimeApprovalID(rawValue: "approval-1"),
        isRetry: true
      )
    )
    guard
      case .request(
        .resolveApproval(
          let conversationID,
          let turnID,
          let approvalID,
          let decision
        )
      ) = records[0].envelope.body
    else {
      return XCTFail("approval must remain a strict Runtime request")
    }
    XCTAssertEqual(conversationID.rawValue, "conversation-1")
    XCTAssertEqual(turnID.rawValue, "turn-1")
    XCTAssertEqual(approvalID.rawValue, "approval-1")
    XCTAssertEqual(decision.requestID, "daemon-request-1")
    XCTAssertEqual(decision.decision.rawValue, ActionDecisionKind.deny.rawValue)
    XCTAssertFalse(decision.persist)
    XCTAssertEqual(
      records[0].envelope.messageID.rawValue,
      "relay-approval-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
    XCTAssertEqual(records[1].envelope.messageID.rawValue, "generated-retry-message")
  }

  func testRetryClaimedAndWrongRevocationSerialFailClosed() async throws {
    let endpoint = RuntimeEndpointSpy(machineID: "machine-1", grantSerial: 7)
    await endpoint.enqueue(
      .approval(.claimed(RuntimeApprovalID(rawValue: "approval-1")))
    )
    await endpoint.enqueue(
      .revocation(.committed(RuntimeGrantSerial(rawValue: 8)))
    )
    let client = try RelayRuntimeCommandClient(endpoints: ["machine-1": endpoint])
    await assertSessionFailure(.securityError) {
      _ = try await client.retryApprovalDelivery(
        machineID: "machine-1",
        conversationID: "conversation-1",
        approvalID: "approval-1"
      )
    }
    await assertSessionFailure(.securityError) {
      _ = try await client.revokeSelf(machineID: "machine-1")
    }
    let records = await endpoint.directedRecords()
    XCTAssertEqual(
      records.last?.contract,
      .revocation(expectedGrantSerial: 7)
    )
  }
}

private struct RuntimeSubscriptionRecord: Sendable {
  let target: RuntimeSubscriptionTargetV1
  let after: RuntimeStreamCursorV1
  let requestID: RuntimeMessageID
}

private struct RuntimeDirectedRecord: Sendable {
  let envelope: RuntimeEnvelopeV2
  let contract: MachineDirectedReplyContract
}

private struct RuntimeUnsubscriptionRecord: Sendable {
  let target: RuntimeSubscriptionTargetV1
  let requestID: RuntimeMessageID
}

private actor RuntimeEndpointSpy: MachineRuntimeRequestEndpoint {
  nonisolated let machineID: String
  private let grantSerial: UInt64
  private var subscriptions: [RuntimeSubscriptionRecord] = []
  private var unsubscriptions: [RuntimeUnsubscriptionRecord] = []
  private var directed: [RuntimeDirectedRecord] = []
  private var replies: [RuntimeReplyV2] = []

  init(machineID: String, grantSerial: UInt64) {
    self.machineID = machineID
    self.grantSerial = grantSerial
  }

  func expectedGrantSerial() -> UInt64 { grantSerial }

  func beginSubscription(
    target: RuntimeSubscriptionTargetV1,
    after: RuntimeStreamCursorV1,
    requestID: RuntimeMessageID
  ) {
    subscriptions.append(
      RuntimeSubscriptionRecord(target: target, after: after, requestID: requestID)
    )
  }

  func endSubscription(
    target: RuntimeSubscriptionTargetV1,
    requestID: RuntimeMessageID
  ) {
    unsubscriptions.append(
      RuntimeUnsubscriptionRecord(target: target, requestID: requestID)
    )
  }

  func sendDirectedRequest(
    _ envelope: RuntimeEnvelopeV2,
    contract: MachineDirectedReplyContract
  ) throws -> RuntimeReplyV2 {
    directed.append(RuntimeDirectedRecord(envelope: envelope, contract: contract))
    guard !replies.isEmpty else { throw RuntimeEndpointSpyError.missingReply }
    return replies.removeFirst()
  }

  func enqueue(_ reply: RuntimeReplyV2) {
    replies.append(reply)
  }

  func subscriptionRecords() -> [RuntimeSubscriptionRecord] { subscriptions }
  func unsubscriptionRecords() -> [RuntimeUnsubscriptionRecord] { unsubscriptions }
  func directedRecords() -> [RuntimeDirectedRecord] { directed }
}

private enum RuntimeEndpointSpyError: Error {
  case missingReply
}

private actor RuntimePairingHandlerSpy: RelayPairingCommandHandling {
  private var shutdowns = 0

  func shutdown() {
    shutdowns += 1
  }

  func inspectPairInvite(_: String) async throws -> PairingPreview {
    throw SessionSourceFailure(code: .commandRejected)
  }

  func pair(_: String) async throws -> AsyncThrowingStream<PairingProgress, Error> {
    throw SessionSourceFailure(code: .commandRejected)
  }

  func shutdownCount() -> Int { shutdowns }
}

private func assertSessionFailure(
  _ expected: SessionSourceFailureCode,
  operation: () async throws -> Void,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    try await operation()
    XCTFail("expected SessionSourceFailure", file: file, line: line)
  } catch let failure as SessionSourceFailure {
    XCTAssertEqual(failure.code, expected, file: file, line: line)
  } catch {
    XCTFail("unexpected error: \(error)", file: file, line: line)
  }
}
