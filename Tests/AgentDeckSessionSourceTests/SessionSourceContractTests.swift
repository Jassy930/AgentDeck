import AgentDeckCore
import AgentDeckSessionSource
import Foundation
import XCTest

final class SessionSourceContractTests: XCTestCase {
  private enum StubError: Error {
    case unavailable
  }

  private actor RemoteSourceStub: SessionSource {
    func machines() async -> AsyncStream<ResourceState<[MachineSummary]>> {
      finishedStream()
    }

    func conversations(
      machineID: String
    ) async -> AsyncStream<ResourceState<[ConversationSummary]>> {
      _ = machineID
      return finishedStream()
    }

    func conversation(conversationID: String) async -> AsyncStream<ConversationUpdate> {
      _ = conversationID
      return finishedStream()
    }

    func inbox() async -> AsyncStream<ResourceState<[InboxItem]>> {
      finishedStream()
    }

    func inspectPairInvite(_ encoded: String) async throws -> PairingPreview {
      _ = encoded
      throw StubError.unavailable
    }

    func pair(
      _ encodedInvite: String
    ) async throws -> AsyncThrowingStream<PairingProgress, Error> {
      _ = encodedInvite
      throw StubError.unavailable
    }

    func revokeSelf(machineID: String) async throws -> RevocationReceipt {
      _ = machineID
      throw StubError.unavailable
    }

    func sendPrompt(
      conversationID: String,
      text: String,
      idempotencyKey: UUID
    ) async throws -> CommandReceipt {
      _ = (conversationID, text, idempotencyKey)
      throw StubError.unavailable
    }

    func resolveApproval(
      conversationID: String,
      turnID: String,
      approvalID: String,
      decision: ActionDecisionKind,
      idempotencyKey: UUID
    ) async throws -> ApprovalReceipt {
      _ = (conversationID, turnID, approvalID, decision, idempotencyKey)
      throw StubError.unavailable
    }

    func retryApprovalDelivery(
      conversationID: String,
      approvalID: String
    ) async throws -> ApprovalReceipt {
      _ = (conversationID, approvalID)
      throw StubError.unavailable
    }
  }

  func testNonMainActorActorConformanceAndAsyncObservationFactories() async {
    let counts = await ObservationProbe().counts(from: RemoteSourceStub())
    XCTAssertEqual(counts, [0, 0, 0, 0])
  }

  func testEveryCrossActorFacadeTypeIsSendable() {
    requireSendable((any SessionSource).self)
    requireSendable(ResourceState<[MachineSummary]>.self)
    requireSendable(ResourceState<[ConversationSummary]>.self)
    requireSendable(ResourceState<[InboxItem]>.self)
    requireSendable(ConversationUpdate.self)
    requireSendable(SessionConnectionState.self)
    requireSendable(PairingPreview.self)
    requireSendable(PairingProgress.self)
    requireSendable(PairedMachine.self)
    requireSendable(CommandReceipt.self)
    requireSendable(ApprovalReceipt.self)
    requireSendable(RevocationReceipt.self)
    requireSendable(PendingPairing.self)
    requireSendable(PairingAdministrationReceipt.self)
  }

  func testConversationUpdateHasExactlyFourCanonicalCases() {
    let snapshot: (ConversationSnapshotV2) -> ConversationUpdate = ConversationUpdate.snapshot
    let event: (RuntimeEventV2) -> ConversationUpdate = ConversationUpdate.event
    let commandState: (CommandStatusReceiptV2) -> ConversationUpdate =
      ConversationUpdate.commandState
    let connectionState: (SessionConnectionState) -> ConversationUpdate =
      ConversationUpdate.connectionState
    _ = (snapshot, event, commandState, connectionState)

    func tag(_ update: ConversationUpdate) -> Int {
      switch update {
      case .snapshot: 0
      case .event: 1
      case .commandState: 2
      case .connectionState: 3
      }
    }
    _ = tag
  }

  func testPairingProgressHasExactlyFiveCasesAndPairedCarriesMachine() {
    let machine = PairedMachine(
      id: "machine",
      name: "Mac Studio",
      relayHost: "relay.example.com",
      rootFingerprint: Data(repeating: 1, count: 32)
    )
    let values: [PairingProgress] = [
      .preparing,
      .waitingForLocalConfirmation,
      .paired(machine),
      .canceled,
      .expired,
    ]
    XCTAssertEqual(values.map(pairingTag), [0, 1, 2, 3, 4])
  }

  func testReceiptNamesAreIdentityAliasesOfCurrentCoreTypes() {
    requireSameType(CommandReceipt.self, CommandReceiptV2.self)
    requireSameType(ApprovalReceipt.self, ApprovalReceiptV1.self)
    requireSameType(RevocationReceipt.self, RevocationReceiptV1.self)
    requireSameType(PendingPairing.self, RuntimePendingPairingV4.self)
    requireSameType(PairingAdministrationReceipt.self, RuntimePairingReceiptV4.self)
  }

  func testSharedSourceBoundaryHasNoFixtureOrPlatformLeak() throws {
    let root = repositoryRoot()
    let source = root.appendingPathComponent("Sources/AgentDeckSessionSource")
    let files = try FileManager.default.contentsOfDirectory(
      at: source,
      includingPropertiesForKeys: nil
    ).filter { $0.pathExtension == "swift" }
    let joined = try files.map { try String(contentsOf: $0, encoding: .utf8) }.joined(
      separator: "\n")
    let forbidden = [
      "import CryptoKit", "import UIKit", "import AppKit", "import Network",
      "URLSession", "streamResource", "@MainActor", "@unchecked Sendable",
      "@preconcurrency", "nonisolated(unsafe)", "isOnline",
    ]
    for token in forbidden {
      XCTAssertFalse(joined.contains(token), "shared facade leaked forbidden token: \(token)")
    }
  }

  func testCompatibilityFileContainsOnlyTypeAliasesAndAvailability() throws {
    let file = repositoryRoot()
      .appendingPathComponent("Sources/AgentDeckSessionSource/SessionSourceCompatibility.swift")
    let source = try String(contentsOf: file, encoding: .utf8)
    XCTAssertTrue(source.contains("typealias MobileSessionSource = SessionSource"))
    XCTAssertTrue(source.contains("typealias SessionSummary = ConversationSummary"))
    XCTAssertTrue(source.contains("typealias SessionGroup = ConversationGroup"))
    XCTAssertFalse(source.contains("SessionStreamElement"))
    XCTAssertFalse(source.contains("enum "))
    XCTAssertFalse(source.contains("struct "))
    XCTAssertFalse(source.contains("protocol "))
  }

  func testConversationSummaryDoesNotExposeFixtureStreamResource() {
    let summary = ConversationSummary(
      id: "conversation",
      machineID: "machine",
      title: "Title",
      cwd: "/workspace",
      agentKind: .codex,
      group: .active,
      lastActiveMs: 7,
      archived: false,
      revision: 3
    )
    let labels = Set(Mirror(reflecting: summary).children.compactMap(\.label))
    XCTAssertFalse(labels.contains("streamResource"))
  }

  func testMachineSummaryUsesTypedConnectionStateWithoutBooleanProjection() {
    let machine = MachineSummary(
      id: "machine",
      name: "Mac Studio",
      connectionState: .reconnecting,
      lastHeartbeat: nil,
      activeConversationCount: 2,
      pendingApprovalCount: 1
    )
    XCTAssertEqual(machine.connectionState, .reconnecting)
    let labels = Set(Mirror(reflecting: machine).children.compactMap(\.label))
    XCTAssertTrue(labels.contains("connectionState"))
    XCTAssertFalse(labels.contains("isOnline"))
  }

  private func pairingTag(_ progress: PairingProgress) -> Int {
    switch progress {
    case .preparing: 0
    case .waitingForLocalConfirmation: 1
    case .paired: 2
    case .canceled: 3
    case .expired: 4
    }
  }

  private func requireSendable<T: Sendable>(_: T.Type) {}
  private func requireSameType<T>(_: T.Type, _: T.Type) {}

  private func repositoryRoot() -> URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }
}

private actor ObservationProbe {
  func counts(from source: any SessionSource) async -> [Int] {
    let machines = await source.machines()
    let conversations = await source.conversations(machineID: "machine")
    let conversation = await source.conversation(conversationID: "conversation")
    let inbox = await source.inbox()
    return await [
      streamCount(machines),
      streamCount(conversations),
      streamCount(conversation),
      streamCount(inbox),
    ]
  }
}

private func streamCount<Element>(_ stream: AsyncStream<Element>) async -> Int {
  var count = 0
  for await _ in stream { count += 1 }
  return count
}

private func finishedStream<Element>() -> AsyncStream<Element> {
  AsyncStream { continuation in continuation.finish() }
}
