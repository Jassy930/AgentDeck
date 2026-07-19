import AgentDeckCore
import Foundation
import XCTest

@testable import AgentDeck

@MainActor
final class SessionModelLiveHistoryTests: XCTestCase {
  func testSubmittingNewConversationAddsCanonicalRuntimeToHistoryGroups() async throws {
    let conversationID = RuntimeConversationID(rawValue: "conversation-history")
    let wire = try LiveHistoryRuntimeWire(conversationID: conversationID)
    let model = SessionModel(runtimeWire: wire)
    defer { model.teardown() }

    let cwd = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("agentdeck-runtime-history")
    try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
    XCTAssertNil(model.chooseCwd(cwd))

    model.submit("hello from current conversation", agentKind: .codex)
    try await waitUntil {
      model.workbench.selectedConversationID == conversationID
    }

    let threads = model.historyGroups.flatMap(\.threads)
    XCTAssertEqual(threads.count, 1)
    XCTAssertEqual(threads.first?.id, conversationID.rawValue)
    XCTAssertEqual(threads.first?.cwd, cwd.path)
    XCTAssertEqual(threads.first?.source, "live")
    XCTAssertEqual(threads.first?.agentKind, .codex)
    XCTAssertEqual(threads.first?.status, "starting")
    XCTAssertEqual(model.workbench.selectedConversationID, conversationID)

    let operations = await wire.recordedOperations()
    XCTAssertEqual(
      operations,
      [
        .describeAgents,
        .start(agentKind: .codex, cwd: cwd.path),
        .configure(conversationID: conversationID, expectedRevision: 0),
        .subscribe(conversationID: conversationID, cursor: .beforeFirst),
        .sendPrompt(
          conversationID: conversationID,
          expectedRevision: 1,
          prompt: "hello from current conversation"
        ),
      ]
    )
  }

  private func waitUntil(
    _ predicate: @MainActor () -> Bool
  ) async throws {
    for _ in 0..<400 {
      if predicate() { return }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw LiveHistoryRuntimeWireError.timeout
  }
}

private enum LiveHistoryRuntimeOperation: Equatable, Sendable {
  case describeAgents
  case start(agentKind: AgentKind, cwd: String)
  case configure(conversationID: RuntimeConversationID, expectedRevision: UInt64)
  case subscribe(conversationID: RuntimeConversationID, cursor: RuntimeStreamCursorV1)
  case sendPrompt(
    conversationID: RuntimeConversationID,
    expectedRevision: UInt64,
    prompt: String
  )
}

private enum LiveHistoryRuntimeWireError: Error {
  case closed
  case timeout
  case unexpectedRequest
}

private actor LiveHistoryRuntimeWire: AppRuntimeWireSession {
  private let conversationID: RuntimeConversationID
  private let descriptions: RuntimeAgentDescriptionsV2
  private let snapshot: ConversationSnapshotV2
  private let terminal: RuntimeSyncCompleteV1
  private var operations: [LiveHistoryRuntimeOperation] = []
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var isClosed = false

  init(conversationID: RuntimeConversationID) throws {
    self.conversationID = conversationID
    let capabilities = try liveHistoryCodexCapabilities()
    let configuration = liveHistoryCodexConfiguration()
    descriptions = try RuntimeAgentDescriptionsV2(
      agents: [
        try RuntimeAgentDescriptionV2(
          agentKind: .codex,
          capabilities: capabilities,
          defaultConfiguration: configuration
        )
      ]
    )
    snapshot = try ConversationSnapshotV2(
      conversationID: conversationID,
      baseEventCursor: .beforeFirst,
      configurationState: try RuntimeConversationConfigurationStateV2(
        configurationRevision: 1,
        configuration: configuration
      ),
      items: [.capabilities(capabilities)]
    )
    terminal = try liveHistorySyncComplete(conversationID: conversationID)
  }

  func start() async throws {}

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    switch request {
    case .describeAgents:
      operations.append(.describeAgents)
      return .agents(descriptions)
    case .start(let agentKind, _, let cwd, _):
      operations.append(.start(agentKind: agentKind, cwd: cwd))
      return .conversationStart(
        ConversationStartReceiptV2(conversationID: conversationID, replayed: false)
      )
    case .configureConversation(let configuration):
      operations.append(
        .configure(
          conversationID: configuration.conversationID,
          expectedRevision: configuration.expectedConfigurationRevision
        )
      )
      return .configuration(
        .applied(conversationID: conversationID, configurationRevision: 1)
      )
    case .sendPrompt(let requestID, _, let revision, let prompt):
      operations.append(
        .sendPrompt(
          conversationID: requestID,
          expectedRevision: revision,
          prompt: prompt.rawValue
        )
      )
      return .command(
        .accepted(
          commandID: RuntimeCommandID(rawValue: "command-history"),
          queuePosition: 0,
          configurationRevision: revision
        )
      )
    default:
      throw LiveHistoryRuntimeWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    guard case .subscribe(let innerCursor) = request,
      case .conversation(let requestID, let cursor) = innerCursor
    else {
      throw LiveHistoryRuntimeWireError.unexpectedRequest
    }
    operations.append(.subscribe(conversationID: requestID, cursor: cursor))
    return LiveHistoryRuntimeReplySequence(
      replies: [
        .subscription(
          .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-history"))
        ),
        .snapshot(snapshot),
        .syncComplete(terminal),
      ]
    )
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !isClosed else { throw LiveHistoryRuntimeWireError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamContinuation == nil)
      streamContinuation = continuation
    }
  }

  func close() async {
    guard !isClosed else { return }
    isClosed = true
    streamContinuation?.resume(throwing: LiveHistoryRuntimeWireError.closed)
    streamContinuation = nil
  }

  func recordedOperations() -> [LiveHistoryRuntimeOperation] {
    operations
  }
}

private actor LiveHistoryRuntimeReplySequence: AppRuntimeWireReplySequence {
  private var replies: [RuntimeReplyV2]

  init(replies: [RuntimeReplyV2]) {
    self.replies = replies
  }

  func next() async throws -> RuntimeReplyV2? {
    guard !replies.isEmpty else { return nil }
    return replies.removeFirst()
  }

  func cancel() async {}
}

private func liveHistoryCodexCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
}

private func liveHistoryCodexConfiguration() -> RuntimeConversationConfigurationV2 {
  RuntimeConversationConfigurationV2(
    vendorControl: .codex(
      RuntimeCodexConversationConfigurationV2(
        approvalPolicy: .onRequest,
        sandbox: .workspaceWrite,
        reasoningEffort: .medium
      )
    )
  )
}

private func liveHistorySyncComplete(
  conversationID: RuntimeConversationID
) throws -> RuntimeSyncCompleteV1 {
  let object: [String: Any] = [
    "streamGeneration": "generation-history",
    "streamCursor": "beforeFirst",
    "innerCursor": [
      "scope": "conversation",
      "conversationId": conversationID.rawValue,
      "cursor": "beforeFirst",
    ],
    "keyDirectoryRevision": 0,
  ]
  return try JSONDecoder().decode(
    RuntimeSyncCompleteV1.self,
    from: JSONSerialization.data(withJSONObject: object)
  )
}
