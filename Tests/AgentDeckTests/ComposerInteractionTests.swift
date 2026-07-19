import AgentDeckCore
import AppKit
import Foundation
import XCTest

@testable import AgentDeck

/// 端到端交互：真实 InputBarView → SessionModel → canonical Runtime v2 wire。
/// 模拟输入、点击与回车，并验证新会话严格走 daemon-issued conversation identity。
@MainActor
final class ComposerInteractionTests: XCTestCase {
  private func makeComposer() throws -> (
    bar: InputBarView,
    model: SessionModel,
    wire: ComposerRuntimeWire,
    tv: InputTextView
  ) {
    let wire = try ComposerRuntimeWire(
      conversationID: RuntimeConversationID(rawValue: "conversation-composer")
    )
    let model = SessionModel(runtimeWire: wire)
    model.cwd = URL(fileURLWithPath: "/tmp/agentdeck-composer")
    let bar = InputBarView(model: model)
    bar.frame = NSRect(x: 0, y: 0, width: 860, height: 120)
    bar.layoutSubtreeIfNeeded()
    guard let tv = bar.firstDescendant(ofType: InputTextView.self) else {
      fatalError("composer 内应有 InputTextView")
    }
    return (bar, model, wire, tv)
  }

  private func type(_ text: String, into tv: InputTextView) {
    tv.string = text
    tv.didChangeText()
  }

  func testSendDisabledWhenEmpty() throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("", into: c.tv)
    let send = c.bar.button(id: "composer-send")
    XCTAssertNotNil(send, "发送按钮应可通过 a11y id 定位")
    XCTAssertFalse(send!.isEnabled, "空输入时发送按钮应禁用")
  }

  func testTypingEnablesSend() throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("hello", into: c.tv)
    XCTAssertTrue(c.bar.button(id: "composer-send")!.isEnabled, "有文本时发送按钮应启用")
  }

  func testClickSendUsesCanonicalRuntimeSequenceAndClears() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("拆分登录模块", into: c.tv)
    c.bar.button(id: "composer-send")!.performClick(nil)

    XCTAssertEqual(c.tv.string, "", "发送后应立即清空输入框")
    try await c.wire.waitForPrompt("拆分登录模块")
    await assertCanonicalSequence(c.wire, prompt: "拆分登录模块")
    XCTAssertEqual(
      c.model.workbench.selectedConversationID,
      RuntimeConversationID(rawValue: "conversation-composer")
    )
  }

  func testEnterKeyUsesCanonicalRuntimeSequence() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("回车发送", into: c.tv)
    c.tv.doCommand(by: #selector(NSResponder.insertNewline(_:)))

    try await c.wire.waitForPrompt("回车发送")
    await assertCanonicalSequence(c.wire, prompt: "回车发送")
  }

  func testWhitespaceOnlyDoesNotSubmit() async throws {
    let c = try makeComposer()
    defer { c.model.teardown() }

    type("   ", into: c.tv)
    c.bar.button(id: "composer-send")?.performClick(nil)
    await Task.yield()

    let operations = await c.wire.recordedOperations()
    XCTAssertEqual(operations, [])
    XCTAssertNil(c.model.workbench.selectedConversationID)
  }

  private func assertCanonicalSequence(
    _ wire: ComposerRuntimeWire,
    prompt: String
  ) async {
    let conversationID = RuntimeConversationID(rawValue: "conversation-composer")
    let operations = await wire.recordedOperations()
    XCTAssertEqual(
      operations,
      [
        .describeAgents,
        .start(agentKind: .codex, cwd: "/tmp/agentdeck-composer"),
        .configure(conversationID: conversationID, expectedRevision: 0),
        .subscribe(conversationID: conversationID, cursor: .beforeFirst),
        .sendPrompt(
          conversationID: conversationID,
          expectedRevision: 1,
          prompt: prompt
        ),
      ]
    )
  }
}

private enum ComposerRuntimeOperation: Equatable, Sendable {
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

private enum ComposerRuntimeWireError: Error {
  case closed
  case timeout
  case unexpectedRequest
}

private actor ComposerRuntimeWire: AppRuntimeWireSession {
  private let conversationID: RuntimeConversationID
  private let descriptions: RuntimeAgentDescriptionsV2
  private let snapshot: ConversationSnapshotV2
  private let terminal: RuntimeSyncCompleteV1
  private var operations: [ComposerRuntimeOperation] = []
  private var streamContinuation: CheckedContinuation<LocalRuntimeStreamFrame, Error>?
  private var isClosed = false

  init(conversationID: RuntimeConversationID) throws {
    self.conversationID = conversationID
    let capabilities = try composerCodexCapabilities()
    let configuration = composerCodexConfiguration()
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
    terminal = try composerSyncComplete(conversationID: conversationID)
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
          commandID: RuntimeCommandID(rawValue: "command-composer"),
          queuePosition: 0,
          configurationRevision: revision
        )
      )
    default:
      throw ComposerRuntimeWireError.unexpectedRequest
    }
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    guard case .subscribe(let innerCursor) = request,
      case .conversation(let requestID, let cursor) = innerCursor
    else {
      throw ComposerRuntimeWireError.unexpectedRequest
    }
    operations.append(.subscribe(conversationID: requestID, cursor: cursor))
    return ComposerRuntimeReplySequence(
      replies: [
        .subscription(
          .subscribed(streamGeneration: RuntimeStreamGeneration(rawValue: "generation-composer"))
        ),
        .snapshot(snapshot),
        .syncComplete(terminal),
      ]
    )
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    guard !isClosed else { throw ComposerRuntimeWireError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      precondition(streamContinuation == nil)
      streamContinuation = continuation
    }
  }

  func close() async {
    guard !isClosed else { return }
    isClosed = true
    streamContinuation?.resume(throwing: ComposerRuntimeWireError.closed)
    streamContinuation = nil
  }

  func recordedOperations() -> [ComposerRuntimeOperation] {
    operations
  }

  func waitForPrompt(_ prompt: String) async throws {
    for _ in 0..<400 {
      if operations.contains(where: { operation in
        guard case .sendPrompt(_, _, let value) = operation else { return false }
        return value == prompt
      }) {
        return
      }
      try await Task.sleep(for: .milliseconds(5))
    }
    throw ComposerRuntimeWireError.timeout
  }
}

private actor ComposerRuntimeReplySequence: AppRuntimeWireReplySequence {
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

private func composerCodexCapabilities() throws -> RuntimeSessionCapabilitiesV1 {
  try JSONDecoder().decode(
    RuntimeSessionCapabilitiesV1.self,
    from: Data(
      #"{"agentKind":"codex","agentVersion":"fixture","features":[],"vendor":{"agentKind":"codex","sandboxModes":[],"persistenceSupported":false,"reasoningEffortLevels":[]}}"#
        .utf8
    )
  )
}

private func composerCodexConfiguration() -> RuntimeConversationConfigurationV2 {
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

private func composerSyncComplete(
  conversationID: RuntimeConversationID
) throws -> RuntimeSyncCompleteV1 {
  let object: [String: Any] = [
    "streamGeneration": "generation-composer",
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
