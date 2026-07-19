import AgentDeckCore
import XCTest

@testable import AgentDeck

@MainActor
final class NewSessionDialogEncodingTests: XCTestCase {

  func testBuildConversationDraftCodex() throws {
    let form = CodexSessionOptionsForm()
    form.loadViewIfNeeded()
    form.setApprovalPolicy(.never)
    form.setSandbox(.readOnly)
    form.setPersistApproval(false)
    form.setReasoningEffort(.high)

    let cwd = URL(fileURLWithPath: "/tmp/proj")
    let draft = try NewSessionDialog.buildConversationDraft(
      agentKind: .codex,
      vendorForm: form,
      cwd: cwd,
      prompt: "hi"
    )
    XCTAssertEqual(draft.agentKind, .codex)
    XCTAssertEqual(draft.cwd, "/tmp/proj")
    XCTAssertEqual(draft.prompt?.rawValue, "hi")
    guard case .codex(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected codex runtime configuration")
    }
    XCTAssertEqual(configuration.approvalPolicy, .never)
    XCTAssertEqual(configuration.sandbox, .readOnly)
    XCTAssertEqual(configuration.reasoningEffort, .high)

    // Dialog 的产物直接进入 Runtime v2 Start request，不再经过 ClientCommand.sessionStart。
    let data = try JSONEncoder().encode(draft.startRequest)
    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    XCTAssertEqual(json?["request"] as? String, "start")
    XCTAssertEqual(json?["agentKind"] as? String, "codex")
    XCTAssertEqual(json?["cwd"] as? String, "/tmp/proj")
  }

  func testBuildConversationDraftClaudeCode() throws {
    let form = ClaudeCodeSessionOptionsForm()
    form.loadViewIfNeeded()
    form.setPermissionMode(.plan)
    form.setModel("opus")

    let draft = try NewSessionDialog.buildConversationDraft(
      agentKind: .claudeCode,
      vendorForm: form,
      cwd: URL(fileURLWithPath: "/tmp/cc"),
      prompt: nil
    )
    XCTAssertEqual(draft.agentKind, .claudeCode)
    XCTAssertNil(draft.prompt)
    guard case .claudeCode(let configuration) = draft.configuration.vendorControl else {
      return XCTFail("expected claude_code runtime configuration")
    }
    XCTAssertEqual(configuration.permissionMode, .plan)
    XCTAssertEqual(configuration.model, "opus")

    let data = try JSONEncoder().encode(
      draft.configureRequest(
        conversationID: RuntimeConversationID(rawValue: "conversation-1")
      ))
    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    XCTAssertEqual(json?["request"] as? String, "configureConversation")
    XCTAssertEqual(json?["conversationId"] as? String, "conversation-1")
    XCTAssertEqual(json?["expectedConfigurationRevision"] as? Int, 0)
  }

  func testUnsupportedLegacyFormFieldsFailInsteadOfBeingDropped() throws {
    let form = CodexSessionOptionsForm()
    form.loadViewIfNeeded()
    form.setPersistApproval(true)

    XCTAssertThrowsError(
      try NewSessionDialog.buildConversationDraft(
        agentKind: .codex,
        vendorForm: form,
        cwd: URL(fileURLWithPath: "/tmp/x"),
        prompt: nil
      )
    ) { error in
      XCTAssertEqual(
        error as? RuntimeConversationDraftError,
        .unsupportedField(.codexPersistApproval)
      )
    }
  }
}
