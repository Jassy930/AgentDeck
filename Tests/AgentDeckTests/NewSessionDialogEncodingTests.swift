import AgentDeckCore
import AppKit
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

  func testDialogDraftPreservesLeadingAndTrailingPromptBytes() throws {
    let form = CodexSessionOptionsForm()
    form.loadViewIfNeeded()
    let prompt = "  修改配置  "

    let draft = try NewSessionDialog.buildConversationDraft(
      agentKind: .codex,
      vendorForm: form,
      cwd: URL(fileURLWithPath: "/tmp/prompt-bytes"),
      prompt: prompt
    )

    XCTAssertEqual(Array(try XCTUnwrap(draft.prompt).rawValue.utf8), Array(prompt.utf8))
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

  func testRejectedAdmissionKeepsDialogOpenAndAcceptedAdmissionClosesIt() throws {
    let dialog = NewSessionDialog()
    let window = try XCTUnwrap(dialog.window)
    let closeProbe = NewSessionDialogCloseProbe()
    window.delegate = closeProbe
    window.makeKeyAndOrderFront(nil)
    defer { window.close() }

    var rejectedDraft: RuntimeConversationDraft?
    dialog.onSubmit = { draft in
      rejectedDraft = draft
      return false
    }

    XCTAssertFalse(dialog.submitDraftIfAccepted())
    XCTAssertTrue(window.isVisible)
    XCTAssertEqual(closeProbe.closeCount, 0)
    let retained = try XCTUnwrap(rejectedDraft)

    var acceptedDraft: RuntimeConversationDraft?
    dialog.onSubmit = { draft in
      acceptedDraft = draft
      return true
    }

    XCTAssertTrue(dialog.submitDraftIfAccepted())
    XCTAssertFalse(window.isVisible)
    XCTAssertEqual(closeProbe.closeCount, 1)
    let accepted = try XCTUnwrap(acceptedDraft)
    XCTAssertEqual(accepted.agentKind, retained.agentKind)
    XCTAssertEqual(accepted.cwd, retained.cwd)
    XCTAssertEqual(accepted.prompt?.rawValue, retained.prompt?.rawValue)
  }
}

private final class NewSessionDialogCloseProbe: NSObject, NSWindowDelegate {
  private(set) var closeCount = 0

  func windowWillClose(_ notification: Notification) {
    closeCount += 1
  }
}
