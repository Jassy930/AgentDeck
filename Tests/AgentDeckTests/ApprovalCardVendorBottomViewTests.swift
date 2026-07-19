import AgentDeckCore
import AppKit
import XCTest

@testable import AgentDeck

@MainActor
final class ApprovalCardVendorBottomViewTests: XCTestCase {
  private func makeModel() -> SessionModel { SessionModel() }

  func testCodexActionMountsCodexApprovalPanel() {
    let card = ApprovalCardView(frame: .zero)
    let action = PendingActionRequest(
      conversationID: RuntimeConversationID(rawValue: "conversation-1"),
      turnID: RuntimeTurnID(rawValue: "turn-1"),
      commandID: RuntimeCommandID(rawValue: "command-1"),
      approvalID: RuntimeApprovalID(rawValue: "approval-1"),
      requestID: "request-1",
      actionKind: .executeCommand,
      summary: "ls",
      vendor: .codex(
        approvalPolicyAtDecision: .onRequest,
        sandboxAtDecision: .workspaceWrite,
        canPersist: true
      )
    )
    card.configure(action: action, model: makeModel(), capabilities: codexCapabilities())
    XCTAssertTrue(card.vendorBottomView is CodexApprovalPanel)
  }

  func testCCActionMountsClaudeCodePermissionPanel() {
    let card = ApprovalCardView(frame: .zero)
    let action = PendingActionRequest(
      conversationID: RuntimeConversationID(rawValue: "conversation-2"),
      turnID: RuntimeTurnID(rawValue: "turn-2"),
      commandID: RuntimeCommandID(rawValue: "command-2"),
      approvalID: RuntimeApprovalID(rawValue: "approval-2"),
      requestID: "request-2",
      actionKind: .editFiles,
      summary: "edit /tmp/x",
      vendor: .claudeCode(permissionModeAtDecision: .default, toolName: "Edit")
    )
    card.configure(action: action, model: makeModel(), capabilities: claudeCapabilities())
    XCTAssertTrue(card.vendorBottomView is ClaudeCodePermissionPanel)
  }

  func testNilCapabilitiesLeavesVendorSlotEmpty() {
    let card = ApprovalCardView(frame: .zero)
    let action = PendingActionRequest(
      conversationID: RuntimeConversationID(rawValue: "conversation-3"),
      turnID: RuntimeTurnID(rawValue: "turn-3"),
      commandID: RuntimeCommandID(rawValue: "command-3"),
      approvalID: RuntimeApprovalID(rawValue: "approval-3"),
      requestID: "request-3",
      actionKind: .executeCommand,
      summary: "noop",
      vendor: .codex(
        approvalPolicyAtDecision: .onRequest,
        sandboxAtDecision: .workspaceWrite,
        canPersist: false
      )
    )
    card.configure(action: action, model: makeModel(), capabilities: nil)
    XCTAssertNil(card.vendorBottomView)
  }

  func testReconfigureReplacesVendorSlot() {
    let card = ApprovalCardView(frame: .zero)
    let codexAction = PendingActionRequest(
      conversationID: RuntimeConversationID(rawValue: "conversation-1"),
      turnID: RuntimeTurnID(rawValue: "turn-1"),
      commandID: RuntimeCommandID(rawValue: "command-1"),
      approvalID: RuntimeApprovalID(rawValue: "approval-1"),
      requestID: "request-1",
      actionKind: .executeCommand,
      summary: "ls",
      vendor: .codex(
        approvalPolicyAtDecision: .onRequest,
        sandboxAtDecision: .workspaceWrite,
        canPersist: true
      )
    )
    card.configure(
      action: codexAction,
      model: makeModel(),
      capabilities: codexCapabilities()
    )
    XCTAssertTrue(card.vendorBottomView is CodexApprovalPanel)

    let ccAction = PendingActionRequest(
      conversationID: RuntimeConversationID(rawValue: "conversation-2"),
      turnID: RuntimeTurnID(rawValue: "turn-2"),
      commandID: RuntimeCommandID(rawValue: "command-2"),
      approvalID: RuntimeApprovalID(rawValue: "approval-2"),
      requestID: "request-2",
      actionKind: .editFiles,
      summary: "edit /tmp/y",
      vendor: .claudeCode(permissionModeAtDecision: .default, toolName: "Edit")
    )
    card.configure(
      action: ccAction,
      model: makeModel(),
      capabilities: claudeCapabilities()
    )
    XCTAssertTrue(card.vendorBottomView is ClaudeCodePermissionPanel)
    XCTAssertFalse(card.vendorBottomView is CodexApprovalPanel)
  }

  private func codexCapabilities() -> SessionCapabilities {
    SessionCapabilities(
      agentKind: .codex,
      agentVersion: "test",
      features: [.approval, .codexApprovalPersistence],
      vendor: .codex(
        CodexCapabilities(
          sandboxModes: [.workspaceWrite],
          persistenceSupported: true,
          reasoningEffortLevels: [.medium]
        )
      )
    )
  }

  private func claudeCapabilities() -> SessionCapabilities {
    SessionCapabilities(
      agentKind: .claudeCode,
      agentVersion: "test",
      features: [.approval, .claudeCodePermissionMode],
      vendor: .claudeCode(
        ClaudeCodeCapabilities(
          permissionModes: [.default],
          outputStyles: [],
          hooksSupported: [],
          cliVersion: "test"
        )
      )
    )
  }
}
