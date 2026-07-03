import XCTest
import AgentDeckCore
import AppKit
@testable import AgentDeck

@MainActor
final class ApprovalCardVendorBottomViewTests: XCTestCase {

    private func makeModel() -> SessionModel {
        SessionModel(
            turnStarter: NoopRuntimeTurnStarter(),
            actionDecider: NoopRuntimeActionDecider()
        )
    }

    func testCodexActionMountsCodexApprovalPanel() {
        let card = ApprovalCardView(frame: .zero)
        let action = PendingActionRequest(
            requestId: "r1",
            actionKind: .executeCommand,
            summary: "ls",
            vendor: .codex(
                approvalPolicyAtDecision: .onRequest,
                sandboxAtDecision: .workspaceWrite,
                canPersist: true
            )
        )
        card.configure(action: action, model: makeModel(), capabilities: .codexStub())
        XCTAssertTrue(card.vendorBottomView is CodexApprovalPanel)
    }

    func testCCActionMountsClaudeCodePermissionPanel() {
        let card = ApprovalCardView(frame: .zero)
        let action = PendingActionRequest(
            requestId: "r2",
            actionKind: .editFiles,
            summary: "edit /tmp/x",
            vendor: .claudeCode(permissionModeAtDecision: .default, toolName: "Edit")
        )
        card.configure(action: action, model: makeModel(), capabilities: .ccStub())
        XCTAssertTrue(card.vendorBottomView is ClaudeCodePermissionPanel)
    }

    func testNilCapabilitiesLeavesVendorSlotEmpty() {
        let card = ApprovalCardView(frame: .zero)
        let action = PendingActionRequest(
            requestId: "r3",
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
            requestId: "r1",
            actionKind: .executeCommand,
            summary: "ls",
            vendor: .codex(
                approvalPolicyAtDecision: .onRequest,
                sandboxAtDecision: .workspaceWrite,
                canPersist: true
            )
        )
        card.configure(action: codexAction, model: makeModel(), capabilities: .codexStub())
        XCTAssertTrue(card.vendorBottomView is CodexApprovalPanel)

        let ccAction = PendingActionRequest(
            requestId: "r2",
            actionKind: .editFiles,
            summary: "edit /tmp/y",
            vendor: .claudeCode(permissionModeAtDecision: .default, toolName: "Edit")
        )
        card.configure(action: ccAction, model: makeModel(), capabilities: .ccStub())
        XCTAssertTrue(card.vendorBottomView is ClaudeCodePermissionPanel)
        XCTAssertFalse(card.vendorBottomView is CodexApprovalPanel)
    }
}
