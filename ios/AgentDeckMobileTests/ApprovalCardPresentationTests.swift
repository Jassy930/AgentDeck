import XCTest
import AgentDeckMobileCore
@testable import AgentDeckMobile

final class ApprovalCardPresentationTests: XCTestCase {
    func testCodexVendorLineUsesVendorWords() {
        let request = ActionRequest(
            requestId: "r1", kind: .executeCommand, summary: "uv run alembic upgrade head",
            vendor: .codex(approvalPolicyAtDecision: .onRequest, sandboxAtDecision: .workspaceWrite, canPersist: true))
        let p = ApprovalCardPresentation.make(from: request)
        XCTAssertEqual(p.summary, "uv run alembic upgrade head")
        // vendor 原词：rawValue 原样透出，不翻译不改写
        XCTAssertTrue(p.vendorLine.contains(CodexApprovalPolicy.onRequest.rawValue))
        XCTAssertTrue(p.vendorLine.contains(CodexSandboxMode.workspaceWrite.rawValue))
    }

    func testClaudeCodeVendorLine() {
        let request = ActionRequest(
            requestId: "r2", kind: .editFiles, summary: "写入 3 个文件",
            vendor: .claudeCode(permissionModeAtDecision: .acceptEdits, toolName: "Write"))
        let p = ApprovalCardPresentation.make(from: request)
        XCTAssertTrue(p.vendorLine.contains(ClaudeCodePermissionMode.acceptEdits.rawValue))
        XCTAssertTrue(p.vendorLine.contains("Write"))
    }
}
