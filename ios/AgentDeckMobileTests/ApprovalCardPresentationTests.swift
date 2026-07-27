import AgentDeckCore
import XCTest

@testable import AgentDeckMobile

final class ApprovalCardPresentationTests: XCTestCase {
    func testCodexVendorLineUsesVendorWords() throws {
        let request = try request(
            kind: "executeCommand",
            summary: "uv run alembic upgrade head",
            vendor: [
                "agentKind": "codex",
                "approvalPolicyAtDecision": "on-request",
                "sandboxAtDecision": "workspace-write",
                "canPersist": true,
            ]
        )
        let presentation = ApprovalCardPresentation.make(from: request)
        XCTAssertEqual(presentation.summary, "uv run alembic upgrade head")
        XCTAssertTrue(presentation.vendorLine.contains(CodexApprovalPolicy.onRequest.rawValue))
        XCTAssertTrue(presentation.vendorLine.contains(CodexSandboxMode.workspaceWrite.rawValue))
    }

    func testClaudeCodeVendorLine() throws {
        let request = try request(
            kind: "editFiles",
            summary: "写入 3 个文件",
            vendor: [
                "agentKind": "claude_code",
                "permissionModeAtDecision": "acceptEdits",
                "toolName": "Write",
            ]
        )
        let presentation = ApprovalCardPresentation.make(from: request)
        XCTAssertTrue(
            presentation.vendorLine.contains(ClaudeCodePermissionMode.acceptEdits.rawValue)
        )
        XCTAssertTrue(presentation.vendorLine.contains("Write"))
    }

    func testReceiptStatesDescribeWinnerAndRetryWithoutAllowingDecisionChange() {
        XCTAssertEqual(
            ApprovalCardPresentation.stateText(
                .alreadyHandled(decision: .deny, deliveryState: .deliveryFailed)
            ),
            "已在另一控制端拒绝 · 投递失败"
        )
        XCTAssertTrue(
            ApprovalCardPresentation.allowsRetry(
                .deliveryFailed(.approve)
            )
        )
        XCTAssertFalse(
            ApprovalCardPresentation.allowsDecision(
                .deliveryFailed(.approve)
            )
        )
    }

    private func request(
        kind: String,
        summary: String,
        vendor: [String: Any]
    ) throws -> RuntimeActionRequestV1 {
        let data = try JSONSerialization.data(
            withJSONObject: [
                "requestId": "request-1",
                "kind": kind,
                "summary": summary,
                "vendor": vendor,
            ],
            options: [.sortedKeys]
        )
        return try JSONDecoder().decode(RuntimeActionRequestV1.self, from: data)
    }
}
