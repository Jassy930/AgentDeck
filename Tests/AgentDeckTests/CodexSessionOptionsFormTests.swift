import XCTest
@testable import AgentDeck

@MainActor
final class CodexSessionOptionsFormTests: XCTestCase {

    func testDefaultOptionsAreReasonable() {
        let form = CodexSessionOptionsForm()
        form.loadViewIfNeeded()
        let opts = form.buildVendorOptions()
        guard case .codex(let codex) = opts else { return XCTFail("expected codex options") }
        XCTAssertEqual(codex.approvalPolicy, .onRequest)
        XCTAssertEqual(codex.sandbox, .workspaceWrite)
        XCTAssertFalse(codex.persistApproval)
        XCTAssertEqual(codex.reasoningEffort, .medium)
        XCTAssertTrue(codex.mcpOverrides.isEmpty)
    }

    func testSettersFlowIntoBuildVendorOptions() {
        let form = CodexSessionOptionsForm()
        form.loadViewIfNeeded()
        form.setApprovalPolicy(.never)
        form.setSandbox(.readOnly)
        form.setPersistApproval(true)
        form.setReasoningEffort(.high)
        let opts = form.buildVendorOptions()
        guard case .codex(let codex) = opts else { return XCTFail() }
        XCTAssertEqual(codex.approvalPolicy, .never)
        XCTAssertEqual(codex.sandbox, .readOnly)
        XCTAssertTrue(codex.persistApproval)
        XCTAssertEqual(codex.reasoningEffort, .high)
    }
}
