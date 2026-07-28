import XCTest
import AgentDeckCore
import AppKit
@testable import AgentDeck

@MainActor
final class CapabilityRouterTests: XCTestCase {

    // MARK: - bottomView routing

    func testCodexApprovalRoutesToCodexPanel() {
        let req = ActionRequest(
            requestId: "r1",
            kind: .executeCommand,
            summary: "ls",
            vendor: .codex(
                approvalPolicyAtDecision: .onRequest,
                sandboxAtDecision: .workspaceWrite,
                canPersist: true
            )
        )
        let caps = SessionCapabilities.codexStub()
        let view = CapabilityRouter.bottomView(for: req, in: caps)
        XCTAssertTrue(view is CodexApprovalPanel, "Codex action must route to CodexApprovalPanel")
    }

    func testCCApprovalRoutesToCCPanel() {
        let req = ActionRequest(
            requestId: "r2",
            kind: .editFiles,
            summary: "edit /tmp/x",
            vendor: .claudeCode(permissionModeAtDecision: .default, toolName: "Edit")
        )
        let caps = SessionCapabilities.ccStub()
        let view = CapabilityRouter.bottomView(for: req, in: caps)
        XCTAssertTrue(view is ClaudeCodePermissionPanel, "CC action must route to ClaudeCodePermissionPanel")
    }

    // MARK: - controlBarMiniView routing

    func testCodexCapsRoutesToCodexControlsView() {
        let view = CapabilityRouter.controlBarMiniView(for: .codexStub())
        XCTAssertTrue(view is CodexControlsView)
    }

    func testCCCapsRoutesToCCControlsView() {
        let view = CapabilityRouter.controlBarMiniView(for: .ccStub())
        XCTAssertTrue(view is ClaudeCodeControlsView)
    }

    // MARK: - sessionOptionsForm routing

    func testCodexFormProducesCodexOptions() {
        let form = CapabilityRouter.sessionOptionsForm(for: .codex)
        XCTAssertTrue(form is CodexSessionOptionsForm)
        let opts = form.buildVendorOptions()
        if case .codex = opts {} else { XCTFail("expected .codex options") }
    }

    func testCCFormProducesCCOptions() {
        let form = CapabilityRouter.sessionOptionsForm(for: .claudeCode)
        XCTAssertTrue(form is ClaudeCodeSessionOptionsForm)
        let opts = form.buildVendorOptions()
        if case .claudeCode = opts {} else { XCTFail("expected .claudeCode options") }
    }

    // MARK: - tokenAuthMiniPanel routing

    func testTokenAuthPanelBuilds() {
        let codexPanel = CapabilityRouter.tokenAuthMiniPanel(for: .codexStub())
        XCTAssertTrue(codexPanel is AgentTokenAuthMiniPanel)
        let ccPanel = CapabilityRouter.tokenAuthMiniPanel(for: .ccStub())
        XCTAssertTrue(ccPanel is AgentTokenAuthMiniPanel)
    }

    // MARK: - AgentKindIcon

    func testAgentKindIconLoadsBothImages() {
        XCTAssertNotNil(AgentKindIcon.image(for: .codex))
        XCTAssertNotNil(AgentKindIcon.image(for: .claudeCode))
    }

    func testAgentKindIconCachesDecodedImagesForHistoryRowReuse() throws {
        let fullCodex = try XCTUnwrap(AgentKindIcon.image(for: .codex))
        let fullCodexSize = fullCodex.size
        let firstCodex = try XCTUnwrap(AgentKindIcon.compactImage(for: .codex))
        let secondCodex = try XCTUnwrap(AgentKindIcon.compactImage(for: .codex))
        let firstClaude = try XCTUnwrap(AgentKindIcon.compactImage(for: .claudeCode))
        let secondClaude = try XCTUnwrap(AgentKindIcon.compactImage(for: .claudeCode))

        XCTAssertTrue(
            firstCodex === secondCodex,
            "历史侧栏复用行时不应重复解析 Codex SVG 资源"
        )
        XCTAssertTrue(
            firstClaude === secondClaude,
            "历史侧栏复用行时不应重复解析 Claude Code SVG 资源"
        )
        XCTAssertFalse(fullCodex === firstCodex, "紧凑图不得修改共享原图尺寸")
        XCTAssertEqual(fullCodex.size, fullCodexSize)
        XCTAssertEqual(firstCodex.size, NSSize(width: 18, height: 18))
    }
}

// MARK: - Capabilities stubs

extension SessionCapabilities {
    static func codexStub() -> SessionCapabilities {
        SessionCapabilities(
            agentKind: .codex,
            agentVersion: "test",
            features: [.streamingMessages, .codexSandboxMode, .codexApprovalPersistence],
            vendor: .codex(CodexCapabilities(
                sandboxModes: [.readOnly, .workspaceWrite, .fullAccess],
                persistenceSupported: true,
                reasoningEffortLevels: [.low, .medium, .high]
            ))
        )
    }

    static func ccStub() -> SessionCapabilities {
        SessionCapabilities(
            agentKind: .claudeCode,
            agentVersion: "test",
            features: [.streamingMessages, .claudeCodePermissionMode, .claudeCodePlanMode],
            vendor: .claudeCode(ClaudeCodeCapabilities(
                permissionModes: [.default, .acceptEdits, .plan],
                outputStyles: ["default", "concise"],
                hooksSupported: [],
                cliVersion: "1.0"
            ))
        )
    }
}
