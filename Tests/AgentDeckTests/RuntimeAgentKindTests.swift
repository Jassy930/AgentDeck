import XCTest
@testable import AgentDeck

@MainActor
final class RuntimeAgentKindTests: XCTestCase {
    func testRuntimeCarriesAgentKindAndCapabilities() throws {
        let model = ThreadRuntimeModel(id: "s1", agentKind: .codex, cwd: URL(fileURLWithPath: "/tmp"))
        XCTAssertEqual(model.agentKind, .codex)
        XCTAssertNil(model.capabilities)

        let caps = SessionCapabilities(
            agentKind: .codex,
            agentVersion: "x",
            features: [.shell],
            vendor: .codex(CodexCapabilities(
                sandboxModes: [.readOnly],
                persistenceSupported: true,
                reasoningEffortLevels: [.medium]
            ))
        )
        model.applyCapabilities(caps)
        XCTAssertEqual(model.capabilities?.features, [.shell])
        XCTAssertEqual(model.capabilities?.agentKind, .codex)
    }

    func testIngestSessionCapabilitiesEventStoresCaps() {
        let runtime = ThreadRuntimeModel(id: "s1", agentKind: .claudeCode, cwd: URL(fileURLWithPath: "/tmp"))
        let caps = SessionCapabilities(
            agentKind: .claudeCode,
            agentVersion: "1.0",
            features: [.claudeCodePermissionMode],
            vendor: .claudeCode(ClaudeCodeCapabilities(
                permissionModes: [.default],
                outputStyles: [],
                hooksSupported: [],
                cliVersion: "1.0"
            ))
        )
        _ = runtime.ingest(.sessionCapabilities(sessionId: "s1", agentKind: .claudeCode, capabilities: caps))
        XCTAssertNotNil(runtime.capabilities)
        XCTAssertTrue(runtime.capabilities?.features.contains(.claudeCodePermissionMode) ?? false)
    }

    func testIngestAgentItemAppendsToItems() {
        let runtime = ThreadRuntimeModel(id: "s1", agentKind: .codex, cwd: URL(fileURLWithPath: "/tmp"))
        _ = runtime.ingest(.agentItem(
            sessionId: "s1", threadId: "t1", agentKind: .codex,
            item: .assistantMessage(text: "hello", meta: AgentItemMeta())
        ))
        XCTAssertEqual(runtime.items.count, 1)
        XCTAssertEqual(runtime.items.first?.text, "hello")
        XCTAssertEqual(runtime.items.first?.kind, "message")
    }

    func testIngestTurnCompleteTransitionsToReady() {
        let runtime = ThreadRuntimeModel(id: "s1", agentKind: .codex, cwd: URL(fileURLWithPath: "/tmp"))
        runtime.phase = .running
        _ = runtime.ingest(.turnComplete(
            sessionId: "s1", threadId: "t1", agentKind: .codex,
            summary: TurnSummary(totalInputTokens: nil, totalOutputTokens: nil, elapsedMs: 0)
        ))
        XCTAssertEqual(runtime.phase, .ready)
    }

    func testIngestActionRequestSetsWaitingApproval() {
        let runtime = ThreadRuntimeModel(id: "s1", agentKind: .codex, cwd: URL(fileURLWithPath: "/tmp"))
        let req = ActionRequest(
            requestId: "r1",
            kind: .executeCommand,
            summary: "run ls",
            vendor: .codex(approvalPolicyAtDecision: .onRequest, sandboxAtDecision: .workspaceWrite, canPersist: true)
        )
        _ = runtime.ingest(.actionRequest(
            sessionId: "s1", threadId: "t1", agentKind: .codex, request: req
        ))
        XCTAssertEqual(runtime.phase, .waitingApproval)
        XCTAssertEqual(runtime.pendingActionRequest?.requestId, "r1")
        XCTAssertEqual(runtime.pendingActionRequest?.actionKind, .executeCommand)
    }

    func testWorkbenchEnsureRuntimeAndIngest() {
        let workbench = WorkbenchModel(turnStarter: NoopRuntimeTurnStarter())
        workbench.ensureRuntime(
            sessionId: "s1", agentKind: .codex, threadId: "t1",
            cwd: URL(fileURLWithPath: "/tmp")
        )
        XCTAssertNotNil(workbench.runtime(sessionId: "s1"))
        workbench.ingestServerEvent(.agentItem(
            sessionId: "s1", threadId: "t1", agentKind: .codex,
            item: .assistantMessage(text: "x", meta: AgentItemMeta())
        ))
        XCTAssertEqual(workbench.runtime(sessionId: "s1")?.items.count, 1)
    }
}
