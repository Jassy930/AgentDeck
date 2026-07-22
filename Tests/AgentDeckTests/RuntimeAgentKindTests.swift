import XCTest
import AgentDeckCore
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

    func testWorkbenchAdoptsDaemonSessionIdForNewRuntime() {
        let workbench = WorkbenchModel(turnStarter: NoopRuntimeTurnStarter())
        workbench.ensureRuntime(
            sessionId: "live-provisional",
            agentKind: .codex,
            threadId: nil,
            cwd: URL(fileURLWithPath: "/tmp/project")
        )
        workbench.selectRuntime(sessionId: "live-provisional")

        workbench.ingestServerEvent(.sessionStarted(
            sessionId: "daemon-session",
            threadId: nil,
            agentKind: .codex
        ))
        workbench.ingestServerEvent(.agentItem(
            sessionId: "daemon-session",
            threadId: "thread-1",
            agentKind: .codex,
            item: .assistantMessage(text: "hello", meta: AgentItemMeta())
        ))

        XCTAssertNil(workbench.runtime(sessionId: "live-provisional"))
        XCTAssertEqual(workbench.selectedSessionId, "daemon-session")
        XCTAssertEqual(workbench.runtime(sessionId: "daemon-session")?.id, "daemon-session")
        XCTAssertEqual(workbench.runtime(sessionId: "daemon-session")?.threadId, "thread-1")
        XCTAssertEqual(workbench.runtime(sessionId: "daemon-session")?.items.first?.text, "hello")
    }

    func testReplayTurnsMatchesSingleStoreReducerResults() {
        let agentItems: [AgentItem] = [
            .userMessage(text: "question", meta: AgentItemMeta()),
            .assistantMessage(text: "answer", meta: AgentItemMeta()),
            .shell(
                command: "pwd",
                status: .completed,
                exitCode: 0,
                durationMs: 12,
                meta: AgentItemMeta()
            ),
            .raw(rawKind: "fixture", rawPayload: "raw payload", meta: AgentItemMeta()),
        ]
        var expected = AgentItemStore()
        for (index, item) in agentItems.enumerated() {
            AgentItemReducer.apply(item, itemId: "ai-\(index + 1)", into: &expected)
        }
        let runtime = ThreadRuntimeModel(
            id: "history",
            agentKind: .codex,
            cwd: URL(fileURLWithPath: "/tmp")
        )

        runtime.applyReplayTurns([
            HistoryTurn(items: Array(agentItems.prefix(2))),
            HistoryTurn(items: Array(agentItems.suffix(2))),
        ])

        XCTAssertEqual(runtime.itemIndexById, expected.itemIndexById)
        XCTAssertEqual(runtime.items.map(\.id), expected.items.map(\.id))
        XCTAssertEqual(runtime.items.map(\.kind), expected.items.map(\.kind))
        XCTAssertEqual(runtime.items.map(\.text), expected.items.map(\.text))
        XCTAssertEqual(runtime.items.map(\.command), expected.items.map(\.command))
        XCTAssertEqual(runtime.items.map(\.statusName), expected.items.map(\.statusName))
    }

    func testReplayTurnsBuildsLargeHistoryInOneCompleteStore() {
        let count = 4_000
        let items: [AgentItem] = (0..<count).map { index in
            .assistantMessage(text: "message-\(index)", meta: AgentItemMeta())
        }
        let runtime = ThreadRuntimeModel(
            id: "large-history",
            agentKind: .claudeCode,
            cwd: URL(fileURLWithPath: "/tmp")
        )

        runtime.applyReplayTurns([HistoryTurn(items: items)])

        XCTAssertEqual(runtime.items.count, count)
        XCTAssertEqual(runtime.itemIndexById.count, count)
        XCTAssertEqual(runtime.items.first?.id, "ai-1")
        XCTAssertEqual(runtime.items.first?.text, "message-0")
        XCTAssertEqual(runtime.items.last?.id, "ai-4000")
        XCTAssertEqual(runtime.items.last?.text, "message-3999")
        XCTAssertEqual(runtime.itemIndexById["ai-4000"], 3_999)
    }
}
