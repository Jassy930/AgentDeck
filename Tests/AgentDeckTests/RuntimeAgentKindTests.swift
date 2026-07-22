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

    func testClaudeToolSnapshotsFoldIntoOneLiveItem() throws {
        let runtime = ThreadRuntimeModel(
            id: "cc-live",
            agentKind: .claudeCode,
            cwd: URL(fileURLWithPath: "/tmp")
        )
        let snapshots = claudeToolSnapshots(toolUseId: "tu-live")

        for item in snapshots {
            _ = runtime.ingest(.agentItem(
                sessionId: "cc-live",
                threadId: "thread-live",
                agentKind: .claudeCode,
                item: item
            ))
        }

        XCTAssertEqual(runtime.items.count, 1)
        XCTAssertEqual(runtime.itemIndexById.count, 1)
        let item = try XCTUnwrap(runtime.items.first)
        XCTAssertEqual(item.id, "tool-tu-live")
        XCTAssertEqual(item.statusName, "failed")
        XCTAssertEqual(item.durationMs, 42)
        XCTAssertEqual(item.success, false)
        XCTAssertTrue(item.result.contains("file not found"))
        XCTAssertFalse(runtime.items.contains { $0.statusName == "inProgress" })
    }

    func testClaudeToolSnapshotsFoldIntoOneHistoryItem() throws {
        let runtime = ThreadRuntimeModel(
            id: "cc-history",
            agentKind: .claudeCode,
            cwd: URL(fileURLWithPath: "/tmp")
        )

        runtime.applyReplayTurns([
            HistoryTurn(items: claudeToolSnapshots(toolUseId: "tu-history")),
        ])

        XCTAssertEqual(runtime.items.count, 1)
        XCTAssertEqual(runtime.itemIndexById.count, 1)
        let item = try XCTUnwrap(runtime.items.first)
        XCTAssertEqual(item.id, "tool-tu-history")
        XCTAssertEqual(item.statusName, "failed")
        XCTAssertEqual(item.durationMs, 42)
        XCTAssertEqual(item.success, false)
        XCTAssertTrue(item.result.contains("file not found"))
        XCTAssertFalse(runtime.items.contains { $0.statusName == "inProgress" })
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

    func testToolReducerPreservesNeutralPresentationMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "server": AnyCodable("node_repl"),
            "status": AnyCodable("failed"),
            "durationMs": AnyCodable(Int64(136)),
            "mcpAppResourceUri": AnyCodable("app://agentdeck"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "js",
            args: AnyCodable(["title": "确认 AgentDeck 窗口"]),
            result: AnyCodable(["success": false]),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-1", into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.server, "node_repl")
        XCTAssertEqual(item.tool, "js")
        XCTAssertEqual(item.toolKind, "mcp")
        XCTAssertEqual(item.statusName, "failed")
        XCTAssertEqual(item.durationMs, 136)
        XCTAssertEqual(item.resourceUri, "app://agentdeck")
        XCTAssertEqual(item.success, false)
    }

    func testToolReducerPreservesClaudeCodeFailureMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "toolUseId": AnyCodable("tool-use-1"),
            "isError": AnyCodable(true),
        ])
        let agentItem = AgentItem.toolCall(
            name: "Read",
            args: AnyCodable(["file_path": "/tmp/missing"]),
            result: AnyCodable("file not found"),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-cc-1", into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.tool, "Read")
        XCTAssertEqual(item.success, false)
        XCTAssertEqual(ToolPresentation.toolStatus(item), "failed")
    }

    func testToolReducerPrefersCanonicalMCPAppContextMetadata() throws {
        let meta = AgentItemMeta(vendorExtensions: [
            "server": AnyCodable("node_repl"),
            "status": AnyCodable("completed"),
            "resourceUri": AnyCodable("app://canonical-agentdeck"),
            "actionName": AnyCodable("确认 AgentDeck 窗口"),
            "mcpAppResourceUri": AnyCodable("app://deprecated-agentdeck"),
        ])
        let agentItem = AgentItem.toolCall(
            name: "js",
            args: AnyCodable(["code": "..."]),
            result: AnyCodable(["success": true]),
            meta: meta
        )
        var store = AgentItemStore()

        AgentItemReducer.apply(agentItem, itemId: "tool-canonical", into: &store)

        let item = try XCTUnwrap(store.items.first)
        XCTAssertEqual(item.resourceUri, "app://canonical-agentdeck")
        XCTAssertEqual(item.action, "确认 AgentDeck 窗口")
        XCTAssertEqual(ToolPresentation.toolContextSummary(item), "确认 AgentDeck 窗口")
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

    private func claudeToolSnapshots(toolUseId: String) -> [AgentItem] {
        let args = AnyCodable(["file_path": "/tmp/missing"])
        return [
            .toolCall(
                name: "Read",
                args: args,
                result: nil,
                meta: AgentItemMeta(vendorExtensions: [
                    "toolUseId": AnyCodable(toolUseId),
                    "status": AnyCodable("inProgress"),
                ])
            ),
            .toolCall(
                name: "Read",
                args: args,
                result: AnyCodable("file not found"),
                meta: AgentItemMeta(vendorExtensions: [
                    "toolUseId": AnyCodable(toolUseId),
                    "status": AnyCodable("failed"),
                    "durationMs": AnyCodable(42),
                    "isError": AnyCodable(true),
                ])
            ),
        ]
    }
}
