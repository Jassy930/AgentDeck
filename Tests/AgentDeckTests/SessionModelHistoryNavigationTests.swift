import AgentDeckCore
import Foundation
import XCTest
@testable import AgentDeck

private final class ControllableHistoryReadTransport: DaemonTransport, @unchecked Sendable {
    struct ReadRequest: Sendable {
        let requestId: String
        let identity: HistoryThreadIdentity
    }

    private let lock = NSLock()
    private var incomingHandler: ((String) -> Void)?
    private var started = false
    private var requests: [ReadRequest] = []

    var isStarted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return started
    }

    var isAlive: Bool { isStarted }

    var readRequestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return requests.count
    }

    func start() throws {
        lock.lock()
        started = true
        lock.unlock()
    }

    func send(_ line: String) throws {
        let command = try JSONDecoder().decode(ClientCommand.self, from: Data(line.utf8))
        guard case .history(let request) = command,
              case .read(let threadId, let agentKind, let requestId) = request,
              let requestId else {
            throw DaemonError.malformedReply("fixture expected a correlated history read")
        }
        lock.lock()
        requests.append(ReadRequest(
            requestId: requestId,
            identity: HistoryThreadIdentity(agentKind: agentKind, threadId: threadId)
        ))
        lock.unlock()
    }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) {
        lock.lock()
        incomingHandler = handler
        lock.unlock()
    }

    func setDisconnectHandler(_ handler: @escaping () -> Void) {}

    func shutdown() {
        lock.lock()
        started = false
        lock.unlock()
    }

    func request(at index: Int) -> ReadRequest? {
        lock.lock()
        defer { lock.unlock() }
        guard requests.indices.contains(index) else { return nil }
        return requests[index]
    }

    func reply(at index: Int, text: String) throws {
        guard let request = request(at: index) else {
            throw DaemonError.malformedReply("fixture read request \(index) does not exist")
        }
        let response = HistoryResponse.read(HistoryReadResponse(
            threadId: request.identity.threadId,
            agentKind: request.identity.agentKind,
            turns: [HistoryTurn(items: [
                .assistantMessage(text: text, meta: AgentItemMeta()),
            ])]
        ))
        let responseData = try JSONEncoder().encode(response)
        let responseObject = try JSONSerialization.jsonObject(with: responseData)
        let envelope: [String: Any] = [
            "reply": "history",
            "requestId": request.requestId,
            "response": responseObject,
        ]
        let data = try JSONSerialization.data(withJSONObject: envelope)
        guard let line = String(data: data, encoding: .utf8) else {
            throw DaemonError.malformedReply("fixture failed to encode history reply")
        }
        lock.lock()
        let handler = incomingHandler
        lock.unlock()
        handler?(line)
    }
}

@MainActor
final class SessionModelHistoryNavigationTests: XCTestCase {
    private func thread(
        id: String,
        agentKind: AgentKind,
        source: String? = nil,
        cwd: String = "/tmp/project"
    ) -> HistoryThreadSummary {
        HistoryThreadSummary(
            id: id,
            name: "\(agentKind.rawValue)-\(id)",
            preview: "preview",
            cwd: cwd,
            createdAt: 1,
            updatedAt: 2,
            status: "ready",
            modelProvider: agentKind == .codex ? "openai" : "anthropic",
            source: source ?? (agentKind == .codex ? "codex" : "claude_code"),
            agentKind: agentKind
        )
    }

    func testSelectingLiveThreadInvalidatesPendingHistoryRead() async throws {
        let transport = ControllableHistoryReadTransport()
        let model = SessionModel(client: DaemonClient(transport: transport))
        let persisted = thread(id: "history-1", agentKind: .codex, cwd: "/tmp/history")
        model.setHistoryThreads([persisted])
        model.workbench.ensureRuntime(
            sessionId: "live-1",
            agentKind: .codex,
            threadId: nil,
            cwd: URL(fileURLWithPath: "/tmp/live")
        )

        model.openHistoryThread(persisted)
        let didSendPersistedRead = await waitUntil { transport.readRequestCount == 1 }
        XCTAssertTrue(didSendPersistedRead)

        let live = try XCTUnwrap(
            model.historyGroups.flatMap(\.threads).first { $0.source == "live" }
        )
        model.openHistoryThread(live)
        XCTAssertNil(model.openingHistoryThreadIdentity)
        XCTAssertNil(model.selectedHistoryThreadIdentity)
        XCTAssertEqual(model.workbench.selectedSessionId, "live-1")
        XCTAssertEqual(model.cwd?.path, "/tmp/live")

        try transport.reply(at: 0, text: "stale history")
        try await Task.sleep(for: .milliseconds(100))

        XCTAssertNil(model.selectedHistoryThreadIdentity)
        XCTAssertEqual(model.workbench.selectedSessionId, "live-1")
        XCTAssertEqual(model.cwd?.path, "/tmp/live")
        XCTAssertNil(model.workbench.runtime(
            forHistory: HistoryThreadIdentity(agentKind: .codex, threadId: "history-1")
        ))
        XCTAssertNil(model.lastHistoryOpenTiming)
    }

    func testStartingNewSessionInvalidatesPendingHistoryRead() async throws {
        let transport = ControllableHistoryReadTransport()
        let model = SessionModel(client: DaemonClient(transport: transport))
        let persisted = thread(id: "history-1", agentKind: .codex, cwd: "/tmp/history")
        model.setHistoryThreads([persisted])
        model.cwd = URL(fileURLWithPath: "/tmp/new")

        model.openHistoryThread(persisted)
        let didSendRead = await waitUntil { transport.readRequestCount == 1 }
        XCTAssertTrue(didSendRead)

        model.startNewSessionFromCurrentProject()
        try transport.reply(at: 0, text: "stale history")
        try await Task.sleep(for: .milliseconds(100))

        XCTAssertNil(model.openingHistoryThreadIdentity)
        XCTAssertNil(model.selectedHistoryThreadIdentity)
        XCTAssertNil(model.workbench.selectedSessionId)
        XCTAssertEqual(model.cwd?.path, "/tmp/new")
        XCTAssertNil(model.workbench.runtime(
            forHistory: HistoryThreadIdentity(agentKind: .codex, threadId: "history-1")
        ))
    }

    func testNewHistorySelectionWithSameRawIdInvalidatesOlderAgentRead() async throws {
        let transport = ControllableHistoryReadTransport()
        let model = SessionModel(client: DaemonClient(transport: transport))
        let codex = thread(id: "shared", agentKind: .codex)
        let claude = thread(id: "shared", agentKind: .claudeCode)
        model.setHistoryThreads([codex, claude])

        model.openHistoryThread(codex)
        let didSendCodexRead = await waitUntil { transport.readRequestCount == 1 }
        XCTAssertTrue(didSendCodexRead)
        model.openHistoryThread(claude)
        XCTAssertEqual(model.openingHistoryThreadIdentity, HistoryThreadIdentity(claude))

        try transport.reply(at: 0, text: "stale codex")
        let didSendClaudeRead = await waitUntil { transport.readRequestCount == 2 }
        XCTAssertTrue(didSendClaudeRead)
        XCTAssertNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(codex)))

        try transport.reply(at: 1, text: "current claude")
        let didSelectClaude = await waitUntil {
            model.selectedHistoryThreadIdentity == HistoryThreadIdentity(claude)
        }
        XCTAssertTrue(didSelectClaude)
        XCTAssertNil(model.openingHistoryThreadIdentity)
        XCTAssertNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(codex)))
        XCTAssertEqual(
            model.workbench.runtime(forHistory: HistoryThreadIdentity(claude))?.items.first?.text,
            "current claude"
        )
    }

    func testCombinedHistoryAndRuntimeLookupUseAgentKindWithThreadId() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let codex = thread(id: "shared", agentKind: .codex)
        let claude = thread(id: "shared", agentKind: .claudeCode)
        model.setHistoryThreads([codex, claude, codex])

        model.applyHistoryReadResponse(
            HistoryReadResponse(threadId: "shared", agentKind: .codex, turns: []),
            originalThread: codex
        )
        model.applyHistoryReadResponse(
            HistoryReadResponse(threadId: "shared", agentKind: .claudeCode, turns: []),
            originalThread: claude
        )

        let visible = model.historyGroups.flatMap(\.threads)
        XCTAssertEqual(visible.count, 2, "相同 vendor 身份重复项应去重，不同 agent 必须同时保留")
        XCTAssertEqual(Set(visible.map(HistoryThreadIdentity.init)), Set([
            HistoryThreadIdentity(codex),
            HistoryThreadIdentity(claude),
        ]))

        let codexRuntime = model.runtime(for: codex)
        let claudeRuntime = model.runtime(for: claude)
        XCTAssertEqual(codexRuntime?.agentKind, .codex)
        XCTAssertEqual(claudeRuntime?.agentKind, .claudeCode)
        XCTAssertNotEqual(codexRuntime?.id, claudeRuntime?.id)
    }
}
