import AgentDeckCore
import Foundation
import XCTest
@testable import AgentDeck

private final class DelayedHistoryMutationTransport: DaemonTransport, @unchecked Sendable {
    enum MutationReply {
        case ack
        case error
        case unexpectedList
    }

    private let lock = NSLock()
    private let mutationReply: MutationReply
    private let listItems: [HistoryListItem]
    private let mutationDelay: TimeInterval
    private var incomingHandler: ((String) -> Void)?
    private var started = false
    private var mutationRequests = 0
    private var listRequests = 0
    private var mutationSentOnMainThread = false

    init(
        mutationReply: MutationReply,
        listItems: [HistoryListItem] = [],
        mutationDelay: TimeInterval = 0.2
    ) {
        self.mutationReply = mutationReply
        self.listItems = listItems
        self.mutationDelay = mutationDelay
    }

    var isStarted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return started
    }

    var isAlive: Bool { isStarted }

    var mutationRequestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return mutationRequests
    }

    var listRequestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return listRequests
    }

    var didSendMutationOnMainThread: Bool {
        lock.lock()
        defer { lock.unlock() }
        return mutationSentOnMainThread
    }

    func start() throws {
        lock.lock()
        started = true
        lock.unlock()
    }

    func send(_ line: String) throws {
        let command = try JSONDecoder().decode(ClientCommand.self, from: Data(line.utf8))
        guard case .history(let request) = command,
              let requestId = request.requestId else {
            throw DaemonError.malformedReply("fixture expected a correlated history request")
        }

        switch request {
        case .archive, .unarchive, .rename:
            lock.lock()
            mutationRequests += 1
            mutationSentOnMainThread = mutationSentOnMainThread || Thread.isMainThread
            lock.unlock()

            Thread.sleep(forTimeInterval: mutationDelay)
            switch mutationReply {
            case .ack:
                try push(response: .ack, requestId: requestId)
            case .error:
                try pushError(requestId: requestId)
            case .unexpectedList:
                try push(response: .list([]), requestId: requestId)
            }
        case .list:
            lock.lock()
            listRequests += 1
            lock.unlock()
            try push(response: .list(listItems), requestId: requestId)
        case .read:
            throw DaemonError.malformedReply("fixture does not support history read")
        }
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

    private func push(response: HistoryResponse, requestId: String) throws {
        let responseData = try JSONEncoder().encode(response)
        let responseObject = try JSONSerialization.jsonObject(with: responseData)
        try push([
            "reply": "history",
            "requestId": requestId,
            "response": responseObject,
        ])
    }

    private func pushError(requestId: String) throws {
        try push([
            "reply": "history",
            "requestId": requestId,
            "error": [
                "code": "history-mutation-fixture",
                "message": "mutation failed",
                "diagnosticRef": NSNull(),
            ],
        ])
    }

    private func push(_ object: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: object)
        guard let line = String(data: data, encoding: .utf8) else {
            throw DaemonError.malformedReply("fixture failed to encode reply")
        }
        lock.lock()
        let handler = incomingHandler
        lock.unlock()
        handler?(line)
    }
}

@MainActor
final class SessionModelHistoryMutationTests: XCTestCase {
    private func thread(
        id: String = "thread-1",
        name: String? = "Original",
        agentKind: AgentKind = .codex
    ) -> HistoryThreadSummary {
        HistoryThreadSummary(
            id: id,
            name: name,
            preview: name ?? "Preview",
            cwd: "/tmp/project",
            createdAt: 1,
            updatedAt: 2,
            status: "ready",
            modelProvider: agentKind == .codex ? "openai" : "anthropic",
            source: agentKind == .codex ? "codex" : "claude_code",
            agentKind: agentKind
        )
    }

    private func listItem(
        id: String = "thread-1",
        title: String,
        agentKind: AgentKind = .codex
    ) -> HistoryListItem {
        HistoryListItem(
            threadId: id,
            agentKind: agentKind,
            title: title,
            cwd: "/tmp/project",
            lastActiveMs: 2_000,
            archived: false
        )
    }

    func testArchiveReturnsImmediatelyAndHandlesThreadRemovedBeforeAck() async {
        let transport = DelayedHistoryMutationTransport(mutationReply: .ack)
        let model = SessionModel(client: DaemonClient(transport: transport))
        let original = thread()
        model.setHistoryThreads([original])
        model.applyHistoryReadResponse(
            HistoryReadResponse(threadId: original.id, agentKind: original.agentKind, turns: []),
            originalThread: original
        )
        XCTAssertNotNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(original)))

        let startedAt = Date()
        model.archiveHistoryThread(original)
        let callDuration = Date().timeIntervalSince(startedAt)

        XCTAssertLessThan(callDuration, 0.1, "归档入口不能等待 daemon round-trip")
        XCTAssertEqual(model.selectedHistoryThreadId, original.id)
        model.setHistoryThreads([]) // 模拟请求期间 outline 数据被另一轮刷新删除。

        let didFinish = await waitUntil {
            transport.listRequestCount == 1 && !model.isLoadingHistory
        }
        XCTAssertTrue(didFinish)
        XCTAssertEqual(transport.mutationRequestCount, 1)
        XCTAssertFalse(transport.didSendMutationOnMainThread)
        XCTAssertNil(model.selectedHistoryThreadId)
        XCTAssertNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(original)))
        XCTAssertTrue(model.historyThreads.isEmpty)
        XCTAssertNil(model.historyErrorMessage)
    }

    func testArchiveRemovesOnlyMatchingHydratedRuntimeWithSharedRawId() async {
        let sharedId = "shared-thread"
        let codex = thread(id: sharedId, name: "Codex", agentKind: .codex)
        let claude = thread(id: sharedId, name: "Claude", agentKind: .claudeCode)
        let transport = DelayedHistoryMutationTransport(
            mutationReply: .ack,
            listItems: [listItem(id: sharedId, title: "Claude", agentKind: .claudeCode)],
            mutationDelay: 0.01
        )
        let model = SessionModel(client: DaemonClient(transport: transport))
        model.setHistoryThreads([codex, claude])
        model.applyHistoryReadResponse(
            HistoryReadResponse(threadId: sharedId, agentKind: .codex, turns: []),
            originalThread: codex
        )
        model.applyHistoryReadResponse(
            HistoryReadResponse(threadId: sharedId, agentKind: .claudeCode, turns: []),
            originalThread: claude
        )

        model.archiveHistoryThread(codex)

        let didFinish = await waitUntil {
            transport.listRequestCount == 1 && !model.isLoadingHistory
        }
        XCTAssertTrue(didFinish)
        XCTAssertNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(codex)))
        XCTAssertNotNil(model.workbench.runtime(forHistory: HistoryThreadIdentity(claude)))
        XCTAssertEqual(model.selectedHistoryThreadIdentity, HistoryThreadIdentity(claude))
        XCTAssertEqual(
            model.historyGroups.flatMap(\.threads).map(HistoryThreadIdentity.init),
            [HistoryThreadIdentity(claude)],
            "归档目标不得被残留 hydrate runtime 作为 live 会话补回"
        )
    }

    func testRenameReturnsImmediatelyAndRefreshesChangedThreadAfterAck() async {
        let transport = DelayedHistoryMutationTransport(
            mutationReply: .ack,
            listItems: [listItem(title: "Server title")]
        )
        let model = SessionModel(client: DaemonClient(transport: transport))
        let original = thread()
        model.setHistoryThreads([original])

        let startedAt = Date()
        model.renameHistoryThread(original, name: "Requested title")
        let callDuration = Date().timeIntervalSince(startedAt)

        XCTAssertLessThan(callDuration, 0.1, "重命名入口不能等待 daemon round-trip")
        model.setHistoryThreads([thread(name: "Concurrent local title")])

        let didFinish = await waitUntil {
            model.historyThreads.first?.name == "Server title" && !model.isLoadingHistory
        }
        XCTAssertTrue(didFinish)
        XCTAssertEqual(transport.listRequestCount, 1)
        XCTAssertFalse(transport.didSendMutationOnMainThread)
        XCTAssertNil(model.historyErrorMessage)
    }

    func testRenameFailureArrivesAsynchronouslyWithoutRefreshingList() async {
        let transport = DelayedHistoryMutationTransport(mutationReply: .error)
        let model = SessionModel(client: DaemonClient(transport: transport))
        let original = thread()
        model.setHistoryThreads([original])

        let startedAt = Date()
        model.renameHistoryThread(original, name: "Requested title")
        let callDuration = Date().timeIntervalSince(startedAt)

        XCTAssertLessThan(callDuration, 0.1, "失败路径也不能阻塞 UI")
        XCTAssertNil(model.historyErrorMessage)
        let didFinish = await waitUntil { model.historyErrorMessage != nil }
        XCTAssertTrue(didFinish)
        XCTAssertEqual(transport.listRequestCount, 0)
        XCTAssertEqual(model.historyThreads.first?.name, "Original")
        XCTAssertEqual(
            model.historyErrorMessage,
            "agentdeckd error [history-mutation-fixture]: mutation failed"
        )
    }

    func testMutationRejectsNonAckResponseWithoutRefreshingList() async {
        let transport = DelayedHistoryMutationTransport(
            mutationReply: .unexpectedList,
            mutationDelay: 0.01
        )
        let model = SessionModel(client: DaemonClient(transport: transport))
        let original = thread()
        model.setHistoryThreads([original])

        model.archiveHistoryThread(original)

        let didFinish = await waitUntil { model.historyErrorMessage != nil }
        XCTAssertTrue(didFinish)
        XCTAssertEqual(transport.listRequestCount, 0)
        XCTAssertEqual(model.historyThreads, [original])
        XCTAssertEqual(
            model.historyErrorMessage,
            "malformed reply from agentdeckd: expected history ack response"
        )
    }
}
