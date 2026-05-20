import Foundation
import AppKit
import Testing
@testable import AgentDeck

// IPC-layer tests. Eng D5 promoted these to P1: the Swift↔Rust IPC layer is
// the most fragile of the three innovation tokens (cross-language + concurrency
// + streaming). The single highest-risk failure is partial-line framing — a
// JSON message split across multiple read() calls — so it gets a dedicated test.

@Suite("Neutral IPC protocol")
struct IpcMessageTests {

    @Test("IpcMessage encodes to newline-free neutral JSON")
    func encodesNeutral() throws {
        let msg = IpcMessage(kind: "ping", id: 1, payload: nil)
        let data = try JSONEncoder().encode(msg)
        let s = String(data: data, encoding: .utf8)!
        #expect(s.contains("\"kind\":\"ping\""))
        #expect(!s.contains("\n"))
    }

    @Test("round-trip decode preserves kind and id")
    func roundTripDecode() throws {
        let original = IpcMessage(kind: "pong", id: 42, payload: nil)
        let data = try JSONEncoder().encode(original)
        let back = try JSONDecoder().decode(IpcMessage.self, from: data)
        #expect(back.kind == "pong")
        #expect(back.id == 42)
    }

    /// Eng D2: the neutral wire must never carry vendor vocabulary. Guard test
    /// — if a future change leaks a Codex-named field onto the Swift side,
    /// this fails. The neutral boundary is a verifiable fact, not a convention.
    @Test("neutral wire has no vendor vocabulary")
    func noVendorVocabulary() throws {
        let msg = IpcMessage(kind: "error", id: 1,
                             payload: AnyCodable(["message": "x"]))
        let s = String(data: try JSONEncoder().encode(msg), encoding: .utf8)!.lowercased()
        #expect(!s.contains("codex"))
        #expect(!s.contains("openai"))
    }

    @Test("logging selfcheck request is neutral")
    func loggingSelfcheckRequestIsNeutral() throws {
        let msg = IpcMessage(kind: "selfcheck/logging", id: 8, payload: nil)
        let data = try JSONEncoder().encode(msg)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: data)
        let wire = String(data: data, encoding: .utf8)!.lowercased()
        #expect(decoded.kind == "selfcheck/logging")
        #expect(!wire.contains("codex"))
        #expect(!wire.contains("openai"))
    }
}

@Suite("BufferedLineReader framing")
struct BufferedLineReaderTests {

    /// Write `input` into a pipe, close it, and collect every line the reader
    /// yields. Closing the write end produces EOF so the reader terminates.
    private func readAll(_ input: Data) -> [String] {
        let pipe = Pipe()
        let reader = BufferedLineReader(handle: pipe.fileHandleForReading)
        pipe.fileHandleForWriting.write(input)
        try? pipe.fileHandleForWriting.close()
        var lines: [String] = []
        while let l = reader.nextLine() { lines.append(l) }
        return lines
    }

    @Test("splits two newline-delimited messages")
    func twoMessages() {
        let lines = readAll(Data("{\"a\":1}\n{\"b\":2}\n".utf8))
        #expect(lines == ["{\"a\":1}", "{\"b\":2}"])
    }

    @Test("a message arriving without a trailing newline is still flushed at EOF")
    func trailingPartialFlushedAtEOF() {
        let lines = readAll(Data("{\"a\":1}".utf8))
        #expect(lines == ["{\"a\":1}"])
    }

    @Test("empty input yields no lines")
    func emptyInput() {
        #expect(readAll(Data()).isEmpty)
    }

    /// The core fragility (Codex C-uitest): one logical JSON message split
    /// across the buffer. Simulated here by interleaving writes with reads.
    @Test("a message split across two writes is reassembled")
    func splitMessageReassembled() {
        let pipe = Pipe()
        let reader = BufferedLineReader(handle: pipe.fileHandleForReading)
        pipe.fileHandleForWriting.write(Data("{\"hel".utf8))
        pipe.fileHandleForWriting.write(Data("lo\":true}\n".utf8))
        try? pipe.fileHandleForWriting.close()
        #expect(reader.nextLine() == "{\"hello\":true}")
    }
}

@Suite("Session render throttling")
@MainActor
struct SessionRenderThrottlingTests {
    private func agentItem(
        id: String,
        lifecycle: String = "delta",
        kind: String = "message",
        text: String
    ) -> IpcMessage {
        IpcMessage(
            kind: "agentItem",
            id: nil,
            payload: AnyCodable([
                "id": id,
                "lifecycle": lifecycle,
                "kind": kind,
                "text": text,
            ])
        )
    }

    @Test("streaming deltas are buffered until the render flush")
    func deltasAreBufferedUntilRenderFlush() {
        let model = SessionModel()

        model.ingest(agentItem(id: "msg1", text: "Hel"))
        model.ingest(agentItem(id: "msg1", text: "lo"))

        #expect(model.items.isEmpty)

        model.flushPendingAgentItems()

        #expect(model.items.count == 1)
        #expect(model.items[0].id == "msg1")
        #expect(model.items[0].text == "Hello")
    }

    @Test("turn completion flushes buffered deltas before marking ready")
    func turnCompleteFlushesBufferedDeltas() {
        let model = SessionModel()
        model.phase = .running

        model.ingest(agentItem(id: "msg1", text: "final"))
        model.ingest(IpcMessage(kind: "turnComplete", id: nil, payload: nil))

        #expect(model.phase == .ready)
        #expect(model.items.count == 1)
        #expect(model.items[0].text == "final")
    }

    @Test("daemon warning is visible without failing the turn")
    func daemonWarningIsVisibleWithoutFailingTheTurn() {
        let model = SessionModel()
        model.phase = .running

        model.ingest(IpcMessage(
            kind: "warning",
            id: nil,
            payload: AnyCodable(["message": "本次未留痕: HOME not set"])
        ))

        #expect(model.warningMessage == "本次未留痕: HOME not set")
        #expect(model.errorMessage == nil)
        #expect(model.phase == .running)
    }

    @Test("loading history groups threads without clearing current stream")
    func loadingHistoryDoesNotClearCurrentStream() {
        let model = SessionModel()

        model.ingest(agentItem(id: "msg1", text: "current"))
        model.flushPendingAgentItems()
        model.setHistoryThreads([
            HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        ])

        #expect(model.items.count == 1)
        #expect(model.items[0].text == "current")
        #expect(model.historyGroups.count == 1)
        #expect(model.historyGroups[0].cwd == "/tmp/project")
    }

    @Test("history auto refresh is requested only once")
    func historyAutoRefreshIsRequestedOnlyOnce() {
        let model = SessionModel()

        #expect(model.shouldAutoRefreshHistoryOnAppear())
        #expect(!model.shouldAutoRefreshHistoryOnAppear())
    }

    @Test("applying history detail replaces stream with replay items")
    func applyingHistoryDetailReplaysItems() {
        let model = SessionModel()
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let detail = HistoryThreadDetail(
            thread: thread,
            items: [
                HistoryReplayItem(id: "u1", lifecycle: "completed", kind: "user", text: "old prompt"),
                HistoryReplayItem(id: "a1", lifecycle: "completed", kind: "message", text: "old answer"),
            ]
        )

        model.applyHistoryThreadDetail(detail)

        #expect(model.cwd?.path == "/tmp/project")
        #expect(model.items.map(\.kind) == ["user", "message"])
        #expect(model.items.map(\.text) == ["old prompt", "old answer"])
        #expect(model.selectedHistoryThreadId == "h1")
    }

    @Test("applying history detail preserves web search replay fields")
    func applyingHistoryDetailPreservesWebSearchFields() {
        let model = SessionModel()
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let detail = HistoryThreadDetail(
            thread: thread,
            items: [
                HistoryReplayItem(
                    id: "ws1",
                    lifecycle: "completed",
                    kind: "webSearch",
                    query: "AgentDeck history",
                    action: "findInPage",
                    actionQuery: "AgentDeck",
                    queries: ["AgentDeck", "history"],
                    url: "https://example.com",
                    pattern: "history"
                ),
            ]
        )

        model.applyHistoryThreadDetail(detail)

        #expect(model.items.count == 1)
        #expect(model.items[0].kind == "webSearch")
        #expect(model.items[0].query == "AgentDeck history")
        #expect(model.items[0].action == "findInPage")
        #expect(model.items[0].actionQuery == "AgentDeck")
        #expect(model.items[0].queries == ["AgentDeck", "history"])
        #expect(model.items[0].url == "https://example.com")
        #expect(model.items[0].pattern == "history")
    }

    @Test("applying history detail preserves complete replay item fields")
    func applyingHistoryDetailPreservesCompleteReplayFields() {
        let model = SessionModel()
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let detail = HistoryThreadDetail(
            thread: thread,
            items: [
                HistoryReplayItem(
                    id: "tool1",
                    lifecycle: "completed",
                    kind: "toolCall",
                    status: "completed",
                    durationMs: 42,
                    toolKind: "mcp",
                    server: "github",
                    tool: "list",
                    arguments: #"{"q":"x"}"#,
                    result: #"{"ok":true}"#,
                    resourceUri: "app://github"
                ),
                HistoryReplayItem(
                    id: "file1",
                    lifecycle: "completed",
                    kind: "fileEdit",
                    path: "a.txt",
                    diff: "+a",
                    status: "applied",
                    changes: [
                        HistoryFileChange(path: "a.txt", diff: "+a", changeKind: "add"),
                        HistoryFileChange(path: "b.txt", diff: "-b", changeKind: "delete"),
                    ]
                ),
            ]
        )

        model.applyHistoryThreadDetail(detail)

        #expect(model.items[0].kind == "toolCall")
        #expect(model.items[0].toolKind == "mcp")
        #expect(model.items[0].server == "github")
        #expect(model.items[0].tool == "list")
        #expect(model.items[0].arguments == #"{"q":"x"}"#)
        #expect(model.items[0].result == #"{"ok":true}"#)
        #expect(model.items[0].durationMs == 42)
        #expect(model.items[0].resourceUri == "app://github")
        #expect(model.items[1].changes.count == 2)
        #expect(model.items[1].changes[1].path == "b.txt")
    }

    @Test("opening a history thread returns immediately while detail loads")
    func openingHistoryThreadReturnsImmediatelyWhileDetailLoads() async throws {
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let gate = BlockingHistoryDetailClient(
            detail: HistoryThreadDetail(
                thread: thread,
                items: [
                    HistoryReplayItem(id: "u1", lifecycle: "completed", kind: "user", text: "old prompt"),
                    HistoryReplayItem(id: "a1", lifecycle: "completed", kind: "message", text: "old answer"),
                ]
            )
        )
        let model = SessionModel(historyDetailClient: gate)

        model.openHistoryThread(thread)

        #expect(model.openingHistoryThreadId == "h1")
        #expect(model.items.isEmpty)

        try await gate.waitUntilStarted()

        gate.release()
        try await Task.sleep(for: .milliseconds(50))

        #expect(model.openingHistoryThreadId == nil)
        #expect(model.selectedHistoryThreadId == "h1")
        #expect(model.items.map(\.text) == ["old prompt", "old answer"])
    }

    @Test("opening history records read and apply timing")
    func openingHistoryRecordsReadAndApplyTiming() async throws {
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let gate = BlockingHistoryDetailClient(
            detail: HistoryThreadDetail(
                thread: thread,
                items: [
                    HistoryReplayItem(id: "u1", lifecycle: "completed", kind: "user", text: "old prompt")
                ]
            )
        )
        let model = SessionModel(historyDetailClient: gate)

        model.openHistoryThread(thread)
        try await gate.waitUntilStarted()
        gate.release()
        try await Task.sleep(for: .milliseconds(50))

        let timing = try #require(model.lastHistoryOpenTiming)
        #expect(timing.threadId == "h1")
        #expect(timing.itemCount == 1)
        #expect(timing.readMilliseconds >= 0)
        #expect(timing.applyMilliseconds >= 0)
        #expect(model.historyTimingSummary.contains("read"))
    }

    @Test("history replay defers large output and diff buffers until requested")
    func historyReplayDefersLargeOutputAndDiffBuffersUntilRequested() {
        let model = SessionModel()
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let largeOutput = String(repeating: "output\n", count: 3_000)
        let largeDiff = String(repeating: "+ changed line\n", count: 3_000)
        let detail = HistoryThreadDetail(
            thread: thread,
            items: [
                HistoryReplayItem(id: "shell1", lifecycle: "completed", kind: "shell", command: "make test", output: largeOutput),
                HistoryReplayItem(id: "diff1", lifecycle: "completed", kind: "fileEdit", path: "a.txt", diff: largeDiff),
            ]
        )

        model.applyHistoryThreadDetail(detail)

        #expect(model.items[0].output == largeOutput)
        #expect(model.items[0].outputBuffer.text.isEmpty)
        #expect(model.items[0].hasDeferredOutputBuffer)
        #expect(model.items[1].diff == largeDiff)
        #expect(model.items[1].diffBuffer.text.isEmpty)
        #expect(model.items[1].hasDeferredDiffBuffer)

        model.materializeDeferredContent(itemId: "shell1", content: .output)
        model.materializeDeferredContent(itemId: "diff1", content: .diff)

        #expect(model.items[0].outputBuffer.text == largeOutput)
        #expect(!model.items[0].hasDeferredOutputBuffer)
        #expect(model.items[1].diffBuffer.text == largeDiff)
        #expect(!model.items[1].hasDeferredDiffBuffer)
    }
}

final class BlockingHistoryDetailClient: HistoryDetailReading, @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var _didStart = false
    private let detail: HistoryThreadDetail

    init(detail: HistoryThreadDetail) {
        self.detail = detail
    }

    var didStart: Bool {
        lock.withLock { _didStart }
    }

    func release() {
        semaphore.signal()
    }

    func waitUntilStarted() async throws {
        let deadline = Date().addingTimeInterval(1)
        while !didStart {
            if Date() > deadline {
                Issue.record("history detail reader did not start")
                return
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    func readHistoryThread(threadId: String) throws -> HistoryThreadDetail {
        lock.withLock { _didStart = true }
        semaphore.wait()
        return detail
    }
}

@Suite("History model")
struct HistoryModelTests {
    @Test("decodes neutral history thread summary")
    func decodesSummary() throws {
        let data = Data("""
        {"id":"thread_1","name":"Fix tests","preview":"please fix tests","cwd":"/tmp/project","createdAt":10,"updatedAt":20,"status":"ready","modelProvider":"openai","source":"cli"}
        """.utf8)
        let item = try JSONDecoder().decode(HistoryThreadSummary.self, from: data)
        #expect(item.id == "thread_1")
        #expect(item.cwd == "/tmp/project")
        #expect(item.displayTitle == "Fix tests")
    }

    @Test("groups threads by project cwd newest first")
    func groupsByProject() {
        let groups = HistoryProjectGroup.group([
            HistoryThreadSummary(id: "old", name: nil, preview: "old", cwd: "/tmp/a", createdAt: 1, updatedAt: 1, status: "ready", modelProvider: "openai", source: "cli"),
            HistoryThreadSummary(id: "new", name: "new", preview: "new", cwd: "/tmp/a", createdAt: 2, updatedAt: 3, status: "ready", modelProvider: "openai", source: "cli"),
            HistoryThreadSummary(id: "other", name: nil, preview: "other", cwd: "/tmp/b", createdAt: 2, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli"),
        ])

        #expect(groups.map(\.cwd) == ["/tmp/a", "/tmp/b"])
        #expect(groups[0].threads.map(\.id) == ["new", "old"])
    }

    @Test("history replay item tolerates per-kind missing fields")
    func replayItemToleratesMissingPerKindFields() throws {
        let data = Data("""
        {"id":"u1","lifecycle":"completed","kind":"user","text":"old prompt"}
        """.utf8)
        let item = try JSONDecoder().decode(HistoryReplayItem.self, from: data)
        #expect(item.kind == "user")
        #expect(item.text == "old prompt")
        #expect(item.command == "")
        #expect(item.path == "")
    }

    @Test("history replay item decodes web search fields")
    func replayItemDecodesWebSearchFields() throws {
        let data = Data("""
        {"id":"ws1","lifecycle":"completed","kind":"webSearch","query":"AgentDeck history","action":"search","actionQuery":"AgentDeck","queries":["AgentDeck","history"],"url":"https://example.com","pattern":"history"}
        """.utf8)
        let item = try JSONDecoder().decode(HistoryReplayItem.self, from: data)
        #expect(item.kind == "webSearch")
        #expect(item.query == "AgentDeck history")
        #expect(item.action == "search")
        #expect(item.actionQuery == "AgentDeck")
        #expect(item.queries == ["AgentDeck", "history"])
        #expect(item.url == "https://example.com")
        #expect(item.pattern == "history")
    }

    @Test("history replay item decodes complete known item fields")
    func replayItemDecodesCompleteKnownItemFields() throws {
        let data = Data("""
        {"id":"m1","lifecycle":"completed","kind":"toolCall","toolKind":"mcp","server":"github","tool":"list","status":"completed","arguments":"{\\"q\\":\\"x\\"}","result":"{\\"ok\\":true}","durationMs":12,"resourceUri":"app://github","contentItems":[{"kind":"inputText","text":"hit"}],"actions":[{"kind":"search","command":"rg x","path":"/tmp","query":"x"}],"changes":[{"path":"a.txt","diff":"+a","changeKind":"add"}],"attachments":[{"kind":"localImage","path":"/tmp/a.png"}],"fragments":[{"hookRunId":"hr1","text":"hook text"}],"receiverThreadIds":["r1"],"mediaKind":"imageGeneration","savedPath":"/tmp/out.png","review":"review text"}
        """.utf8)
        let item = try JSONDecoder().decode(HistoryReplayItem.self, from: data)
        #expect(item.toolKind == "mcp")
        #expect(item.server == "github")
        #expect(item.arguments == #"{"q":"x"}"#)
        #expect(item.result == #"{"ok":true}"#)
        #expect(item.durationMs == 12)
        #expect(item.contentItems[0].text == "hit")
        #expect(item.actions[0].query == "x")
        #expect(item.changes[0].changeKind == "add")
        #expect(item.attachments[0].path == "/tmp/a.png")
        #expect(item.fragments[0].hookRunId == "hr1")
        #expect(item.receiverThreadIds == ["r1"])
        #expect(item.mediaKind == "imageGeneration")
        #expect(item.savedPath == "/tmp/out.png")
        #expect(item.review == "review text")
    }
}

@Suite("Daemon history requests")
struct DaemonHistoryRequestTests {
    @Test("history list request encodes neutral filters")
    func historyListRequestEncodesFilters() throws {
        let msg = DaemonClient.historyListRequest(
            id: 7,
            cwd: "/tmp/project",
            searchTerm: "fix"
        )
        let data = try JSONEncoder().encode(msg)
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let payload = try #require(json["payload"] as? [String: Any])
        #expect(json["kind"] as? String == "history/listThreads")
        #expect(payload["cwd"] as? String == "/tmp/project")
        #expect(payload["searchTerm"] as? String == "fix")
        #expect(!String(data: data, encoding: .utf8)!.lowercased().contains("codex"))
    }

    @Test("start turn request encodes restored thread id")
    func startTurnRequestEncodesThreadId() throws {
        let msg = DaemonClient.startTurnRequest(
            id: 9,
            threadId: "thread_1",
            prompt: "continue"
        )
        let data = try JSONEncoder().encode(msg)
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let payload = try #require(json["payload"] as? [String: Any])
        #expect(json["kind"] as? String == "startTurn")
        #expect(payload["threadId"] as? String == "thread_1")
        #expect(payload["prompt"] as? String == "continue")
    }

    @Test("thread management requests encode intended action")
    func threadManagementRequestsEncodeAction() throws {
        let rename = DaemonClient.renameThreadRequest(id: 10, threadId: "thread_1", name: "New name")
        let archive = DaemonClient.archiveThreadRequest(id: 11, threadId: "thread_1")
        let unarchive = DaemonClient.unarchiveThreadRequest(id: 12, threadId: "thread_1")

        let renameJSON = try #require(JSONSerialization.jsonObject(with: try JSONEncoder().encode(rename)) as? [String: Any])
        let archiveJSON = try #require(JSONSerialization.jsonObject(with: try JSONEncoder().encode(archive)) as? [String: Any])
        let unarchiveJSON = try #require(JSONSerialization.jsonObject(with: try JSONEncoder().encode(unarchive)) as? [String: Any])

        #expect(renameJSON["kind"] as? String == "history/renameThread")
        #expect(archiveJSON["kind"] as? String == "history/archiveThread")
        #expect(unarchiveJSON["kind"] as? String == "history/unarchiveThread")
    }
}

@Suite("Streaming TextKit renderer")
@MainActor
struct StreamingTextKitRendererTests {
    @Test("growing text appends only the new suffix")
    func growingTextAppendsSuffix() {
        let storage = NSTextStorage(string: "")
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 13),
            .foregroundColor: NSColor.labelColor,
        ]

        let first = StreamingTextStorageSynchronizer.sync(
            storage,
            to: "Hel",
            attributes: attrs
        )
        let second = StreamingTextStorageSynchronizer.sync(
            storage,
            to: "Hello",
            attributes: attrs
        )

        #expect(first == .appended(characterCount: 3))
        #expect(second == .appended(characterCount: 2))
        #expect(storage.string == "Hello")
    }

    @Test("non-prefix text replaces the storage")
    func nonPrefixTextReplacesStorage() {
        let storage = NSTextStorage(string: "Hello")
        let result = StreamingTextStorageSynchronizer.sync(
            storage,
            to: "Reset",
            attributes: [.font: NSFont.systemFont(ofSize: 13)]
        )

        #expect(result == .replaced)
        #expect(storage.string == "Reset")
    }

    @Test("streaming buffer notifies incremental appends")
    func streamingBufferNotifiesIncrementalAppends() {
        let buffer = StreamingTextBuffer()
        var changes: [StreamingTextBufferChange] = []
        let token = buffer.observe { changes.append($0) }

        buffer.append("Hel")
        buffer.append("lo")
        buffer.replace(with: "Reset")
        buffer.removeObserver(token)
        buffer.append(" ignored")

        #expect(buffer.text == "Reset ignored")
        #expect(changes == [
            .replace(""),
            .append("Hel"),
            .append("lo"),
            .replace("Reset"),
        ])
    }
}
