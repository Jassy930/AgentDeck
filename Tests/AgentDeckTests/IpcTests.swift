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

    @Test("IpcMessage decodes session and thread routing fields")
    func decodesRoutingFields() throws {
        let data = Data("""
        {"kind":"session/event","sessionId":"session_1","threadId":"thread_1","payload":{"event":{"kind":"turnComplete"}}}
        """.utf8)

        let msg = try JSONDecoder().decode(IpcMessage.self, from: data)

        #expect(msg.kind == "session/event")
        #expect(msg.sessionId == "session_1")
        #expect(msg.threadId == "thread_1")
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
}

@Suite("Daemon message routing")
struct DaemonMessageRoutingTests {
    @Test("routes replies by id and session events by session id")
    func routesRepliesAndSessionEventsSeparately() {
        let router = DaemonMessageRouter()
        var events: [IpcMessage] = []
        router.onSessionEvent = { events.append($0) }

        #expect(router.registerPending(id: 31))
        router.route(IpcMessage(kind: "session/event", sessionId: "s1", payload: AnyCodable([
            "event": ["kind": "agentItem"]
        ])))
        router.route(IpcMessage(kind: "historyThread", id: 31, payload: AnyCodable(["thread": [:], "items": []])))

        #expect(events.count == 1)
        #expect(router.takeReply(id: 31)?.kind == "historyThread")
    }

    @Test("routes session events to the active raw stream as legacy events")
    func routesSessionEventsToActiveRawStreamAsLegacyEvents() throws {
        let router = DaemonMessageRouter()
        var events: [IpcMessage] = []
        var rawLines: [String] = []
        router.onSessionEvent = { events.append($0) }
        router.onStreamLine = { rawLines.append($0) }

        router.route(IpcMessage(kind: "session/event", sessionId: "s1", payload: AnyCodable([
            "event": ["kind": "turnComplete", "payload": ["ok": true]]
        ])))

        #expect(events.count == 1)
        let rawLine = try #require(rawLines.first)
        let legacy = try JSONDecoder().decode(IpcMessage.self, from: Data(rawLine.utf8))
        #expect(legacy.kind == "turnComplete")
        #expect(legacy.sessionId == nil)
        #expect(legacy.payload?.value as? [String: Bool] == ["ok": true])
    }

    @Test("routes agent item and error session events as legacy stream events")
    func routesAgentItemAndErrorSessionEventsAsLegacyStreamEvents() throws {
        let router = DaemonMessageRouter()
        var rawLines: [String] = []
        router.onStreamLine = { rawLines.append($0) }

        router.route(IpcMessage(kind: "session/event", sessionId: "s1", payload: AnyCodable([
            "event": [
                "kind": "agentItem",
                "id": "item1",
                "text": "hello"
            ]
        ])))
        router.route(IpcMessage(kind: "session/event", sessionId: "s1", payload: AnyCodable([
            "event": [
                "kind": "error",
                "payload": ["message": "boom"]
            ]
        ])))

        let agentItem = try JSONDecoder().decode(IpcMessage.self, from: Data(try #require(rawLines.first).utf8))
        let error = try JSONDecoder().decode(IpcMessage.self, from: Data(try #require(rawLines.last).utf8))
        #expect(rawLines.count == 2)
        #expect(agentItem.kind == "agentItem")
        #expect((agentItem.payload?.value as? [String: Any])?["id"] as? String == "item1")
        #expect((agentItem.payload?.value as? [String: Any])?["text"] as? String == "hello")
        #expect(error.kind == "error")
        #expect((error.payload?.value as? [String: Any])?["message"] as? String == "boom")
    }

    @Test("rejects duplicate pending ids before a reply is routed")
    func rejectsDuplicatePendingIdsBeforeReplyIsRouted() {
        let router = DaemonMessageRouter()

        #expect(router.registerPending(id: 42))
        #expect(!router.registerPending(id: 42))
        router.route(IpcMessage(kind: "pong", id: 42, payload: nil))

        #expect(router.takeReply(id: 42)?.kind == "pong")
    }

    @Test("keeps ids occupied while routed replies are buffered")
    func keepsIdsOccupiedWhileRoutedRepliesAreBuffered() {
        let router = DaemonMessageRouter()

        #expect(router.registerPending(id: 43))
        router.route(IpcMessage(kind: "pong", id: 43, payload: nil))

        #expect(!router.registerPending(id: 43))
        #expect(router.takeReply(id: 43)?.kind == "pong")
        #expect(router.registerPending(id: 43))
    }

    @Test("preserves explicit ids but can generate ids for reused static factory ids")
    func preservesExplicitIdsButCanGenerateIdsForReusedStaticFactoryIds() throws {
        let client = DaemonClient()
        let ping = try client.prepareRoundTripRequest(IpcMessage(kind: "ping", id: 1, payload: nil))
        let first = try client.prepareGeneratedIdRequest(DaemonClient.historyListRequest(
            id: 2,
            cwd: "/tmp/project",
            searchTerm: nil
        ))
        let second = try client.prepareGeneratedIdRequest(DaemonClient.historyListRequest(
            id: 2,
            cwd: "/tmp/project",
            searchTerm: nil
        ))

        #expect(ping.id == 1)
        #expect(first.kind == "history/listThreads")
        #expect(first.id != 2)
        #expect(second.id != 2)
        #expect(first.id != second.id)
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

    @Test("runtime streaming deltas are flushed by timer")
    func runtimeStreamingDeltasAreFlushedByTimer() async throws {
        let runtime = ThreadRuntimeModel(id: "s1", threadId: "t1", cwd: URL(fileURLWithPath: "/tmp/project"))

        runtime.ingest(agentItem(id: "msg1", text: "Hel"))
        runtime.ingest(agentItem(id: "msg1", text: "lo"))

        #expect(runtime.items.isEmpty)

        try await Task.sleep(for: .milliseconds(80))

        #expect(runtime.items.count == 1)
        #expect(runtime.items[0].text == "Hello")
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

    @Test("applying history detail selects replay without replacing legacy stream")
    func applyingHistoryDetailSelectsReplayWithoutReplacingLegacyStream() {
        let model = SessionModel()
        model.ingest(agentItem(id: "live1", lifecycle: "completed", text: "current answer"))
        model.flushPendingAgentItems()
        model.phase = .running
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
        #expect(model.phase == .running)
        #expect(model.items.map(\.text) == ["current answer"])
        #expect(model.selectedItems.map(\.kind) == ["user", "message"])
        #expect(model.selectedItems.map(\.text) == ["old prompt", "old answer"])
        #expect(model.selectedHistoryThreadId == "h1")
    }

    @Test("starting new session clears selected history runtime")
    func startingNewSessionClearsSelectedHistoryRuntime() {
        let model = SessionModel()
        let thread = HistoryThreadSummary(id: "h1", name: nil, preview: "old", cwd: "/tmp/project", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli")
        let detail = HistoryThreadDetail(
            thread: thread,
            items: [
                HistoryReplayItem(id: "a1", lifecycle: "completed", kind: "message", text: "old answer"),
            ]
        )

        model.applyHistoryThreadDetail(detail)
        model.startNewSessionFromCurrentProject()

        #expect(model.selectedItems.isEmpty)
        #expect(model.workbench.selectedSessionId == nil)
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

        #expect(model.selectedItems.count == 1)
        #expect(model.selectedItems[0].kind == "webSearch")
        #expect(model.selectedItems[0].query == "AgentDeck history")
        #expect(model.selectedItems[0].action == "findInPage")
        #expect(model.selectedItems[0].actionQuery == "AgentDeck")
        #expect(model.selectedItems[0].queries == ["AgentDeck", "history"])
        #expect(model.selectedItems[0].url == "https://example.com")
        #expect(model.selectedItems[0].pattern == "history")
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

        #expect(model.selectedItems[0].kind == "toolCall")
        #expect(model.selectedItems[0].toolKind == "mcp")
        #expect(model.selectedItems[0].server == "github")
        #expect(model.selectedItems[0].tool == "list")
        #expect(model.selectedItems[0].arguments == #"{"q":"x"}"#)
        #expect(model.selectedItems[0].result == #"{"ok":true}"#)
        #expect(model.selectedItems[0].durationMs == 42)
        #expect(model.selectedItems[0].resourceUri == "app://github")
        #expect(model.selectedItems[1].changes.count == 2)
        #expect(model.selectedItems[1].changes[1].path == "b.txt")
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
        #expect(model.selectedItems.map(\.text) == ["old prompt", "old answer"])
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

        #expect(model.selectedItems[0].output == largeOutput)
        #expect(model.selectedItems[0].outputBuffer.text.isEmpty)
        #expect(model.selectedItems[0].hasDeferredOutputBuffer)
        #expect(model.selectedItems[1].diff == largeDiff)
        #expect(model.selectedItems[1].diffBuffer.text.isEmpty)
        #expect(model.selectedItems[1].hasDeferredDiffBuffer)

        model.materializeDeferredContent(itemId: "shell1", content: .output)
        model.materializeDeferredContent(itemId: "diff1", content: .diff)

        #expect(model.selectedItems[0].outputBuffer.text == largeOutput)
        #expect(!model.selectedItems[0].hasDeferredOutputBuffer)
        #expect(model.selectedItems[1].diffBuffer.text == largeDiff)
        #expect(!model.selectedItems[1].hasDeferredDiffBuffer)
    }
}

@Suite("Workbench runtime model")
@MainActor
struct WorkbenchRuntimeModelTests {
    @Test("routes session events to the matching runtime")
    func routesEventsToMatchingRuntime() {
        let workbench = WorkbenchModel()
        workbench.ensureRuntime(sessionId: "s1", threadId: "t1", cwd: URL(fileURLWithPath: "/tmp/a"))
        workbench.ensureRuntime(sessionId: "s2", threadId: "t2", cwd: URL(fileURLWithPath: "/tmp/b"))

        workbench.ingestSessionEvent(IpcMessage(
            kind: "session/event",
            sessionId: "s2",
            threadId: "t2",
            payload: AnyCodable([
                "event": [
                    "kind": "agentItem",
                    "payload": [
                        "id": "m1",
                        "lifecycle": "completed",
                        "kind": "message",
                        "text": "B done",
                    ],
                ],
            ])
        ))

        #expect(workbench.runtime(sessionId: "s1")?.items.isEmpty == true)
        #expect(workbench.runtime(sessionId: "s2")?.items.count == 1)
    }

    @Test("opening history does not change an existing running runtime")
    func openingHistoryDoesNotChangeRunningRuntime() {
        let workbench = WorkbenchModel()
        workbench.ensureRuntime(sessionId: "running", threadId: "thread_running", cwd: URL(fileURLWithPath: "/tmp/a"))
        workbench.runtime(sessionId: "running")?.phase = .running

        let detail = HistoryThreadDetail(
            thread: HistoryThreadSummary(id: "thread_b", name: nil, preview: "B", cwd: "/tmp/b", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli"),
            items: [HistoryReplayItem(id: "m1", lifecycle: "completed", kind: "message", text: "old")]
        )

        workbench.applyHistoryThreadDetail(detail)

        #expect(workbench.runtime(sessionId: "running")?.phase == .running)
        #expect(workbench.selectedSessionId == "thread_b")
    }

    @Test("materializing selected history deferred content does not replace legacy running items")
    func materializingSelectedHistoryDeferredContentDoesNotReplaceLegacyRunningItems() {
        let model = SessionModel()
        model.phase = .running
        model.items = [
            UIItem(id: "current1", lifecycle: "delta", kind: "message", text: "current stream")
        ]
        let largeOutput = String(repeating: "output\n", count: 3_000)
        let largeDiff = String(repeating: "+ changed line\n", count: 3_000)
        let detail = HistoryThreadDetail(
            thread: HistoryThreadSummary(id: "thread_b", name: nil, preview: "B", cwd: "/tmp/b", createdAt: 1, updatedAt: 2, status: "ready", modelProvider: "openai", source: "cli"),
            items: [
                HistoryReplayItem(id: "shell1", lifecycle: "completed", kind: "shell", command: "make test", output: largeOutput),
                HistoryReplayItem(id: "diff1", lifecycle: "completed", kind: "fileEdit", path: "a.txt", diff: largeDiff),
            ]
        )

        model.applyHistoryThreadDetail(detail)

        #expect(model.items.map(\.id) == ["current1"])
        #expect(model.selectedItems[0].hasDeferredOutputBuffer)
        #expect(model.selectedItems[1].hasDeferredDiffBuffer)

        model.materializeDeferredContent(itemId: "shell1", content: .output)
        model.materializeDeferredContent(itemId: "diff1", content: .diff)

        #expect(model.items.map(\.id) == ["current1"])
        #expect(model.items[0].text == "current stream")
        #expect(model.selectedItems[0].outputBuffer.text == largeOutput)
        #expect(!model.selectedItems[0].hasDeferredOutputBuffer)
        #expect(model.selectedItems[1].diffBuffer.text == largeDiff)
        #expect(!model.selectedItems[1].hasDeferredDiffBuffer)
    }

    @Test("selected runtime materialize misses do not fall back to legacy deferred items")
    func selectedRuntimeMaterializeMissesDoNotFallbackToLegacyDeferredItems() {
        let model = SessionModel()
        let legacyOutput = String(repeating: "legacy output\n", count: 2)
        let legacyDiff = String(repeating: "+ legacy diff\n", count: 2)
        model.ingest(IpcMessage(
            kind: "agentItem",
            payload: AnyCodable([
                "id": "shell1",
                "lifecycle": "completed",
                "kind": "shell",
                "output": legacyOutput,
            ])
        ))
        model.ingest(IpcMessage(
            kind: "agentItem",
            payload: AnyCodable([
                "id": "legacyDiff",
                "lifecycle": "completed",
                "kind": "fileEdit",
                "diff": legacyDiff,
            ])
        ))
        model.flushPendingAgentItems()
        model.items[0].hasDeferredOutputBuffer = true
        model.items[0].outputBuffer.replace(with: "")
        model.items[1].hasDeferredDiffBuffer = true
        model.items[1].diffBuffer.replace(with: "")

        model.workbench.ensureRuntime(sessionId: "selected", threadId: "thread_selected", cwd: URL(fileURLWithPath: "/tmp/selected"))
        model.workbench.runtime(sessionId: "selected")?.applyReplayItems([
            HistoryReplayItem(id: "shell1", lifecycle: "completed", kind: "shell", output: "selected small output"),
            HistoryReplayItem(id: "selectedDiff", lifecycle: "completed", kind: "fileEdit", diff: "+ selected small diff"),
        ])

        model.materializeDeferredContent(itemId: "shell1", content: .output)
        model.materializeDeferredContent(itemId: "legacyDiff", content: .diff)

        #expect(model.items[0].hasDeferredOutputBuffer)
        #expect(model.items[0].outputBuffer.text.isEmpty)
        #expect(model.items[0].output == legacyOutput)
        #expect(model.items[1].hasDeferredDiffBuffer)
        #expect(model.items[1].diffBuffer.text.isEmpty)
        #expect(model.items[1].diff == legacyDiff)
        #expect(model.selectedItems[0].outputBuffer.text == "selected small output")
        #expect(!model.selectedItems[0].hasDeferredOutputBuffer)
        #expect(model.selectedItems[1].diffBuffer.text == "+ selected small diff")
        #expect(!model.selectedItems[1].hasDeferredDiffBuffer)
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
