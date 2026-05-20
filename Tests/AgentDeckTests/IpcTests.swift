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
