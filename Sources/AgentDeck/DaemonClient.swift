import Foundation

/// Errors surfaced by the daemon client. Every failure is a named, visible
/// error — never a silent hang (Eng premise 9 / reverse-of-silent).
enum DaemonError: Error, CustomStringConvertible {
    case binaryNotFound(String)
    case spawnFailed(String)
    case disconnected
    case malformedReply(String)

    var description: String {
        switch self {
        case .binaryNotFound(let p): return "agentdeckd not found at \(p)"
        case .spawnFailed(let m): return "failed to spawn agentdeckd: \(m)"
        case .disconnected: return "agentdeckd disconnected (EOF on its stdout)"
        case .malformedReply(let s): return "malformed reply from agentdeckd: \(s)"
        }
    }
}

/// A message on the agent-neutral IPC wire. Mirrors the Rust `IpcMessage`.
///
/// There is intentionally NO Codex vocabulary in this type, and there never
/// will be — that is the verifiable form of Eng premise D2. The Swift app
/// only ever speaks the neutral protocol; a future non-Codex adapter changes
/// nothing on this side.
struct IpcMessage: Codable {
    let kind: String
    var id: UInt64?
    var sessionId: String?
    var threadId: String?
    var payload: AnyCodable?

    init(
        kind: String,
        id: UInt64? = nil,
        sessionId: String? = nil,
        threadId: String? = nil,
        payload: AnyCodable? = nil
    ) {
        self.kind = kind
        self.id = id
        self.sessionId = sessionId
        self.threadId = threadId
        self.payload = payload
    }
}

/// Minimal type-erased JSON value so the neutral payload can carry any
/// kind-specific shape (Eng D4 per-kind structured schema lands in Step 3+).
struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) { self.value = value }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode([String: AnyCodable].self) {
            value = v.mapValues(\.value)
        } else if let v = try? c.decode([AnyCodable].self) {
            value = v.map(\.value)
        } else if let v = try? c.decode(String.self) {
            value = v
        } else if let v = try? c.decode(Int.self) {
            value = v
        } else if let v = try? c.decode(Bool.self) {
            value = v
        } else if let v = try? c.decode(Double.self) {
            value = v
        } else {
            value = NSNull()
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as String: try c.encode(v)
        case let v as Int: try c.encode(v)
        case let v as Bool: try c.encode(v)
        case let v as Double: try c.encode(v)
        case let v as [String: Any]: try c.encode(v.mapValues(AnyCodable.init))
        case let v as [Any]: try c.encode(v.map(AnyCodable.init))
        default: try c.encodeNil()
        }
    }
}

final class DaemonMessageRouter: @unchecked Sendable {
    private let condition = NSCondition()
    private var pendingReplyIds: Set<UInt64> = []
    private var replies: [UInt64: IpcMessage] = [:]
    private var unmatched: [IpcMessage] = []
    private var isClosed = false
    private var sessionEventHandler: ((IpcMessage) -> Void)?
    private var streamLineHandler: ((String) -> Void)?
    private var unmatchedMessageHandler: ((IpcMessage) -> Void)?

    var onSessionEvent: ((IpcMessage) -> Void)? {
        get {
            condition.lock()
            defer { condition.unlock() }
            return sessionEventHandler
        }
        set {
            condition.lock()
            sessionEventHandler = newValue
            condition.unlock()
        }
    }

    var onStreamLine: ((String) -> Void)? {
        get {
            condition.lock()
            defer { condition.unlock() }
            return streamLineHandler
        }
        set {
            condition.lock()
            streamLineHandler = newValue
            condition.unlock()
        }
    }

    var onUnmatchedMessage: ((IpcMessage) -> Void)? {
        get {
            condition.lock()
            defer { condition.unlock() }
            return unmatchedMessageHandler
        }
        set {
            condition.lock()
            unmatchedMessageHandler = newValue
            condition.unlock()
        }
    }

    func registerPending(id: UInt64) {
        condition.lock()
        pendingReplyIds.insert(id)
        condition.unlock()
    }

    func route(_ message: IpcMessage, rawLine: String? = nil) {
        let sessionHandler: ((IpcMessage) -> Void)?
        let streamHandler: ((String) -> Void)?
        let streamRawLine: String?
        let unmatchedHandler: ((IpcMessage) -> Void)?

        condition.lock()
        if let id = message.id, pendingReplyIds.contains(id) {
            replies[id] = message
            pendingReplyIds.remove(id)
            condition.broadcast()
            condition.unlock()
            return
        }

        if message.kind == "session/event" {
            sessionHandler = sessionEventHandler
            streamRawLine = Self.encodeLegacySessionEventRawLine(message)
            streamHandler = streamRawLine == nil ? nil : streamLineHandler
            if Self.isTerminalSessionEvent(message) && streamRawLine != nil {
                streamLineHandler = nil
            }
            if streamRawLine == nil || (sessionHandler == nil && streamHandler == nil) {
                unmatched.append(message)
                unmatchedHandler = unmatchedMessageHandler
            } else {
                unmatchedHandler = nil
            }
        } else if Self.isLegacyStreamKind(message.kind) {
            sessionHandler = nil
            streamHandler = streamLineHandler
            streamRawLine = rawLine ?? Self.encodeRawLine(message)
            if Self.isTerminalStreamKind(message.kind) {
                streamLineHandler = nil
            }
            if streamHandler == nil {
                unmatched.append(message)
                unmatchedHandler = unmatchedMessageHandler
            } else {
                unmatchedHandler = nil
            }
        } else {
            sessionHandler = nil
            streamHandler = nil
            streamRawLine = nil
            unmatched.append(message)
            unmatchedHandler = unmatchedMessageHandler
        }
        condition.unlock()

        if let sessionHandler {
            sessionHandler(message)
        }
        if let streamHandler, let streamRawLine {
            streamHandler(streamRawLine)
        }
        if let unmatchedHandler {
            unmatchedHandler(message)
        }
    }

    func routeMalformedLine(_ rawLine: String) {
        let payload = AnyCodable(["message": "malformed reply from agentdeckd: \(rawLine)"])

        condition.lock()
        if !pendingReplyIds.isEmpty {
            for id in pendingReplyIds {
                replies[id] = IpcMessage(kind: "error", id: id, payload: payload)
            }
            pendingReplyIds.removeAll()
            condition.broadcast()
            condition.unlock()
            return
        }
        condition.unlock()

        route(IpcMessage(
            kind: "error",
            payload: payload
        ))
    }

    func takeReply(id: UInt64) -> IpcMessage? {
        condition.lock()
        defer { condition.unlock() }
        return replies.removeValue(forKey: id)
    }

    func waitForReply(id: UInt64) -> IpcMessage? {
        condition.lock()
        defer { condition.unlock() }
        while true {
            if let reply = replies.removeValue(forKey: id) {
                return reply
            }
            if isClosed {
                return nil
            }
            condition.wait()
        }
    }

    func takeUnmatchedMessages() -> [IpcMessage] {
        condition.lock()
        defer { condition.unlock() }
        let messages = unmatched
        unmatched.removeAll()
        return messages
    }

    func close() {
        condition.lock()
        isClosed = true
        condition.broadcast()
        condition.unlock()
    }

    private static func isLegacyStreamKind(_ kind: String) -> Bool {
        kind == "agentItem"
            || kind == "sessionState"
            || kind == "turnComplete"
            || kind == "error"
    }

    private static func isTerminalStreamKind(_ kind: String) -> Bool {
        kind == "turnComplete" || kind == "error"
    }

    private static func isTerminalSessionEvent(_ message: IpcMessage) -> Bool {
        guard let eventKind = legacySessionEventMessage(from: message)?.kind else {
            return false
        }
        return isTerminalStreamKind(eventKind)
    }

    private static func encodeLegacySessionEventRawLine(_ message: IpcMessage) -> String? {
        guard let legacy = legacySessionEventMessage(from: message) else {
            return nil
        }
        return encodeRawLine(legacy)
    }

    private static func legacySessionEventMessage(from message: IpcMessage) -> IpcMessage? {
        guard let payload = message.payload?.value as? [String: Any],
              let event = payload["event"] as? [String: Any],
              let kind = event["kind"] as? String else {
            return nil
        }
        if let eventPayload = event["payload"] {
            return IpcMessage(kind: kind, payload: AnyCodable(eventPayload))
        }
        var legacyPayload = event
        legacyPayload.removeValue(forKey: "kind")
        return IpcMessage(
            kind: kind,
            payload: legacyPayload.isEmpty ? nil : AnyCodable(legacyPayload)
        )
    }

    private static func encodeRawLine(_ message: IpcMessage) -> String? {
        guard let data = try? JSONEncoder().encode(message) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

final class DaemonRequestIdAllocator: @unchecked Sendable {
    private let lock = NSLock()
    private var nextId: UInt64

    init(startingAt: UInt64 = 1) {
        nextId = startingAt
    }

    func assignUniqueId(to message: IpcMessage) -> IpcMessage {
        lock.lock()
        let id = nextId
        nextId += 1
        lock.unlock()

        var message = message
        message.id = id
        return message
    }
}

/// Owns the agentdeckd child process and the JSONL IPC channel to it.
///
/// Process lifecycle (Eng A1, first layer): the Swift app spawns the daemon;
/// when the app exits — normally OR via this object deinit — the daemon is
/// killed. There is no shared / persistent / orphan daemon. (Step 3+ extends
/// this so the daemon process-group-owns the Codex app-server child, so
/// killing the daemon cascades to the app-server too — A1's second layer.)
final class DaemonClient {
    private let process = Process()
    private let toDaemon = Pipe()
    private let fromDaemon = Pipe()
    private var reader: BufferedLineReader?
    private let router = DaemonMessageRouter()
    private let requestIdAllocator = DaemonRequestIdAllocator(startingAt: 1_000)
    private let lifecycleLock = NSLock()
    private let writeLock = NSLock()
    private var readerLoopStarted = false

    /// Locate the daemon binary. v0.1 uses PATH / dev-build lookup (Eng D-cwd
    /// scope: bundling is a later good-first-issue). GUI-launched apps have a
    /// different PATH than the terminal (Codex C-path), so we also probe the
    /// Cargo dev build paths relative to the executable.
    static func locateDaemon() -> String? {
        let candidates = [
            // Dev: SwiftPM exe is .build/<cfg>/AgentDeck; daemon is
            // target/<cfg>/agentdeckd next to the repo root.
            "target/debug/agentdeckd",
            "target/release/agentdeckd",
            "/usr/local/bin/agentdeckd",
            "/opt/homebrew/bin/agentdeckd",
        ]
        let fm = FileManager.default
        for c in candidates where fm.isExecutableFile(atPath: c) {
            return c
        }
        // Absolute fallback relative to current working directory.
        for c in candidates {
            let abs = fm.currentDirectoryPath + "/" + c
            if fm.isExecutableFile(atPath: abs) { return abs }
        }
        return nil
    }

    func start() throws {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        if readerLoopStarted {
            return
        }
        guard let path = Self.locateDaemon() else {
            throw DaemonError.binaryNotFound("target/{debug,release}/agentdeckd or PATH")
        }
        process.executableURL = URL(fileURLWithPath: path)
        process.standardInput = toDaemon
        process.standardOutput = fromDaemon
        // stderr inherits — daemon diagnostic logging (Eng O1) lands in Step 5.
        do {
            try process.run()
        } catch {
            throw DaemonError.spawnFailed("\(error)")
        }
        let lineReader = BufferedLineReader(handle: fromDaemon.fileHandleForReading)
        reader = lineReader
        router.onUnmatchedMessage = { message in
            Self.writeDiagnostic("unmatched daemon message: \(message.kind)")
        }
        startReaderLoop(lineReader)
    }

    /// Send one neutral message and block for the correlated reply.
    func roundTrip(_ msg: IpcMessage) throws -> IpcMessage {
        try sendRoundTrip(try prepareRoundTripRequest(msg))
    }

    func prepareRoundTripRequest(_ msg: IpcMessage) throws -> IpcMessage {
        if msg.id != nil {
            return msg
        }
        return requestIdAllocator.assignUniqueId(to: msg)
    }

    func prepareGeneratedIdRequest(_ msg: IpcMessage) throws -> IpcMessage {
        requestIdAllocator.assignUniqueId(to: msg)
    }

    private func roundTripWithGeneratedId(_ msg: IpcMessage) throws -> IpcMessage {
        try sendRoundTrip(try prepareGeneratedIdRequest(msg))
    }

    private func sendRoundTrip(_ msg: IpcMessage) throws -> IpcMessage {
        if reader == nil {
            try start()
        }
        guard let id = msg.id else {
            throw DaemonError.malformedReply("failed to assign id: \(msg.kind)")
        }
        let enc = JSONEncoder()
        var data = try enc.encode(msg)
        data.append(0x0A) // newline-delimited JSON (D7-confirmed framing)
        router.registerPending(id: id)
        write(data)

        guard let reply = router.waitForReply(id: id) else {
            throw DaemonError.disconnected
        }
        return reply
    }

    static func historyListRequest(
        id: UInt64,
        cwd: String?,
        searchTerm: String?,
        cursor: String? = nil,
        limit: Int? = nil
    ) -> IpcMessage {
        var payload: [String: Any] = [:]
        if let cwd { payload["cwd"] = cwd }
        if let searchTerm { payload["searchTerm"] = searchTerm }
        if let cursor { payload["cursor"] = cursor }
        if let limit { payload["limit"] = limit }
        return IpcMessage(
            kind: "history/listThreads",
            id: id,
            payload: payload.isEmpty ? nil : AnyCodable(payload)
        )
    }

    func listHistoryThreads(
        cwd: String?,
        searchTerm: String?,
        cursor: String? = nil,
        limit: Int? = 50
    ) throws -> HistoryThreadListPayload {
        if reader == nil {
            try start()
        }
        let reply = try roundTripWithGeneratedId(Self.historyListRequest(
            id: 2,
            cwd: cwd,
            searchTerm: searchTerm,
            cursor: cursor,
            limit: limit
        ))
        guard reply.kind == "historyThreads", let payload = reply.payload?.value else {
            if reply.kind == "error",
               let dict = reply.payload?.value as? [String: Any],
               let message = dict["message"] as? String {
                throw DaemonError.malformedReply(message)
            }
            throw DaemonError.malformedReply("expected historyThreads, got \(reply.kind)")
        }
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try JSONDecoder().decode(HistoryThreadListPayload.self, from: data)
    }

    static func historyReadRequest(id: UInt64, threadId: String) -> IpcMessage {
        IpcMessage(
            kind: "history/readThread",
            id: id,
            payload: AnyCodable(["threadId": threadId])
        )
    }

    func readHistoryThread(threadId: String) throws -> HistoryThreadDetail {
        if reader == nil {
            try start()
        }
        let reply = try roundTripWithGeneratedId(Self.historyReadRequest(id: 3, threadId: threadId))
        guard reply.kind == "historyThread", let payload = reply.payload?.value else {
            if reply.kind == "error",
               let dict = reply.payload?.value as? [String: Any],
               let message = dict["message"] as? String {
                throw DaemonError.malformedReply(message)
            }
            throw DaemonError.malformedReply("expected historyThread, got \(reply.kind)")
        }
        let data = try JSONSerialization.data(withJSONObject: payload)
        return try JSONDecoder().decode(HistoryThreadDetail.self, from: data)
    }

    static func startTurnRequest(id: UInt64, threadId: String, prompt: String) -> IpcMessage {
        IpcMessage(
            kind: "startTurn",
            id: id,
            payload: AnyCodable(["threadId": threadId, "prompt": prompt])
        )
    }

    static func archiveThreadRequest(id: UInt64, threadId: String) -> IpcMessage {
        IpcMessage(kind: "history/archiveThread", id: id, payload: AnyCodable(["threadId": threadId]))
    }

    static func unarchiveThreadRequest(id: UInt64, threadId: String) -> IpcMessage {
        IpcMessage(kind: "history/unarchiveThread", id: id, payload: AnyCodable(["threadId": threadId]))
    }

    static func renameThreadRequest(id: UInt64, threadId: String, name: String) -> IpcMessage {
        IpcMessage(
            kind: "history/renameThread",
            id: id,
            payload: AnyCodable(["threadId": threadId, "name": name])
        )
    }

    func archiveHistoryThread(threadId: String) throws {
        try manageHistoryThread(Self.archiveThreadRequest(id: 5, threadId: threadId))
    }

    func unarchiveHistoryThread(threadId: String) throws {
        try manageHistoryThread(Self.unarchiveThreadRequest(id: 6, threadId: threadId))
    }

    func renameHistoryThread(threadId: String, name: String) throws {
        try manageHistoryThread(Self.renameThreadRequest(id: 7, threadId: threadId, name: name))
    }

    private func manageHistoryThread(_ request: IpcMessage) throws {
        if reader == nil {
            try start()
        }
        let reply = try roundTripWithGeneratedId(request)
        if reply.kind == "historyThreadUpdated" {
            return
        }
        if reply.kind == "error",
           let dict = reply.payload?.value as? [String: Any],
           let message = dict["message"] as? String {
            throw DaemonError.malformedReply(message)
        }
        throw DaemonError.malformedReply("expected historyThreadUpdated, got \(reply.kind)")
    }

    /// Start a streaming session. Sends `startSession {cwd, prompt}` and
    /// lets the single daemon reader dispatch stream lines to the main thread.
    ///
    /// Eng C-uitest / D5: the background-reader → MainActor hop is exactly
    /// the fragile seam in a streaming Swift↔Rust IPC. Delivering on
    /// MainActor here means SwiftUI state mutation is always main-thread —
    /// no out-of-order refresh, no UI crash. The stream ends when the daemon
    /// emits `turnComplete` or an `error` (Eng premise 9: visible, never a
    /// silent hang).
    func startSession(
        cwd: String,
        prompt: String,
        onLine: @escaping @MainActor (String) -> Void
    ) {
        let payload = AnyCodable(["cwd": cwd, "prompt": prompt])
        let msg = IpcMessage(kind: "startSession", id: 1, payload: payload)
        guard let data = try? JSONEncoder().encode(msg) else {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"failed to encode startSession"}}"#)
            }
            return
        }
        var line = data
        line.append(0x0A)

        if reader == nil {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        router.onStreamLine = { raw in
            DispatchQueue.main.async { onLine(raw) }
        }
        write(line)
    }

    func startTurn(
        threadId: String,
        prompt: String,
        onLine: @escaping @MainActor (String) -> Void
    ) {
        let msg = Self.startTurnRequest(id: 4, threadId: threadId, prompt: prompt)
        guard let data = try? JSONEncoder().encode(msg) else {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"failed to encode startTurn"}}"#)
            }
            return
        }
        var line = data
        line.append(0x0A)

        if reader == nil {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        router.onStreamLine = { raw in
            DispatchQueue.main.async { onLine(raw) }
        }
        write(line)
    }

    /// Ask the daemon to shut down, then ensure it is gone (A1: app exit
    /// kills the daemon — request a clean shutdown, then hard-kill as backstop).
    func shutdown() {
        if process.isRunning {
            let bye = IpcMessage(kind: "shutdown", id: 0, payload: nil)
            _ = try? roundTrip(bye)
        }
        if process.isRunning {
            process.terminate()
        }
    }

    deinit {
        // Backstop: even if the app forgot to call shutdown(), the daemon
        // must not outlive its owner (A1 — no orphan daemon).
        if process.isRunning { process.terminate() }
    }

    private func startReaderLoop(_ reader: BufferedLineReader) {
        readerLoopStarted = true
        let router = router
        Thread.detachNewThread {
            while let raw = reader.nextLine() {
                if raw.isEmpty { continue }
                do {
                    let message = try JSONDecoder().decode(IpcMessage.self, from: Data(raw.utf8))
                    router.route(message, rawLine: raw)
                } catch {
                    router.routeMalformedLine(raw)
                }
            }
            router.close()
        }
    }

    private func write(_ data: Data) {
        writeLock.lock()
        defer { writeLock.unlock() }
        toDaemon.fileHandleForWriting.write(data)
    }

    private static func writeDiagnostic(_ message: String) {
        if let data = (message + "\n").data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
}

protocol HistoryDetailReading: AnyObject, Sendable {
    func readHistoryThread(threadId: String) throws -> HistoryThreadDetail
    func shutdown()
}

extension HistoryDetailReading {
    func shutdown() {}
}

extension DaemonClient: @unchecked Sendable {}
extension DaemonClient: HistoryDetailReading {}

final class DaemonHistoryDetailReader: HistoryDetailReading, @unchecked Sendable {
    private let client = DaemonClient()
    private let lock = NSLock()

    func readHistoryThread(threadId: String) throws -> HistoryThreadDetail {
        lock.lock()
        defer { lock.unlock() }
        return try client.readHistoryThread(threadId: threadId)
    }

    func shutdown() {
        lock.lock()
        defer { lock.unlock() }
        client.shutdown()
    }
}

/// Reads `\n`-delimited lines from a FileHandle, buffering partial reads.
/// A single JSONL message can arrive split across multiple read() calls
/// (Codex C-uitest / Eng D5: partial-line framing is exactly what breaks in
/// IPC). This handles that; Step 1 unit tests cover the split case.
///
/// `@unchecked Sendable` is sound here by ownership discipline, not by
/// thread-safety primitives: exactly ONE consumer touches a reader at a time.
/// DaemonClient owns that consumer in its single reader loop. There is no
/// overlap, so no lock is needed. (If a future change adds a second concurrent
/// reader, this annotation is the thing to revisit.)
final class BufferedLineReader: @unchecked Sendable {
    private let handle: FileHandle
    private var buffer = Data()

    init(handle: FileHandle) { self.handle = handle }

    func nextLine() -> String? {
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                return String(data: lineData, encoding: .utf8)
            }
            let chunk = handle.availableData
            if chunk.isEmpty {
                // EOF. Flush any trailing partial line, else signal disconnect.
                if buffer.isEmpty { return nil }
                let rest = String(data: buffer, encoding: .utf8)
                buffer.removeAll()
                return rest
            }
            buffer.append(chunk)
        }
    }
}
