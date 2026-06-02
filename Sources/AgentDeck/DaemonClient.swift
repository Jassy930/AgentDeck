import Foundation

/// Errors surfaced by the daemon client. Every failure is a named, visible
/// error — never a silent hang (Eng premise 9 / reverse-of-silent).
enum DaemonError: Error, CustomStringConvertible {
    case binaryNotFound(String)
    case spawnFailed(String)
    case disconnected
    case malformedReply(String)
    case duplicateRequestId(UInt64)

    var description: String {
        switch self {
        case .binaryNotFound(let p): return "agentdeckd not found at \(p)"
        case .spawnFailed(let m): return "failed to spawn agentdeckd: \(m)"
        case .disconnected: return "agentdeckd disconnected (EOF on its stdout)"
        case .malformedReply(let s): return "malformed reply from agentdeckd: \(s)"
        case .duplicateRequestId(let id): return "duplicate pending request id: \(id)"
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
    private struct StreamLineSubscription {
        let expectedSessionId: String?
        let handler: (String) -> Void
    }

    private let condition = NSCondition()
    private var pendingReplyIds: Set<UInt64> = []
    private var replies: [UInt64: IpcMessage] = [:]
    private var unmatched: [IpcMessage] = []
    private var isClosed = false
    private var sessionEventHandler: ((IpcMessage) -> Void)?
    private var streamLineSubscription: StreamLineSubscription?
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
            return streamLineSubscription?.handler
        }
        set {
            condition.lock()
            streamLineSubscription = newValue.map {
                StreamLineSubscription(expectedSessionId: nil, handler: $0)
            }
            condition.unlock()
        }
    }

    func setStreamLineHandler(
        expectedSessionId: String?,
        _ handler: @escaping (String) -> Void
    ) {
        condition.lock()
        streamLineSubscription = StreamLineSubscription(
            expectedSessionId: expectedSessionId,
            handler: handler
        )
        condition.unlock()
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

    @discardableResult
    func registerPending(id: UInt64) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard !pendingReplyIds.contains(id), replies[id] == nil else {
            return false
        }
        pendingReplyIds.insert(id)
        return true
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
            let streamSubscription = streamLineSubscription
            let shouldRouteToStream = streamRawLine != nil
                && streamSubscription != nil
                && Self.sessionEvent(message, matches: streamSubscription?.expectedSessionId)
            streamHandler = shouldRouteToStream ? streamSubscription?.handler : nil
            if Self.isTerminalSessionEvent(message) && shouldRouteToStream {
                streamLineSubscription = nil
            }
            if streamRawLine == nil || (sessionHandler == nil && streamHandler == nil) {
                unmatched.append(message)
                unmatchedHandler = unmatchedMessageHandler
            } else {
                unmatchedHandler = nil
            }
        } else if Self.isLegacyStreamKind(message.kind) {
            sessionHandler = nil
            streamHandler = streamLineSubscription?.handler
            streamRawLine = rawLine ?? Self.encodeRawLine(message)
            if Self.isTerminalStreamKind(message.kind) {
                streamLineSubscription = nil
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

    private static func sessionEvent(_ message: IpcMessage, matches expectedSessionId: String?) -> Bool {
        guard let expectedSessionId else { return true }
        return message.sessionId == expectedSessionId
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

@MainActor
protocol RuntimeTurnStarting: AnyObject {
    func startTurn(
        sessionId: String,
        threadId: String?,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        onEvent: @escaping @MainActor (IpcMessage) -> Void
    )
}

@MainActor
protocol RuntimeActionDeciding: AnyObject {
    func sendActionDecision(sessionId: String, requestId: UInt64, decision: String)
}

/// Speaks the neutral JSONL IPC protocol on top of a `DaemonTransport`.
///
/// B3 extracted the process+pipes+reader machinery into
/// `ProcessDaemonTransport`; this class now owns only the protocol-level
/// concerns (request-id allocation, router, kind-specific request/reply
/// shaping). It still spawns the daemon eagerly today via a concrete
/// `ProcessDaemonTransport`; B4 swaps that for an injected `DaemonTransport`
/// so tests can stub the wire.
///
/// Process lifecycle (Eng A1, first layer): the Swift app spawns the daemon;
/// when the app exits — normally OR via this object deinit — the daemon is
/// killed. There is no shared / persistent / orphan daemon. (Step 3+ extends
/// this so the daemon process-group-owns the Codex app-server child, so
/// killing the daemon cascades to the app-server too — A1's second layer.)
final class DaemonClient {
    private let profile: AgentDeckProfile
    private let transport: ProcessDaemonTransport
    private let router = DaemonMessageRouter()
    private let requestIdAllocator = DaemonRequestIdAllocator(startingAt: 1_000)

    init(profile: AgentDeckProfile = .stable) {
        self.profile = profile
        self.transport = ProcessDaemonTransport(profile: profile)
        // Wire the router as the transport's sink. The reader thread runs
        // inside the transport; these handlers run on that thread and the
        // router's locks make the cross-thread hop safe (B3 reshape).
        let router = self.router
        transport.setIncomingHandler { message in
            router.route(message)
        }
        transport.setMalformedLineHandler { rawLine in
            router.routeMalformedLine(rawLine)
        }
        transport.setDisconnectHandler {
            router.close()
        }
        router.onUnmatchedMessage = { message in
            Self.writeDiagnostic("unmatched daemon message: \(message.kind)")
        }
    }

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

    static func daemonEnvironment(
        profile: AgentDeckProfile,
        base: [String: String] = ProcessInfo.processInfo.environment
    ) -> [String: String] {
        var env = base
        env["AGENTDECK_PROFILE"] = profile.rawValue
        return env
    }

    func start() throws {
        try transport.start()
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

    func prepareRuntimeTurnRequest(
        sessionId: String,
        threadId: String?,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String
    ) throws -> IpcMessage {
        try prepareGeneratedIdRequest(Self.runtimeTurnRequest(
            id: 0,
            sessionId: sessionId,
            threadId: threadId,
            cwd: cwd,
            prompt: prompt,
            optimisticUserItemId: optimisticUserItemId
        ))
    }

    private func roundTripWithGeneratedId(_ msg: IpcMessage) throws -> IpcMessage {
        try sendRoundTrip(try prepareGeneratedIdRequest(msg))
    }

    private func sendRoundTrip(_ msg: IpcMessage) throws -> IpcMessage {
        if !transport.isStarted {
            try start()
        }
        guard let id = msg.id else {
            throw DaemonError.malformedReply("failed to assign id: \(msg.kind)")
        }
        guard router.registerPending(id: id) else {
            throw DaemonError.duplicateRequestId(id)
        }
        try transport.send(msg)

        guard let reply = router.waitForReply(id: id) else {
            throw DaemonError.disconnected
        }
        return reply
    }

    func loggingSelfcheck() throws -> [String: Any] {
        let reply = try roundTrip(IpcMessage(kind: "selfcheck/logging", id: 8, payload: nil))
        guard reply.kind == "loggingSelfcheck",
              let payload = reply.payload?.value as? [String: Any] else {
            if reply.kind == "error",
               let dict = reply.payload?.value as? [String: Any],
               let message = dict["message"] as? String {
                throw DaemonError.malformedReply(message)
            }
            throw DaemonError.malformedReply("expected loggingSelfcheck, got \(reply.kind)")
        }
        return payload
    }

    func diagnosticsReport(limit: Int? = 50, sinceSeconds: Int? = 3600, runId: String? = nil) throws -> [String: Any] {
        var requestPayload: [String: Any] = [:]
        if let limit { requestPayload["limit"] = limit }
        if let sinceSeconds { requestPayload["sinceSeconds"] = sinceSeconds }
        if let runId, !runId.isEmpty { requestPayload["runId"] = runId }

        let reply = try roundTrip(IpcMessage(
            kind: "diagnostics/report",
            id: 9,
            payload: requestPayload.isEmpty ? nil : AnyCodable(requestPayload)
        ))
        guard reply.kind == "diagnosticsReport",
              let payload = reply.payload?.value as? [String: Any] else {
            if reply.kind == "error",
               let dict = reply.payload?.value as? [String: Any],
               let message = dict["message"] as? String {
                throw DaemonError.malformedReply(message)
            }
            throw DaemonError.malformedReply("expected diagnosticsReport, got \(reply.kind)")
        }
        return payload
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
        if !transport.isStarted {
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
        if !transport.isStarted {
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

    static func runtimeTurnRequest(
        id: UInt64,
        sessionId: String,
        threadId: String?,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String
    ) -> IpcMessage {
        if let threadId {
            return IpcMessage(
                kind: "startTurn",
                id: id,
                sessionId: sessionId,
                payload: AnyCodable([
                    "threadId": threadId,
                    "prompt": prompt,
                    "optimisticUserItemId": optimisticUserItemId,
                ])
            )
        }

        return IpcMessage(
            kind: "startSession",
            id: id,
            sessionId: sessionId,
            payload: AnyCodable([
                "cwd": cwd.path,
                "prompt": prompt,
                "optimisticUserItemId": optimisticUserItemId,
            ])
        )
    }

    static func actionDecisionRequest(
        id: UInt64,
        sessionId: String,
        requestId: UInt64,
        decision: String
    ) -> IpcMessage {
        IpcMessage(
            kind: "actionDecision",
            id: id,
            sessionId: sessionId,
            payload: AnyCodable([
                "requestId": Int(requestId),
                "decision": decision,
            ])
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
        if !transport.isStarted {
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

    /// Deprecated compatibility path for pre-runtime tests. Runtime-first UI
    /// code should call `startTurn(sessionId:threadId:cwd:prompt:onEvent:)`
    /// so `session/event` routing preserves the outer session/thread ids.
    ///
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

        if !transport.isStarted {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        router.setStreamLineHandler(expectedSessionId: "session_1") { raw in
            DispatchQueue.main.async { onLine(raw) }
        }
        do {
            try transport.send(msg)
        } catch {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"failed to send startSession"}}"#)
            }
        }
    }

    func startTurn(
        threadId: String,
        prompt: String,
        onLine: @escaping @MainActor (String) -> Void
    ) {
        // Deprecated compatibility path. Runtime-first callers must use the
        // overload below so events stay wrapped in neutral `session/event`.
        let msg = Self.startTurnRequest(id: 4, threadId: threadId, prompt: prompt)
        if !transport.isStarted {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        router.setStreamLineHandler(expectedSessionId: "session_\(threadId)") { raw in
            DispatchQueue.main.async { onLine(raw) }
        }
        do {
            try transport.send(msg)
        } catch {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"failed to send startTurn"}}"#)
            }
        }
    }

    func startTurn(
        sessionId: String,
        threadId: String?,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        onEvent: @escaping @MainActor (IpcMessage) -> Void
    ) {
        let msg: IpcMessage
        do {
            msg = try prepareRuntimeTurnRequest(
                sessionId: sessionId,
                threadId: threadId,
                cwd: cwd,
                prompt: prompt,
                optimisticUserItemId: optimisticUserItemId
            )
        } catch {
            Task { @MainActor in
                onEvent(Self.syntheticSessionEvent(
                    sessionId: sessionId,
                    threadId: threadId,
                    kind: "error",
                    payload: ["message": "\(error)"]
                ))
            }
            return
        }
        do {
            if !transport.isStarted {
                try start()
            }
        } catch {
            Task { @MainActor in
                onEvent(Self.syntheticSessionEvent(
                    sessionId: sessionId,
                    threadId: threadId,
                    kind: "error",
                    payload: ["message": "\(error)"]
                ))
            }
            return
        }

        router.onSessionEvent = { message in
            let encoded = (try? JSONEncoder().encode(message))
                .flatMap { String(data: $0, encoding: .utf8) }
            DispatchQueue.main.async {
                guard let encoded,
                      let decoded = try? JSONDecoder().decode(
                        IpcMessage.self,
                        from: Data(encoded.utf8)
                      ) else { return }
                onEvent(decoded)
            }
        }
        if let id = msg.id {
            guard router.registerPending(id: id) else {
                Task { @MainActor in
                    onEvent(Self.syntheticSessionEvent(
                        sessionId: sessionId,
                        threadId: threadId,
                        kind: "error",
                        payload: ["message": DaemonError.duplicateRequestId(id).description]
                    ))
                }
                return
            }
            waitForTurnAccepted(
                id: id,
                sessionId: sessionId,
                threadId: threadId,
                onEvent: onEvent
            )
        }
        do {
            try transport.send(msg)
        } catch {
            Task { @MainActor in
                onEvent(Self.syntheticSessionEvent(
                    sessionId: sessionId,
                    threadId: threadId,
                    kind: "error",
                    payload: ["message": "\(error)"]
                ))
            }
        }
    }

    func sendActionDecision(sessionId: String, requestId: UInt64, decision: String) {
        let msg = requestIdAllocator.assignUniqueId(to: Self.actionDecisionRequest(
            id: 0,
            sessionId: sessionId,
            requestId: requestId,
            decision: decision
        ))
        do {
            if !transport.isStarted {
                try start()
            }
        } catch {
            Self.writeDiagnostic("failed to start daemon for actionDecision: \(error)")
            return
        }
        if let id = msg.id {
            _ = router.registerPending(id: id)
            DispatchQueue.global(qos: .utility).async { [router] in
                _ = router.waitForReply(id: id)
            }
        }
        do {
            try transport.send(msg)
        } catch {
            Self.writeDiagnostic("failed to send actionDecision: \(error)")
        }
    }

    private func waitForTurnAccepted(
        id: UInt64,
        sessionId: String,
        threadId: String?,
        onEvent: @escaping @MainActor (IpcMessage) -> Void
    ) {
        let router = router
        DispatchQueue.global(qos: .utility).async {
            guard let reply = router.waitForReply(id: id) else {
                DispatchQueue.main.async {
                    onEvent(Self.syntheticSessionEvent(
                        sessionId: sessionId,
                        threadId: threadId,
                        kind: "error",
                        payload: ["message": DaemonError.disconnected.description]
                    ))
                }
                return
            }
            guard reply.kind != "turnAccepted" else { return }
            let message: String
            if reply.kind == "error",
               let payload = reply.payload?.value as? [String: Any],
               let errorMessage = payload["message"] as? String {
                message = errorMessage
            } else {
                message = "expected turnAccepted, got \(reply.kind)"
            }
            DispatchQueue.main.async {
                onEvent(Self.syntheticSessionEvent(
                    sessionId: sessionId,
                    threadId: threadId,
                    kind: "error",
                    payload: ["message": message]
                ))
            }
        }
    }

    private static func syntheticSessionEvent(
        sessionId: String,
        threadId: String?,
        kind: String,
        payload: [String: Any]
    ) -> IpcMessage {
        IpcMessage(
            kind: "session/event",
            sessionId: sessionId,
            threadId: threadId,
            payload: AnyCodable([
                "event": [
                    "kind": kind,
                    "payload": payload,
                ],
            ])
        )
    }

    /// Ask the daemon to shut down, then ensure it is gone (A1: app exit
    /// kills the daemon — request a clean shutdown, then hard-kill as backstop).
    func shutdown() {
        // Gate the `bye` send on `isAlive` (not `isStarted`): if the daemon
        // already crashed/EOF'd, the reader loop is still "started" but the
        // pipe is broken, so writing would surface a noisy error and waste a
        // roundTrip on a guaranteed-fail path. Pre-B3 behaviour used
        // `process.isRunning` directly; `isAlive` restores it via the transport.
        if transport.isAlive {
            let bye = IpcMessage(kind: "shutdown", id: 0, payload: nil)
            _ = try? roundTrip(bye)
        }
        transport.shutdown()
    }

    deinit {
        // Backstop: even if the app forgot to call shutdown(), the daemon
        // must not outlive its owner (A1 — no orphan daemon). The transport's
        // own deinit also terminates the process; calling shutdown() here
        // makes the ordering explicit and idempotent.
        transport.shutdown()
    }

    private static func writeDiagnostic(_ message: String) {
        if let data = (message + "\n").data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
}

protocol SessionClienting: HistoryDetailReading {
    func start() throws
    func listHistoryThreads(
        cwd: String?,
        searchTerm: String?,
        cursor: String?,
        limit: Int?
    ) throws -> HistoryThreadListPayload
    func startSession(
        cwd: String,
        prompt: String,
        onLine: @escaping @MainActor (String) -> Void
    )
    func startTurn(
        threadId: String,
        prompt: String,
        onLine: @escaping @MainActor (String) -> Void
    )
    func archiveHistoryThread(threadId: String) throws
    func renameHistoryThread(threadId: String, name: String) throws
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
extension DaemonClient: RuntimeTurnStarting {}
extension DaemonClient: SessionClienting {}

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
/// `ProcessDaemonTransport` owns that consumer in its single reader loop
/// (post-B3 the loop moved off `DaemonClient`). There is no overlap, so no
/// lock is needed. (If a future change adds a second concurrent reader, this
/// annotation is the thing to revisit.)
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
