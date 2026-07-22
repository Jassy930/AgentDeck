import Foundation
import AgentDeckCore

/// Errors surfaced by the daemon client.
enum DaemonError: Error, CustomStringConvertible {
    case binaryNotFound(String)
    case spawnFailed(String)
    case disconnected
    case malformedReply(String)
    case adminReplyMismatch(expected: String, got: String)

    var description: String {
        switch self {
        case .binaryNotFound(let p): return "agentdeckd not found at \(p)"
        case .spawnFailed(let m): return "failed to spawn agentdeckd: \(m)"
        case .disconnected: return "agentdeckd disconnected (EOF on its stdout)"
        case .malformedReply(let s): return "malformed reply from agentdeckd: \(s)"
        case .adminReplyMismatch(let e, let g): return "expected admin reply '\(e)', got '\(g)'"
        }
    }
}

// MARK: - Protocol-side service interfaces consumed by UI/model layer

@MainActor
protocol RuntimeTurnStarting: AnyObject {
    /// Drives one streaming turn. For new sessions pass `threadId = nil` and
    /// supply a fully populated `SessionStart`; for continuation pass the
    /// existing thread id + agent kind.
    func startTurn(
        sessionId: String,
        threadId: String?,
        agentKind: AgentKind,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        sessionStart: SessionStart?,
        onEvent: @escaping @MainActor (ServerEvent) -> Void
    )
}

@MainActor
protocol RuntimeActionDeciding: AnyObject {
    func sendActionDecision(sessionId: String, requestId: String, decision: ActionDecisionKind, persist: Bool)
}

// MARK: - Admin reply router

/// Dispatches incoming raw lines to either (a) a per-session event handler
/// when the line decodes as `ServerEvent`, or (b) the next waiting admin
/// round-trip when the line is `{"reply":"..."}`.
final class DaemonRouter: @unchecked Sendable {
    private let lock = NSLock()
    private let cond = NSCondition()
    private var sessionHandlers: [String: (ServerEvent) -> Void] = [:]
    private var pendingNewSessionHandlers: [(ServerEvent) -> Void] = []
    private var globalEventHandler: ((ServerEvent) -> Void)?
    private var pendingAdminReplies: [String] = []
    private var isClosed = false

    var globalHandler: ((ServerEvent) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return globalEventHandler }
        set { lock.lock(); globalEventHandler = newValue; lock.unlock() }
    }

    func registerSessionHandler(_ sessionId: String, _ handler: @escaping (ServerEvent) -> Void) {
        lock.lock()
        sessionHandlers[sessionId] = handler
        lock.unlock()
    }

    func registerPendingNewSessionHandler(_ handler: @escaping (ServerEvent) -> Void) {
        lock.lock()
        pendingNewSessionHandlers.append(handler)
        lock.unlock()
    }

    func removeSessionHandler(_ sessionId: String) {
        lock.lock()
        sessionHandlers.removeValue(forKey: sessionId)
        lock.unlock()
    }

    /// Push an incoming raw line. Tries `ServerEvent` first; on failure
    /// checks for `"reply"` key and routes to the admin queue.
    func push(rawLine line: String) {
        // First try ServerEvent.
        if let event = try? JSONDecoder().decode(ServerEvent.self, from: Data(line.utf8)) {
            routeEvent(event)
            return
        }
        // Then try as an admin reply (`{"reply":"..."}`).
        if let data = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
           data["reply"] is String {
            cond.lock()
            pendingAdminReplies.append(line)
            cond.broadcast()
            cond.unlock()
            return
        }
        // Otherwise: unparseable — surface as a synthetic ServerEvent.error so
        // diagnostics aren't silently lost.
        let synth = ServerEvent.error(
            sessionId: nil,
            error: ProtocolError(code: "swift.malformed", message: "unparseable daemon line: \(line)")
        )
        routeEvent(synth)
    }

    private func routeEvent(_ event: ServerEvent) {
        lock.lock()
        let perSession = event.sessionId.flatMap { sessionHandlers[$0] }
        var adoptedPending: ((ServerEvent) -> Void)?
        if perSession == nil, !pendingNewSessionHandlers.isEmpty {
            switch event {
            case .sessionStarted(let sessionId, _, _):
                let handler = pendingNewSessionHandlers.removeFirst()
                sessionHandlers[sessionId] = handler
                adoptedPending = handler
            case .error(nil, _):
                adoptedPending = pendingNewSessionHandlers.removeFirst()
            default:
                break
            }
        }
        let global = globalEventHandler
        lock.unlock()
        (perSession ?? adoptedPending)?(event)
        global?(event)
    }

    /// Wait for next admin reply line whose `"reply"` field matches
    /// `expectedReply`. Other admin replies are skipped and re-enqueued for
    /// subsequent waiters. Returns nil if the transport disconnects.
    func waitForAdminReply(expectedReply: String, timeoutSeconds: TimeInterval = 10) -> String? {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        cond.lock()
        defer { cond.unlock() }
        while true {
            for (index, line) in pendingAdminReplies.enumerated() {
                if let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                   let reply = obj["reply"] as? String,
                   reply == expectedReply {
                    pendingAdminReplies.remove(at: index)
                    return line
                }
            }
            if isClosed { return nil }
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { return nil }
            cond.wait(until: Date().addingTimeInterval(remaining))
        }
    }

    func close() {
        cond.lock()
        isClosed = true
        cond.broadcast()
        cond.unlock()
    }
}

// MARK: - DaemonClient

/// v2 daemon client. Speaks `ClientCommand` outward, parses `ServerEvent`
/// inward, plus admin reply side-channel.
final class DaemonClient {
    private let profile: AgentDeckProfile
    private let transport: DaemonTransport
    private let router = DaemonRouter()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = []
        return e
    }()

    init(profile: AgentDeckProfile = .stable, transport: DaemonTransport? = nil) {
        self.profile = profile
        self.transport = transport ?? ProcessDaemonTransport(profile: profile)
        let router = self.router
        self.transport.setIncomingHandler { line in
            router.push(rawLine: line)
        }
        self.transport.setDisconnectHandler {
            router.close()
        }
    }

    /// Locate the daemon binary without relying on the process cwd.
    ///
    /// LaunchServices starts an `.app` with `/` as its working directory, so a
    /// cwd-relative `target/debug/agentdeckd` lookup cannot support a packaged
    /// development app. The bundle therefore carries `agentdeckd` next to the
    /// App executable. `AGENTDECK_DAEMON_PATH` remains the explicit override
    /// for local harnesses; source-tree and PATH candidates are development
    /// fallbacks for `swift run AgentDeck`.
    static func locateDaemon(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        executableURL: URL? = Bundle.main.executableURL,
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) -> String? {
        var candidates: [String] = []

        if let override = environment["AGENTDECK_DAEMON_PATH"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !override.isEmpty {
            candidates.append(override)
        }

        if let executableURL {
            candidates.append(
                executableURL.deletingLastPathComponent()
                    .appendingPathComponent("agentdeckd", isDirectory: false)
                    .path
            )
        }

        candidates.append(contentsOf: [
            (currentDirectoryPath as NSString).appendingPathComponent("target/debug/agentdeckd"),
            (currentDirectoryPath as NSString).appendingPathComponent("target/release/agentdeckd"),
        ])

        if let path = environment["PATH"] {
            candidates.append(contentsOf: path.split(separator: ":").map {
                (String($0) as NSString).appendingPathComponent("agentdeckd")
            })
        }

        candidates.append(contentsOf: [
            "/usr/local/bin/agentdeckd",
            "/opt/homebrew/bin/agentdeckd",
        ])

        for rawCandidate in candidates {
            let expanded = (rawCandidate as NSString).expandingTildeInPath
            let absolute = (expanded as NSString).isAbsolutePath
                ? expanded
                : (currentDirectoryPath as NSString).appendingPathComponent(expanded)
            let normalized = URL(fileURLWithPath: absolute).standardizedFileURL.path
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: normalized, isDirectory: &isDirectory),
               !isDirectory.boolValue,
               fileManager.isExecutableFile(atPath: normalized) {
                return normalized
            }
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

    var isStarted: Bool { transport.isStarted }

    // MARK: - Send

    func send(_ command: ClientCommand) throws {
        if !transport.isStarted {
            try start()
        }
        let data = try encoder.encode(command)
        guard let line = String(data: data, encoding: .utf8) else {
            throw DaemonError.malformedReply("failed to UTF-8 encode ClientCommand")
        }
        try transport.send(line)
    }

    /// Send a command and wait for the matching admin reply line.
    @discardableResult
    func adminRoundTrip(_ command: ClientCommand, expectedReply: String, timeoutSeconds: TimeInterval = 10) throws -> [String: Any] {
        try send(command)
        guard let line = router.waitForAdminReply(expectedReply: expectedReply, timeoutSeconds: timeoutSeconds) else {
            if !transport.isAlive {
                throw DaemonError.disconnected
            }
            throw DaemonError.malformedReply("timed out waiting for admin reply '\(expectedReply)'")
        }
        guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            throw DaemonError.malformedReply("non-JSON admin reply: \(line)")
        }
        return obj
    }

    // MARK: - Admin commands

    func ping() throws {
        _ = try adminRoundTrip(.ping, expectedReply: "ping")
    }

    func selfcheck() throws -> [String: Any] {
        try adminRoundTrip(.selfcheck, expectedReply: "selfcheck")
    }

    func protocolVersion() throws -> Int {
        let reply = try adminRoundTrip(.protocolVersion, expectedReply: "protocolVersion")
        return reply["version"] as? Int ?? 0
    }

    func protocolSchema() throws -> [String: Any] {
        try adminRoundTrip(.protocolSchema, expectedReply: "protocolSchema")
    }

    func agentList() throws -> [AgentKind] {
        let reply = try adminRoundTrip(.agentList, expectedReply: "agentList")
        guard let arr = reply["agents"] as? [String] else { return [] }
        return arr.compactMap { AgentKind(rawValue: $0) }
    }

    func agentCapabilities(_ kind: AgentKind) throws -> SessionCapabilities {
        let reply = try adminRoundTrip(.agentCapabilities(agentKind: kind), expectedReply: "agentCapabilities")
        guard let caps = reply["capabilities"] else {
            throw DaemonError.malformedReply("missing capabilities in reply")
        }
        let data = try JSONSerialization.data(withJSONObject: caps)
        return try JSONDecoder().decode(SessionCapabilities.self, from: data)
    }

    func history(_ req: HistoryRequest) throws -> HistoryResponse {
        let reply = try adminRoundTrip(.history(req), expectedReply: "history")
        guard let response = reply["response"] else {
            throw DaemonError.malformedReply("missing response field in history reply")
        }
        let data = try JSONSerialization.data(withJSONObject: response)
        return try JSONDecoder().decode(HistoryResponse.self, from: data)
    }

    // MARK: - Streaming session lifecycle

    /// Register a per-session event handler. Future ServerEvents whose
    /// sessionId matches will be routed to `handler`.
    func setSessionEventHandler(sessionId: String, handler: @escaping (ServerEvent) -> Void) {
        router.registerSessionHandler(sessionId, handler)
    }

    func removeSessionEventHandler(sessionId: String) {
        router.removeSessionHandler(sessionId)
    }

    /// Receive every ServerEvent (mirrors per-session routing for orchestration).
    var globalEventHandler: ((ServerEvent) -> Void)? {
        get { router.globalHandler }
        set { router.globalHandler = newValue }
    }

    func startSession(_ start: SessionStart) throws {
        try send(.sessionStart(start))
    }

    /// Resume an existing thread. `cwd` is REQUIRED so the daemon
    /// adapter can point CC `--resume` at the right per-cwd resume
    /// file and run tool_use in the original directory (C3 fix,
    /// v0.2 final review).
    func continueThread(threadId: String, agentKind: AgentKind, cwd: String, prompt: String) throws {
        try send(.sessionContinue(threadId: threadId, agentKind: agentKind, cwd: cwd, prompt: prompt))
    }

    func cancelSession(sessionId: String) throws {
        try send(.sessionCancel(sessionId: sessionId))
    }

    func submitDecision(sessionId: String, decision: ActionDecision) throws {
        try send(.actionDecision(sessionId: sessionId, decision: decision))
    }

    func submitVendorControl(sessionId: String, payload: VendorControlPayload) throws {
        try send(.vendorControl(sessionId: sessionId, payload: payload))
    }

    func shutdown() {
        transport.shutdown()
    }

    deinit {
        transport.shutdown()
    }

    // MARK: - Static helpers (used by tests)

    static func decodeServerEvent(_ jsonLine: String) throws -> ServerEvent {
        try JSONDecoder().decode(ServerEvent.self, from: Data(jsonLine.utf8))
    }

    static func encodeClientCommand(_ command: ClientCommand) throws -> String {
        let data = try JSONEncoder().encode(command)
        return String(data: data, encoding: .utf8) ?? ""
    }
}

// MARK: - RuntimeTurnStarting adoption

extension DaemonClient: @unchecked Sendable {}

extension DaemonClient: RuntimeTurnStarting {
    @MainActor
    func startTurn(
        sessionId: String,
        threadId: String?,
        agentKind: AgentKind,
        cwd: URL,
        prompt: String,
        optimisticUserItemId: String,
        sessionStart: SessionStart?,
        onEvent: @escaping @MainActor (ServerEvent) -> Void
    ) {
        let handler: (ServerEvent) -> Void = { event in
            DispatchQueue.main.async { onEvent(event) }
        }
        router.registerPendingNewSessionHandler(handler)
        setSessionEventHandler(sessionId: sessionId, handler: handler)
        do {
            if let threadId {
                // C3 fix: propagate the original cwd so CC `--resume`
                // and tool_use run in the same directory as the
                // original session.
                try continueThread(
                    threadId: threadId,
                    agentKind: agentKind,
                    cwd: cwd.path,
                    prompt: prompt
                )
            } else if let sessionStart {
                try startSession(sessionStart)
            } else {
                // No session start payload — synthesize a minimal one with sensible defaults
                // matching the chosen agentKind.
                let synthesized: SessionStart
                switch agentKind {
                case .codex:
                    synthesized = SessionStart(
                        agentKind: .codex,
                        cwd: cwd.path,
                        prompt: prompt,
                        vendorOptions: .codex(CodexSessionOptions(
                            approvalPolicy: .onRequest,
                            sandbox: .workspaceWrite,
                            persistApproval: false,
                            reasoningEffort: .medium
                        ))
                    )
                case .claudeCode:
                    synthesized = SessionStart(
                        agentKind: .claudeCode,
                        cwd: cwd.path,
                        prompt: prompt,
                        vendorOptions: .claudeCode(ClaudeCodeSessionOptions(permissionMode: .default))
                    )
                }
                try startSession(synthesized)
            }
        } catch {
            let synth = ServerEvent.error(
                sessionId: sessionId,
                error: ProtocolError(code: "swift.send-failed", message: "\(error)")
            )
            DispatchQueue.main.async { onEvent(synth) }
        }
    }
}

extension DaemonClient: RuntimeActionDeciding {
    @MainActor
    func sendActionDecision(sessionId: String, requestId: String, decision: ActionDecisionKind, persist: Bool) {
        do {
            try submitDecision(
                sessionId: sessionId,
                decision: ActionDecision(requestId: requestId, decision: decision, persist: persist)
            )
        } catch {
            Self.writeDiagnostic("failed to send actionDecision: \(error)")
        }
    }
}

private extension DaemonClient {
    static func writeDiagnostic(_ message: String) {
        if let data = (message + "\n").data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
}
