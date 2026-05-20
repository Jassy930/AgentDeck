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
    var payload: AnyCodable?
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
        reader = BufferedLineReader(handle: fromDaemon.fileHandleForReading)
    }

    /// Send one neutral message and block for the correlated reply.
    /// Step 1 is request/reply; the streaming item path (background reader →
    /// MainActor, Eng D9 state machine) lands in Step 3+.
    func roundTrip(_ msg: IpcMessage) throws -> IpcMessage {
        let enc = JSONEncoder()
        var data = try enc.encode(msg)
        data.append(0x0A) // newline-delimited JSON (D7-confirmed framing)
        toDaemon.fileHandleForWriting.write(data)

        guard let line = reader?.nextLine() else {
            throw DaemonError.disconnected
        }
        do {
            return try JSONDecoder().decode(IpcMessage.self, from: Data(line.utf8))
        } catch {
            throw DaemonError.malformedReply(line)
        }
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
        if reader == nil {
            try start()
        }
        let reply = try roundTrip(Self.historyListRequest(
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
        let reply = try roundTrip(Self.historyReadRequest(id: 3, threadId: threadId))
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
        let reply = try roundTrip(request)
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

    /// Start a streaming session. Sends `startSession {cwd, prompt}`, then
    /// reads neutral IPC messages on a BACKGROUND thread and delivers each
    /// one to `onMessage` ON THE MAIN THREAD.
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
        toDaemon.fileHandleForWriting.write(line)

        // Cross the thread boundary with a plain String (Sendable). Decoding
        // happens ON the main actor in onLine — so the IpcMessage (which
        // holds non-Sendable AnyCodable) never crosses threads at all. This
        // sidesteps the background→main data race entirely (Eng C-uitest):
        // the safe fix is to not share a non-Sendable value, not to bolt
        // Sendable onto it.
        // Capture ONLY the reader, not self. The background thread must not
        // reach back into DaemonClient (non-Sendable) — it owns nothing but
        // the line stream. This is the minimal-sharing fix, not a Sendable
        // bolt-on.
        guard let reader else {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        Thread.detachNewThread {
            while let raw = reader.nextLine() {
                if raw.isEmpty { continue }
                let terminal = raw.contains("\"turnComplete\"")
                    || raw.contains("\"kind\":\"error\"")
                DispatchQueue.main.async { onLine(raw) }
                if terminal { break }
            }
        }
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
        toDaemon.fileHandleForWriting.write(line)

        guard let reader else {
            Task { @MainActor in
                onLine(#"{"kind":"error","payload":{"message":"reader not initialized"}}"#)
            }
            return
        }
        Thread.detachNewThread {
            while let raw = reader.nextLine() {
                if raw.isEmpty { continue }
                let terminal = raw.contains("\"turnComplete\"")
                    || raw.contains("\"kind\":\"error\"")
                DispatchQueue.main.async { onLine(raw) }
                if terminal { break }
            }
        }
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
/// thread-safety primitives: exactly ONE consumer touches a reader at a
/// time. Step 1's roundTrip reads it synchronously on the caller's thread;
/// the streaming path moves it to a single dedicated background thread and
/// the main thread never reads it concurrently. There is no overlap, so no
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
