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

/// Reads `\n`-delimited lines from a FileHandle, buffering partial reads.
/// A single JSONL message can arrive split across multiple read() calls
/// (Codex C-uitest / Eng D5: partial-line framing is exactly what breaks in
/// IPC). This handles that; Step 1 unit tests cover the split case.
final class BufferedLineReader {
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
