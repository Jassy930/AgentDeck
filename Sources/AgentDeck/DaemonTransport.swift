import Foundation

/// Neutral IPC transport: ships frames in/out, owns nothing else.
///
/// Exists so `DaemonClient` stops directly owning `Process`/`Pipe`/reader —
/// that coupling is what makes the client untestable. Implementations may
/// spawn a child process, drive an in-memory pair, or replay fixtures; the
/// client only sees `IpcMessage` frames.
///
/// Stays agent-neutral per AGENTS.md §"项目边界": only carries the already-
/// neutral `IpcMessage`, never parses Codex vendor JSON.
protocol DaemonTransport: AnyObject {
    /// Spawn/connect and begin delivering frames to the registered handler.
    /// Idempotent: a second call after a successful start is a no-op.
    func start() throws

    /// Synchronously ship one frame (JSON + newline on the wire). Blocks
    /// until the write completes; throws on transport-layer faults so the
    /// caller can surface a named error rather than hang (Eng premise 9).
    func send(_ message: IpcMessage) throws

    /// Register the sink for incoming frames. Called exactly once during
    /// setup, before `start()`. The handler runs on the transport's reader
    /// context; implementations rely on it not blocking.
    func setIncomingHandler(_ handler: @escaping (IpcMessage) -> Void)

    /// Best-effort synchronous teardown. Idempotent; never throws — shutdown
    /// is cleanup, not a failure path.
    func shutdown()
}

/// Errors raised by `DaemonTransport` implementations. Kept separate from
/// `DaemonError` because transport faults are a layer below the client's
/// protocol-level errors.
enum TransportError: Error, CustomStringConvertible {
    case notStarted
    case alreadyShutdown
    case writeFailed(String)
    case readFailed(String)
    case spawnFailed(String)

    var description: String {
        switch self {
        case .notStarted: return "transport not started"
        case .alreadyShutdown: return "transport already shut down"
        case .writeFailed(let s): return "transport write failed: \(s)"
        case .readFailed(let s): return "transport read failed: \(s)"
        case .spawnFailed(let s): return "transport spawn failed: \(s)"
        }
    }
}
