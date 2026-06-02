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

    /// Register the sink for raw lines that failed to decode as `IpcMessage`.
    /// B3 added this because the daemon's "send something garbage" diagnostic
    /// surfaces here, and DaemonClient needs to route it to the router's
    /// malformed-line bookkeeping rather than silently drop it.
    func setMalformedLineHandler(_ handler: @escaping (String) -> Void)

    /// Register the callback fired exactly once when the underlying transport
    /// hits EOF / the peer goes away. DaemonClient uses it to close the router
    /// (B3) so in-flight roundTrips fail fast instead of hanging.
    func setDisconnectHandler(_ handler: @escaping () -> Void)

    /// True between a successful `start()` and `shutdown()`. DaemonClient
    /// uses this to guard `send` paths against "you forgot to start()" so the
    /// error name is `notStarted` instead of a generic write failure.
    var isStarted: Bool { get }

    /// True while the underlying transport is believed live (process running,
    /// pipe open, etc.). DaemonClient.shutdown gates its courtesy `bye` send
    /// on this to avoid a guaranteed-fail roundTrip when the peer has already
    /// gone away.
    var isAlive: Bool { get }

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
