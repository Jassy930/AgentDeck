import Foundation

/// Neutral IPC transport: ships JSONL frames in/out as raw strings.
///
/// v2 redesign (Task 6A): the transport no longer parses messages — it
/// shuttles raw lines and lets `DaemonClient` decide whether each line is a
/// `ServerEvent` or an admin reply (`{"reply":...}`). The two-channel
/// disambiguation is done up at the client because admin replies bypass
/// `ServerEvent` (per daemon Task 3C / cli Task 5A design).
protocol DaemonTransport: AnyObject {
    /// Spawn/connect and begin delivering frames to the registered handler.
    /// Idempotent: a second call after a successful start is a no-op.
    func start() throws

    /// Synchronously ship one raw JSON line (the transport appends the
    /// trailing newline). Blocks until the write completes; throws on
    /// transport-layer faults.
    func send(_ line: String) throws

    /// Register the sink for incoming raw lines. Called exactly once during
    /// setup, before `start()`. The handler runs on the transport's reader
    /// context; implementations rely on it not blocking.
    func setIncomingHandler(_ handler: @escaping (String) -> Void)

    /// Register the callback fired exactly once when the underlying transport
    /// hits EOF / the peer goes away. DaemonClient uses it to fail in-flight
    /// admin round-trips so they don't hang.
    func setDisconnectHandler(_ handler: @escaping () -> Void)

    /// True between a successful `start()` and `shutdown()`.
    var isStarted: Bool { get }

    /// True while the underlying transport is believed live.
    var isAlive: Bool { get }

    /// Best-effort synchronous teardown. Idempotent; never throws.
    func shutdown()
}

/// Errors raised by `DaemonTransport` implementations.
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
