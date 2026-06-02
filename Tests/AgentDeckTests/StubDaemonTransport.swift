import Foundation
@testable import AgentDeck

/// In-memory `DaemonTransport` for driving `DaemonClient` from synthetic
/// events. B6-B9 use it to replace the forked `agentdeckd` binary so the
/// client's lifecycle, send paths, incoming routing, malformed-line fan-out,
/// and disconnect handling can be exercised without process spawn.
///
/// Mirrors `ProcessDaemonTransport`'s threading model: a single `NSLock` guards
/// all mutable state so tests can `push(_:)` from any thread, and `@unchecked
/// Sendable` matches the production transport's shape.
///
/// Tests inspect outbound traffic via `sent`, inject faults via
/// `nextSendError` / `nextStartError`, and drive incoming traffic via
/// `push`, `pushMalformed`, and `triggerDisconnect`. Lifecycle counters
/// (`startCount`, `shutdownCount`) let assertions distinguish idempotent
/// no-ops from real start/shutdown calls.
final class StubDaemonTransport: DaemonTransport, @unchecked Sendable {
    private let lock = NSLock()

    private var _isStarted = false
    private var _isAlive = false
    private var _startCount = 0
    private var _shutdownCount = 0
    private var _sent: [IpcMessage] = []
    private var _incomingHandler: ((IpcMessage) -> Void)?
    private var _malformedHandler: ((String) -> Void)?
    private var _disconnectHandler: (() -> Void)?
    private var _nextSendError: TransportError?
    private var _nextStartError: TransportError?

    init() {}

    // MARK: - Fault injection

    /// When non-nil the NEXT `send(_:)` call throws this error and clears it.
    /// One-shot semantics keep tests explicit — every fault must be re-armed.
    var nextSendError: TransportError? {
        get { lock.lock(); defer { lock.unlock() }; return _nextSendError }
        set { lock.lock(); _nextSendError = newValue; lock.unlock() }
    }

    /// When non-nil the NEXT `start()` call throws this error and clears it.
    var nextStartError: TransportError? {
        get { lock.lock(); defer { lock.unlock() }; return _nextStartError }
        set { lock.lock(); _nextStartError = newValue; lock.unlock() }
    }

    // MARK: - DaemonTransport protocol

    func start() throws {
        lock.lock()
        if let err = _nextStartError {
            _nextStartError = nil
            lock.unlock()
            throw err
        }
        _startCount += 1
        _isStarted = true
        _isAlive = true
        lock.unlock()
    }

    func send(_ message: IpcMessage) throws {
        lock.lock()
        if let err = _nextSendError {
            _nextSendError = nil
            lock.unlock()
            throw err
        }
        _sent.append(message)
        lock.unlock()
    }

    func setIncomingHandler(_ handler: @escaping (IpcMessage) -> Void) {
        lock.lock(); defer { lock.unlock() }
        _incomingHandler = handler
    }

    func setMalformedLineHandler(_ handler: @escaping (String) -> Void) {
        lock.lock(); defer { lock.unlock() }
        _malformedHandler = handler
    }

    func setDisconnectHandler(_ handler: @escaping () -> Void) {
        lock.lock(); defer { lock.unlock() }
        _disconnectHandler = handler
    }

    var isStarted: Bool {
        lock.lock(); defer { lock.unlock() }
        return _isStarted
    }

    var isAlive: Bool {
        lock.lock(); defer { lock.unlock() }
        return _isAlive
    }

    func shutdown() {
        lock.lock(); defer { lock.unlock() }
        _shutdownCount += 1
        _isAlive = false
        // `_isStarted` stays true to match `ProcessDaemonTransport`'s
        // "isStarted means we ever started successfully" semantic — only
        // `isAlive` flips on teardown.
    }

    // MARK: - Test driver API

    /// Deliver a synthetic frame to the incoming handler registered by the
    /// client during setup. Runs the handler outside the lock so re-entrant
    /// calls (e.g., the handler calling back into `send`) don't deadlock.
    func push(_ message: IpcMessage) {
        lock.lock()
        let handler = _incomingHandler
        lock.unlock()
        handler?(message)
    }

    /// Deliver a synthetic raw line that failed JSON decoding, exercising the
    /// router's malformed-line fan-out path.
    func pushMalformed(_ line: String) {
        lock.lock()
        let handler = _malformedHandler
        lock.unlock()
        handler?(line)
    }

    /// Simulate the transport hitting EOF: flip `isAlive` to false and fire
    /// the registered disconnect handler so blocked `roundTrip` callers can
    /// surface `DaemonError.disconnected`.
    func triggerDisconnect() {
        lock.lock()
        _isAlive = false
        let handler = _disconnectHandler
        lock.unlock()
        handler?()
    }

    /// Tests that need to simulate "started but daemon died mid-flight" can
    /// flip this without going through `triggerDisconnect` (which also fires
    /// the disconnect callback).
    func setAlive(_ alive: Bool) {
        lock.lock(); defer { lock.unlock() }
        _isAlive = alive
    }

    // MARK: - Inspection

    /// Snapshot of every frame the client has handed to `send(_:)`, in order.
    var sent: [IpcMessage] {
        lock.lock(); defer { lock.unlock() }
        return _sent
    }

    /// Number of successful `start()` calls. Useful for asserting lazy-start
    /// idempotency on second roundTrip calls.
    var startCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _startCount
    }

    /// Number of `shutdown()` calls. Useful for asserting shutdown idempotency
    /// and that the client's deinit path actually tears the transport down.
    var shutdownCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _shutdownCount
    }

    /// Drop captured sends so a test can reset between phases without
    /// reconstructing the stub.
    func clearSent() {
        lock.lock(); defer { lock.unlock() }
        _sent.removeAll()
    }
}
