import Foundation

/// Concrete `DaemonTransport` that spawns the real `agentdeckd` binary,
/// shuttles JSONL frames in/out over its stdin/stdout, and surfaces incoming
/// `IpcMessage` frames through a registered handler.
///
/// Extracted from `DaemonClient` in B3 so the process/pipes/reader machinery
/// lives behind the neutral transport seam (B2). After the B4 step
/// `DaemonClient` accepts any `DaemonTransport`, so tests can swap this for an
/// in-memory stub instead of forking a binary.
///
/// `daemonEnvironment` and `locateDaemon` deliberately stay on `DaemonClient`
/// as statics — the B1 baseline tests reference them by their original symbol
/// path, so the extraction must not move them. This class calls back into
/// those statics to keep the wire-format and lookup policy single-sourced.
///
/// `@unchecked Sendable`: the two locks (`lifecycleLock`, `writeLock`) and the
/// single reader thread (which owns its `BufferedLineReader`) make the shared
/// state safe across threads. The same pattern previously lived on
/// `DaemonClient` and is preserved verbatim.
final class ProcessDaemonTransport: DaemonTransport, @unchecked Sendable {
    private let profile: AgentDeckProfile
    private let process = Process()
    private let toDaemon = Pipe()
    private let fromDaemon = Pipe()
    private var reader: BufferedLineReader?
    private let lifecycleLock = NSLock()
    private let writeLock = NSLock()
    private var readerLoopStarted = false
    private var incomingHandler: ((IpcMessage) -> Void)?
    private var malformedLineHandler: ((String) -> Void)?
    private var disconnectHandler: (() -> Void)?

    init(profile: AgentDeckProfile = .stable) {
        self.profile = profile
    }

    deinit {
        // Backstop: even if the owner forgot to call shutdown(), the daemon
        // must not outlive its transport (A1 — no orphan daemon).
        if process.isRunning { process.terminate() }
    }

    /// Whether `start()` has already spawned the daemon and the reader loop is
    /// running. Used by the owning client to lazy-start on the first request.
    /// Not on the `DaemonTransport` protocol yet — B4 will revisit how clients
    /// observe transport readiness.
    var isStarted: Bool {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        return readerLoopStarted
    }

    func setIncomingHandler(_ handler: @escaping (IpcMessage) -> Void) {
        lifecycleLock.lock()
        incomingHandler = handler
        lifecycleLock.unlock()
    }

    /// Sink for raw lines that fail JSON decoding. Kept off the `DaemonTransport`
    /// protocol because the protocol only carries `IpcMessage`; the router
    /// needs the raw-line variant to fan an `error` reply out to every pending
    /// id (pinned by the B1 baseline `router_routes_malformed_line_...` test).
    func setMalformedLineHandler(_ handler: @escaping (String) -> Void) {
        lifecycleLock.lock()
        malformedLineHandler = handler
        lifecycleLock.unlock()
    }

    /// Sink for reader-loop termination (daemon EOF or shutdown). Kept off
    /// the `DaemonTransport` protocol because shutdown signaling is the
    /// router's concern, not the wire format's — `DaemonClient` uses it to
    /// close the router so blocked `waitForReply` calls surface
    /// `DaemonError.disconnected` instead of hanging (Eng premise 9).
    func setDisconnectHandler(_ handler: @escaping () -> Void) {
        lifecycleLock.lock()
        disconnectHandler = handler
        lifecycleLock.unlock()
    }

    func start() throws {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        if readerLoopStarted {
            return
        }
        guard let path = DaemonClient.locateDaemon() else {
            throw DaemonError.binaryNotFound("target/{debug,release}/agentdeckd or PATH")
        }
        process.executableURL = URL(fileURLWithPath: path)
        process.standardInput = toDaemon
        process.standardOutput = fromDaemon
        process.environment = DaemonClient.daemonEnvironment(profile: profile)
        // stderr inherits — daemon diagnostic logging (Eng O1) lands in Step 5.
        do {
            try process.run()
        } catch {
            throw DaemonError.spawnFailed("\(error)")
        }
        let lineReader = BufferedLineReader(handle: fromDaemon.fileHandleForReading)
        reader = lineReader
        startReaderLoop(lineReader)
    }

    /// Ship one frame as JSON + `\n`. Encoding happens here so the transport
    /// — not its callers — owns the on-wire framing (D7-confirmed JSONL).
    func send(_ message: IpcMessage) throws {
        let encoded: Data
        do {
            encoded = try JSONEncoder().encode(message)
        } catch {
            throw TransportError.writeFailed("encode failed: \(error)")
        }
        var line = encoded
        line.append(0x0A)
        writeLock.lock()
        defer { writeLock.unlock() }
        toDaemon.fileHandleForWriting.write(line)
    }

    /// Best-effort teardown: kills the daemon if it's still running. The
    /// reader loop exits on its own once `fromDaemon` reaches EOF. Idempotent
    /// and non-throwing per `DaemonTransport`'s shutdown contract.
    func shutdown() {
        if process.isRunning {
            process.terminate()
        }
    }

    private func startReaderLoop(_ reader: BufferedLineReader) {
        readerLoopStarted = true
        Thread.detachNewThread { [weak self] in
            while let raw = reader.nextLine() {
                if raw.isEmpty { continue }
                do {
                    let message = try JSONDecoder().decode(IpcMessage.self, from: Data(raw.utf8))
                    self?.deliverIncoming(message)
                } catch {
                    self?.deliverMalformed(raw)
                }
            }
            self?.deliverDisconnect()
        }
    }

    private func deliverIncoming(_ message: IpcMessage) {
        lifecycleLock.lock()
        let handler = incomingHandler
        lifecycleLock.unlock()
        handler?(message)
    }

    private func deliverMalformed(_ rawLine: String) {
        lifecycleLock.lock()
        let handler = malformedLineHandler
        lifecycleLock.unlock()
        handler?(rawLine)
    }

    private func deliverDisconnect() {
        lifecycleLock.lock()
        let handler = disconnectHandler
        lifecycleLock.unlock()
        handler?()
    }
}
