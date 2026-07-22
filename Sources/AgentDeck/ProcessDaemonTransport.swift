import Foundation

/// Concrete `DaemonTransport` that spawns the real `agentdeckd` binary and
/// shuttles raw JSONL lines in/out over its stdin/stdout.
///
/// v2 redesign (Task 6A): the reader loop no longer attempts to decode each
/// line — it forwards strings to the incoming handler. `DaemonClient` parses
/// `ServerEvent` vs admin `{"reply":...}` shapes.
final class ProcessDaemonTransport: DaemonTransport, @unchecked Sendable {
    private let profile: AgentDeckProfile
    private let process = Process()
    private let toDaemon = Pipe()
    private let fromDaemon = Pipe()
    private var reader: BufferedLineReader?
    private let lifecycleLock = NSLock()
    private let writeLock = NSLock()
    private var readerLoopStarted = false
    private var incomingHandler: ((String) -> Void)?
    private var disconnectHandler: (() -> Void)?

    init(profile: AgentDeckProfile = .stable) {
        self.profile = profile
    }

    deinit {
        if process.isRunning { process.terminate() }
    }

    var isStarted: Bool {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        return readerLoopStarted
    }

    var isAlive: Bool {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        return readerLoopStarted && process.isRunning
    }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) {
        lifecycleLock.lock()
        incomingHandler = handler
        lifecycleLock.unlock()
    }

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
            throw DaemonError.binaryNotFound(
                "AGENTDECK_DAEMON_PATH, app bundle, target/{debug,release}, or PATH"
            )
        }
        process.executableURL = URL(fileURLWithPath: path)
        process.standardInput = toDaemon
        process.standardOutput = fromDaemon
        process.environment = DaemonClient.daemonEnvironment(profile: profile)
        do {
            try process.run()
        } catch {
            throw DaemonError.spawnFailed("\(error)")
        }
        let lineReader = BufferedLineReader(handle: fromDaemon.fileHandleForReading)
        reader = lineReader
        startReaderLoop(lineReader)
    }

    /// Ship one raw JSON line to the daemon, appending the trailing newline.
    func send(_ line: String) throws {
        var data = Data(line.utf8)
        data.append(0x0A)
        writeLock.lock()
        defer { writeLock.unlock() }
        toDaemon.fileHandleForWriting.write(data)
    }

    func shutdown() {
        if process.isRunning {
            process.terminate()
        }
    }

    private func startReaderLoop(_ reader: BufferedLineReader) {
        readerLoopStarted = true
        Thread.detachNewThread {
            while let raw = reader.nextLine() {
                if raw.isEmpty { continue }
                self.deliverIncoming(raw)
            }
            self.deliverDisconnect()
        }
    }

    private func deliverIncoming(_ rawLine: String) {
        lifecycleLock.lock()
        let handler = incomingHandler
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

/// Reads `\n`-delimited lines from a FileHandle, buffering partial reads.
/// A single JSONL message can arrive split across multiple read() calls.
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
                if buffer.isEmpty { return nil }
                let rest = String(data: buffer, encoding: .utf8)
                buffer.removeAll()
                return rest
            }
            buffer.append(chunk)
        }
    }
}
