import Foundation
import Testing
@testable import AgentDeck

// B6-B9 (merged): DaemonClient behavioural coverage atop StubDaemonTransport.
//
// Each test constructs a fresh `DaemonClient` bound to a `StubDaemonTransport`
// so the wire is fully synthetic. The stub's lifecycle counters and `sent`
// buffer let assertions pin both the outbound IpcMessage shape and the
// idempotent start/shutdown contract — without spawning `agentdeckd`.
//
// Concurrency notes:
// * `client.roundTrip(_:)` blocks waiting on the router's NSCondition. Tests
//   drive the round-trip on `DispatchQueue.global()` and push the matching
//   reply (or a disconnect) from the test thread once `stub.sent` shows the
//   request landed.
// * `waitUntilSent(...)` polls `stub.sent` with a short bounded loop so a hang
//   surfaces as a test failure (Eng premise 9) rather than wedging CI.

/// Spin until the stub captures `count` sent frames or `timeoutSeconds`
/// elapses. Returning false signals the caller's round-trip never reached
/// `transport.send`, which is itself a failure.
private func waitUntilSent(
    _ stub: StubDaemonTransport,
    count: Int,
    timeoutSeconds: Double = 1.0
) -> Bool {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while stub.sent.count < count {
        if Date() > deadline { return false }
        Thread.sleep(forTimeInterval: 0.005)
    }
    return true
}

@Suite("DaemonClient request-response pairing")
struct DaemonClientRequestResponseTests {

    @Test("roundtrip resolves when matching response arrives")
    func roundtripResolvesWhenMatchingResponseArrives() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)

        let result = DispatchQueue.global().asyncResult {
            try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
        }

        #expect(waitUntilSent(stub, count: 1))
        let sentId = try #require(stub.sent.first?.id)
        stub.push(IpcMessage(kind: "pong", id: sentId, payload: nil))

        let reply = try result.get(timeoutSeconds: 1.0)
        #expect(reply.kind == "pong")
        #expect(reply.id == sentId)
    }

    @Test("roundtrip throws disconnected when disconnect fires before reply")
    func roundtripThrowsDisconnectedWhenDisconnectFiresBeforeReply() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)

        let result = DispatchQueue.global().asyncResult {
            try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
        }

        #expect(waitUntilSent(stub, count: 1))
        stub.triggerDisconnect()

        var thrown: Error?
        do {
            _ = try result.get(timeoutSeconds: 1.0)
        } catch {
            thrown = error
        }
        let error = try #require(thrown as? DaemonError)
        if case .disconnected = error {
            // expected
        } else {
            Issue.record("expected DaemonError.disconnected, got \(error)")
        }
    }

    @Test("request id allocator assigns unique ids across concurrent sends")
    func requestIdAllocatorAssignsUniqueIdsAcrossConcurrentSends() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        let parallel = 5

        // Launch N concurrent round-trips. Each blocks on its own id;
        // once all are parked we walk the captured `sent` ids and push
        // matching replies so every caller unblocks deterministically.
        let results = (0..<parallel).map { _ in
            DispatchQueue.global().asyncResult {
                try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
            }
        }

        #expect(waitUntilSent(stub, count: parallel))
        let ids = stub.sent.compactMap(\.id)
        #expect(ids.count == parallel)
        #expect(Set(ids).count == parallel)

        for id in ids {
            stub.push(IpcMessage(kind: "pong", id: id, payload: nil))
        }
        for result in results {
            _ = try result.get(timeoutSeconds: 1.0)
        }
    }
}

@Suite("DaemonClient streaming event dispatch")
struct DaemonClientStreamingTests {

    @Test("stream event for known session routes to session handler")
    func streamEventForKnownSessionRoutesToSessionHandler() async throws {
        // Reshape: `DaemonClient` does not expose a public stream-listener
        // registration API. The session-event stream is registered as a side
        // effect of `startTurn(sessionId:...)` or `startSession(...)`. Use the
        // legacy `startSession` overload (which installs a stream handler with
        // `expectedSessionId: "session_1"`) and push a matching `session/event`.
        // The handler dispatches onto the main queue, so we poll after.
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        try stub.start()

        let collected = LineCollector()
        await MainActor.run {
            client.startSession(cwd: "/tmp/project", prompt: "hi") { line in
                collected.append(line)
            }
        }

        #expect(waitUntilSent(stub, count: 1))
        stub.push(IpcMessage(
            kind: "session/event",
            sessionId: "session_1",
            payload: AnyCodable(["event": ["kind": "turnComplete"]])
        ))

        // Allow the DispatchQueue.main.async hop to drain.
        try await Task.sleep(for: .milliseconds(50))
        let lines = collected.snapshot()
        #expect(lines.count == 1)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: Data(try #require(lines.first).utf8))
        #expect(decoded.kind == "turnComplete")
    }

    @Test("stream event for unknown session is dropped without throwing")
    func streamEventForUnknownSessionIsDroppedWithoutThrowing() async throws {
        // Same reshape rationale as #4: register the legacy stream via
        // startSession (expectedSessionId = "session_1") then push an event
        // for a DIFFERENT sessionId. The handler must NOT see it and no
        // crash/throw can escape into the transport.
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        try stub.start()

        let collected = LineCollector()
        await MainActor.run {
            client.startSession(cwd: "/tmp/project", prompt: "hi") { line in
                collected.append(line)
            }
        }

        #expect(waitUntilSent(stub, count: 1))
        stub.push(IpcMessage(
            kind: "session/event",
            sessionId: "session_other",
            payload: AnyCodable(["event": ["kind": "turnComplete"]])
        ))

        try await Task.sleep(for: .milliseconds(50))
        #expect(collected.snapshot().isEmpty)
    }

    @Test("malformed line fans out to pending round trips")
    func malformedLineFansOutToPendingRoundTrips() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        let pending = 3

        let results = (0..<pending).map { _ in
            DispatchQueue.global().asyncResult {
                try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
            }
        }

        #expect(waitUntilSent(stub, count: pending))
        stub.pushMalformed("not a valid json line")

        for result in results {
            let reply = try result.get(timeoutSeconds: 1.0)
            #expect(reply.kind == "error")
            let payload = reply.payload?.value as? [String: Any]
            let message = payload?["message"] as? String
            #expect(message?.contains("malformed reply") == true)
        }
    }
}

@Suite("DaemonClient error paths")
struct DaemonClientErrorTests {

    @Test("roundtrip propagates transport send error")
    func roundtripPropagatesTransportSendError() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        stub.nextSendError = .writeFailed("simulated")

        var thrown: Error?
        do {
            _ = try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
        } catch {
            thrown = error
        }
        let error = try #require(thrown)
        let description = "\(error)".lowercased()
        #expect(description.contains("transport") || description.contains("write"))
    }

    @Test("start propagates transport start error")
    func startPropagatesTransportStartError() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        stub.nextStartError = .spawnFailed("simulated")

        // `client.roundTrip` lazily calls `start()` when the transport is
        // not yet started, so the spawn failure must surface from the very
        // first roundTrip attempt. (Direct `client.start()` is the same
        // path; using roundTrip exercises the lazy guard too.)
        var thrown: Error?
        do {
            _ = try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
        } catch {
            thrown = error
        }
        let error = try #require(thrown)
        let description = "\(error)".lowercased()
        #expect(description.contains("spawn"))
    }

    @Test("disconnect signal aborts blocked round trips with named error")
    func disconnectSignalAbortsBlockedRoundTripsWithNamedError() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        let pending = 3

        let results = (0..<pending).map { _ in
            DispatchQueue.global().asyncResult {
                try client.roundTrip(IpcMessage(kind: "ping", id: nil, payload: nil))
            }
        }

        #expect(waitUntilSent(stub, count: pending))
        stub.triggerDisconnect()

        for result in results {
            var thrown: Error?
            do {
                _ = try result.get(timeoutSeconds: 1.0)
            } catch {
                thrown = error
            }
            let error = try #require(thrown as? DaemonError)
            if case .disconnected = error {
                // expected
            } else {
                Issue.record("expected DaemonError.disconnected, got \(error)")
            }
        }
    }
}

@Suite("DaemonClient shutdown semantics")
struct DaemonClientShutdownTests {

    @Test("shutdown sends bye when transport is alive")
    func shutdownSendsByeWhenTransportIsAlive() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        try stub.start()

        // shutdown() does a round-trip on "shutdown" — the daemon would
        // normally reply, but the stub does not auto-reply, so we push the
        // reply from a background dispatch after observing the send.
        let result = DispatchQueue.global().asyncResult { () -> Void in
            client.shutdown()
        }

        #expect(waitUntilSent(stub, count: 1))
        let byeMsg = try #require(stub.sent.first)
        #expect(byeMsg.kind == "shutdown")
        if let id = byeMsg.id {
            stub.push(IpcMessage(kind: "shutdownAck", id: id, payload: nil))
        }
        try result.get(timeoutSeconds: 1.0)
        #expect(stub.shutdownCount == 1)
    }

    @Test("shutdown skips bye when transport is dead")
    func shutdownSkipsByeWhenTransportIsDead() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        try client.start()
        stub.setAlive(false)

        client.shutdown()

        let kinds = stub.sent.map(\.kind)
        #expect(!kinds.contains("shutdown"))
        // The transport teardown still ran even though the courtesy `bye`
        // was skipped — important for ensuring cleanup is unconditional.
        #expect(stub.shutdownCount == 1)
    }

    @Test("shutdown is idempotent")
    func shutdownIsIdempotent() async throws {
        let stub = StubDaemonTransport()
        let client = DaemonClient(profile: .stable, transport: stub)
        // Start, then mark dead so shutdown skips the round-trip path on
        // both calls (avoids hanging on a `bye` no one will reply to).
        try client.start()
        stub.setAlive(false)

        client.shutdown()
        client.shutdown()

        // The stub increments `shutdownCount` on every call — DaemonClient
        // does not debounce, so two shutdown() calls produce two transport
        // teardowns. No error escapes either call.
        #expect(stub.shutdownCount == 2)
    }
}

// MARK: - Concurrency test helpers

/// Thread-safe collector for `@MainActor` stream callbacks. Uses an `NSLock`
/// so a background `push` can race with the main-queue handler without
/// triggering Swift Concurrency strict-isolation diagnostics.
private final class LineCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        lines.append(line)
    }

    func snapshot() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return lines
    }
}

/// Wraps a throwing background-queue computation in a `DispatchSemaphore`
/// so the test thread can synchronously wait for it with a timeout. Mirrors
/// the pattern in `BlockingHistoryDetailClient` but for the "block on a
/// roundTrip then collect its result" shape.
private final class AsyncResult<T>: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private var value: Result<T, Error>?
    private let lock = NSLock()

    fileprivate func fulfill(_ result: Result<T, Error>) {
        lock.lock()
        value = result
        lock.unlock()
        semaphore.signal()
    }

    func get(timeoutSeconds: Double) throws -> T {
        guard semaphore.wait(timeout: .now() + timeoutSeconds) == .success else {
            throw AsyncResultTimeout()
        }
        lock.lock(); defer { lock.unlock() }
        switch value! {
        case .success(let v): return v
        case .failure(let e): throw e
        }
    }
}

private struct AsyncResultTimeout: Error, CustomStringConvertible {
    var description: String { "AsyncResult timed out" }
}

private extension DispatchQueue {
    func asyncResult<T>(_ work: @escaping @Sendable () throws -> T) -> AsyncResult<T> {
        let result = AsyncResult<T>()
        self.async {
            do {
                result.fulfill(.success(try work()))
            } catch {
                result.fulfill(.failure(error))
            }
        }
        return result
    }
}
