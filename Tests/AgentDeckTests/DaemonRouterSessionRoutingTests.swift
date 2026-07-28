import XCTest
import AgentDeckCore
@testable import AgentDeck

private final class ControllableHistoryTransport: DaemonTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var incomingHandler: ((String) -> Void)?
    private var started = false
    private var sentLineCount = 0
    private var historyRequestIds: [String] = []
    var onSend: ((Int) -> Void)?

    var isStarted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return started
    }

    var isAlive: Bool { isStarted }

    var sendCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return sentLineCount
    }

    func start() throws {
        lock.lock()
        started = true
        lock.unlock()
    }

    func send(_ line: String) throws {
        let command = try JSONDecoder().decode(ClientCommand.self, from: Data(line.utf8))
        guard case .history(let request) = command,
              let requestId = request.requestId else {
            throw DaemonError.malformedReply("history test transport received an uncorrelated request")
        }
        lock.lock()
        sentLineCount += 1
        historyRequestIds.append(requestId)
        let count = sentLineCount
        let callback = onSend
        lock.unlock()
        callback?(count)
    }

    func setIncomingHandler(_ handler: @escaping (String) -> Void) {
        lock.lock()
        incomingHandler = handler
        lock.unlock()
    }

    func setDisconnectHandler(_ handler: @escaping () -> Void) {}

    func shutdown() {
        lock.lock()
        started = false
        lock.unlock()
    }

    func historyRequestId(atSendNumber number: Int) -> String? {
        lock.lock()
        defer { lock.unlock() }
        let index = number - 1
        guard historyRequestIds.indices.contains(index) else { return nil }
        return historyRequestIds[index]
    }

    func pushHistoryListReply(requestId: String) {
        lock.lock()
        let handler = incomingHandler
        lock.unlock()
        handler?(#"{"reply":"history","requestId":"\#(requestId)","response":{"kind":"list","value":[]}}"#)
    }

    func pushHistoryErrorReply(requestId: String) {
        lock.lock()
        let handler = incomingHandler
        lock.unlock()
        handler?(#"{"reply":"history","requestId":"\#(requestId)","error":{"code":"history-all-sources-failed","message":"all registered history sources failed","diagnosticRef":null}}"#)
    }
}

final class DaemonRouterSessionRoutingTests: XCTestCase {
    func testPendingNewSessionHandlerAdoptsDaemonSessionId() {
        let router = DaemonRouter()
        var received: [String] = []
        router.registerPendingNewSessionHandler { event in
            received.append(event.sessionId ?? "nil")
        }

        router.push(rawLine: #"{"type":"sessionStarted","sessionId":"daemon-session","threadId":null,"agentKind":"codex"}"#)
        router.push(rawLine: #"{"type":"turnComplete","sessionId":"daemon-session","threadId":"thread-1","agentKind":"codex","summary":{"totalInputTokens":1,"totalOutputTokens":1,"elapsedMs":10}}"#)

        XCTAssertEqual(received, ["daemon-session", "daemon-session"])
    }

    func testPendingNewSessionHandlerReceivesPreflightErrorWithoutSessionId() {
        let router = DaemonRouter()
        var receivedCodes: [String] = []
        router.registerPendingNewSessionHandler { event in
            if case .error(_, let error) = event {
                receivedCodes.append(error.code)
            }
        }

        router.push(rawLine: #"{"type":"error","sessionId":null,"error":{"code":"cc-not-authenticated","message":"login required","diagnosticRef":null}}"#)

        XCTAssertEqual(receivedCodes, ["cc-not-authenticated"])
    }

    func testHistoryTimeoutIncludesDaemonDeadlineTransportGrace() {
        XCTAssertEqual(DaemonClient.historyTimeoutSeconds, 35)
    }

    func testHistoryRoundTripsStaySingleFlightUntilReplyArrives() {
        let transport = ControllableHistoryTransport()
        let client = DaemonClient(transport: transport)
        let firstSent = expectation(description: "first history request sent")
        let secondSent = expectation(description: "second history request sent")
        let bothFinished = expectation(description: "both history requests finished")
        bothFinished.expectedFulfillmentCount = 2
        transport.onSend = { count in
            if count == 1 { firstSent.fulfill() }
            if count == 2 { secondSent.fulfill() }
        }

        for _ in 0..<2 {
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    _ = try client.history(.list(agentKind: nil, cwdFilter: nil, limit: nil))
                } catch {
                    XCTFail("history round-trip should succeed: \(error)")
                }
                bothFinished.fulfill()
            }
        }

        wait(for: [firstSent], timeout: 1)
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(transport.sendCount, 1, "第二个 history 请求必须等待第一个 round-trip 完成")

        let firstRequestId = try! XCTUnwrap(transport.historyRequestId(atSendNumber: 1))
        transport.pushHistoryListReply(requestId: firstRequestId)
        wait(for: [secondSent], timeout: 1)
        XCTAssertEqual(transport.sendCount, 2)

        let secondRequestId = try! XCTUnwrap(transport.historyRequestId(atSendNumber: 2))
        XCTAssertNotEqual(firstRequestId, secondRequestId)
        transport.pushHistoryListReply(requestId: secondRequestId)
        wait(for: [bothFinished], timeout: 1)
    }

    func testHistoryDiscardsStaleReplyBeforeMatchingRequestId() throws {
        let transport = ControllableHistoryTransport()
        let client = DaemonClient(transport: transport)
        transport.onSend = { count in
            guard let currentRequestId = transport.historyRequestId(atSendNumber: count) else { return }
            transport.pushHistoryErrorReply(requestId: "stale-history-request")
            transport.pushHistoryListReply(requestId: currentRequestId)
        }

        let response = try client.history(
            .list(agentKind: nil, cwdFilter: nil, limit: nil, requestId: "caller-supplied-id")
        )

        guard case .list(let items) = response else {
            return XCTFail("matching history reply should win over a stale reply")
        }
        XCTAssertTrue(items.isEmpty)
        let generatedRequestId = try XCTUnwrap(transport.historyRequestId(atSendNumber: 1))
        XCTAssertNotEqual(generatedRequestId, "caller-supplied-id")
        XCTAssertNotNil(UUID(uuidString: generatedRequestId))
    }

    func testHistorySurfacesDaemonProtocolErrorReply() {
        let transport = ControllableHistoryTransport()
        let client = DaemonClient(transport: transport)
        transport.onSend = { count in
            guard let requestId = transport.historyRequestId(atSendNumber: count) else { return }
            transport.pushHistoryErrorReply(requestId: requestId)
        }

        XCTAssertThrowsError(
            try client.history(.list(agentKind: nil, cwdFilter: nil, limit: nil))
        ) { error in
            guard case DaemonError.remoteProtocol(let code, let message, let diagnosticRef) = error else {
                return XCTFail("expected daemon protocol error, got \(error)")
            }
            XCTAssertEqual(code, "history-all-sources-failed")
            XCTAssertEqual(message, "all registered history sources failed")
            XCTAssertNil(diagnosticRef)
        }
    }
}
