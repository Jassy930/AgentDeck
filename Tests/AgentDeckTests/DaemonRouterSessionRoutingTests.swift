import XCTest
@testable import AgentDeck

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
}
