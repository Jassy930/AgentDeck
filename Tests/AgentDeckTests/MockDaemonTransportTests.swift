import XCTest
import AgentDeckCore
@testable import AgentDeck

final class MockDaemonTransportTests: XCTestCase {
    private func lines(from transport: MockDaemonTransport, after send: ClientCommand, count: Int, timeout: TimeInterval = 2) -> [String] {
        var received: [String] = []
        let exp = expectation(description: "frames")
        transport.setIncomingHandler { line in
            received.append(line)
            if received.count >= count { exp.fulfill() }
        }
        try? transport.start()
        let data = try! JSONEncoder().encode(send)
        try? transport.send(String(data: data, encoding: .utf8)!)
        wait(for: [exp], timeout: timeout)
        return received
    }

    func testHistoryListReplyDecodes() {
        let t = MockDaemonTransport()
        let frames = lines(
            from: t,
            after: .history(.list(
                agentKind: nil,
                cwdFilter: nil,
                limit: nil,
                requestId: "mock-history-request"
            )),
            count: 1
        )
        XCTAssertEqual(frames.count, 1)
        let obj = try! JSONSerialization.jsonObject(with: Data(frames[0].utf8)) as! [String: Any]
        XCTAssertEqual(obj["reply"] as? String, "history")
        XCTAssertEqual(obj["requestId"] as? String, "mock-history-request")
        let responseData = try! JSONSerialization.data(withJSONObject: obj["response"]!)
        let resp = try! JSONDecoder().decode(HistoryResponse.self, from: responseData)
        guard case .list(let items) = resp else { return XCTFail("应为 list") }
        XCTAssertFalse(items.isEmpty)
    }

    func testSessionStartEmitsStartedThenComplete() {
        let t = MockDaemonTransport()
        let start = SessionStart(agentKind: .codex, cwd: MockDaemonScript.previewCwd, prompt: "hi",
                                 vendorOptions: .codex(CodexSessionOptions(approvalPolicy: .onRequest, sandbox: .workspaceWrite, persistApproval: false, reasoningEffort: .medium)))
        // 帧数由脚本推导，避免与脚本实现硬耦合
        let expectedCount = MockDaemonScript.liveTurnEvents(sessionId: "mock-session-1", threadId: "mock-live-thread").count
        let frames = lines(from: t, after: .sessionStart(start), count: expectedCount, timeout: 4)
        let events = frames.compactMap { try? DaemonClient.decodeServerEvent($0) }
        guard case .sessionStarted = events.first else { return XCTFail("首帧 sessionStarted") }
        guard case .turnComplete = events.last else { return XCTFail("末帧 turnComplete") }
    }

    func testUnknownLineEmitsError() {
        let t = MockDaemonTransport()
        var received: [String] = []
        let exp = expectation(description: "err")
        t.setIncomingHandler { line in received.append(line); exp.fulfill() }
        try? t.start()
        try? t.send("{\"garbage\":true}")
        wait(for: [exp], timeout: 2)
        let ev = try? DaemonClient.decodeServerEvent(received[0])
        if case .error = ev {} else { XCTFail("未知行应回 ServerEvent.error") }
    }
}
