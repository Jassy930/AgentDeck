import XCTest
import AgentDeckMobileCore
@testable import AgentDeckMobile

@MainActor
final class FixtureSessionSourceTests: XCTestCase {
    private var testBundle: Bundle { Bundle(for: MachineListViewController.self) }

    private func makeSource() -> FixtureSessionSource {
        FixtureSessionSource(bundle: testBundle, tickScale: 0)
    }

    private func collect<T>(_ stream: AsyncStream<T>, until stop: @escaping (T) -> Bool) async -> [T] {
        var out: [T] = []
        for await value in stream {
            out.append(value)
            if stop(value) { break }
        }
        return out
    }

    func testMachinesSnapshot() async {
        let source = makeSource()
        var it = source.machines().makeAsyncIterator()
        let machines = await it.next() ?? []
        XCTAssertEqual(machines.map(\.id).sorted(), ["mac-studio", "macbook-air"])
        let studio = machines.first { $0.id == "mac-studio" }
        XCTAssertEqual(studio?.activeSessionCount, 2)
        XCTAssertEqual(studio?.pendingApprovalCount, 1)
    }

    func testReplayDeliversAllEventsAndKeepsTranscript() async {
        let source = makeSource()
        func isTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete = e.event { return true }
            return false
        }
        let first = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnComplete)
        XCTAssertEqual(first.count, 9)
        // 二次订阅（模拟切屏返回）应立刻拿到完整 transcript。
        let second = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnComplete)
        XCTAssertEqual(second.count, 9)
    }

    func testApprovalGatePausesUntilResolved() async {
        let source = makeSource()
        var received: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            received.append(element)
            if case .actionRequest = element.event { break }
        }
        XCTAssertEqual(received.count, 3) // sessionStarted + userMessage + actionRequest
        await source.resolveApproval(sessionID: "sess-approval-01", requestID: "req-1", approve: true)
        var rest: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            rest.append(element)
            if case .turnComplete = element.event { break }
        }
        XCTAssertEqual(rest.count, 6) // transcript 3 + shell + assistant + turnComplete
    }

    func testSendPromptEchoesUserMessageAndReplies() async {
        let source = makeSource()
        func isTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete = e.event { return true }
            return false
        }
        // prompt 产生的 turn 的 threadId 以 "t-prompt" 开头；第二次 collect
        // 用它做停止条件，越过旧 turnComplete，验证全量 transcript 保持。
        func isPromptTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete(_, let threadId, _, _) = e.event { return threadId.hasPrefix("t-prompt") }
            return false
        }
        _ = await collect(source.events(sessionID: "sess-cc-01"), until: isTurnComplete)
        await source.sendPrompt(sessionID: "sess-cc-01", text: "继续，补第三个边界")
        let after = await collect(source.events(sessionID: "sess-cc-01"), until: isPromptTurnComplete)
        let texts: [String] = after.compactMap { element in
            if case .agentItem(_, _, _, let item) = element.event,
               case .userMessage(let text, _) = item { return text }
            return nil
        }
        XCTAssertTrue(texts.contains("继续，补第三个边界"))
        // 状态保持语义：切屏返回（全新订阅）仍能看到完整历史 + prompt 回声。
        // 原 transcript 4 + userMessage + assistantMessage + promptTurnComplete。
        XCTAssertGreaterThanOrEqual(after.count, 7)
    }
}
