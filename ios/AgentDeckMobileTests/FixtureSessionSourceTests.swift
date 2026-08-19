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
        func isTurnFinished(_ e: SessionStreamElement) -> Bool {
            if case .turnFinished = e.event { return true }
            return false
        }
        let first = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnFinished)
        XCTAssertEqual(first.count, 11)
        guard case let .sessionStarted(_, threadId, kind) = first[0].event else {
            return XCTFail("expected SessionStarted first")
        }
        XCTAssertEqual(threadId, "t1")
        XCTAssertEqual(kind, .codex)
        guard case .sessionCapabilities = first[1].event else {
            return XCTFail("expected SessionCapabilities second")
        }
        guard case let .turnStarted(_, turnThreadId, turnKind, turnId) = first[2].event else {
            return XCTFail("expected TurnStarted third")
        }
        XCTAssertEqual(turnThreadId, "t1")
        XCTAssertEqual(turnKind, .codex)
        XCTAssertEqual(turnId, "turn-codex-01")
        let assistantSnapshots = first.compactMap { element -> (AgentItemState, String)? in
            guard case let .agentItem(_, _, _, _, itemId, state, item) = element.event,
                  itemId == "i4",
                  case let .assistantMessage(text, _) = item
            else { return nil }
            return (state, text)
        }
        XCTAssertEqual(assistantSnapshots.map(\.0), [.streaming, .streaming, .completed])
        XCTAssertTrue(zip(assistantSnapshots, assistantSnapshots.dropFirst()).allSatisfy {
            $1.1.hasPrefix($0.1)
        })
        // 二次订阅（模拟切屏返回）应立刻拿到完整 transcript。
        let second = await collect(source.events(sessionID: "sess-codex-01"), until: isTurnFinished)
        XCTAssertEqual(second.count, 11)
    }

    func testApprovalGatePausesUntilResolved() async {
        let source = makeSource()
        var received: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            received.append(element)
            if case .actionRequest = element.event { break }
        }
        // SessionStarted + SessionCapabilities + TurnStarted + userMessage + ActionRequest.
        XCTAssertEqual(received.count, 5)
        await source.resolveApproval(sessionID: "sess-approval-01", requestID: "req-1", approve: true)
        var rest: [SessionStreamElement] = []
        for await element in source.events(sessionID: "sess-approval-01") {
            rest.append(element)
            if case .turnFinished = element.event { break }
        }
        XCTAssertEqual(rest.count, 8) // transcript 5 + shell + assistant + TurnFinished
    }

    func testSendPromptEchoesUserMessageAndReplies() async {
        let source = makeSource()
        func isTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case .turnComplete = e.event { return true }
            return false
        }
        // CC 仍走 legacy TurnComplete；用 prompt fixture 的 elapsedMs 区分
        // 同一 thread 上旧 terminal 与本次 prompt terminal。
        func isPromptTurnComplete(_ e: SessionStreamElement) -> Bool {
            if case let .turnComplete(_, threadId, kind, summary) = e.event {
                return threadId == "t2"
                    && kind == .claudeCode
                    && summary.elapsedMs == 800
            }
            return false
        }
        let initial = await collect(source.events(sessionID: "sess-cc-01"), until: isTurnComplete)
        XCTAssertEqual(initial.count, 6)
        await source.sendPrompt(sessionID: "sess-cc-01", text: "继续，补第三个边界")
        let after = await collect(source.events(sessionID: "sess-cc-01"), until: isPromptTurnComplete)
        let texts: [String] = after.compactMap { element in
            if case .agentItem(_, _, _, _, _, _, let item) = element.event,
               case .userMessage(let text, _) = item { return text }
            return nil
        }
        XCTAssertTrue(texts.contains("继续，补第三个边界"))
        let promptItems = after.compactMap { element -> (String, String, TurnId)? in
            guard case let .agentItem(_, threadId, _, turnId, itemId, _, _) = element.event,
                  itemId.hasPrefix("prompt-")
            else { return nil }
            return (itemId, threadId, turnId)
        }
        XCTAssertEqual(promptItems.map(\.0), ["prompt-user-1", "prompt-reply-1"])
        XCTAssertTrue(promptItems.allSatisfy { $0.1 == "t2" && $0.2 == "turn-prompt-1" })
        // 状态保持语义：切屏返回（全新订阅）仍能看到完整历史 + prompt 回声。
        // 原 transcript 6 + userMessage + assistantMessage + promptTurnComplete。
        XCTAssertEqual(after.count, 9)
    }

    func testSendPromptUsesTurnFinishedForCodex() async {
        let source = makeSource()
        func isInitialTurnFinished(_ e: SessionStreamElement) -> Bool {
            if case .turnFinished = e.event { return true }
            return false
        }
        func isPromptTurnFinished(_ e: SessionStreamElement) -> Bool {
            guard case let .turnFinished(
                _, threadId, kind, turnId, outcome, nextState, _, _
            ) = e.event else { return false }
            return threadId == "t1"
                && kind == .codex
                && turnId.hasPrefix("turn-prompt")
                && outcome == .succeeded
                && nextState == .ready
        }

        _ = await collect(source.events(sessionID: "sess-codex-01"), until: isInitialTurnFinished)
        await source.sendPrompt(sessionID: "sess-codex-01", text: "继续验证 Codex terminal")
        let after = await collect(source.events(sessionID: "sess-codex-01"), until: isPromptTurnFinished)

        XCTAssertTrue(after.contains(where: isPromptTurnFinished))
        let promptSequence = after.compactMap { element -> String? in
            switch element.event {
            case let .turnStarted(_, threadId, kind, turnId)
                where threadId == "t1" && kind == .codex && turnId == "turn-prompt-1":
                return "turnStarted"
            case let .agentItem(_, threadId, kind, turnId, itemId, _, _)
                where threadId == "t1" && kind == .codex
                    && turnId == "turn-prompt-1" && itemId.hasPrefix("prompt-"):
                return "agentItem"
            case let .turnFinished(_, threadId, kind, turnId, _, _, _, _)
                where threadId == "t1" && kind == .codex && turnId == "turn-prompt-1":
                return "turnFinished"
            default:
                return nil
            }
        }
        XCTAssertEqual(promptSequence, ["turnStarted", "agentItem", "agentItem", "turnFinished"])
    }
}
