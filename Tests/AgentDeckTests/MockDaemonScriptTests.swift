import XCTest
import AgentDeckCore
@testable import AgentDeck

final class MockDaemonScriptTests: XCTestCase {
    func testHistoryListContainsPrimaryThread() {
        let list = MockDaemonScript.historyList()
        XCTAssertFalse(list.isEmpty)
        XCTAssertTrue(list.contains { $0.threadId == MockDaemonScript.primaryThreadId })
        XCTAssertTrue(list.contains { ($0.title ?? "").contains("把登录模块拆分为独立 service") })
    }

    func testReadResponseHasShellAndDiffItems() {
        let resp = MockDaemonScript.readResponse(threadId: MockDaemonScript.primaryThreadId)
        let items = resp.turns.flatMap { $0.items }
        XCTAssertTrue(items.contains { if case .shell = $0 { return true } else { return false } })
        XCTAssertTrue(items.contains { if case .diff = $0 { return true } else { return false } })
    }

    func testLiveTurnStartsAndCompletes() {
        let events = MockDaemonScript.liveTurnEvents(sessionId: "s1", threadId: "t1")
        guard case .sessionStarted = events.first else { return XCTFail("首帧应为 sessionStarted") }
        guard case .turnComplete = events.last else { return XCTFail("末帧应为 turnComplete") }
    }

    func testEnvironmentInfoMatchesDesign() {
        XCTAssertEqual(MockDaemonScript.environmentInfo.changesSummary, "+128 -34")
        XCTAssertEqual(MockDaemonScript.environmentInfo.fileCount, 3)
        XCTAssertEqual(MockDaemonScript.environmentInfo.branch, "main")
    }
}
