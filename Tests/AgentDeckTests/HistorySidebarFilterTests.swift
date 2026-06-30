import XCTest
@testable import AgentDeck

final class HistorySidebarFilterTests: XCTestCase {
    func testFilterAllShowsBoth() {
        let items: [HistoryListItem] = [
            HistoryListItem.stub(kind: .codex, title: "a"),
            HistoryListItem.stub(kind: .claudeCode, title: "b"),
        ]
        XCTAssertEqual(HistoryFilter.apply(items, filter: .all).count, 2)
    }
    func testFilterCodexOnly() {
        let items: [HistoryListItem] = [
            HistoryListItem.stub(kind: .codex, title: "a"),
            HistoryListItem.stub(kind: .claudeCode, title: "b"),
        ]
        XCTAssertEqual(HistoryFilter.apply(items, filter: .codex).count, 1)
    }
    func testFilterClaudeCodeOnly() {
        let items: [HistoryListItem] = [
            HistoryListItem.stub(kind: .codex, title: "a"),
            HistoryListItem.stub(kind: .claudeCode, title: "b"),
        ]
        XCTAssertEqual(HistoryFilter.apply(items, filter: .claudeCode).count, 1)
    }
}

extension HistoryListItem {
    static func stub(kind: AgentKind, title: String) -> HistoryListItem {
        HistoryListItem(threadId: "id-\(title)", agentKind: kind, title: title,
                        cwd: "/tmp", lastActiveMs: 0, archived: false)
    }
}
