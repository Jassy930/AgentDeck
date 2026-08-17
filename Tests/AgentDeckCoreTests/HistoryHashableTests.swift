import AgentDeckCore
import XCTest

final class HistoryHashableTests: XCTestCase {
    private func summary(_ id: String, cwd: String) -> HistoryThreadSummary {
        HistoryThreadSummary(
            id: id, name: nil, preview: "", cwd: cwd,
            createdAt: 0, updatedAt: 0, status: "ready",
            modelProvider: "openai", source: "codex", agentKind: .codex
        )
    }

    func testThreadSummaryHashConsistentWithEquality() {
        let first = summary("t1", cwd: "/p")
        let second = summary("t1", cwd: "/p")

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.hashValue, second.hashValue)
        XCTAssertEqual(Set([first, second]).count, 1)
    }

    func testProjectGroupHashInSet() {
        let first = HistoryProjectGroup(cwd: "/p", threads: [summary("t1", cwd: "/p")])
        let second = HistoryProjectGroup(cwd: "/p", threads: [summary("t1", cwd: "/p")])
        let different = HistoryProjectGroup(cwd: "/q", threads: [])

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.hashValue, second.hashValue)
        XCTAssertEqual(Set([first, second, different]).count, 2)
    }
}
