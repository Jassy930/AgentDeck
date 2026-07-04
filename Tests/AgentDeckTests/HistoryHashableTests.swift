import XCTest
import AgentDeckCore

/// 回归：`HistoryThreadSummary` / `HistoryProjectGroup` 作为 `NSOutlineView` item
/// 被 AppKit 哈希，必须是 `Hashable`（仅 `Equatable` 会退化为恒定哈希 → O(n) 查找）。
/// 这里验证一致性：相等即哈希相等，且能正确参与 `Set` 去重。
final class HistoryHashableTests: XCTestCase {
    private func summary(_ id: String, cwd: String) -> HistoryThreadSummary {
        HistoryThreadSummary(
            id: id, name: nil, preview: "", cwd: cwd,
            createdAt: 0, updatedAt: 0, status: "ready",
            modelProvider: "openai", source: "codex", agentKind: .codex
        )
    }

    func testThreadSummaryHashConsistentWithEquality() {
        let a = summary("t1", cwd: "/p")
        let b = summary("t1", cwd: "/p")
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.hashValue, b.hashValue)
        XCTAssertEqual(Set([a, b]).count, 1, "相等值应在 Set 中去重为一")
    }

    func testProjectGroupHashInSet() {
        let g1 = HistoryProjectGroup(cwd: "/p", threads: [summary("t1", cwd: "/p")])
        let g2 = HistoryProjectGroup(cwd: "/p", threads: [summary("t1", cwd: "/p")])
        let g3 = HistoryProjectGroup(cwd: "/q", threads: [])
        XCTAssertEqual(g1, g2)
        XCTAssertEqual(g1.hashValue, g2.hashValue)
        XCTAssertEqual(Set([g1, g2, g3]).count, 2, "两个相等组 + 一个不同组 → 去重为二")
    }
}
