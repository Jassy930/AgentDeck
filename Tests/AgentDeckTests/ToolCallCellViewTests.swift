import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

@MainActor
final class ToolCallCellViewTests: XCTestCase {

    private final class FixedDisclosureStore: ConversationDisclosureStateStore {
        let expanded: Bool

        init(expanded: Bool) {
            self.expanded = expanded
        }

        func isItemExpanded(_ itemId: String) -> Bool { expanded }
        func setItem(_ itemId: String, expanded: Bool) {}
    }

    func testCollapsedRowShowsToolTargetStatusAndDisclosureOnOneLine() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(id: "read-1", lifecycle: "completed", kind: "toolCall")
        item.tool = "Read"
        item.arguments = #"{"file_path":"/repo/Sources/First.swift"}"#
        item.statusName = "completed"
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-1",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let cell = ToolCallCellView()
        cell.configure(row: row, width: 620, model: model)

        let visibleLabels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
        XCTAssertTrue(visibleLabels.contains("Read"))
        XCTAssertTrue(visibleLabels.contains("path: /repo/Sources/First.swift"))
        XCTAssertTrue(visibleLabels.contains("已完成"))
        XCTAssertFalse(visibleLabels.contains("Tool call"), "不应再显示会被压成 T 的泛化标题")
        XCTAssertFalse(visibleLabels.contains { $0.hasPrefix("arguments\n") })

        let disclosure = try? XCTUnwrap(
            cell.allDescendants(ofType: NSButton.self).first
        )
        XCTAssertEqual(disclosure?.state, .off)
        XCTAssertEqual(disclosure?.isHidden, false)
    }

    func testExpandedRowKeepsCompactStatusAndShowsFullPayload() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(id: "grep-1", lifecycle: "completed", kind: "toolCall")
        item.tool = "Grep"
        item.arguments = #"{"pattern":"ToolCallCellView","path":"/repo/Sources"}"#
        item.result = #"{"matches":3}"#
        item.errorText = "search failed"
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-2",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let store = FixedDisclosureStore(expanded: true)
        let cell = ToolCallCellView()
        cell.disclosureStore = store
        cell.configure(row: row, width: 620, model: model)

        let visibleLabels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
        XCTAssertTrue(visibleLabels.contains("失败"), "展开后状态仍应留在摘要行")
        XCTAssertTrue(
            visibleLabels.contains { $0.contains("arguments\n") && $0.contains("result\n") },
            "展开后应保留完整 arguments/result payload"
        )
        XCTAssertEqual(
            cell.allDescendants(ofType: NSButton.self).first?.state,
            .on
        )
    }

    func testStatusUsesReadableSemanticColor() throws {
        let cases: [(status: String, label: String, color: NSColor)] = [
            ("running", "进行中", DesignTokens.running),
            ("completed", "已完成", DesignTokens.text3),
            ("failed", "失败", DesignTokens.danger),
            ("queued", "等待中", DesignTokens.text2),
        ]

        for testCase in cases {
            let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
            var item = UIItem(
                id: "status-\(testCase.status)",
                lifecycle: "completed",
                kind: "toolCall"
            )
            item.tool = "Read"
            item.statusName = testCase.status
            let row = ConversationDisplayRow(
                role: .assistantItem,
                turnId: "turn-status",
                item: item,
                firstInTurn: true,
                lastInTurn: true
            )
            let cell = ToolCallCellView()
            cell.configure(row: row, width: 620, model: model)

            let label = try XCTUnwrap(
                cell.allDescendants(ofType: NSTextField.self)
                    .first { $0.stringValue == testCase.label }
            )
            XCTAssertTrue(
                label.textColor?.isEqual(testCase.color) == true,
                "\(testCase.status) 应使用对应语义色"
            )
        }
    }

    func testNodeReplRowShowsServerActionTitleAndTrueMetadata() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(id: "computer-use-1", lifecycle: "completed", kind: "toolCall")
        item.server = "node_repl"
        item.tool = "js"
        item.arguments = #"{"code":"...","title":"确认 AgentDeck 窗口","timeout_ms":30000}"#
        item.statusName = "failed"
        item.durationMs = 136
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-computer-use",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let cell = ToolCallCellView()
        cell.configure(row: row, width: 720, model: model)

        let visibleLabels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
        XCTAssertTrue(visibleLabels.contains("node_repl/js"))
        XCTAssertTrue(visibleLabels.contains("确认 AgentDeck 窗口"))
        XCTAssertTrue(visibleLabels.contains("失败 · 136ms"))
    }

    func testCollaborationActivityUsesCompactNameAndEventDescription() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        var item = UIItem(
            id: "subagent-activity",
            lifecycle: "completed",
            kind: "toolCall"
        )
        item.tool = "Schema mapping check"
        item.activityKind = "collaboration"
        item.activityEvent = "interacted"
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-collaboration",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let cell = ToolCallCellView()
        cell.configure(row: row, width: 720, model: model)

        let visibleLabels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
        XCTAssertTrue(visibleLabels.contains("Schema mapping check"))
        XCTAssertTrue(visibleLabels.contains("已更新"))
        XCTAssertFalse(visibleLabels.contains("已完成"))
    }
}
