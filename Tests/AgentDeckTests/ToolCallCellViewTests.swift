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
        XCTAssertTrue(visibleLabels.contains("completed"))
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
        XCTAssertTrue(visibleLabels.contains("failed"), "展开后状态仍应留在摘要行")
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
        let cases: [(status: String, color: NSColor)] = [
            ("running", DesignTokens.running),
            ("completed", DesignTokens.success),
            ("failed", DesignTokens.danger),
            ("queued", DesignTokens.text2),
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
                    .first { $0.stringValue == testCase.status }
            )
            XCTAssertTrue(
                label.textColor?.isEqual(testCase.color) == true,
                "\(testCase.status) 应使用对应语义色"
            )
        }
    }
}
