import AppKit
import AgentDeckCore
import XCTest
@testable import AgentDeck

@MainActor
final class ToolActivityGroupCellViewTests: XCTestCase {
    private final class FixedDisclosureStore: ConversationDisclosureStateStore {
        let expanded: Bool

        init(expanded: Bool) {
            self.expanded = expanded
        }

        func isItemExpanded(_ itemId: String) -> Bool { expanded }
        func setItem(_ itemId: String, expanded: Bool) {}
    }

    func testCollapsedGroupShowsConcreteWorkCountFailureAndDisclosure() throws {
        var read = UIItem(id: "read", lifecycle: "completed", kind: "toolCall")
        read.tool = "Read"
        read.statusName = "completed"
        var shell = UIItem(id: "shell", lifecycle: "completed", kind: "shell")
        shell.command = "swift test"
        shell.statusName = "failed"
        shell.exitCode = 1
        let turn = ConversationTurn(
            id: "turn-cell",
            user: nil,
            assistantItems: [read, shell]
        )
        let row = try XCTUnwrap(ConversationDisplayRowBuilder.rows(
            from: [turn], toolGrouping: .consecutiveActivity
        ).first)

        let cell = ToolActivityGroupCellView()
        cell.configure(
            row: row,
            width: 620,
            model: SessionModel(turnStarter: NoopRuntimeTurnStarter())
        )

        let labels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
        XCTAssertTrue(labels.map(\.stringValue).contains("读取 1 个文件并运行 1 个命令"))
        let status = try XCTUnwrap(labels.first { $0.stringValue == "2 项 · 1 项失败" })
        XCTAssertTrue(status.textColor?.isEqual(DesignTokens.danger) == true)

        let disclosure = try XCTUnwrap(cell.allDescendants(ofType: NSButton.self).first)
        XCTAssertEqual(disclosure.state, .off)
        XCTAssertEqual(disclosure.accessibilityLabel(), "展开工具活动详情")
        XCTAssertTrue(cell.accessibilityLabel()?.contains("已折叠") == true)
    }

    func testExpandedStoreRestoresDisclosureState() throws {
        let row = ConversationDisplayRowTestSupport.toolActivityGroupRow()
        let cell = ToolActivityGroupCellView()
        let store = FixedDisclosureStore(expanded: true)
        cell.disclosureStore = store
        cell.configure(
            row: row,
            width: 620,
            model: SessionModel(turnStarter: NoopRuntimeTurnStarter())
        )

        let disclosure = try XCTUnwrap(cell.allDescendants(ofType: NSButton.self).first)
        XCTAssertEqual(disclosure.state, .on)
        XCTAssertEqual(disclosure.accessibilityLabel(), "收起工具活动详情")
        XCTAssertTrue(cell.accessibilityLabel()?.contains("已展开") == true)
    }
}
