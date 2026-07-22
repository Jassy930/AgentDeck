import AppKit
import AgentDeckCore
import XCTest

@testable import AgentDeck

@MainActor
final class ReasoningCellViewTests: XCTestCase {
    private final class RecordingDisclosureStore: ConversationDisclosureStateStore {
        var expandedItemIds: Set<String> = []
        var collapsedItemIds: Set<String> = []

        func isItemExpanded(_ itemId: String) -> Bool {
            expandedItemIds.contains(itemId)
        }

        func isItemCollapsed(_ itemId: String) -> Bool {
            collapsedItemIds.contains(itemId)
        }

        func setItem(_ itemId: String, expanded: Bool) {
            if expanded {
                expandedItemIds.insert(itemId)
                collapsedItemIds.remove(itemId)
            } else {
                expandedItemIds.remove(itemId)
                collapsedItemIds.insert(itemId)
            }
        }
    }

    func testCollapsedHeaderUsesAnUncompressedStandaloneTitle() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let item = UIItem(
            id: "reasoning-1",
            lifecycle: "completed",
            kind: "reasoning",
            text: "Planning app launch"
        )
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-reasoning",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )

        let cell = ReasoningCellView()
        cell.configure(row: row, width: 620, model: model)

        let visibleLabels = cell.allDescendants(ofType: NSTextField.self)
            .filter { !$0.isHidden }
            .map(\.stringValue)
        XCTAssertTrue(visibleLabels.contains("思考过程"))
        XCTAssertFalse(visibleLabels.contains("R"))
        XCTAssertEqual(
            cell.allDescendants(ofType: NSButton.self).first?.accessibilityLabel(),
            "思考过程"
        )
    }

    func testReasoningExpansionPersistsThroughDisclosureStore() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let item = UIItem(
            id: "reasoning-persisted",
            lifecycle: "completed",
            kind: "reasoning",
            text: "Planning app launch"
        )
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-reasoning",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        let store = RecordingDisclosureStore()
        let cell = ReasoningCellView()
        cell.disclosureStore = store
        cell.configure(row: row, width: 620, model: model)
        let button = try XCTUnwrap(cell.allDescendants(ofType: NSButton.self).first)

        button.state = .on
        let action = try XCTUnwrap(button.action)
        let target = try XCTUnwrap(button.target as? NSObject)
        _ = target.perform(action, with: button)

        XCTAssertTrue(store.expandedItemIds.contains(item.id))

        let reconfigured = ReasoningCellView()
        reconfigured.disclosureStore = store
        reconfigured.configure(row: row, width: 620, model: model)
        XCTAssertEqual(
            reconfigured.allDescendants(ofType: NSButton.self).first?.state,
            .on
        )
    }

    func testExplicitCollapseOverridesRunningAutoExpansion() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        model.phase = .running
        let item = UIItem(
            id: "reasoning-running",
            lifecycle: "inProgress",
            kind: "reasoning",
            text: "Planning app launch"
        )
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-running",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        let store = RecordingDisclosureStore()
        let cell = ReasoningCellView()
        cell.disclosureStore = store
        cell.configure(row: row, width: 620, model: model)
        let button = try XCTUnwrap(cell.allDescendants(ofType: NSButton.self).first)
        XCTAssertEqual(button.state, .on)

        button.state = .off
        let action = try XCTUnwrap(button.action)
        let target = try XCTUnwrap(button.target as? NSObject)
        _ = target.perform(action, with: button)

        let reconfigured = ReasoningCellView()
        reconfigured.disclosureStore = store
        reconfigured.configure(row: row, width: 620, model: model)
        XCTAssertEqual(
            reconfigured.allDescendants(ofType: NSButton.self).first?.state,
            .off
        )
    }
}
