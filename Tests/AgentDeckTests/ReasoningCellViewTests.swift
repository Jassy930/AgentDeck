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

    func testExpandedReasoningUsesFullConversationWidth() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let item = UIItem(
            id: "reasoning-full-width",
            lifecycle: "completed",
            kind: "reasoning",
            text: "Planning targeted documentation and code inspection before implementing the layout fix."
        )
        let row = ConversationDisplayRow(
            role: .assistantItem,
            turnId: "turn-reasoning",
            item: item,
            firstInTurn: true,
            lastInTurn: true
        )
        let store = RecordingDisclosureStore()
        store.expandedItemIds.insert(item.id)

        let width: CGFloat = 620
        let cell = ReasoningCellView(
            frame: NSRect(x: 0, y: 0, width: width, height: 240)
        )
        cell.disclosureStore = store
        cell.configure(row: row, width: width, model: model)
        cell.layoutSubtreeIfNeeded()

        let body = try XCTUnwrap(
            cell.allDescendants(ofType: StreamingTextContainerView.self).first
        )
        let expectedContentWidth = width - ConversationRowCellView.horizontalInset * 2
        XCTAssertEqual(cell.contentStack.frame.width, expectedContentWidth, accuracy: 1)
        XCTAssertEqual(body.frame.width, expectedContentWidth, accuracy: 1)
    }

    func testExpandedReasoningUsesDesignTypographyAndRendersMarkdown() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let row = ConversationDisplayRowTestSupport.assistantRow(
            kind: "reasoning",
            text: "先 **梳理** 依赖"
        )
        let store = RecordingDisclosureStore()
        store.expandedItemIds.insert(row.item.id)
        let cell = ReasoningCellView(
            frame: NSRect(x: 0, y: 0, width: 620, height: 160)
        )
        cell.disclosureStore = store
        cell.configure(row: row, width: 620, model: model)

        let body = try XCTUnwrap(
            cell.allDescendants(ofType: StreamingTextContainerView.self).first
        )
        XCTAssertEqual(body.currentText, "先 梳理 依赖")
        XCTAssertFalse(body.currentText.contains("**"))

        let attributed = body.currentAttributedText
        let ns = attributed.string as NSString
        let plainRange = ns.range(of: "先")
        let boldRange = ns.range(of: "梳理")
        let plainFont = try XCTUnwrap(
            attributed.attribute(.font, at: plainRange.location, effectiveRange: nil) as? NSFont
        )
        let boldFont = try XCTUnwrap(
            attributed.attribute(.font, at: boldRange.location, effectiveRange: nil) as? NSFont
        )
        let color = try XCTUnwrap(
            attributed.attribute(.foregroundColor, at: plainRange.location, effectiveRange: nil)
                as? NSColor
        )
        let paragraph = try XCTUnwrap(
            attributed.attribute(.paragraphStyle, at: plainRange.location, effectiveRange: nil)
                as? NSParagraphStyle
        )

        XCTAssertEqual(plainFont.pointSize, DesignTokens.typeCallout)
        XCTAssertEqual(boldFont.pointSize, DesignTokens.typeCallout)
        XCTAssertTrue(boldFont.fontDescriptor.symbolicTraits.contains(.bold))
        XCTAssertTrue(color.isEqual(DesignTokens.text2))
        XCTAssertEqual(
            paragraph.minimumLineHeight,
            DesignTokens.typeCallout * DesignTokens.lineHeightCJK,
            accuracy: 0.001
        )
        XCTAssertEqual(cell.verticalPadding, DesignTokens.sp1)
        XCTAssertEqual(cell.contentStack.spacing, DesignTokens.sp1)
    }

    func testCollapsedReasoningFactoryHeightUsesFourPointItemPadding() {
        let row = ConversationDisplayRowTestSupport.assistantRow(
            kind: "reasoning",
            text: "Inspect dependencies"
        )
        let headerHeight = max(
            ConversationRowMetrics.lineHeight(ConversationRowMetrics.monoCaptionFont),
            16
        )

        XCTAssertEqual(
            ConversationRowFactory.height(for: row, width: 620),
            DesignTokens.sp1 * 2 + headerHeight,
            accuracy: 0.001
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
