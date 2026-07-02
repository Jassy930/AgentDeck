import XCTest
import AppKit
@testable import AgentDeck

/// End-to-end smoke tests: verify the main window assembly components can be
/// instantiated and wired without crashing, using stub models so no daemon is needed.
@MainActor
final class EndToEndWindowAssemblyTests: XCTestCase {

    // MARK: - StatusBarView

    func testStatusBarViewBuildsWithoutModel() {
        let bar = StatusBarView()
        XCTAssertNotNil(bar)
        // Ensure subviews exist (at least dot + icon + label)
        XCTAssertFalse(bar.subviews.isEmpty)
    }

    func testStatusBarBindAgentKindCodex() {
        let bar = StatusBarView()
        bar.bind(agentKind: .codex)
        let imageViews = bar.subviews.compactMap { $0 as? NSImageView }
        // At least one NSImageView should have an image after binding
        XCTAssertFalse(imageViews.isEmpty)
    }

    func testStatusBarBindAgentKindNilHidesIcon() {
        let bar = StatusBarView()
        bar.bind(agentKind: .codex)  // show first
        bar.bind(agentKind: nil)     // then hide
        let imageViews = bar.subviews.compactMap { $0 as? NSImageView }
        // All image views should be hidden or have no image
        let visibleWithImage = imageViews.filter { !$0.isHidden && $0.image != nil }
        XCTAssertTrue(visibleWithImage.isEmpty)
    }

    // MARK: - InputBarView

    func testInputBarBuildsWithoutModel() {
        let bar = InputBarView()
        XCTAssertNotNil(bar)
    }

    func testInputBarPlanModeToggle() {
        let bar = InputBarView()
        bar.applyState(planMode: true)
        let labels = bar.allTextFields()
        let planVisible = labels.contains(where: { $0.stringValue.contains("Plan") && !$0.isHidden })
        XCTAssertTrue(planVisible, "Plan badge should be visible when planMode=true")
    }

    func testInputBarPlanModeHidden() {
        let bar = InputBarView()
        bar.applyState(planMode: false)
        let labels = bar.allTextFields()
        let planVisible = labels.contains(where: { $0.stringValue.contains("Plan") && !$0.isHidden })
        XCTAssertFalse(planVisible, "Plan badge should be hidden when planMode=false")
    }

    // MARK: - SessionModel + HistoryThreadSummary agentKind field

    func testHistoryThreadSummaryCarriesAgentKind() {
        let thread = HistoryThreadSummary(
            id: "t1",
            name: "Test",
            preview: "preview",
            cwd: "/tmp",
            createdAt: 0,
            updatedAt: 0,
            status: "ready",
            modelProvider: "openai",
            source: "codex",
            agentKind: .codex
        )
        XCTAssertEqual(thread.agentKind, .codex)
    }

    func testHistoryThreadSummaryClaudeCode() {
        let thread = HistoryThreadSummary(
            id: "t2",
            name: "CC Thread",
            preview: "preview",
            cwd: "/tmp",
            createdAt: 0,
            updatedAt: 0,
            status: "ready",
            modelProvider: "anthropic",
            source: "claude_code",
            agentKind: .claudeCode
        )
        XCTAssertEqual(thread.agentKind, .claudeCode)
    }
}

private extension NSView {
    func allTextFields() -> [NSTextField] {
        var fields = subviews.compactMap { $0 as? NSTextField }
        for subview in subviews {
            fields.append(contentsOf: subview.allTextFields())
        }
        return fields
    }
}
