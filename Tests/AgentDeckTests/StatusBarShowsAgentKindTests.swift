import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class StatusBarShowsAgentKindTests: XCTestCase {
    func testStatusBarShowsCodexIcon() {
        let bar = StatusBarView()
        bar.bind(agentKind: .codex)
        // assert at least one NSImageView with an image (icon)
        let imageViews = bar.subviews.compactMap { $0 as? NSImageView }
        XCTAssertFalse(imageViews.isEmpty)
    }
    func testInputBarShowsPlanBadgeWhenPlanMode() {
        let bar = InputBarView()
        bar.applyState(planMode: true)
        let labels = bar.allTextFields()
        XCTAssertTrue(labels.contains(where: { $0.stringValue.contains("Plan") }))
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
