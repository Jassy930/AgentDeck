import XCTest
import AppKit
@testable import AgentDeck

@MainActor
final class HistorySidebarUnifiedHistoryTests: XCTestCase {
    func testSidebarDoesNotExposeAgentKindSwitch() {
        let model = SessionModel()
        let vc = HistorySidebarViewController(model: model)
        _ = vc.view

        let segments = Self.allViews(vc.view).compactMap { $0 as? NSSegmentedControl }
        XCTAssertTrue(segments.isEmpty, "History sidebar should show all agent threads without an agent-kind switch")
    }

    func testThreadRowDoesNotDisplayAgentKindInLeftSidebar() {
        let row = HistoryThreadRowView()
        let thread = HistoryThreadSummary(
            id: "cc-1",
            name: "Unified history",
            preview: "preview",
            cwd: "/tmp/project",
            createdAt: 0,
            updatedAt: 0,
            status: "ready",
            modelProvider: "anthropic",
            source: "claude_code",
            agentKind: .claudeCode
        )
        let presentation = HistoryThreadRowPresentation(
            threadId: thread.id,
            selectedThreadId: nil,
            openingThreadId: nil,
            hoveredThreadId: nil,
            runtimePhase: nil
        )

        row.configure(with: thread, presentation: presentation)

        let views = Self.allViews(row)
        XCTAssertFalse(
            views.contains { $0 is NSImageView },
            "History rows should not use agent-specific icons in the left sidebar"
        )

        let visibleText = views
            .compactMap { $0 as? NSTextField }
            .map(\.stringValue)
            .joined(separator: "\n")
        XCTAssertFalse(visibleText.contains("Codex"))
        XCTAssertFalse(visibleText.contains("Claude Code"))
        XCTAssertFalse(visibleText.contains("claude_code"))
    }

    private static func allViews(_ root: NSView) -> [NSView] {
        var result = [root]
        for subview in root.subviews {
            result += allViews(subview)
        }
        if let scrollView = root as? NSScrollView, let documentView = scrollView.documentView {
            result += allViews(documentView)
        }
        return result
    }
}
