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

    func testThreadRowShowsAgentIconButNoAgentText() {
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
        // 设计系统：侧栏会话行显示 agent 图标（数据→图像映射，非 vendor 分支）
        XCTAssertTrue(
            views.contains { ($0 as? NSImageView)?.image != nil },
            "History rows should show the agent icon per the design system"
        )

        // 但仍不显示 agent kind 文字（保持列表中性、避免文案噪声）
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
