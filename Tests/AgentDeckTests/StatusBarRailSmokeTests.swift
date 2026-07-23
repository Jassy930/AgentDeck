import XCTest
import AppKit
import AgentDeckCore
@testable import AgentDeck

/// Smoke tests for StatusBarView and TurnJumpRailView (Task 10).
/// Constructing both views and accessing them must not crash
/// and must NOT spawn `agentdeckd` — `SessionModel()` only builds a
/// `DaemonClient` whose transport stays dormant until `start()` is called
/// (never called here), exactly like ConversationViewControllerSmokeTests /
/// HistorySidebarSmokeTests.
@MainActor
final class StatusBarRailSmokeTests: XCTestCase {

    // MARK: - StatusBarView

    func testStatusBarViewConstructsWithoutCrash() {
        let model = SessionModel()
        let view = StatusBarView(model: model)
        XCTAssertNotNil(view)
    }

    func testStatusBarViewHasSubviews() {
        let model = SessionModel()
        let view = StatusBarView(model: model)
        XCTAssertFalse(view.subviews.isEmpty, "StatusBarView must add subviews during init")
    }

    func testStatusBarViewSizesToFit() {
        let model = SessionModel()
        let view = StatusBarView(model: model)
        view.frame = CGRect(x: 0, y: 0, width: 600, height: 36)
        view.layoutSubtreeIfNeeded()
        XCTAssertGreaterThan(view.bounds.width, 0)
    }

    // MARK: - TurnJumpRailView

    func testTurnJumpRailViewConstructsWithoutCrash() {
        let model = SessionModel()
        let view = TurnJumpRailView(model: model)
        XCTAssertNotNil(view)
    }

    func testTurnJumpRailViewSyncSelectionDoesNotCrash() {
        let model = SessionModel()
        let view = TurnJumpRailView(model: model)
        // nil selection (latest)
        view.syncSelection(topVisibleTurnId: nil)
        // non-nil (no matching turn — should be a no-op, not a crash)
        view.syncSelection(topVisibleTurnId: "turn-1")
    }

    func testTurnJumpRailViewCallbacksWire() {
        let model = SessionModel()
        let view = TurnJumpRailView(model: model)
        var receivedTurn: String?
        var jumpedToLatest = false
        view.onSelectTurn = { receivedTurn = $0 }
        view.onJumpToLatest = { jumpedToLatest = true }
        XCTAssertNil(receivedTurn, "onSelectTurn must not fire during construction")
        XCTAssertFalse(jumpedToLatest, "onJumpToLatest must not fire during construction")
    }

    func testTurnJumpRailViewSizesToFit() {
        let model = SessionModel()
        let view = TurnJumpRailView(model: model)
        view.frame = CGRect(x: 0, y: 0, width: TurnJumpRailLayout.width, height: 400)
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(TurnJumpRailLayout.width, 44, "轨道尾列应保持 44pt 布局宽度")
        XCTAssertGreaterThan(view.bounds.height, 0)
    }

    func testTurnJumpRailLeavesTrailingWindowResizeGutter() throws {
        let view = TurnJumpRailView(model: SessionModel())
        view.frame = NSRect(x: 0, y: 0, width: TurnJumpRailLayout.width, height: 400)
        view.layoutSubtreeIfNeeded()
        let expectedInteractiveWidth = TurnJumpRailLayout.width - 8

        let interaction = try XCTUnwrap(
            view.firstDescendant(ofType: RailInteractionNSView.self)
        )
        XCTAssertEqual(
            interaction.frame.width,
            expectedInteractiveWidth,
            accuracy: 0.5,
            "回合导航必须为窗口右缘保留原生缩放命中区"
        )
        XCTAssertTrue(
            view.hitTest(NSPoint(x: expectedInteractiveWidth - 1, y: 200))
                === interaction,
            "缩放区左侧仍应保持完整的轨道交互"
        )
        XCTAssertNil(
            view.hitTest(NSPoint(x: TurnJumpRailLayout.width - 1, y: 200)),
            "窗口最右侧不能被轨道吞掉，必须交还给原生缩放"
        )
    }

    func testTurnJumpRailSummaryBubbleClampsInsideNarrowContainer() {
        let frame = TurnJumpRailLayout.summaryBubbleFrame(
            preferredSize: CGSize(width: 280, height: 28),
            targetPoint: CGPoint(x: 278, y: 100),
            railFrame: CGRect(x: 256, y: 0, width: 44, height: 400),
            containerBounds: CGRect(x: 0, y: 0, width: 300, height: 400)
        )

        XCTAssertEqual(frame.width, 244, accuracy: 0.5)
        XCTAssertGreaterThanOrEqual(
            frame.minX,
            4,
            "300pt 内容面板中的摘要气泡不得越出容器左边界"
        )
        XCTAssertLessThanOrEqual(frame.maxX, 248, "摘要气泡与轨道视觉应保留间距")
    }

    func testTurnJumpRailKeyboardNavigationMapping() {
        XCTAssertEqual(RailInteractionNSView.keyboardCommand(for: 126), .previous)
        XCTAssertEqual(RailInteractionNSView.keyboardCommand(for: 125), .next)
        XCTAssertEqual(RailInteractionNSView.keyboardCommand(for: 115), .first)
        XCTAssertEqual(RailInteractionNSView.keyboardCommand(for: 119), .latest)
        XCTAssertNil(RailInteractionNSView.keyboardCommand(for: 0))
    }

    func testTurnJumpRailExposesAccessibilityNavigation() throws {
        let view = TurnJumpRailView(model: SessionModel())
        view.frame = NSRect(x: 0, y: 0, width: TurnJumpRailLayout.width, height: 400)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 400),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView?.addSubview(view)
        view.layoutSubtreeIfNeeded()

        XCTAssertEqual(view.accessibilityIdentifier(), "turn-jump-rail")
        XCTAssertEqual(view.accessibilityRole(), .group)
        XCTAssertEqual(view.accessibilityLabel(), "对话回合导航")
        XCTAssertEqual(view.accessibilityCustomActions()?.count, 3)
        let interaction = try XCTUnwrap(view.firstDescendant(ofType: RailInteractionNSView.self))
        XCTAssertNotEqual(
            interaction.focusRingType,
            .none,
            "键盘聚焦轨道时必须有可见焦点环"
        )
        XCTAssertTrue(window.makeFirstResponder(interaction))
        XCTAssertTrue(window.firstResponder === interaction)
        XCTAssertFalse(interaction.focusRingMaskBounds.isEmpty)
    }

    func testTurnJumpRailLoadsExistingTurnsAndAccessibilityActionNavigates() throws {
        let model = SessionModel()
        model.items = [
            UIItem(id: "u1", lifecycle: "completed", kind: "user", text: "第一回合"),
            UIItem(id: "u2", lifecycle: "completed", kind: "user", text: "第二回合"),
        ]
        let view = TurnJumpRailView(model: model)
        var selectedTurnId: String?
        view.onSelectTurn = { selectedTurnId = $0 }

        let previous = try XCTUnwrap(
            view.accessibilityCustomActions()?.first { $0.name == "上一个回合" }
        )
        _ = (previous.target as? NSObject)?.perform(previous.selector)

        XCTAssertEqual(selectedTurnId, "u2", "从最新位置执行 VoiceOver 上一回合应落到最后一个真实回合")
    }
}
