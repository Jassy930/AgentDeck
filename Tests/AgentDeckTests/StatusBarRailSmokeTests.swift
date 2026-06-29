import XCTest
import AppKit
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
        view.frame = CGRect(x: 0, y: 0, width: 28, height: 400)
        view.layoutSubtreeIfNeeded()
        XCTAssertGreaterThan(view.bounds.height, 0)
    }
}
