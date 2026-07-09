import XCTest
import AppKit
@testable import AgentDeck

/// Smoke tests for SessionViewController (Task 11).
///
/// Constructing the controller and accessing `.view` must NOT crash and must
/// NOT spawn `agentdeckd` — `SessionModel()` only builds a `DaemonClient`
/// whose transport stays dormant until `start()` is called (never called here),
/// exactly like ConversationViewControllerSmokeTests / HistorySidebarSmokeTests.
@MainActor
final class SessionViewControllerSmokeTests: XCTestCase {

    // MARK: - Construction

    func testConstructsAndLoadsView() {
        let model = SessionModel()
        let vc = SessionViewController(model: model)
        XCTAssertNotNil(vc.view, "loadView must not crash and must return a view")
    }

    func testViewHasSubviews() {
        let model = SessionModel()
        let vc = SessionViewController(model: model)
        XCTAssertFalse(vc.view.subviews.isEmpty, "Root view must contain subviews after loadView")
    }

    // MARK: - Empty state (cwd == nil)

    func testEmptyStateShownWhenNoCwd() {
        let model = SessionModel()
        // model.cwd is nil by default
        XCTAssertNil(model.cwd)
        let vc = SessionViewController(model: model)
        _ = vc.view  // trigger loadView
        // No assertion beyond "no crash"; the pane swap is internal.
    }

    // MARK: - ConversationViewController scroll methods

    func testScrollToTurnDoesNotCrashWithEmptyData() {
        let model = SessionModel()
        let convVC = ConversationViewController(model: model)
        _ = convVC.view  // trigger loadView
        // No rows loaded — scrollToTurn should be a silent no-op
        convVC.scrollToTurn("nonexistent-turn-id")
    }

    func testScrollToLatestDoesNotCrashWithEmptyData() {
        let model = SessionModel()
        let convVC = ConversationViewController(model: model)
        _ = convVC.view
        convVC.scrollToLatest()
    }

    // MARK: - Initial history auto-refresh on appear

    /// Regression for the AppKit cutover (83e8853) dropping the SwiftUI
    /// `.onAppear { model.loadHistoryOnAppear() }`, which left the initial
    /// history scan never firing — persisted sessions only showed after a
    /// manual Refresh. The nil-client test init keeps `loadHistory` from
    /// spawning `agentdeckd`; we only assert the one-shot guard was consumed.
    func testViewDidAppearTriggersInitialHistoryRefresh() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let vc = SessionViewController(model: model)
        _ = vc.view  // trigger loadView
        vc.viewDidAppear()

        XCTAssertFalse(
            model.shouldAutoRefreshHistoryOnAppear(),
            "viewDidAppear must consume the one-shot initial history auto-refresh"
        )
    }

    // MARK: - Window must not resize when a session opens

    /// Regression: the content pane is hosted in a window created via
    /// `NSWindow(contentViewController:)`, which sizes the window to the
    /// content view's Auto Layout `fittingSize`. The conversation pane used a
    /// fixed `width == 900` transcript constraint, inflating its fitting width
    /// to ~1620pt, so opening a session grew the 1280pt window. The transcript
    /// now fills the available pane width (still capped at 900), keeping the
    /// fitting size small so the window stays put.
    func testOpeningSessionDoesNotGrowWindowWidth() {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let vc = SessionViewController(model: model)
        let win = NSWindow(contentViewController: vc)
        win.styleMask.insert([.titled, .resizable, .fullSizeContentView])
        win.setContentSize(NSSize(width: 1280, height: 760))
        win.makeKeyAndOrderFront(nil)
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        let widthBefore = win.frame.width

        // Set cwd → swaps EmptyState → conversation pane (observation-driven,
        // so spin the runloop to let the pane swap and relayout settle).
        model.cwd = URL(fileURLWithPath: NSTemporaryDirectory())
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        let widthAfter = win.frame.width

        XCTAssertLessThanOrEqual(
            widthAfter, widthBefore + 0.5,
            "Opening a session must not grow the window (was \(widthBefore) → \(widthAfter))"
        )
    }

    func testDividerResizeSticksWithoutEventGuard() throws {
        let model = SessionModel(turnStarter: NoopRuntimeTurnStarter())
        let vc = SessionViewController(model: model)
        let win = NSWindow(contentViewController: vc)
        win.styleMask.insert([.titled, .resizable, .fullSizeContentView])
        win.setContentSize(NSSize(width: 1280, height: 760))
        win.makeKeyAndOrderFront(nil)
        defer { win.close() }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        let splitView = try XCTUnwrap(vc.view.firstDescendant(ofType: NSSplitView.self))
        splitView.setPosition(250, ofDividerAt: 0)
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        XCTAssertEqual(
            splitView.subviews.first?.frame.width ?? 0,
            250,
            accuracy: 1,
            "A valid divider position must remain effective without relying on NSApp.currentEvent"
        )

        model.cwd = URL(fileURLWithPath: NSTemporaryDirectory())
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))

        XCTAssertEqual(
            splitView.subviews.first?.frame.width ?? 0,
            250,
            accuracy: 1,
            "Opening the conversation pane must not let content fitting reclaim sidebar width"
        )
    }

    // MARK: - Child controllers

    func testSessionViewControllerHasChildControllers() {
        let model = SessionModel()
        let vc = SessionViewController(model: model)
        _ = vc.view
        // After loadView, the VC should have at least the split VC + conversationVC
        // as children (addChild was called for both).
        XCTAssertFalse(vc.children.isEmpty, "SessionViewController must embed child VCs")
    }
}
