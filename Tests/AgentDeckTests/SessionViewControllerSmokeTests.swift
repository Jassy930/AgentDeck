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
