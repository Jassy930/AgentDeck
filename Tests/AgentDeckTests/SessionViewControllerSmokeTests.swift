import AgentDeckCore
import AppKit
import XCTest

@testable import AgentDeck

/// Smoke tests for SessionViewController (Task 11).
///
/// Constructing the controller and accessing `.view` must NOT crash and must
/// NOT connect to `agentdeckd`。测试注入 dormant Runtime v2 wire，确保构造与布局
/// 不依赖 OS-account shared-daemon 环境。
@MainActor
final class SessionViewControllerSmokeTests: XCTestCase {

  private func makeModel() -> SessionModel {
    SessionModel(runtimeWire: SessionViewDormantRuntimeWire())
  }

  // MARK: - Construction

  func testConstructsAndLoadsView() {
    let model = makeModel()
    let vc = SessionViewController(model: model)
    XCTAssertNotNil(vc.view, "loadView must not crash and must return a view")
  }

  func testViewHasSubviews() {
    let model = makeModel()
    let vc = SessionViewController(model: model)
    XCTAssertFalse(vc.view.subviews.isEmpty, "Root view must contain subviews after loadView")
  }

  // MARK: - Empty state (cwd == nil)

  func testEmptyStateShownWhenNoCwd() {
    let model = makeModel()
    // model.cwd is nil by default
    XCTAssertNil(model.cwd)
    let vc = SessionViewController(model: model)
    _ = vc.view  // trigger loadView
    // No assertion beyond "no crash"; the pane swap is internal.
  }

  // MARK: - ConversationViewController scroll methods

  func testScrollToTurnDoesNotCrashWithEmptyData() {
    let model = makeModel()
    let convVC = ConversationViewController(model: model)
    _ = convVC.view  // trigger loadView
    // No rows loaded — scrollToTurn should be a silent no-op
    convVC.scrollToTurn("nonexistent-turn-id")
  }

  func testScrollToLatestDoesNotCrashWithEmptyData() {
    let model = makeModel()
    let convVC = ConversationViewController(model: model)
    _ = convVC.view
    convVC.scrollToLatest()
  }

  // MARK: - Initial history auto-refresh on appear

  /// Regression for the AppKit cutover (83e8853) dropping the SwiftUI
  /// `.onAppear { model.loadHistoryOnAppear() }`, which left the initial
  /// history scan never firing — persisted sessions only showed after a
  /// manual Refresh。dormant Runtime wire 会 fail-close；这里只断言一次性 guard 被消费。
  func testViewDidAppearTriggersInitialHistoryRefresh() {
    let model = makeModel()
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
    let model = makeModel()
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
    let model = makeModel()
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
    let model = makeModel()
    let vc = SessionViewController(model: model)
    _ = vc.view
    // After loadView, the VC should have at least the split VC + conversationVC
    // as children (addChild was called for both).
    XCTAssertFalse(vc.children.isEmpty, "SessionViewController must embed child VCs")
  }
}

private enum SessionViewDormantRuntimeWireError: Error {
  case unexpectedUse
}

private struct SessionViewDormantRuntimeWire: AppRuntimeWireSession {
  func start() async throws {
    throw SessionViewDormantRuntimeWireError.unexpectedUse
  }

  func request(_ request: RuntimeRequestV2) async throws -> RuntimeReplyV2 {
    throw SessionViewDormantRuntimeWireError.unexpectedUse
  }

  func beginAppSynchronizedRequest(
    _ request: RuntimeRequestV2
  ) async throws -> any AppRuntimeWireReplySequence {
    throw SessionViewDormantRuntimeWireError.unexpectedUse
  }

  func nextStream() async throws -> LocalRuntimeStreamFrame {
    throw SessionViewDormantRuntimeWireError.unexpectedUse
  }

  func close() async {}
}
