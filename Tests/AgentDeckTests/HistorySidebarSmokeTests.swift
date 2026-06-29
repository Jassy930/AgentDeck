import XCTest
@testable import AgentDeck

@MainActor
final class HistorySidebarSmokeTests: XCTestCase {
    /// Constructing the VC and accessing `.view` (which triggers `loadView`)
    /// must not crash and must NOT spawn `agentdeckd` — `SessionModel()`
    /// only builds a `DaemonClient` whose transport stays dormant until
    /// `start()` (never called here), exactly like the existing IpcTests /
    /// ConversationViewControllerSmokeTests.
    func testConstructsAndLoadsView() {
        let model = SessionModel()
        let vc = HistorySidebarViewController(model: model)
        XCTAssertNotNil(vc.view)
    }

    func testOutlineViewIsPresent() {
        let model = SessionModel()
        let vc = HistorySidebarViewController(model: model)
        // Trigger loadView
        _ = vc.view
        // The VC must expose an NSOutlineView in its view hierarchy.
        func findOutline(in view: NSView) -> NSOutlineView? {
            if let ov = view as? NSOutlineView { return ov }
            for sub in view.subviews {
                if let found = findOutline(in: sub) { return found }
            }
            return nil
        }
        // Look inside the scroll view's document view as well
        func allViews(_ root: NSView) -> [NSView] {
            var result = [root]
            for s in root.subviews { result += allViews(s) }
            if let sv = root as? NSScrollView, let doc = sv.documentView {
                result += allViews(doc)
            }
            return result
        }
        let hasOutline = allViews(vc.view).contains { $0 is NSOutlineView }
        XCTAssertTrue(hasOutline, "Expected NSOutlineView in view hierarchy")
    }
}
