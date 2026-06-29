import XCTest
@testable import AgentDeck

@MainActor
final class ConversationViewControllerSmokeTests: XCTestCase {
    /// Constructing the controller and accessing `.view` (which triggers
    /// `loadView`) must not crash and must NOT spawn `agentdeckd` — `SessionModel()`
    /// only builds a `DaemonClient`, whose transport stays dormant until
    /// `start()` (never called here), exactly like the existing IpcTests.
    func testConstructsAndLoadsView() {
        let model = SessionModel()
        let vc = ConversationViewController(model: model)
        XCTAssertNotNil(vc.view)
    }
}
