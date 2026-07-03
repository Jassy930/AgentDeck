import XCTest
@testable import AgentDeckMobile

@MainActor
final class InboxViewModelTests: XCTestCase {
    func testInboxSeededWithPendingApproval() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = InboxViewModel(source: source)
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.items.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.items.first?.kind, .waitingApproval)
        XCTAssertEqual(vm.items.first?.sessionID, "sess-approval-01")
    }
}
