import XCTest
@testable import AgentDeckMobile

@MainActor
final class SessionListViewModelTests: XCTestCase {
    func testGroupsOrderedAndFiltered() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = SessionListViewModel(source: source, machineID: "mac-studio")
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.groups.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.groups.map(\.group), [.waitingApproval, .active, .recent])
        XCTAssertEqual(vm.groups.first?.sessions.map(\.id), ["sess-approval-01"])
    }
}
