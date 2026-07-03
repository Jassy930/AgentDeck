import XCTest
@testable import AgentDeckMobile

@MainActor
final class MachineListViewModelTests: XCTestCase {
    func testLoadsMachinesFromFixture() async {
        let source = FixtureSessionSource(bundle: Bundle(for: MachineListViewController.self), tickScale: 0)
        let vm = MachineListViewModel(source: source)
        let updated = expectation(description: "updated")
        vm.onUpdate = { if !vm.machines.isEmpty { updated.fulfill() } }
        vm.start()
        await fulfillment(of: [updated], timeout: 2)
        XCTAssertEqual(vm.machines.count, 2)
        XCTAssertEqual(vm.machines.first?.name, "Mac Studio")
    }
}
