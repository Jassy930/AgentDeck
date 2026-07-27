import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

@MainActor
final class MachineListViewModelTests: XCTestCase {
    func testStartIsIdempotentAndConsumesTypedResourceState() async {
        let source = SessionSourceSpy()
        let vm = MachineListViewModel(source: source)

        vm.start()
        vm.start()
        await source.waitForMachineSubscriptions(1)
        let subscriptionCount = await source.machineSubscriptionCount()
        XCTAssertEqual(subscriptionCount, 1)
        guard case .loading(previous: nil) = vm.resourceState else {
            return XCTFail("初始状态必须是 loading(nil)")
        }

        let machine = makeMachine(id: "machine-ready", state: .connected)
        await source.emitMachines(.ready(value: [machine], revision: 7))
        await waitForMainActorState { vm.machines == [machine] }

        XCTAssertEqual(vm.machines, [machine])
        guard case .ready(let value, let revision) = vm.resourceState else {
            return XCTFail("应保留 ready resource state")
        }
        XCTAssertEqual(value, [machine])
        XCTAssertEqual(revision, 7)
    }

    func testMachineRowsDistinguishAllRequiredConnectionFailures() {
        let cases: [(SessionConnectionState, String, Bool)] = [
            (.relayUnavailable, "Relay 不可达", false),
            (.machineOffline, "机器离线", false),
            (.reconnecting, "正在重连", false),
            (.revoked, "授权已撤销", false),
            (.incompatible, "版本不兼容", false),
            (.securityError, "安全错误", false),
        ]

        for (state, expectedText, expectedSelectable) in cases {
            let presentation = MachineRowPresentation.make(
                from: makeMachine(id: expectedText, state: state)
            )
            XCTAssertEqual(presentation.statusText, expectedText)
            XCTAssertEqual(presentation.isSelectable, expectedSelectable)
        }
    }

    func testRetryableFailedStateClearsReadyMachinesAndPublishesUpdate() async {
        let source = SessionSourceSpy()
        let vm = MachineListViewModel(source: source)
        var updateCount = 0
        vm.onUpdate = { updateCount += 1 }
        vm.start()
        await source.waitForMachineSubscriptions(1)

        let machine = makeMachine(id: "machine-ready", state: .connected)
        await source.emitMachines(.ready(value: [machine], revision: 7))
        await waitForMainActorState { vm.machines == [machine] }
        let readyUpdateCount = updateCount

        let failure = SessionSourceFailure(code: .securityError, message: "invalid signature")
        await source.emitMachines(.failed(error: failure, retryable: true))
        await waitForMainActorState {
            vm.machines.isEmpty && updateCount == readyUpdateCount + 1
        }

        XCTAssertTrue(vm.machines.isEmpty)
        XCTAssertEqual(updateCount, readyUpdateCount + 1)
        guard case .failed(let observedFailure, let retryable) = vm.resourceState else {
            return XCTFail("failed 必须替换旧 ready 数据并保持错误")
        }
        XCTAssertEqual(observedFailure, failure)
        XCTAssertTrue(retryable)
    }

    func testDeinitCancelsMachineObservation() async {
        let source = SessionSourceSpy()
        weak var releasedViewModel: MachineListViewModel?
        do {
            let vm = MachineListViewModel(source: source)
            releasedViewModel = vm
            vm.start()
            await source.waitForMachineSubscriptions(1)
        }

        await source.waitForMachineTerminations(1)
        XCTAssertNil(releasedViewModel)
    }

    private func makeMachine(
        id: String,
        state: SessionConnectionState
    ) -> MachineSummary {
        MachineSummary(
            id: id,
            name: id,
            connectionState: state,
            lastHeartbeat: nil,
            activeConversationCount: 1,
            pendingApprovalCount: 0
        )
    }
}
