import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

@MainActor
final class InboxViewModelTests: XCTestCase {
    func testInboxConsumesTypedStatesAndKeepsStaleValue() async {
        let source = SessionSourceSpy()
        let vm = InboxViewModel(source: source)
        vm.start()
        vm.start()
        await source.waitForInboxSubscriptions(1)
        let subscriptionCount = await source.inboxSubscriptionCount()
        XCTAssertEqual(subscriptionCount, 1)

        let item = InboxItem(
            id: "inbox-1",
            conversationID: "conversation-1",
            machineID: "machine-1",
            kind: .waitingApproval,
            title: "等待审批"
        )
        await source.emitInbox(.ready(value: [item], revision: 3))
        await waitForMainActorState { vm.items == [item] }
        XCTAssertEqual(vm.items.first?.conversationID, "conversation-1")

        await source.emitInbox(.stale(value: [item], reason: .relayUnavailable))
        await waitForMainActorState {
            if case .stale = vm.resourceState { return true }
            return false
        }
        XCTAssertEqual(vm.items, [item])
    }

    func testRetryableFailedStateClearsReadyInboxItemsAndPublishesUpdate() async {
        let source = SessionSourceSpy()
        let vm = InboxViewModel(source: source)
        var updateCount = 0
        vm.onUpdate = { updateCount += 1 }
        vm.start()
        await source.waitForInboxSubscriptions(1)

        let item = InboxItem(
            id: "inbox-1",
            conversationID: "conversation-1",
            machineID: "machine-1",
            kind: .waitingApproval,
            title: "等待审批"
        )
        await source.emitInbox(.ready(value: [item], revision: 3))
        await waitForMainActorState { vm.items == [item] }
        let readyUpdateCount = updateCount

        let failure = SessionSourceFailure(code: .incompatible, message: "upgrade required")
        await source.emitInbox(.failed(error: failure, retryable: true))
        await waitForMainActorState {
            vm.items.isEmpty && updateCount == readyUpdateCount + 1
        }

        XCTAssertTrue(vm.items.isEmpty)
        XCTAssertEqual(updateCount, readyUpdateCount + 1)
        guard case .failed(let observedFailure, let retryable) = vm.resourceState else {
            return XCTFail("failed 必须替换旧 ready 收件箱并保持错误")
        }
        XCTAssertEqual(observedFailure, failure)
        XCTAssertTrue(retryable)
    }

    func testDeinitCancelsInboxObservation() async {
        let source = SessionSourceSpy()
        weak var releasedViewModel: InboxViewModel?
        do {
            let vm = InboxViewModel(source: source)
            releasedViewModel = vm
            vm.start()
            await source.waitForInboxSubscriptions(1)
        }

        await source.waitForInboxTerminations(1)
        XCTAssertNil(releasedViewModel)
    }
}
