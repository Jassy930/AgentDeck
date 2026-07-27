import AgentDeckCore
import AgentDeckSessionSource
import XCTest

@testable import AgentDeckMobile

@MainActor
final class SessionListViewModelTests: XCTestCase {
    func testGroupsTypedReadyAndStaleValuesInProductOrder() async {
        let source = SessionSourceSpy()
        let vm = SessionListViewModel(source: source, machineID: "machine-1")
        vm.start()
        vm.start()
        await source.waitForConversationListSubscriptions(1)
        let subscriptionCount = await source.conversationListSubscriptionCount()
        XCTAssertEqual(subscriptionCount, 1)

        let sessions = [
            makeConversation(id: "recent", group: .recent),
            makeConversation(id: "approval", group: .waitingApproval),
            makeConversation(id: "active", group: .active),
        ]
        await source.emitConversations(.ready(value: sessions, revision: 9))
        await waitForMainActorState { vm.groups.count == 3 }
        XCTAssertEqual(vm.groups.map(\.group), [.waitingApproval, .active, .recent])
        XCTAssertEqual(vm.groups.first?.sessions.map(\.id), ["approval"])

        await source.emitConversations(.stale(value: sessions, reason: .reconnecting))
        await waitForMainActorState {
            if case .stale = vm.resourceState { return true }
            return false
        }
        XCTAssertEqual(vm.groups.flatMap(\.sessions).count, 3)
        guard case .stale(_, let reason) = vm.resourceState else {
            return XCTFail("应保留 stale resource state")
        }
        XCTAssertEqual(reason, .reconnecting)
    }

    func testRetryableFailedStateClearsReadyGroupsAndPublishesUpdate() async {
        let source = SessionSourceSpy()
        let vm = SessionListViewModel(source: source, machineID: "machine-1")
        var updateCount = 0
        vm.onUpdate = { updateCount += 1 }
        vm.start()
        await source.waitForConversationListSubscriptions(1)

        let conversation = makeConversation(id: "active", group: .active)
        await source.emitConversations(.ready(value: [conversation], revision: 9))
        await waitForMainActorState { vm.groups.count == 1 }
        let readyUpdateCount = updateCount

        let failure = SessionSourceFailure(code: .revoked, message: "device revoked")
        await source.emitConversations(.failed(error: failure, retryable: true))
        await waitForMainActorState {
            vm.groups.isEmpty && updateCount == readyUpdateCount + 1
        }

        XCTAssertTrue(vm.groups.isEmpty)
        XCTAssertEqual(updateCount, readyUpdateCount + 1)
        guard case .failed(let observedFailure, let retryable) = vm.resourceState else {
            return XCTFail("failed 必须替换旧 ready 分组并保持错误")
        }
        XCTAssertEqual(observedFailure, failure)
        XCTAssertTrue(retryable)
    }

    func testDeinitCancelsConversationListObservation() async {
        let source = SessionSourceSpy()
        weak var releasedViewModel: SessionListViewModel?
        do {
            let vm = SessionListViewModel(source: source, machineID: "machine-1")
            releasedViewModel = vm
            vm.start()
            await source.waitForConversationListSubscriptions(1)
        }

        await source.waitForConversationListTerminations(1)
        XCTAssertNil(releasedViewModel)
    }

    private func makeConversation(
        id: String,
        group: ConversationGroup
    ) -> ConversationSummary {
        ConversationSummary(
            id: id,
            machineID: "machine-1",
            title: id,
            cwd: "/tmp",
            agentKind: .codex,
            group: group,
            lastActiveMs: 1,
            archived: false,
            revision: 1
        )
    }
}
